//! WebRTC transport receiver: WebRTC with Nostr signaling
//!
//! This module handles receiving files over webrtc transport:
//! 1. Uses Nostr for WebRTC signaling
//! 2. Attempts direct P2P connection via STUN
//! 3. Manual signaling fallback via copy/paste

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::core::crypto::decrypt_chunk;
use crate::core::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
};

use crate::signaling::nostr::{create_receiver_signaling, NostrSignaling, SignalingMessage};
use crate::core::transfer::{
    find_available_filename, format_bytes, make_webrtc_abort_msg, make_webrtc_ack_msg,
    make_webrtc_proceed_msg, num_chunks, prompt_file_exists, FileExistsChoice, FileHeader,
    TransferType,
};

use crate::webrtc::common::{setup_data_channel_handlers, WebRtcPeer};
use crate::signaling::offline::ice_candidates_to_payloads;
use crate::core::wormhole::{decode_key, parse_code, PROTOCOL_WEBRTC};

/// Connection timeout for WebRTC handshake
const WEBRTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for extraction directory cleanup on interrupt
type ExtractDirCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Print transfer progress, handling zero-byte files safely
fn print_progress(bytes_received: u64, total_size: u64) {
    let percent = if total_size == 0 {
        100
    } else {
        (bytes_received as f64 / total_size as f64 * 100.0) as u32
    };
    print!(
        "\r   Progress: {}% ({}/{})",
        percent,
        format_bytes(bytes_received),
        format_bytes(total_size)
    );
    let _ = std::io::stdout().flush();
}

/// Set up Ctrl+C handler to clean up temp file.
fn setup_file_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                eprintln!("Interrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}

/// Set up Ctrl+C handler to clean up extraction directory.
fn setup_dir_cleanup_handler(cleanup_path: ExtractDirCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_dir_all(&path).await;
                eprintln!("Interrupted. Cleaned up extraction directory.");
            }
            std::process::exit(130);
        }
    });
}

/// Result of WebRTC connection attempt
enum WebRtcResult {
    Success,
    Failed(String),
}

/// Attempt WebRTC receive with Nostr signaling
async fn try_webrtc_receive(
    signaling: &NostrSignaling,
    sender_pubkey: &nostr_sdk::PublicKey,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<WebRtcResult> {
    eprintln!("Attempting WebRTC connection...");

    // Create WebRTC peer
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel BEFORE creating offer
    let _local_dc = rtc_peer.create_data_channel("file-transfer").await?;

    // Start listening for signaling messages
    let (mut signal_rx, signal_handle) = signaling.start_message_receiver();

    // Create and send offer to sender
    let offer = rtc_peer.create_offer().await?;
    rtc_peer.set_local_description(offer.clone()).await?;

    // Gather ICE candidates with retry logic
    eprintln!("Gathering ICE candidates...");
    let mut candidate_payloads;
    let mut attempt_count = 0;
    const MAX_ICE_GATHER_ATTEMPTS: usize = 2;

    loop {
        let candidates = rtc_peer
            .gather_ice_candidates(Duration::from_secs(10))
            .await?;
        candidate_payloads = ice_candidates_to_payloads(candidates);

        if !candidate_payloads.is_empty() {
            eprintln!("Gathered {} ICE candidates", candidate_payloads.len());
            break;
        }

        // No ICE candidates gathered
        attempt_count += 1;
        if attempt_count < MAX_ICE_GATHER_ATTEMPTS {
            log::warn!(
                "Warning: No ICE candidates gathered on attempt {}. Retrying...",
                attempt_count
            );
            // Brief delay before retry
            tokio::time::sleep(Duration::from_millis(500)).await;
        } else {
            // After all attempts exhausted, log and continue anyway
            // (relay fallback or STUN might still work with empty candidates)
            log::warn!(
                "Warning: Failed to gather any ICE candidates after {} attempts. \
                 Proceeding with empty candidate list - connection may fall back to relay servers.",
                MAX_ICE_GATHER_ATTEMPTS
            );
            break;
        }
    }

    signaling
        .publish_offer(sender_pubkey, &offer.sdp, candidate_payloads)
        .await?;
    eprintln!("Sent offer to sender");

    // Wait for answer with timeout
    eprintln!("Waiting for answer from sender...");
    let answer_result: Result<Option<WebRtcResult>> = timeout(WEBRTC_CONNECTION_TIMEOUT, async {
        loop {
            match signal_rx.recv().await {
                Some(SignalingMessage::Answer { sdp, .. }) => {
                    eprintln!("Received answer from sender");
                    let answer_sdp = RTCSessionDescription::answer(sdp.sdp)
                        .context("Failed to create answer SDP");
                    
                    // Set remote description first
                    match answer_sdp {
                        Ok(sdp) => {
                             if let Err(e) = rtc_peer.set_remote_description(sdp).await {
                                 break Err(anyhow::anyhow!("Failed to set remote description: {}", e));
                             }
                        },
                        Err(e) => break Err(e),
                    }

                    // Then add bundled ICE candidates with error propagation
                    eprintln!("Received {} bundled ICE candidates", sdp.candidates.len());
                    let mut candidate_error: Option<anyhow::Error> = None;
                    for candidate in sdp.candidates {
                        let candidate_init = RTCIceCandidateInit {
                            candidate: candidate.candidate,
                            sdp_mid: candidate.sdp_mid,
                            sdp_mline_index: candidate.sdp_m_line_index,
                            username_fragment: None,
                        };
                         if let Err(e) = rtc_peer.add_ice_candidate(candidate_init).await {
                             candidate_error = Some(anyhow::anyhow!("Failed to add bundled ICE candidate: {}", e));
                             break;
                         }
                    }

                    if let Some(err) = candidate_error {
                        break Err(err);
                    }

                    break Ok(None);
                }

                Some(_) => continue,
                None => {
                    break Err(anyhow::anyhow!("Signaling channel closed"));
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timeout waiting for answer"))
    .and_then(|r| r);

    // Handle the result
    match answer_result {
        Ok(Some(result)) => {
            // Early return case (e.g., relay fallback)
            signal_handle.abort();
            return Ok(result);
        }
        Ok(None) => {
            // Success case, continue
        }
        Err(e) => {
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(format!(
                "Failed to receive answer: {}",
                e
            )));
        }
    }



    // Take data channel receiver from peer
    let mut data_channel_rx = rtc_peer
        .take_data_channel_rx()
        .expect("Data channel receiver already taken");

    // Wait for data channel from sender
    eprintln!("Waiting for data channel from sender...");
    let data_channel = timeout(WEBRTC_CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for data channel"))?
        .context("Failed to receive data channel")?;

    // Set up message receiving
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    // Wait for data channel to be confirmed open
    match timeout(Duration::from_secs(10), open_rx).await {
        Ok(Ok(())) => {
            eprintln!("Data channel opened successfully");
        }
        Ok(Err(_)) => {
            // ice_receiver_handle removed
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(
                "Data channel failed to open".to_string(),
            ));
        }
        Err(_) => {
            // ice_receiver_handle removed
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(
                "Timeout waiting for data channel to open".to_string(),
            ));
        }
    }

    // Display connection info
    let conn_info = rtc_peer.get_connection_info().await;
    eprintln!("WebRTC connection established!");
    eprintln!("   Connection: {}", conn_info.connection_type);
    if let (Some(local), Some(remote)) = (&conn_info.local_address, &conn_info.remote_address) {
        eprintln!("   Local: {} -> Remote: {}", local, remote);
    }

    // Receive header message
    eprintln!("Receiving file information...");
    let header_msg = timeout(Duration::from_secs(30), async {
        while let Some(msg) = message_rx.recv().await {
            if !msg.is_empty() && msg[0] == 0 {
                return Ok(msg);
            }
        }
        Err(anyhow::anyhow!("Channel closed without header"))
    })
    .await
    .context("Timeout waiting for header")?
    .context("Failed to receive header")?;

    // Parse header message: [type(1)][len(4)][encrypted_header]
    if header_msg.len() < 5 {
        anyhow::bail!("Header message too short");
    }
    let encrypted_len =
        u32::from_be_bytes([header_msg[1], header_msg[2], header_msg[3], header_msg[4]]) as usize;
    if header_msg.len() < 5 + encrypted_len {
        anyhow::bail!("Header message truncated");
    }
    let encrypted_header = &header_msg[5..5 + encrypted_len];

    // Decrypt header
    let header_bytes = decrypt_chunk(key, 0, encrypted_header)?;
    let header = FileHeader::from_bytes(&header_bytes)?;

    eprintln!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    // Check file existence and get final output path (for files only)
    // This happens BEFORE data transfer, so user can cancel without wasting bandwidth
    let final_output_path = if header.transfer_type == TransferType::File {
        let output_path = output_dir.join(&header.filename);

        if output_path.exists() {
            // Prompt user in blocking context
            let path_clone = output_path.clone();
            let choice = tokio::task::spawn_blocking(move || prompt_file_exists(&path_clone))
                .await
                .context("Prompt task panicked")??;

            match choice {
                FileExistsChoice::Overwrite => {
                    tokio::fs::remove_file(&output_path)
                        .await
                        .context("Failed to remove existing file")?;
                    output_path
                }
                FileExistsChoice::Rename => {
                    let new_path = find_available_filename(&output_path);
                    eprintln!("Will save as: {}", new_path.display());
                    new_path
                }
                FileExistsChoice::Cancel => {
                    // Send encrypted ABORT signal to sender
                    let abort_msg = make_webrtc_abort_msg(key)?;
                    data_channel
                        .send(&Bytes::from(abort_msg))
                        .await
                        .context("Failed to send abort signal")?;
                    anyhow::bail!("Transfer cancelled by user");
                }
            }
        } else {
            output_path
        }
    } else {
        // For folders, we extract to a directory - handled separately
        output_dir.clone()
    };

    // Send encrypted confirmation to sender that we're ready to receive data
    let proceed_msg = make_webrtc_proceed_msg(key)?;
    data_channel
        .send(&Bytes::from(proceed_msg))
        .await
        .context("Failed to send proceed signal")?;
    eprintln!("Ready to receive data...");

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            receive_file_impl(&mut message_rx, &header, key, final_output_path, &data_channel).await?;
        }
        TransferType::Folder => {
            receive_folder_impl(message_rx, &header, key, Some(output_dir), &data_channel).await?;
        }
    }

    // Close connections and abort background tasks
    // ice_receiver_handle removed
    let _ = rtc_peer.close().await;
    signal_handle.abort();

    Ok(WebRtcResult::Success)
}



/// Receive a file or folder via webrtc transport
pub async fn receive_webrtc(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    if token.protocol != PROTOCOL_WEBRTC {
        anyhow::bail!("Expected webrtc protocol, got: {}", token.protocol);
    }

    // Extract webrtc-specific fields
    let sender_pubkey_hex = token
        .webrtc_sender_pubkey
        .clone()
        .context("Missing sender pubkey in wormhole code")?;
    let transfer_id = token
        .webrtc_transfer_id
        .clone()
        .context("Missing transfer ID in wormhole code")?;
    let relays = token
        .webrtc_relays
        .clone()
        .context("Missing relay list in wormhole code")?;
    let key_str = Some(token.key.as_str())
        .filter(|s| !s.is_empty())
        .context("Missing encryption key in wormhole code")?;
    let key = decode_key(key_str)
        .context("Failed to decode encryption key")?;

    // Parse sender public key
    let sender_pubkey: nostr_sdk::PublicKey = sender_pubkey_hex
        .parse()
        .context("Failed to parse sender public key")?;

    eprintln!("Encryption enabled");
    eprintln!("Connecting to sender: {}", sender_pubkey_hex);

    // Create Nostr signaling client
    eprintln!("Connecting to Nostr relays for signaling...");
    let signaling = create_receiver_signaling(&transfer_id, relays.clone()).await?;

    eprintln!("Receiver pubkey: {}", signaling.public_key().to_hex());

    // Send ready signal to sender - REMOVED (No backward compatibility)
    // signaling.publish_ready(&sender_pubkey).await?;
    // eprintln!("Sent ready signal to sender"); -- REMOVED

    // Try WebRTC transfer
    match try_webrtc_receive(&signaling, &sender_pubkey, &key, output_dir.clone()).await? {
        WebRtcResult::Success => {
            signaling.disconnect().await;
            eprintln!("Connection closed.");
            Ok(())
        }
        WebRtcResult::Failed(reason) => {
            signaling.disconnect().await;
            anyhow::bail!(
                "WebRTC connection failed: {}\n\n\
                 If direct P2P connection is not possible, ask the sender to try:\n  \
                 - Tor mode: wormhole-rs send-tor <file>\n  \
                 - Manual signaling: wormhole-rs send --manual-signaling <file>",
                reason
            );
        }
    }
}

/// Internal implementation for receiving a file via WebRTC
/// output_path is the final destination path (file existence already checked)
async fn receive_file_impl(
    message_rx: &mut mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_path: PathBuf,
    data_channel: &Arc<webrtc::data_channel::RTCDataChannel>,
) -> Result<()> {
    // Get output directory from path
    let output_dir = output_path.parent().unwrap_or(std::path::Path::new("."));

    // Create temp file in same directory
    let temp_file =
        NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
    let temp_path = temp_file.path().to_path_buf();

    // Set up cleanup handler
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_file_cleanup_handler(cleanup_path.clone());

    let mut temp_file = temp_file;

    // Receive chunks
    let total_chunks = num_chunks(header.file_size);
    let mut bytes_received = 0u64;

    eprintln!("Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let msg = timeout(Duration::from_secs(30), message_rx.recv())
            .await
            .context("Timeout waiting for chunk")?
            .context("Channel closed")?;

        if msg.is_empty() {
            continue;
        }

        match msg[0] {
            1 => {
                // Chunk message: [type(1)][chunk_num(8)][len(4)][encrypted_chunk]
                if msg.len() < 13 {
                    anyhow::bail!("Chunk message too short");
                }
                let chunk_num = u64::from_be_bytes([
                    msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
                ]);
                let encrypted_len =
                    u32::from_be_bytes([msg[9], msg[10], msg[11], msg[12]]) as usize;
                if msg.len() < 13 + encrypted_len {
                    anyhow::bail!("Chunk message truncated");
                }
                let encrypted_chunk = &msg[13..13 + encrypted_len];

                // Decrypt chunk
                let chunk = decrypt_chunk(key, chunk_num, encrypted_chunk)?;

                // Write to temp file
                temp_file
                    .write_all(&chunk)
                    .context("Failed to write chunk")?;

                bytes_received += chunk.len() as u64;

                // Progress update
                if chunk_num % 10 == 0 || bytes_received == header.file_size {
                    print_progress(bytes_received, header.file_size);
                }
            }
            2 => {
                // Done message
                eprintln!("\nTransfer complete signal received");
                break;
            }
            _ => {
                // Ignore other messages
            }
        }
    }

    // Clear cleanup path
    cleanup_path.lock().await.take();

    // Persist temp file to final path
    temp_file.flush().context("Failed to flush file")?;
    temp_file
        .persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

    eprintln!("\nFile received successfully!");
    eprintln!("Saved to: {}", output_path.display());

    // Send encrypted ACK
    let ack_msg = make_webrtc_ack_msg(key)?;
    data_channel
        .send(&Bytes::from(ack_msg))
        .await
        .context("Failed to send ACK")?;
    eprintln!("Sent confirmation to sender");

    Ok(())
}

/// Internal implementation for receiving a folder via WebRTC
async fn receive_folder_impl(
    message_rx: mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    data_channel: &Arc<webrtc::data_channel::RTCDataChannel>,
) -> Result<()> {
    eprintln!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    // Set up cleanup handler
    let cleanup_path: ExtractDirCleanup = Arc::new(Mutex::new(Some(extract_dir.clone())));
    setup_dir_cleanup_handler(cleanup_path.clone());

    eprintln!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Create streaming reader
    let runtime_handle = tokio::runtime::Handle::current();
    let reader = WebRtcStreamingReader::new(message_rx, *key, header.file_size, runtime_handle);

    // Extract tar archive in a blocking task
    let extract_dir_clone = extract_dir.clone();
    
    // We need to keep the reader alive for ACK sending if we wanted to drain it,
    // but here we just want to extract. We can't easily return the reader from spawn_blocking
    // and use it back in async context effectively if it consumed the receiver.
    // Actually, WebRtcStreamingReader owns the receiver.
    // If extraction finishes successfully, we assume transfer is done.
    
    let skipped_entries = tokio::task::spawn_blocking(move || {
        extract_tar_archive(reader, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    // Clear cleanup path
    cleanup_path.lock().await.take();

    eprintln!("\nFolder received successfully!");
    eprintln!("Extracted to: {}", extract_dir.display());

    // Send encrypted ACK
    let ack_msg = make_webrtc_ack_msg(key)?;
    data_channel
        .send(&Bytes::from(ack_msg))
        .await
        .context("Failed to send ACK")?;
    eprintln!("Sent confirmation to sender");

    Ok(())
}

/// Adapter to stream chunks from WebRTC channel to std::io::Read
pub(crate) struct WebRtcStreamingReader {
    receiver: mpsc::Receiver<Vec<u8>>,
    key: [u8; 32],
    buffer: Vec<u8>,
    buffer_pos: usize,
    bytes_remaining: u64,
    runtime_handle: tokio::runtime::Handle,
}

impl WebRtcStreamingReader {
    pub(crate) fn new(
        receiver: mpsc::Receiver<Vec<u8>>,
        key: [u8; 32],
        file_size: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            receiver,
            key,
            buffer: Vec::new(),
            buffer_pos: 0,
            bytes_remaining: file_size,
            runtime_handle,
        }
    }
}

impl std::io::Read for WebRtcStreamingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If buffer is exhausted and there's more data, fetch next chunk
        // Use a loop instead of recursion to avoid stack overflow on many non-chunk messages
        while self.buffer_pos >= self.buffer.len() && self.bytes_remaining > 0 {
            // Block on async receive
            let msg_result = self.runtime_handle.block_on(async {
                timeout(Duration::from_secs(30), self.receiver.recv()).await
            });

            match msg_result {
                Ok(Some(msg)) => {
                    if msg.is_empty() {
                        return Ok(0);
                    }

                    // Parse message
                    match msg[0] {
                        1 => {
                            // Chunk message
                            if msg.len() < 13 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Chunk too short",
                                ));
                            }
                            let chunk_num = u64::from_be_bytes([
                                msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
                            ]);
                            let encrypted_len =
                                u32::from_be_bytes([msg[9], msg[10], msg[11], msg[12]]) as usize;
                            if msg.len() < 13 + encrypted_len {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Chunk truncated",
                                ));
                            }
                            let encrypted_chunk = &msg[13..13 + encrypted_len];

                            // Decrypt
                            match decrypt_chunk(&self.key, chunk_num, encrypted_chunk) {
                                Ok(chunk) => {
                                    self.bytes_remaining =
                                        self.bytes_remaining.saturating_sub(chunk.len() as u64);
                                    self.buffer = chunk;
                                    self.buffer_pos = 0;
                                    // Got a chunk, break out of loop to return data
                                    break;
                                }
                                Err(e) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("Decrypt failed: {}", e),
                                    ));
                                }
                            }
                        }
                        2 => return Ok(0), // EOF
                        _ => {
                            // Ignore other messages, continue loop to fetch next
                            continue;
                        }
                    }
                }
                Ok(None) => return Ok(0), // Channel closed
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timeout waiting for chunk",
                    ));
                }
            }
        }

        // Return data from buffer
        if self.buffer_pos >= self.buffer.len() {
            return Ok(0); // EOF
        }

        let available = self.buffer.len() - self.buffer_pos;
        let to_copy = std::cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;

        Ok(to_copy)
    }
}
