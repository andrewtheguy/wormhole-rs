//! Offline WebRTC receiver - Direct LAN transfer without any servers
//!
//! This module implements WebRTC file receiving using copy/paste JSON signaling.
//! No STUN servers, no Nostr relays, no internet connection required.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::crypto::decrypt_chunk;
use crate::folder::{extract_tar_archive, print_tar_extraction_info};
use crate::transfer::{format_bytes, num_chunks, FileHeader, TransferType};
use crate::webrtc_common::{setup_data_channel_handlers, WebRtcPeer};
use crate::webrtc_offline_signaling::{
    display_answer_json, ice_candidates_to_payloads, read_offer_json, OfflineAnswer,
};

/// Timeout for ICE gathering
const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for WebRTC connection
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for temp directory cleanup on interrupt
type ExtractDirCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
fn setup_file_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                eprintln!("\nInterrupted. Cleaned up temp file.");
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
                eprintln!("\nInterrupted. Cleaned up extraction directory.");
            }
            std::process::exit(130);
        }
    });
}

/// Get extraction directory for folders
fn get_extraction_dir(output_dir: Option<PathBuf>) -> PathBuf {
    output_dir.unwrap_or_else(|| PathBuf::from("."))
}

/// Print progress during transfer
fn print_progress(bytes_received: u64, total_bytes: u64) {
    let percent = if total_bytes == 0 {
        100
    } else {
        (bytes_received as f64 / total_bytes as f64 * 100.0) as u32
    };
    print!(
        "\r   Progress: {}% ({}/{})",
        percent,
        format_bytes(bytes_received),
        format_bytes(total_bytes)
    );
    let _ = std::io::stdout().flush();
}

/// Receive a file via offline WebRTC (copy/paste JSON signaling)
pub async fn receive_file_offline(output_dir: Option<PathBuf>) -> Result<()> {
    println!("Offline WebRTC Receiver");
    println!("=======================\n");

    // Read offer from user
    let offer = read_offer_json()?;

    let transfer_info = &offer.transfer_info;
    println!(
        "\nPreparing to receive: {} ({})",
        transfer_info.filename,
        format_bytes(transfer_info.file_size)
    );
    println!("Transfer type: {}", transfer_info.transfer_type);

    // Create WebRTC peer in offline mode (no STUN servers)
    let mut rtc_peer = WebRtcPeer::new_offline().await?;

    // Set remote description with offer
    let offer_sdp =
        RTCSessionDescription::offer(offer.sdp.clone()).context("Failed to create offer SDP")?;
    rtc_peer.set_remote_description(offer_sdp).await?;

    // Add remote ICE candidates
    for candidate in &offer.ice_candidates {
        let candidate_init = RTCIceCandidateInit {
            candidate: candidate.candidate.clone(),
            sdp_mid: candidate.sdp_mid.clone(),
            sdp_mline_index: candidate.sdp_m_line_index,
            username_fragment: None,
        };
        rtc_peer.add_ice_candidate(candidate_init).await?;
    }

    println!("Added {} remote ICE candidates", offer.ice_candidates.len());

    // Create answer
    let answer = rtc_peer.create_answer().await?;
    rtc_peer.set_local_description(answer.clone()).await?;

    println!("Gathering connection info...");

    // Wait for ICE gathering to complete
    let candidates = rtc_peer.gather_ice_candidates(ICE_GATHERING_TIMEOUT).await?;
    println!("Collected {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!(
            "No ICE candidates gathered. Make sure you're on the same network as the sender."
        );
    }

    // Create and display answer JSON
    let offline_answer = OfflineAnswer {
        sdp: answer.sdp,
        ice_candidates: ice_candidates_to_payloads(candidates),
    };

    display_answer_json(&offline_answer)?;

    println!("Connecting...");

    // Take data channel receiver before wrapping in Arc
    let mut data_channel_rx = rtc_peer
        .take_data_channel_rx()
        .context("Data channel receiver already taken")?;

    // Wrap peer in Arc
    let rtc_peer_arc = Arc::new(rtc_peer);

    // Wait for data channel from sender
    let data_channel = tokio::time::timeout(CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Connection timeout. Make sure you're on the same network as the sender."
            )
        })?
        .context("Failed to receive data channel")?;

    // Set up message receiving
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    // Wait for data channel to be confirmed open
    match tokio::time::timeout(Duration::from_secs(10), open_rx).await {
        Ok(Ok(())) => {
            println!("Data channel opened!");
        }
        Ok(Err(_)) => {
            anyhow::bail!("Data channel failed to open");
        }
        Err(_) => {
            let state = rtc_peer_arc.connection_state();
            anyhow::bail!(
                "Timeout waiting for data channel to open. State: {:?}",
                state
            );
        }
    }

    // Check connection state
    let state = rtc_peer_arc.connection_state();
    if state != RTCPeerConnectionState::Connected {
        anyhow::bail!("Connection failed. State: {:?}", state);
    }

    // Display connection info
    let conn_info = rtc_peer_arc.get_connection_info().await;
    println!("WebRTC connection established!");
    println!("   Connection: {}", conn_info.connection_type);
    if let (Some(local), Some(remote)) = (&conn_info.local_address, &conn_info.remote_address) {
        println!("   Local: {} -> Remote: {}", local, remote);
    }

    // Extract encryption key from offer
    let key_bytes = hex::decode(&offer.transfer_info.encryption_key)
        .context("Failed to decode encryption key")?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid encryption key length"))?;

    // Receive header message
    println!("Receiving file information...");
    let header_msg = tokio::time::timeout(Duration::from_secs(30), async {
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
    let header_bytes = decrypt_chunk(&key, 0, encrypted_header)?;
    let header = FileHeader::from_bytes(&header_bytes)?;

    println!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            receive_file_impl(&mut message_rx, &header, &key, output_dir, &data_channel).await?;
        }
        TransferType::Folder => {
            receive_folder_impl(message_rx, &header, &key, output_dir, &data_channel).await?;
        }
    }

    // Close connections
    let _ = rtc_peer_arc.close().await;

    println!("Connection closed.");
    Ok(())
}

/// Internal implementation for receiving a file
async fn receive_file_impl(
    message_rx: &mut mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    data_channel: &Arc<RTCDataChannel>,
) -> Result<()> {
    // Determine output directory and final path
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&header.filename);

    // Check if file already exists
    if output_path.exists() {
        let prompt_path = output_path.display().to_string();
        let should_overwrite = tokio::task::spawn_blocking(move || {
            print!("File already exists: {}. Overwrite? [y/N] ", prompt_path);
            std::io::Write::flush(&mut std::io::stdout())?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            Ok::<bool, std::io::Error>(input.trim().eq_ignore_ascii_case("y"))
        })
        .await
        .context("Prompt task panicked")??;

        if !should_overwrite {
            anyhow::bail!("Transfer cancelled - file exists");
        }

        tokio::fs::remove_file(&output_path)
            .await
            .context("Failed to remove existing file")?;
    }

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

    println!("Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let msg = tokio::time::timeout(Duration::from_secs(30), message_rx.recv())
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
                println!("\nTransfer complete signal received");
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

    println!("\nFile received successfully!");
    println!("Saved to: {}", output_path.display());

    // Send ACK
    let ack_msg = vec![3u8]; // Message type: ACK
    data_channel
        .send(&Bytes::from(ack_msg))
        .await
        .context("Failed to send ACK")?;
    println!("Sent confirmation to sender");

    Ok(())
}

/// Streaming reader for receiving tar archives
struct WebRtcStreamingReader {
    message_rx: mpsc::Receiver<Vec<u8>>,
    key: [u8; 32],
    total_bytes: u64,
    bytes_received: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    runtime_handle: tokio::runtime::Handle,
}

impl WebRtcStreamingReader {
    fn new(
        message_rx: mpsc::Receiver<Vec<u8>>,
        key: [u8; 32],
        total_bytes: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            message_rx,
            key,
            total_bytes,
            bytes_received: 0,
            buffer: Vec::new(),
            buffer_pos: 0,
            runtime_handle,
        }
    }
}

impl std::io::Read for WebRtcStreamingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have buffered data, return that first
        if self.buffer_pos < self.buffer.len() {
            let available = self.buffer.len() - self.buffer_pos;
            let to_copy = std::cmp::min(available, buf.len());
            buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;
            return Ok(to_copy);
        }

        // Check if we've received all data
        if self.bytes_received >= self.total_bytes {
            return Ok(0);
        }

        // Wait for next message
        let msg = self
            .runtime_handle
            .block_on(async { self.message_rx.recv().await });

        let msg = match msg {
            Some(m) => m,
            None => return Ok(0),
        };

        if msg.is_empty() {
            return Ok(0);
        }

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
                let chunk = decrypt_chunk(&self.key, chunk_num, encrypted_chunk).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;

                self.bytes_received += chunk.len() as u64;

                // Progress update
                if chunk_num % 10 == 0 || self.bytes_received >= self.total_bytes {
                    print_progress(self.bytes_received, self.total_bytes);
                }

                // Buffer the decrypted data
                self.buffer = chunk;
                self.buffer_pos = 0;

                // Return as much as we can
                let to_copy = std::cmp::min(self.buffer.len(), buf.len());
                buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
                self.buffer_pos = to_copy;
                Ok(to_copy)
            }
            2 => {
                // Done message
                Ok(0)
            }
            _ => Ok(0),
        }
    }
}

/// Internal implementation for receiving a folder
async fn receive_folder_impl(
    message_rx: mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    data_channel: &Arc<RTCDataChannel>,
) -> Result<()> {
    println!(
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

    println!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Create streaming reader
    let runtime_handle = tokio::runtime::Handle::current();
    let reader = WebRtcStreamingReader::new(message_rx, *key, header.file_size, runtime_handle);

    // Extract tar archive in a blocking task
    let extract_dir_clone = extract_dir.clone();
    let skipped_entries = tokio::task::spawn_blocking(move || {
        extract_tar_archive(reader, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    if !skipped_entries.is_empty() {
        println!("\nSkipped entries (outside target directory):");
        for entry in &skipped_entries {
            println!("  - {}", entry);
        }
    }

    // Clear cleanup path
    cleanup_path.lock().await.take();

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    // Send ACK
    let ack_msg = vec![3u8];
    data_channel
        .send(&Bytes::from(ack_msg))
        .await
        .context("Failed to send ACK")?;
    println!("Sent confirmation to sender");

    Ok(())
}
