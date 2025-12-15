//! WebRTC-based file receiver using PeerJS signaling
//!
//! This module handles receiving files over WebRTC data channels.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use uuid::Uuid;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

/// Type alias for PeerJS client shared between tasks
type SharedPeerJs = Arc<PeerJsClient>;

use crate::crypto::decrypt_chunk;
use crate::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
};
use crate::transfer::{format_bytes, num_chunks, FileHeader, TransferType};
use crate::webrtc_common::{
    generate_peer_id, setup_data_channel_handlers, PeerJsClient, ServerMessage, WebRtcPeer,
    DEFAULT_PEERJS_SERVER,
};
use crate::wormhole::{decode_key, parse_code, PROTOCOL_WEBRTC};

/// Connection timeout for WebRTC handshake
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for extraction directory cleanup on interrupt
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

/// Receive a file or folder via WebRTC
pub async fn receive_webrtc(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    println!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    if token.protocol != PROTOCOL_WEBRTC {
        anyhow::bail!("Expected WebRTC protocol, got: {}", token.protocol);
    }

    // Extract WebRTC-specific fields
    let sender_peer_id = token
        .webrtc_peer_id
        .context("Missing peer ID in wormhole code")?;
    let key = token
        .key
        .as_ref()
        .map(|k| decode_key(k))
        .transpose()
        .context("Failed to decode encryption key")?
        .context("Encryption key required for WebRTC transfers")?;
    let server = token.webrtc_server.as_deref();

    println!("Encryption enabled");
    println!("Connecting to sender: {}", sender_peer_id);

    // Generate our own peer ID
    let my_peer_id = generate_peer_id();

    // Connect to PeerJS server
    let peerjs_server = server.unwrap_or(DEFAULT_PEERJS_SERVER);
    let peerjs = PeerJsClient::connect(&my_peer_id, Some(peerjs_server)).await?;
    peerjs.wait_for_open().await?;

    // Create WebRTC peer
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel BEFORE creating offer (so it's included in SDP)
    let _local_dc = rtc_peer.create_data_channel("file-transfer").await?;

    // Generate connection ID
    let connection_id = Uuid::new_v4().to_string();

    // Create and send offer to sender
    let offer = rtc_peer.create_offer().await?;
    rtc_peer.set_local_description(offer.clone()).await?;
    peerjs
        .send_offer(&sender_peer_id, &offer.sdp, &connection_id)
        .await?;
    println!("Sent offer to sender");

    // Wait for answer with timeout
    let answer_result = timeout(CONNECTION_TIMEOUT, async {
        loop {
            match peerjs.recv_message().await {
                Ok(ServerMessage::Answer { payload, .. }) => {
                    println!("Received answer from sender");
                    let answer_sdp = RTCSessionDescription::answer(payload.sdp.sdp)
                        .context("Failed to create answer SDP")?;
                    rtc_peer.set_remote_description(answer_sdp).await?;
                    return Ok::<(), anyhow::Error>(());
                }
                Ok(ServerMessage::Candidate { payload, .. }) => {
                    // Handle early ICE candidates
                    let candidate = RTCIceCandidateInit {
                        candidate: payload.candidate.candidate,
                        sdp_mid: payload.candidate.sdp_mid,
                        sdp_mline_index: payload.candidate.sdp_m_line_index,
                        username_fragment: None,
                    };
                    let _ = rtc_peer.add_ice_candidate(candidate).await;
                }
                Ok(ServerMessage::Heartbeat) => {
                    let _ = peerjs.send_heartbeat().await;
                }
                Ok(msg) => {
                    println!("Ignoring message while waiting for answer: {:?}", msg);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Error receiving message: {}", e));
                }
            }
        }
    })
    .await;

    answer_result
        .context("Timeout waiting for answer from sender")?
        .context("Failed to receive answer")?;

    // Set up ICE candidate exchange
    // Use Arc<PeerJsClient> - no outer Mutex needed since PeerJsClient has interior mutability
    let peerjs_arc: SharedPeerJs = Arc::new(peerjs);
    let sender_peer_id_clone = sender_peer_id.clone();
    let connection_id_clone = connection_id.clone();
    let peerjs_clone = peerjs_arc.clone();

    // Take ownership of receivers before wrapping rtc_peer in Arc
    let mut ice_rx = rtc_peer.take_ice_candidate_rx().expect("ICE candidate receiver already taken");
    let mut data_channel_rx = rtc_peer.take_data_channel_rx().expect("Data channel receiver already taken");

    // Spawn task to send our ICE candidates (no mutex lock needed)
    tokio::spawn(async move {
        while let Some(candidate) = ice_rx.recv().await {
            let candidate_str = candidate.to_json().map(|c| c.candidate).unwrap_or_default();
            let sdp_mid = candidate.to_json().ok().and_then(|c| c.sdp_mid);
            let sdp_m_line_index = candidate.to_json().ok().and_then(|c| c.sdp_mline_index);

            let _ = peerjs_clone
                .send_candidate(
                    &sender_peer_id_clone,
                    &candidate_str,
                    sdp_mid.as_deref(),
                    sdp_m_line_index,
                    &connection_id_clone,
                )
                .await;
        }
    });

    // Take message receiver for dedicated receiving task (allows concurrent send/receive)
    let mut peerjs_rx = peerjs_arc
        .take_message_rx()
        .await
        .expect("Message receiver already taken");

    // Process incoming ICE candidates in background
    let peerjs_clone2 = peerjs_arc.clone();
    let rtc_peer_arc = Arc::new(rtc_peer);
    let rtc_peer_clone = rtc_peer_arc.clone();

    tokio::spawn(async move {
        while let Some(msg) = peerjs_rx.recv().await {
            match msg {
                ServerMessage::Candidate { payload, .. } => {
                    let candidate = RTCIceCandidateInit {
                        candidate: payload.candidate.candidate,
                        sdp_mid: payload.candidate.sdp_mid,
                        sdp_mline_index: payload.candidate.sdp_m_line_index,
                        username_fragment: None,
                    };
                    let _ = rtc_peer_clone.add_ice_candidate(candidate).await;
                }
                ServerMessage::Heartbeat => {
                    let _ = peerjs_clone2.send_heartbeat().await;
                }
                ServerMessage::Leave { .. } => {
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for data channel from sender
    println!("Waiting for data channel from sender...");
    let data_channel = timeout(CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .context("Timeout waiting for data channel")?
        .context("Failed to receive data channel")?;

    // Set up message receiving
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    // Wait for channel to be ready
    let _ = timeout(Duration::from_secs(5), open_rx).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Connected to sender!");

    // Receive header message
    println!("Receiving file information...");
    let header_msg = timeout(Duration::from_secs(30), async {
        while let Some(msg) = message_rx.recv().await {
            if msg.len() >= 1 && msg[0] == 0 {
                // Message type: header
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
    let encrypted_len = u32::from_be_bytes([header_msg[1], header_msg[2], header_msg[3], header_msg[4]]) as usize;
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
            receive_folder_impl(&mut message_rx, &header, &key, output_dir, &data_channel).await?;
        }
    }

    // Close connections
    let _ = rtc_peer_arc.close().await;
    println!("Connection closed.");

    Ok(())
}

/// Internal implementation for receiving a file via WebRTC
async fn receive_file_impl(
    message_rx: &mut mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    data_channel: &Arc<webrtc::data_channel::RTCDataChannel>,
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
        let msg = timeout(Duration::from_secs(30), message_rx.recv())
            .await
            .context("Timeout waiting for chunk")?
            .context("Channel closed")?;

        // Check message type
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
                temp_file.write_all(&chunk).context("Failed to write chunk")?;

                bytes_received += chunk.len() as u64;

                // Progress update
                if chunk_num % 10 == 0 || bytes_received == header.file_size {
                    let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
                    print!(
                        "\r   Progress: {}% ({}/{})",
                        percent,
                        format_bytes(bytes_received),
                        format_bytes(header.file_size)
                    );
                    let _ = std::io::stdout().flush();
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

/// Internal implementation for receiving a folder via WebRTC
async fn receive_folder_impl(
    message_rx: &mut mpsc::Receiver<Vec<u8>>,
    header: &FileHeader,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    data_channel: &Arc<webrtc::data_channel::RTCDataChannel>,
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

    // Collect all chunks first (WebRTC provides them as messages)
    let mut tar_data = Vec::new();
    let mut bytes_received = 0u64;
    let total_chunks = num_chunks(header.file_size);

    println!("Receiving {} chunks...", total_chunks);

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
                // Chunk message
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

                tar_data.extend_from_slice(&chunk);
                bytes_received += chunk.len() as u64;

                // Progress update
                if chunk_num % 10 == 0 || bytes_received == header.file_size {
                    let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
                    print!(
                        "\r   Progress: {}% ({}/{})",
                        percent,
                        format_bytes(bytes_received),
                        format_bytes(header.file_size)
                    );
                    let _ = std::io::stdout().flush();
                }
            }
            2 => {
                // Done message
                println!("\nTransfer complete signal received");
                break;
            }
            _ => {}
        }
    }

    // Extract tar archive
    let extract_dir_clone = extract_dir.clone();
    let skipped_entries = tokio::task::spawn_blocking(move || {
        let cursor = std::io::Cursor::new(tar_data);
        extract_tar_archive(cursor, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    // Clear cleanup path
    cleanup_path.lock().await.take();

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    // Send ACK
    let ack_msg = vec![3u8]; // Message type: ACK
    data_channel
        .send(&Bytes::from(ack_msg))
        .await
        .context("Failed to send ACK")?;
    println!("Sent confirmation to sender");

    Ok(())
}
