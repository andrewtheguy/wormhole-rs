//! WebRTC-based file sender using PeerJS signaling
//!
//! This module handles sending files over WebRTC data channels.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

/// Type alias for PeerJS client shared between tasks (now using Arc directly since
/// PeerJsClient has interior mutability via internal Mutex)
type SharedPeerJs = Arc<PeerJsClient>;

use crate::crypto::{encrypt_chunk, generate_key, CHUNK_SIZE};
use crate::folder::{create_tar_archive, print_tar_creation_info};
use crate::transfer::{format_bytes, num_chunks, FileHeader, TransferType};
use crate::webrtc_common::{
    generate_peer_id, setup_data_channel_handlers, PeerJsClient, ServerMessage, WebRtcPeer,
    DEFAULT_PEERJS_SERVER,
};
use crate::wormhole::generate_webrtc_code;

/// Connection timeout for WebRTC handshake
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
fn setup_cleanup_handler(cleanup_path: TempFileCleanup) {
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

/// Internal helper for WebRTC transfer logic.
async fn transfer_data_webrtc_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    peerjs_server: Option<&str>,
) -> Result<()> {
    // Generate encryption key (always required for WebRTC)
    let key = generate_key();
    println!("Encryption enabled for WebRTC transfer");

    // Generate human-friendly peer ID
    let peer_id = generate_peer_id();
    println!("Generated peer ID: {}", peer_id);

    // Connect to PeerJS server
    let server = peerjs_server.unwrap_or(DEFAULT_PEERJS_SERVER);
    let peerjs = PeerJsClient::connect(&peer_id, Some(server)).await?;
    peerjs.wait_for_open().await?;

    // Generate wormhole code
    let server_for_code = if server != DEFAULT_PEERJS_SERVER {
        Some(server.to_string())
    } else {
        None
    };
    let code = generate_webrtc_code(&key, peer_id.clone(), server_for_code)?;

    println!("\nWormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive\n");
    println!("Then enter the code above when prompted.\n");
    println!("Waiting for receiver to connect...");

    // Create WebRTC peer
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel BEFORE receiving offer (so it's included in SDP)
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Set up channel for receiving data channel messages
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    let mut remote_peer_id: Option<String> = None;

    // Wait for OFFER from receiver (with timeout)
    let offer_result = timeout(CONNECTION_TIMEOUT, async {
        loop {
            match peerjs.recv_message().await {
                Ok(ServerMessage::Offer { src, payload, .. }) => {
                    println!("Received offer from: {}", src);
                    remote_peer_id = Some(src);

                    // Set remote description
                    let offer_sdp = RTCSessionDescription::offer(payload.sdp.sdp)
                        .context("Failed to create offer SDP")?;
                    rtc_peer.set_remote_description(offer_sdp).await?;

                    return Ok::<String, anyhow::Error>(payload.connection_id);
                }
                Ok(ServerMessage::Candidate { src, payload, .. }) => {
                    // Buffer ICE candidates (will be added after setting remote description)
                    println!("Received early ICE candidate from: {}", src);
                    let candidate = RTCIceCandidateInit {
                        candidate: payload.candidate.candidate,
                        sdp_mid: payload.candidate.sdp_mid,
                        sdp_mline_index: payload.candidate.sdp_m_line_index,
                        username_fragment: None,
                    };
                    let _ = rtc_peer.add_ice_candidate(candidate).await;
                }
                Ok(ServerMessage::Heartbeat) => {
                    // Send heartbeat response
                    let _ = peerjs.send_heartbeat().await;
                }
                Ok(msg) => {
                    println!("Ignoring message while waiting for offer: {:?}", msg);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Error receiving message: {}", e));
                }
            }
        }
    })
    .await;

    let remote_connection_id = offer_result
        .context("Timeout waiting for receiver to connect")?
        .context("Failed to receive offer")?;

    let remote_peer = remote_peer_id.context("No remote peer ID")?;

    // Create and send answer
    let answer = rtc_peer.create_answer().await?;
    rtc_peer.set_local_description(answer.clone()).await?;
    peerjs
        .send_answer(&remote_peer, &answer.sdp, &remote_connection_id)
        .await?;
    println!("Sent answer to receiver");

    // Exchange ICE candidates
    // Use Arc<PeerJsClient> - no outer Mutex needed since PeerJsClient has interior mutability
    let peerjs_arc: SharedPeerJs = Arc::new(peerjs);
    let remote_peer_clone = remote_peer.clone();
    // Use remote_connection_id from offer (not a locally generated ID) for protocol correctness
    let remote_connection_id_clone = remote_connection_id.clone();
    let peerjs_clone = peerjs_arc.clone();

    // Take ownership of ICE candidate receiver before wrapping rtc_peer in Arc
    let mut ice_rx = rtc_peer.take_ice_candidate_rx().expect("ICE candidate receiver already taken");

    // Spawn task to send our ICE candidates (no mutex lock needed)
    tokio::spawn(async move {
        while let Some(candidate) = ice_rx.recv().await {
            let candidate_str = candidate.to_json().map(|c| c.candidate).unwrap_or_default();
            let sdp_mid = candidate.to_json().ok().and_then(|c| c.sdp_mid);
            let sdp_m_line_index = candidate.to_json().ok().and_then(|c| c.sdp_mline_index);

            let _ = peerjs_clone
                .send_candidate(
                    &remote_peer_clone,
                    &candidate_str,
                    sdp_mid.as_deref(),
                    sdp_m_line_index,
                    &remote_connection_id_clone,
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

    // Wait for data channel to open
    println!("Waiting for data channel to open...");
    timeout(CONNECTION_TIMEOUT, open_rx)
        .await
        .context("Timeout waiting for data channel to open")?
        .context("Data channel failed to open")?;

    // Display connection info
    let conn_info = rtc_peer_arc.get_connection_info().await;
    conn_info.print(&remote_peer);

    // Small delay to ensure connection is stable
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send file header as first message
    let header = FileHeader::new(transfer_type, filename.clone(), file_size);
    let header_bytes = header.to_bytes();
    let encrypted_header = encrypt_chunk(&key, 0, &header_bytes)?;

    // Prepend message type (0 = control/header)
    let mut header_msg = vec![0u8]; // Message type: header
    header_msg.extend_from_slice(&(encrypted_header.len() as u32).to_be_bytes());
    header_msg.extend_from_slice(&encrypted_header);

    data_channel
        .send(&Bytes::from(header_msg))
        .await
        .context("Failed to send header")?;

    println!("Sent file header: {} ({})", filename, format_bytes(file_size));

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    println!("Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
        if bytes_read == 0 {
            break;
        }

        // Encrypt chunk
        let encrypted_chunk = encrypt_chunk(&key, chunk_num, &buffer[..bytes_read])?;

        // Prepend message type (1 = chunk)
        let mut chunk_msg = vec![1u8]; // Message type: chunk
        chunk_msg.extend_from_slice(&chunk_num.to_be_bytes());
        chunk_msg.extend_from_slice(&(encrypted_chunk.len() as u32).to_be_bytes());
        chunk_msg.extend_from_slice(&encrypted_chunk);

        data_channel
            .send(&Bytes::from(chunk_msg))
            .await
            .context("Failed to send chunk")?;

        chunk_num += 1;
        bytes_sent += bytes_read as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_sent == file_size {
            let percent = if file_size == 0 {
                100
            } else {
                (bytes_sent as f64 / file_size as f64 * 100.0) as u32
            };
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_sent),
                format_bytes(file_size)
            );
            let _ = std::io::stdout().flush();
        }
    }

    println!("\nTransfer complete!");

    // Send done message
    let done_msg = vec![2u8]; // Message type: done
    data_channel
        .send(&Bytes::from(done_msg))
        .await
        .context("Failed to send done message")?;

    // Wait for ACK from receiver
    println!("Waiting for receiver to confirm...");
    let ack_result = timeout(Duration::from_secs(30), async {
        while let Some(msg) = message_rx.recv().await {
            if msg.len() >= 1 && msg[0] == 3 {
                // Message type: ACK
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("Channel closed without ACK"))
    })
    .await;

    match ack_result {
        Ok(Ok(())) => {
            println!("Receiver confirmed!");
        }
        _ => {
            println!("Warning: Did not receive confirmation from receiver");
        }
    }

    // Close connections
    let _ = rtc_peer_arc.close().await;
    println!("Connection closed.");

    Ok(())
}

/// Send a file via WebRTC
pub async fn send_file_webrtc(file_path: &Path, peerjs_server: Option<&str>) -> Result<()> {
    // Get file metadata
    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?
        .to_string();

    println!(
        "Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Open file
    let file = File::open(file_path).await.context("Failed to open file")?;

    // Transfer using WebRTC
    transfer_data_webrtc_internal(file, filename, file_size, TransferType::File, peerjs_server).await
}

/// Send a folder as a tar archive via WebRTC
pub async fn send_folder_webrtc(folder_path: &Path, peerjs_server: Option<&str>) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("Creating tar archive of: {}", folder_name);
    print_tar_creation_info();

    // Create tar archive using shared folder logic
    let tar_archive = create_tar_archive(folder_path)?;
    let temp_tar = tar_archive.temp_file;
    let tar_filename = tar_archive.filename;
    let file_size = tar_archive.file_size;

    // Set up cleanup handler for Ctrl+C
    let temp_path = temp_tar.path().to_path_buf();
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    println!(
        "Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

    // Open tar file
    let file = File::open(temp_tar.path())
        .await
        .context("Failed to open tar file")?;

    // Transfer using WebRTC
    let result = transfer_data_webrtc_internal(
        file,
        tar_filename,
        file_size,
        TransferType::Folder,
        peerjs_server,
    )
    .await;

    // Clear cleanup path
    cleanup_path.lock().await.take();

    result
}
