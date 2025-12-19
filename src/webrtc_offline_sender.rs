//! Manual signaling WebRTC sender - Direct transfer with copy/paste signaling
//!
//! This module implements WebRTC file transfer using copy/paste JSON signaling.
//! Uses STUN servers for NAT traversal but no Nostr relays for signaling.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::crypto::{encrypt_chunk, generate_key, CHUNK_SIZE};
use crate::folder::{create_tar_archive, print_tar_creation_info};
use crate::transfer::{format_bytes, num_chunks, FileHeader, TransferType};
use crate::webrtc_common::{setup_data_channel_handlers, WebRtcPeer};
use crate::webrtc_offline_signaling::{
    display_offer_json, ice_candidates_to_payloads, read_answer_json, OfflineAnswer, OfflineOffer,
    TransferInfo,
};

/// Timeout for ICE gathering
const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for WebRTC connection
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

/// Send a file via offline WebRTC (copy/paste JSON signaling)
pub async fn send_file_offline(file_path: &Path) -> Result<()> {
    let filename = file_path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();

    let file = File::open(file_path).await.context("Failed to open file")?;

    println!("Sending: {} ({})", filename, format_bytes(file_size));

    transfer_offline_internal(file, filename, file_size, TransferType::File, None).await
}

/// Send a folder via offline WebRTC (copy/paste JSON signaling)
pub async fn send_folder_offline(folder_path: &Path) -> Result<()> {
    let folder_name = folder_path
        .file_name()
        .context("Invalid folder path")?
        .to_string_lossy()
        .to_string();

    // Create tar archive
    println!("Creating archive of folder: {}", folder_name);
    let archive = create_tar_archive(folder_path)?;
    print_tar_creation_info();

    let tar_path = archive.temp_file.path().to_path_buf();
    let tar_size = archive.file_size;
    let filename = archive.filename.clone();

    // Set up cleanup handler
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(tar_path.clone())));
    setup_cleanup_handler(cleanup_path.clone());

    let file = File::open(&tar_path)
        .await
        .context("Failed to open tar archive")?;

    println!("Sending: {} ({})", filename, format_bytes(tar_size));

    let result =
        transfer_offline_internal(file, filename, tar_size, TransferType::Folder, Some(&tar_path))
            .await;

    // Clean up temp file
    cleanup_path.lock().await.take();
    let _ = tokio::fs::remove_file(&tar_path).await;

    result
}

/// Internal transfer implementation
async fn transfer_offline_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    _temp_file: Option<&Path>,
) -> Result<()> {
    // Generate encryption key
    let key = generate_key();
    println!("Encryption enabled for transfer");

    println!("\nPreparing WebRTC offline transfer...");

    // Create WebRTC peer with STUN for NAT traversal
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Set up channel for receiving data channel messages (for ACK)
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    // Create offer
    let offer = rtc_peer.create_offer().await?;
    rtc_peer.set_local_description(offer.clone()).await?;

    println!("Gathering connection info...");

    // Wait for ICE gathering to complete
    let candidates = rtc_peer.gather_ice_candidates(ICE_GATHERING_TIMEOUT).await?;
    println!("Collected {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Create and display offer JSON
    let offline_offer = OfflineOffer {
        sdp: offer.sdp,
        ice_candidates: ice_candidates_to_payloads(candidates),
        transfer_info: TransferInfo {
            filename: filename.clone(),
            file_size,
            transfer_type: match transfer_type {
                TransferType::File => "file".to_string(),
                TransferType::Folder => "folder".to_string(),
            },
            encryption_key: hex::encode(key),
        },
    };

    display_offer_json(&offline_offer)?;

    // Read answer from user
    let answer: OfflineAnswer = read_answer_json()?;

    println!("\nProcessing receiver's response...");

    // Set remote description
    let answer_sdp =
        RTCSessionDescription::answer(answer.sdp).context("Failed to create answer SDP")?;
    rtc_peer.set_remote_description(answer_sdp).await?;

    // Add remote ICE candidates
    for candidate in &answer.ice_candidates {
        let candidate_init = RTCIceCandidateInit {
            candidate: candidate.candidate.clone(),
            sdp_mid: candidate.sdp_mid.clone(),
            sdp_mline_index: candidate.sdp_m_line_index,
            username_fragment: None,
        };
        rtc_peer.add_ice_candidate(candidate_init).await?;
    }

    println!(
        "Added {} remote ICE candidates",
        answer.ice_candidates.len()
    );

    // Wrap peer in Arc for connection monitoring
    let rtc_peer_arc = Arc::new(rtc_peer);

    // Wait for data channel to open
    println!("Connecting...");

    let open_result = tokio::time::timeout(CONNECTION_TIMEOUT, open_rx).await;
    match open_result {
        Ok(Ok(())) => {
            println!("Data channel opened!");
        }
        Ok(Err(_)) => {
            anyhow::bail!("Data channel open signal was cancelled");
        }
        Err(_) => {
            // Check connection state on timeout
            let state = rtc_peer_arc.connection_state();
            anyhow::bail!(
                "Connection timeout. State: {:?}. \
                 NAT traversal may have failed.",
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

    // Small delay to ensure connection is stable
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send file header as first message
    let header = FileHeader::new(transfer_type, filename.clone(), file_size);
    let header_bytes = header.to_bytes();
    let encrypted_header = encrypt_chunk(&key, 0, &header_bytes)?;

    // Prepend message type (0 = control/header)
    let mut header_msg = vec![0u8];
    header_msg.extend_from_slice(&(encrypted_header.len() as u32).to_be_bytes());
    header_msg.extend_from_slice(&encrypted_header);

    data_channel
        .send(&Bytes::from(header_msg))
        .await
        .context("Failed to send header")?;

    println!(
        "Sent file header: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64;
    let mut bytes_sent = 0u64;

    println!("Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .context("Failed to read data")?;
        if bytes_read == 0 {
            break;
        }

        // Encrypt chunk
        let encrypted_chunk = encrypt_chunk(&key, chunk_num, &buffer[..bytes_read])?;

        // Prepend message type (1 = chunk)
        let mut chunk_msg = vec![1u8];
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
    let done_msg = vec![2u8];
    data_channel
        .send(&Bytes::from(done_msg))
        .await
        .context("Failed to send done message")?;

    // Wait for ACK from receiver
    println!("Waiting for receiver to confirm...");
    let ack_result = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = message_rx.recv().await {
            if !msg.is_empty() && msg[0] == 3 {
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

    Ok(())
}
