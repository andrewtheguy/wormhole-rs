//! Manual signaling WebRTC sender - Direct transfer with copy/paste signaling
//!
//! This module implements WebRTC file transfer using copy/paste JSON signaling.
//! Uses STUN servers for NAT traversal but no Nostr relays for signaling.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::core::crypto::{encrypt, generate_key, CHUNK_SIZE};
use crate::core::transfer::{
    format_bytes, make_webrtc_done_msg, num_chunks, parse_webrtc_control_msg,
    prepare_file_for_send, prepare_folder_for_send, ControlSignal, FileHeader, TransferType,
};
use crate::signaling::offline::{
    display_offer_json, ice_candidates_to_payloads, read_answer_json, OfflineAnswer, OfflineOffer,
    TransferInfo,
};
use crate::webrtc::common::{setup_data_channel_handlers, WebRtcPeer};

/// Timeout for ICE gathering
const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for WebRTC connection (3 minutes to allow time for copy/paste signaling)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
fn setup_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                log::error!("\nInterrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}

/// Set up data channel close handler that notifies via channel
fn setup_data_channel_close_handler(
    dc: &Arc<webrtc::data_channel::RTCDataChannel>,
    close_tx: tokio::sync::oneshot::Sender<()>,
) {
    let close_tx = Arc::new(Mutex::new(Some(close_tx)));
    dc.on_close(Box::new(move || {
        let close_tx = close_tx.clone();
        Box::pin(async move {
            if let Some(tx) = close_tx.lock().await.take() {
                let _ = tx.send(());
            }
            eprintln!("Data channel closed");
        })
    }));
}

/// Send a file via offline WebRTC (copy/paste JSON signaling)
pub async fn send_file_offline(file_path: &Path) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_offline_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::File,
        None,
    )
    .await
}

/// Send a folder via offline WebRTC (copy/paste JSON signaling)
pub async fn send_folder_offline(folder_path: &Path) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_cleanup_handler(cleanup_path.clone());

    let result = transfer_offline_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::Folder,
        Some(&temp_path),
    )
    .await;

    // Clean up temp file
    cleanup_path.lock().await.take();
    let _ = tokio::fs::remove_file(&temp_path).await;

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
    eprintln!("Encryption enabled for transfer");

    eprintln!("\nPreparing WebRTC offline transfer...");

    // Create WebRTC peer with STUN for NAT traversal
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Set up channel for receiving data channel messages (for ACK)
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));
    setup_data_channel_close_handler(&data_channel, close_tx);

    // Create offer
    let offer = rtc_peer.create_offer().await?;
    rtc_peer.set_local_description(offer.clone()).await?;

    eprintln!("Gathering connection info...");

    // Wait for ICE gathering to complete
    let candidates = rtc_peer
        .gather_ice_candidates(ICE_GATHERING_TIMEOUT)
        .await?;
    eprintln!("Collected {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Create and display offer JSON
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
        created_at,
    };

    display_offer_json(&offline_offer)?;

    // Read answer from user
    let answer: OfflineAnswer = read_answer_json()?;

    eprintln!("\nProcessing receiver's response...");

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

    eprintln!(
        "Added {} remote ICE candidates",
        answer.ice_candidates.len()
    );

    // Wrap peer in Arc for connection monitoring
    let rtc_peer_arc = Arc::new(rtc_peer);

    // Wait for data channel to open
    eprintln!("Connecting...");

    let open_result = tokio::time::timeout(CONNECTION_TIMEOUT, open_rx).await;
    match open_result {
        Ok(Ok(())) => {
            eprintln!("Data channel opened!");
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
    eprintln!("WebRTC connection established!");
    eprintln!("   Connection: {}", conn_info.connection_type);
    if let (Some(local), Some(remote)) = (&conn_info.local_address, &conn_info.remote_address) {
        eprintln!("   Local: {} -> Remote: {}", local, remote);
    }

    // Small delay to ensure connection is stable
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send file header as first message
    let header = FileHeader::new(transfer_type, filename.clone(), file_size);
    let header_bytes = header.to_bytes();
    let encrypted_header = encrypt(&key, &header_bytes)?;

    // Prepend message type (0 = control/header)
    let mut header_msg = vec![0u8];
    header_msg.extend_from_slice(&(encrypted_header.len() as u32).to_be_bytes());
    header_msg.extend_from_slice(&encrypted_header);

    data_channel
        .send(&Bytes::from(header_msg))
        .await
        .context("Failed to send header")?;

    eprintln!(
        "Sent file header: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Wait for receiver confirmation before sending data
    eprintln!("Waiting for receiver to confirm...");
    let key_for_confirm = key;
    let confirm_result = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match message_rx.recv().await {
                Some(data) => {
                    match parse_webrtc_control_msg(&data, &key_for_confirm) {
                        Ok(Some(ControlSignal::Proceed)) => return Ok(true),
                        Ok(Some(ControlSignal::Abort)) => return Ok::<bool, ()>(false),
                        Ok(Some(ControlSignal::Ack | ControlSignal::Done)) => continue, // Unexpected, ignore
                        Ok(None) => continue, // Not a control message
                        Err(_) => continue,   // Parse error, ignore
                    }
                }
                None => return Ok(false),
            }
        }
    })
    .await;

    match confirm_result {
        Ok(Ok(true)) => {
            eprintln!("Receiver ready, starting transfer...");
        }
        Ok(Ok(false)) | Ok(Err(_)) => {
            eprintln!("Receiver declined transfer");
            let _ = rtc_peer_arc.close().await;
            anyhow::bail!("Transfer cancelled by receiver");
        }
        Err(_) => {
            eprintln!("Confirmation timeout");
            let _ = rtc_peer_arc.close().await;
            anyhow::bail!("Timed out waiting for receiver confirmation");
        }
    }

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64;
    let mut bytes_sent = 0u64;

    eprintln!("Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .context("Failed to read data")?;
        if bytes_read == 0 {
            break;
        }

        // Encrypt chunk
        let encrypted_chunk = encrypt(&key, &buffer[..bytes_read])?;

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

    eprintln!("\nTransfer complete!");

    // Send encrypted done message
    let done_msg = make_webrtc_done_msg(&key).context("Failed to create done message")?;
    data_channel
        .send(&Bytes::from(done_msg))
        .await
        .context("Failed to send done message")?;

    // Wait for ACK from receiver (or data channel close, which means receiver is done)
    eprintln!("Waiting for receiver to confirm...");

    // Wrap close_rx in a Mutex so it can be used in async block
    let close_rx = Arc::new(Mutex::new(Some(close_rx)));
    let close_rx_clone = close_rx.clone();
    let key_for_ack = key;

    let ack_result: Result<bool, ()> = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                msg = message_rx.recv() => {
                    match msg {
                        Some(data) => {
                            match parse_webrtc_control_msg(&data, &key_for_ack) {
                                Ok(Some(ControlSignal::Ack)) => return true, // Got explicit ACK
                                Ok(_) => continue,
                                Err(_) => continue,
                            }
                        }
                        None => return false, // Channel closed
                    }
                }
                _ = async {
                    if let Some(rx) = close_rx_clone.lock().await.take() {
                        let _ = rx.await;
                    } else {
                        // Already consumed, just pend forever
                        std::future::pending::<()>().await;
                    }
                } => {
                    return false; // Data channel closed
                }
            }
        }
    })
    .await
    .map_err(|_| ());

    match ack_result {
        Ok(true) => {
            eprintln!("Receiver confirmed!");
        }
        Ok(false) => {
            // Data channel closed - receiver got the data and disconnected
            eprintln!("Transfer complete (receiver disconnected)");
        }
        Err(_) => {
            eprintln!("Warning: Did not receive confirmation from receiver (timeout)");
        }
    }

    // Close connections
    let _ = rtc_peer_arc.close().await;

    Ok(())
}
