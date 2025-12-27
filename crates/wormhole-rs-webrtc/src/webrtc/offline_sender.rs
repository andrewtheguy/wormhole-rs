//! Manual signaling WebRTC sender - Direct transfer with copy/paste signaling
//!
//! Uses STUN servers for NAT traversal but no Nostr relays for signaling.

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::time::Duration;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use wormhole_common::core::crypto::generate_key;
use wormhole_common::core::transfer::{
    prepare_file_for_send, prepare_folder_for_send, run_sender_transfer,
    setup_temp_file_cleanup_handler, FileHeader, Interrupted, TransferType,
};

use crate::signaling::offline::{
    display_offer_json, ice_candidates_to_payloads, read_answer_json, OfflineOffer, TransferInfo,
};
use crate::webrtc::common::{DataChannelStream, WebRtcPeer};

/// Timeout for ICE gathering
const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for WebRTC connection (3 minutes to allow time for copy/paste signaling)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

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
        prepared.checksum,
        TransferType::File,
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
    let cleanup_handler = setup_temp_file_cleanup_handler(temp_path.clone());

    // Run transfer with interrupt handling
    let result = tokio::select! {
        result = transfer_offline_internal(
            prepared.file,
            prepared.filename,
            prepared.file_size,
            0, // Folders are not resumable
            TransferType::Folder,
        ) => result,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - clean up and return Interrupted error
            cleanup_handler.cleanup_path.lock().await.take();
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(Interrupted.into());
        }
    };

    // Clean up temp file
    cleanup_handler.cleanup_path.lock().await.take();
    let _ = tokio::fs::remove_file(&temp_path).await;

    result
}

/// Internal transfer implementation using common transfer protocol
async fn transfer_offline_internal(
    mut file: tokio::fs::File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
) -> Result<()> {
    // Generate encryption key
    let key = generate_key();
    eprintln!("Encryption enabled for transfer");

    eprintln!("\nPreparing WebRTC offline transfer...");

    // Create WebRTC peer with STUN for NAT traversal
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Create oneshot channel for open notification
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();

    // Create the DataChannelStream (sets up handlers)
    let stream = DataChannelStream::new(data_channel.clone(), Some(open_tx));

    // Create offer
    let offer = rtc_peer.create_offer().await?;
    rtc_peer.set_local_description(offer.clone()).await?;

    eprintln!("Gathering connection info...");

    // Wait for ICE gathering to complete
    let candidates = rtc_peer.gather_ice_candidates(ICE_GATHERING_TIMEOUT).await?;
    eprintln!("Collected {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Create and display offer JSON
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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
    let answer = read_answer_json()?;

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
    if state != webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connected {
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

    // Create header for common transfer protocol
    let header = FileHeader::new(transfer_type, filename.clone(), file_size, checksum);

    // Use common transfer protocol
    let mut stream = stream;
    let result = run_sender_transfer(&mut file, &mut stream, &key, &header).await;

    // Close connections
    let _ = rtc_peer_arc.close().await;

    result.map(|_| ())
}
