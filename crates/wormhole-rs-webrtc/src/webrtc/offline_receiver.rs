//! Manual signaling WebRTC receiver - Direct transfer with copy/paste signaling
//!
//! Uses STUN servers for NAT traversal but no Nostr relays for signaling.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Duration;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use wormhole_common::core::transfer::{format_bytes, run_receiver_transfer};

use crate::signaling::offline::{
    OfflineAnswer, display_answer_json, ice_candidates_to_payloads, read_offer_json,
};
use crate::webrtc::common::{DataChannelStream, WebRtcPeer};

/// Timeout for ICE gathering
const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for WebRTC connection (3 minutes to allow time for copy/paste signaling)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// Receive a file via offline WebRTC (copy/paste JSON signaling)
pub async fn receive_file_offline(output_dir: Option<PathBuf>, no_resume: bool) -> Result<()> {
    eprintln!("Offline WebRTC Receiver");
    eprintln!("=======================\n");

    // Read offer from user
    let offer = read_offer_json()?;

    let transfer_info = &offer.transfer_info;
    eprintln!(
        "\nPreparing to receive: {} ({})",
        transfer_info.filename,
        format_bytes(transfer_info.file_size)
    );
    eprintln!("Transfer type: {}", transfer_info.transfer_type);

    // Create WebRTC peer with STUN for NAT traversal
    let mut rtc_peer = WebRtcPeer::new().await?;

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

    eprintln!("Added {} remote ICE candidates", offer.ice_candidates.len());

    // Create answer
    let answer = rtc_peer.create_answer().await?;
    rtc_peer.set_local_description(answer.clone()).await?;

    eprintln!("Gathering connection info...");

    // Wait for ICE gathering to complete
    let candidates = rtc_peer
        .gather_ice_candidates(ICE_GATHERING_TIMEOUT)
        .await?;
    eprintln!("Collected {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Create and display answer JSON
    let offline_answer = OfflineAnswer {
        sdp: answer.sdp,
        ice_candidates: ice_candidates_to_payloads(candidates)?,
    };

    display_answer_json(&offline_answer)?;

    eprintln!("Connecting...");

    // Take data channel receiver before wrapping in Arc
    let mut data_channel_rx = rtc_peer
        .take_data_channel_rx()
        .context("Data channel receiver already taken")?;

    // Wrap peer in Arc
    let rtc_peer_arc = Arc::new(rtc_peer);

    // Wait for data channel from sender
    let data_channel = tokio::time::timeout(CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout. NAT traversal may have failed."))?
        .context("Failed to receive data channel")?;

    // Create oneshot channel for open notification
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();

    // Create the DataChannelStream (sets up handlers)
    let stream = DataChannelStream::new(data_channel.clone(), Some(open_tx));

    // Wait for data channel to be confirmed open
    match tokio::time::timeout(Duration::from_secs(10), open_rx).await {
        Ok(Ok(())) => {
            eprintln!("Data channel opened!");
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
    eprintln!("WebRTC connection established!");
    eprintln!("   Connection: {}", conn_info.connection_type);
    if let (Some(local), Some(remote)) = (&conn_info.local_address, &conn_info.remote_address) {
        eprintln!("   Local: {} -> Remote: {}", local, remote);
    }

    // Extract encryption key from offer
    let key_bytes = hex::decode(&offer.transfer_info.encryption_key)
        .context("Failed to decode encryption key")?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid encryption key length"))?;

    // Use common transfer protocol
    let (_, stream) = run_receiver_transfer(stream, key, output_dir, no_resume).await?;

    // Wait for sender to close the connection (confirms ACK was received)
    // This ensures the ACK is delivered before we close our side
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.closed()).await;

    // Close connections
    let _ = rtc_peer_arc.close().await;

    eprintln!("Connection closed.");

    Ok(())
}
