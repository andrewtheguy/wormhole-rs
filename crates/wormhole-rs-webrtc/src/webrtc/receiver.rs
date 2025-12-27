//! WebRTC transport receiver: WebRTC with Nostr signaling
//!
//! Uses WebRTC data channels for reliable file transfer with Nostr signaling.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use wormhole_common::core::transfer::run_receiver_transfer;
use wormhole_common::core::wormhole::{decode_key, parse_code, PROTOCOL_WEBRTC};

use crate::signaling::nostr::{create_receiver_signaling, NostrSignaling, SignalingMessage};
use crate::signaling::offline::ice_candidates_to_payloads;
use crate::webrtc::common::{DataChannelStream, WebRtcPeer};

/// Connection timeout for WebRTC handshake
const WEBRTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of WebRTC connection attempt
enum WebRtcResult {
    Success,
    Failed(String),
}

/// Attempt WebRTC receive with Nostr signaling using common transfer protocol
async fn try_webrtc_receive(
    signaling: &NostrSignaling,
    sender_pubkey: &nostr_sdk::PublicKey,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    no_resume: bool,
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

    // Gather ICE candidates
    eprintln!("Gathering ICE candidates...");
    let candidates = rtc_peer
        .gather_ice_candidates(Duration::from_secs(10))
        .await?;
    let candidate_payloads = ice_candidates_to_payloads(candidates)?;
    eprintln!("Gathered {} ICE candidates", candidate_payloads.len());

    signaling
        .publish_offer(sender_pubkey, &offer.sdp, candidate_payloads)
        .await?;
    eprintln!("Sent offer to sender");

    // Wait for answer with timeout
    eprintln!("Waiting for answer from sender...");
    let answer_result: Result<()> = timeout(WEBRTC_CONNECTION_TIMEOUT, async {
        loop {
            match signal_rx.recv().await {
                Some(SignalingMessage::Answer { sdp, .. }) => {
                    eprintln!("Received answer from sender");
                    let answer_sdp = RTCSessionDescription::answer(sdp.sdp)
                        .context("Failed to create answer SDP")?;

                    rtc_peer
                        .set_remote_description(answer_sdp)
                        .await
                        .context("Failed to set remote description")?;

                    // Add bundled ICE candidates
                    eprintln!("Received {} bundled ICE candidates", sdp.candidates.len());
                    for candidate in sdp.candidates {
                        let candidate_init = RTCIceCandidateInit {
                            candidate: candidate.candidate,
                            sdp_mid: candidate.sdp_mid,
                            sdp_mline_index: candidate.sdp_m_line_index,
                            username_fragment: None,
                        };
                        if let Err(e) = rtc_peer.add_ice_candidate(candidate_init).await {
                            log::warn!("Failed to add bundled ICE candidate: {}", e);
                        }
                    }

                    break Ok(());
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

    if let Err(e) = answer_result {
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(format!(
            "Failed to receive answer: {}",
            e
        )));
    }

    // Take data channel receiver from peer
    let mut data_channel_rx = rtc_peer
        .take_data_channel_rx()
        .ok_or_else(|| anyhow::anyhow!("Data channel receiver already taken"))?;

    // Wait for data channel from sender
    eprintln!("Waiting for data channel from sender...");
    let data_channel = timeout(WEBRTC_CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for data channel"))?
        .context("Failed to receive data channel")?;

    // Create oneshot channel for open notification
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();

    // Create the DataChannelStream (sets up handlers)
    let stream = DataChannelStream::new(data_channel.clone(), Some(open_tx));

    // Wait for data channel to be confirmed open
    match timeout(Duration::from_secs(10), open_rx).await {
        Ok(Ok(())) => {
            eprintln!("Data channel opened successfully");
        }
        Ok(Err(_)) => {
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(
                "Data channel failed to open".to_string(),
            ));
        }
        Err(_) => {
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

    // Wrap peer in Arc for cleanup
    let rtc_peer = Arc::new(rtc_peer);

    // Use common transfer protocol
    let (_, stream) = run_receiver_transfer(stream, *key, output_dir, no_resume).await?;

    // Wait for sender to close the connection (confirms ACK was received)
    // This ensures the ACK is delivered before we close our side
    let close_timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();
    while !stream.is_closed() && start.elapsed() < close_timeout {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Cleanup
    let _ = rtc_peer.close().await;
    signal_handle.abort();

    Ok(WebRtcResult::Success)
}

/// Receive a file or folder via webrtc transport
pub async fn receive_webrtc(
    code: &str,
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<()> {
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
    let key = decode_key(key_str).context("Failed to decode encryption key")?;

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

    // Try WebRTC transfer
    match try_webrtc_receive(&signaling, &sender_pubkey, &key, output_dir.clone(), no_resume)
        .await?
    {
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
                 - Manual signaling: wormhole-rs-webrtc send --manual-signaling <file>",
                reason
            );
        }
    }
}
