//! WebRTC transport sender: WebRTC with Nostr signaling
//!
//! Uses WebRTC data channels for reliable file transfer with Nostr signaling.

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use wormhole_common::core::crypto::generate_key;
use wormhole_common::core::transfer::{
    format_bytes, prepare_file_for_send, prepare_folder_for_send, run_sender_transfer,
    setup_temp_file_cleanup_handler, FileHeader, Interrupted, TransferType,
};
use wormhole_common::core::wormhole::generate_webrtc_code;

use crate::signaling::nostr::{create_sender_signaling, NostrSignaling, SignalingMessage};
use crate::signaling::offline::ice_candidates_to_payloads;
use crate::webrtc::common::{DataChannelStream, WebRtcPeer};

/// Connection timeout for WebRTC handshake
const WEBRTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Check if an error is a signaling-related error (vs file/transfer error).
///
/// Uses specific phrase matching to avoid false positives from generic terms
/// like "connection" or "timeout" which could appear in unrelated errors.
fn is_signaling_error(err: &anyhow::Error) -> bool {
    let err_msg = err.to_string().to_lowercase();

    // Specific signaling-related terms (always indicate signaling issues)
    if err_msg.contains("nostr") || err_msg.contains("signaling") {
        return true;
    }

    // "relay" alone is specific enough (Nostr relays, not generic relays)
    if err_msg.contains("relay") {
        return true;
    }

    // Require compound phrases for generic terms to avoid false positives
    // e.g., "relay connection" but not "webrtc connection"
    let signaling_phrases = [
        "nostr connection",
        "relay connection",
        "signaling timeout",
        "signaling failed",
        "relay timeout",
        "failed to connect to relay",
        "failed to publish",
        "failed to subscribe",
    ];

    signaling_phrases.iter().any(|phrase| err_msg.contains(phrase))
}

/// Handle signaling error with fallback to manual mode
async fn handle_signaling_error_with_fallback<F, Fut>(
    error: anyhow::Error,
    fallback_fn: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if is_signaling_error(&error) {
        eprintln!("\nNostr signaling failed: {}", error);
        eprintln!("Press Enter to use manual signaling (copy/paste), or Ctrl+C to abort...");

        // Wait for Enter with timeout to avoid blocking forever
        const FALLBACK_PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();
        match timeout(FALLBACK_PROMPT_TIMEOUT, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {
                // User pressed Enter, fall back to manual signaling
                fallback_fn().await
            }
            Ok(Err(e)) => {
                // IO error reading stdin
                Err(e).context("Failed to read user input")
            }
            Err(_) => {
                // Timeout elapsed
                anyhow::bail!(
                    "Timed out waiting for user input ({:?}). Aborting.",
                    FALLBACK_PROMPT_TIMEOUT
                )
            }
        }
    } else {
        // Non-signaling error, propagate it
        Err(error)
    }
}

/// Display transfer code or PIN to the user with instructions
async fn display_transfer_code(
    use_pin: bool,
    signaling_keys: &nostr_sdk::Keys,
    code_str: &str,
    transfer_id: &str,
) -> Result<()> {
    if use_pin {
        let pin = wormhole_common::auth::nostr_pin::publish_wormhole_code_via_pin(
            signaling_keys,
            code_str,
            transfer_id,
        )
        .await?;

        eprintln!("\n--- Receiver Instructions ---");
        eprintln!("Run: wormhole-rs-webrtc receive --pin");
        eprintln!("PIN: {}\n", pin);
    } else {
        eprintln!("\n--- Receiver Instructions ---");
        eprintln!("Run: wormhole-rs-webrtc receive");
        eprintln!("Wormhole code:\n{}\n", code_str);
    }
    Ok(())
}

/// Result of WebRTC connection attempt
enum WebRtcResult {
    Success,
    Failed(String),
}

/// Attempt WebRTC transfer with Nostr signaling using common transfer protocol
async fn try_webrtc_transfer(
    file: &mut File,
    header: &FileHeader,
    key: &[u8; 32],
    signaling: &NostrSignaling,
) -> Result<WebRtcResult> {
    eprintln!("Attempting WebRTC connection...");

    // Create WebRTC peer
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel BEFORE receiving offer (so it's included in SDP)
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Create oneshot channel for open notification
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();

    // Create the DataChannelStream (sets up handlers)
    let stream = DataChannelStream::new(data_channel.clone(), Some(open_tx));

    // Start listening for signaling messages
    let (mut signal_rx, signal_handle) = signaling.start_message_receiver();

    // Wait for receiver's offer
    eprintln!("Waiting for receiver to connect via Nostr signaling...");

    let receiver_pubkey;

    // Wait loop with timeout to prevent hanging indefinitely
    loop {
        let recv_result = timeout(WEBRTC_CONNECTION_TIMEOUT, signal_rx.recv()).await;

        match recv_result {
            Ok(Some(SignalingMessage::Offer { sender_pubkey, sdp })) => {
                eprintln!("Received offer from: {}", sender_pubkey.to_hex());
                receiver_pubkey = Some(sender_pubkey);

                // Set remote description
                let offer_sdp =
                    RTCSessionDescription::offer(sdp.sdp).context("Failed to create offer SDP")?;
                rtc_peer.set_remote_description(offer_sdp).await?;

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
                        eprintln!("Failed to add bundled ICE candidate: {}", e);
                    }
                }
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return Ok(WebRtcResult::Failed("Signaling channel closed".to_string()));
            }
            Err(_) => {
                // Timeout waiting for receiver's offer
                return Ok(WebRtcResult::Failed(
                    "Timeout waiting for receiver's offer. \
                     If receiver is not connecting, try manual signaling mode or check relay connectivity."
                        .to_string(),
                ));
            }
        }
    }

    let remote_pubkey =
        receiver_pubkey.expect("receiver_pubkey must be Some after receiving Offer");

    // Create and send answer
    let answer = rtc_peer.create_answer().await?;
    rtc_peer.set_local_description(answer.clone()).await?;

    // Gather ICE candidates
    eprintln!("Gathering ICE candidates...");
    let candidates = rtc_peer
        .gather_ice_candidates(Duration::from_secs(10))
        .await?;
    let candidate_payloads = ice_candidates_to_payloads(candidates)?;
    eprintln!("Gathered {} ICE candidates", candidate_payloads.len());

    signaling
        .publish_answer(&remote_pubkey, &answer.sdp, candidate_payloads)
        .await?;
    eprintln!("Sent answer to receiver");

    // Wait for data channel to open
    eprintln!("Waiting for data channel to open...");
    let open_result = timeout(WEBRTC_CONNECTION_TIMEOUT, open_rx).await;

    match open_result {
        Err(_) => {
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(
                "Timeout waiting for data channel".to_string(),
            ));
        }
        Ok(Err(_)) => {
            signal_handle.abort();
            return Ok(WebRtcResult::Failed(
                "Data channel failed to open".to_string(),
            ));
        }
        Ok(Ok(())) => {
            // Success: data channel opened
        }
    }

    // Display connection info
    let conn_info = rtc_peer.get_connection_info().await;
    eprintln!("WebRTC connection established!");
    eprintln!("   Connection: {}", conn_info.connection_type);
    if let (Some(local), Some(remote)) = (&conn_info.local_address, &conn_info.remote_address) {
        eprintln!("   Local: {} -> Remote: {}", local, remote);
    }

    // Small delay to ensure connection is stable
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Wrap peer in Arc for cleanup
    let rtc_peer = Arc::new(rtc_peer);

    // Use common transfer protocol
    let mut stream = stream;
    let result = run_sender_transfer(file, &mut stream, key, header).await;

    // Cleanup
    let _ = rtc_peer.close().await;
    signal_handle.abort();

    match result {
        Ok(_) => Ok(WebRtcResult::Success),
        Err(e) => Ok(WebRtcResult::Failed(format!("Transfer failed: {}", e))),
    }
}

/// Internal helper for webrtc transfer logic.
async fn transfer_data_webrtc_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
) -> Result<()> {
    // Generate encryption key (always required)
    let key = generate_key();
    eprintln!("Encryption enabled for transfer");

    // Create Nostr signaling client
    eprintln!("Connecting to Nostr relays for signaling...");
    let signaling = create_sender_signaling(custom_relays.clone(), use_default_relays).await?;

    eprintln!("Sender pubkey: {}", signaling.public_key().to_hex());
    eprintln!("Transfer ID: {}", signaling.transfer_id());

    // Generate wormhole code
    let code = generate_webrtc_code(
        &key,
        signaling.public_key().to_hex(),
        signaling.transfer_id().to_string(),
        Some(signaling.relay_urls().to_vec()),
        filename.clone(),
        match transfer_type {
            TransferType::File => "file",
            TransferType::Folder => "folder",
        },
    )?;

    let code_str = code.clone();

    display_transfer_code(use_pin, signaling.signing_keys(), &code_str, signaling.transfer_id()).await?;

    eprintln!("Filename: {}", filename);
    eprintln!("Size: {}", format_bytes(file_size));
    eprintln!("\nWaiting for receiver to connect...");

    // Create header for common transfer protocol
    let header = FileHeader::new(transfer_type, filename.clone(), file_size, checksum);

    // Try WebRTC transfer
    match try_webrtc_transfer(&mut file, &header, &key, &signaling).await? {
        WebRtcResult::Success => {
            signaling.disconnect().await;
            eprintln!("Connection closed.");
            Ok(())
        }
        WebRtcResult::Failed(reason) => {
            signaling.disconnect().await;
            anyhow::bail!(
                "WebRTC connection failed: {}\n\n\
                 If direct P2P connection is not possible, try:\n  \
                 - Use manual signaling: wormhole-rs-webrtc send --manual-signaling <file>",
                reason
            );
        }
    }
}

/// Send a file via webrtc transport
pub async fn send_file_webrtc(
    file_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
    manual_signaling: bool,
) -> Result<()> {
    // If manual signaling mode, use offline sender directly
    if manual_signaling {
        return crate::webrtc::offline_sender::send_file_offline(file_path).await;
    }

    // Try normal Nostr signaling path
    match send_file_webrtc_internal(file_path, custom_relays, use_default_relays, use_pin).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let path = file_path.to_path_buf();
            handle_signaling_error_with_fallback(e, || async move {
                crate::webrtc::offline_sender::send_file_offline(&path).await
            })
            .await
        }
    }
}

/// Internal function for normal Nostr signaling path
async fn send_file_webrtc_internal(
    file_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_data_webrtc_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        prepared.checksum,
        TransferType::File,
        custom_relays,
        use_default_relays,
        use_pin,
    )
    .await
}

/// Send a folder as a tar archive via webrtc transport
pub async fn send_folder_webrtc(
    folder_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
    manual_signaling: bool,
) -> Result<()> {
    // If manual signaling mode, use offline sender directly
    if manual_signaling {
        return crate::webrtc::offline_sender::send_folder_offline(folder_path).await;
    }

    // Try normal Nostr signaling path
    match send_folder_webrtc_internal(folder_path, custom_relays, use_default_relays, use_pin).await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            let path = folder_path.to_path_buf();
            handle_signaling_error_with_fallback(e, || async move {
                crate::webrtc::offline_sender::send_folder_offline(&path).await
            })
            .await
        }
    }
}

/// Internal function for normal Nostr signaling path (folder)
async fn send_folder_webrtc_internal(
    folder_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler for Ctrl+C
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_handler = setup_temp_file_cleanup_handler(temp_path.clone());

    // Run transfer with interrupt handling
    let result = tokio::select! {
        result = transfer_data_webrtc_internal(
            prepared.file,
            prepared.filename,
            prepared.file_size,
            0, // Folders are not resumable
            TransferType::Folder,
            custom_relays,
            use_default_relays,
            use_pin,
        ) => result,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - clean up and return Interrupted error
            cleanup_handler.cleanup_path.lock().await.take();
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(Interrupted.into());
        }
    };

    // Clear cleanup path
    cleanup_handler.cleanup_path.lock().await.take();

    result
}
