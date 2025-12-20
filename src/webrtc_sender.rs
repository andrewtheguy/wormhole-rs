//! WebRTC transport sender: WebRTC with Nostr signaling
//!
//! This module implements the webrtc transport which:
//! 1. Uses Nostr for WebRTC signaling
//! 2. Attempts direct P2P connection via STUN
//! 3. Manual signaling fallback via copy/paste

use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::crypto::{encrypt_chunk, generate_key, CHUNK_SIZE};
use crate::nostr_signaling::{create_sender_signaling, NostrSignaling, SignalingMessage};
use crate::transfer::{
    format_bytes, num_chunks, prepare_file_for_send, prepare_folder_for_send, FileHeader,
    TransferType,
};
use crate::webrtc_common::{setup_data_channel_handlers, WebRtcPeer};
use crate::wormhole::generate_webrtc_code;
use crate::cli_instructions::print_receiver_command;

/// Connection timeout for WebRTC handshake
const WEBRTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

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
            println!("Data channel closed");
        })
    }));
}

/// Check if an error is a signaling-related error (vs file/transfer error)
fn is_signaling_error(err: &anyhow::Error) -> bool {
    let err_msg = err.to_string().to_lowercase();
    err_msg.contains("relay")
        || err_msg.contains("nostr")
        || err_msg.contains("signaling")
        || err_msg.contains("connection")
        || err_msg.contains("timeout")
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

        // Wait for Enter
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        // Fall back to manual signaling
        fallback_fn().await
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
        let pin = crate::nostr_pin::publish_wormhole_code_via_pin(
            signaling_keys,
            code_str,
            transfer_id,
        )
        .await?;

        print_receiver_command("wormhole-rs receive --pin");
        println!("🔢 PIN: {}\n", pin);
        println!("Then enter the PIN above when prompted.\n");
    } else {
        print_receiver_command("wormhole-rs receive");
        println!("🔮 Wormhole code:\n{}\n", code_str);
        println!("Then enter the code above when prompted.\n");
    }
    Ok(())
}

/// Result of WebRTC connection attempt
enum WebRtcResult {
    Success,
    Failed(String),
}

/// Attempt WebRTC transfer with Nostr signaling
async fn try_webrtc_transfer(
    file: &mut File,
    filename: &str,
    file_size: u64,
    transfer_type: TransferType,
    key: &[u8; 32],
    signaling: &NostrSignaling,
) -> Result<WebRtcResult> {
    println!("Attempting WebRTC connection...");

    // Create WebRTC peer
    let mut rtc_peer = WebRtcPeer::new().await?;

    // Create data channel BEFORE receiving offer (so it's included in SDP)
    let data_channel = rtc_peer.create_data_channel("file-transfer").await?;

    // Set up channel for receiving data channel messages
    let (message_tx, mut message_rx) = mpsc::channel::<Vec<u8>>(100);
    let (open_tx, open_rx) = tokio::sync::oneshot::channel();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));
    setup_data_channel_close_handler(&data_channel, close_tx);

    // Start listening for signaling messages
    let (mut signal_rx, signal_handle) = signaling.start_message_receiver();

    // Wait for receiver's "ready" signal and offer
    println!("Waiting for receiver to connect via Nostr signaling...");

    let receiver_pubkey;

    // Wait loop without timeout (unless user forces fallback)
    loop {
        match signal_rx.recv().await {
            Some(SignalingMessage::Ready { sender_pubkey }) => {
                println!("Receiver ready: {}", sender_pubkey.to_hex());
                // Note: We don't need to store receiver_pubkey here as we'll get it again with the Offer
            }
            Some(SignalingMessage::Offer { sender_pubkey, sdp }) => {
                println!("Received offer from: {}", sender_pubkey.to_hex());
                receiver_pubkey = Some(sender_pubkey);

                // Set remote description
                let offer_sdp = RTCSessionDescription::offer(sdp.sdp)
                    .context("Failed to create offer SDP")?;
                rtc_peer.set_remote_description(offer_sdp).await?;
                break;
            }
            Some(SignalingMessage::IceCandidate {
                candidate, seq, ..
            }) => {
                // Buffer early ICE candidates
                println!("Received early ICE candidate (seq: {})", seq);
                let candidate_init = RTCIceCandidateInit {
                    candidate: candidate.candidate,
                    sdp_mid: candidate.sdp_mid,
                    sdp_mline_index: candidate.sdp_m_line_index,
                    username_fragment: None,
                };
                let _ = rtc_peer.add_ice_candidate(candidate_init).await;
            }
            Some(_) => continue,
            None => {
                return Ok(WebRtcResult::Failed("Signaling channel closed".to_string()));
            }
        }
    }

    let remote_pubkey = match receiver_pubkey {
        Some(pk) => pk,
        None => {
            signal_handle.abort();
            return Ok(WebRtcResult::Failed("No receiver pubkey".to_string()));
        }
    };

    // Create and send answer
    let answer = rtc_peer.create_answer().await?;
    rtc_peer.set_local_description(answer.clone()).await?;
    signaling.publish_answer(&remote_pubkey, &answer.sdp).await?;
    println!("Sent answer to receiver");

    // Take ownership of ICE candidate receiver before wrapping rtc_peer in Arc
    let mut ice_rx = rtc_peer
        .take_ice_candidate_rx()
        .expect("ICE candidate receiver already taken");

    // Spawn task to send our ICE candidates
    let signaling_clone = signaling.client.clone();
    let signaling_keys = signaling.keys.clone();
    let transfer_id = signaling.transfer_id().to_string();
    let remote_pubkey_clone = remote_pubkey;

    let ice_seq = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let ice_seq_clone = ice_seq.clone();

    let ice_sender_handle = tokio::spawn(async move {
        while let Some(candidate) = ice_rx.recv().await {
            let candidate_json = match candidate.to_json() {
                Ok(json) => json,
                Err(_) => continue,
            };

            let seq = ice_seq_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            // Create ICE candidate event manually
            let payload = crate::nostr_signaling::IceCandidatePayload {
                candidate: candidate_json.candidate,
                sdp_m_line_index: candidate_json.sdp_mline_index,
                sdp_mid: candidate_json.sdp_mid,
            };

            let content =
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&payload).unwrap());

            let tags = vec![
                nostr_sdk::Tag::custom(
                    nostr_sdk::TagKind::SingleLetter(nostr_sdk::SingleLetterTag::lowercase(
                        nostr_sdk::Alphabet::T,
                    )),
                    vec![transfer_id.clone()],
                ),
                nostr_sdk::Tag::custom(
                    nostr_sdk::TagKind::SingleLetter(nostr_sdk::SingleLetterTag::lowercase(
                        nostr_sdk::Alphabet::P,
                    )),
                    vec![remote_pubkey_clone.to_hex()],
                ),
                nostr_sdk::Tag::custom(
                    nostr_sdk::TagKind::Custom("type".into()),
                    vec!["webrtc-ice".to_string()],
                ),
                nostr_sdk::Tag::custom(
                    nostr_sdk::TagKind::Custom("seq".into()),
                    vec![seq.to_string()],
                ),
            ];

            if let Ok(event) = nostr_sdk::EventBuilder::new(
                crate::nostr_protocol::nostr_file_transfer_kind(),
                &content,
            )
            .tags(tags)
            .sign_with_keys(&signaling_keys)
            {
                let _ = signaling_clone.send_event(&event).await;
            }
        }
    });

    // Process incoming ICE candidates in background
    let rtc_peer_arc = Arc::new(rtc_peer);
    let rtc_peer_clone = rtc_peer_arc.clone();

    let ice_receiver_handle = tokio::spawn(async move {
        while let Some(msg) = signal_rx.recv().await {
            if let SignalingMessage::IceCandidate { candidate, .. } = msg {
                let candidate_init = RTCIceCandidateInit {
                    candidate: candidate.candidate,
                    sdp_mid: candidate.sdp_mid,
                    sdp_mline_index: candidate.sdp_m_line_index,
                    username_fragment: None,
                };
                let _ = rtc_peer_clone.add_ice_candidate(candidate_init).await;
            }
        }
    });

    // Wait for data channel to open
    println!("Waiting for data channel to open...");
    let open_result = timeout(WEBRTC_CONNECTION_TIMEOUT, open_rx).await;

    if open_result.is_err() {
        ice_sender_handle.abort();
        ice_receiver_handle.abort();
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(
            "Timeout waiting for data channel".to_string(),
        ));
    }

    if open_result.unwrap().is_err() {
        ice_sender_handle.abort();
        ice_receiver_handle.abort();
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(
            "Data channel failed to open".to_string(),
        ));
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
    let header = FileHeader::new(transfer_type, filename.to_string(), file_size);
    let header_bytes = header.to_bytes();
    let encrypted_header = encrypt_chunk(key, 0, &header_bytes)?;

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
        let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
        if bytes_read == 0 {
            break;
        }

        // Encrypt chunk
        let encrypted_chunk = encrypt_chunk(key, chunk_num, &buffer[..bytes_read])?;

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

    // Wait for ACK from receiver (or data channel close, which means receiver is done)
    println!("Waiting for receiver to confirm...");

    // Wrap close_rx in a Mutex so it can be used in async block
    let close_rx = Arc::new(Mutex::new(Some(close_rx)));
    let close_rx_clone = close_rx.clone();

    let ack_result: Result<bool, ()> = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                msg = message_rx.recv() => {
                    match msg {
                        Some(data) if !data.is_empty() && data[0] == 3 => {
                            return true; // Got explicit ACK
                        }
                        Some(_) => continue,
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
            println!("Receiver confirmed!");
        }
        Ok(false) => {
            // Data channel closed - receiver got the data and disconnected
            println!("Transfer complete (receiver disconnected)");
        }
        Err(_) => {
            println!("Warning: Did not receive confirmation from receiver (timeout)");
        }
    }

    // Close connections and abort background tasks
    ice_sender_handle.abort();
    ice_receiver_handle.abort();
    let _ = rtc_peer_arc.close().await;
    signal_handle.abort();

    Ok(WebRtcResult::Success)
}

/// Internal helper for webrtc transfer logic.
async fn transfer_data_webrtc_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
    use_pin: bool,
) -> Result<()> {
    // Generate encryption key (always required)
    let key = generate_key();
    println!("Encryption enabled for transfer");

    // Create Nostr signaling client
    println!("Connecting to Nostr relays for signaling...");
    let signaling = create_sender_signaling(custom_relays.clone(), use_default_relays).await?;

    println!("Sender pubkey: {}", signaling.public_key().to_hex());
    println!("Transfer ID: {}", signaling.transfer_id());

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

    display_transfer_code(use_pin, &signaling.keys, &code_str, &signaling.transfer_id()).await?;

    // Try WebRTC transfer
    match try_webrtc_transfer(
        &mut file,
        &filename,
        file_size,
        transfer_type,
        &key,
        &signaling,
    )
    .await?
    {
        WebRtcResult::Success => {
            signaling.disconnect().await;
            println!("Connection closed.");
            Ok(())
        }
        WebRtcResult::Failed(reason) => {
            signaling.disconnect().await;
            anyhow::bail!(
                "WebRTC connection failed: {}\n\n\
                 If direct P2P connection is not possible, try one of these alternatives:\n  \
                 - Use Tor mode: wormhole-rs send-tor <file>\n  \
                 - Use manual signaling: wormhole-rs send --manual-signaling <file>\n  \
                 - Use local mode (same LAN): wormhole-rs send-local <file>",
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
        return crate::webrtc_offline_sender::send_file_offline(file_path).await;
    }

    // Try normal Nostr signaling path
    match send_file_webrtc_internal(
        file_path,
        custom_relays,
        use_default_relays,
        use_pin,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            let path = file_path.to_path_buf();
            handle_signaling_error_with_fallback(e, || async move {
                crate::webrtc_offline_sender::send_file_offline(&path).await
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
        return crate::webrtc_offline_sender::send_folder_offline(folder_path).await;
    }

    // Try normal Nostr signaling path
    match send_folder_webrtc_internal(
        folder_path,
        custom_relays,
        use_default_relays,
        use_pin,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            let path = folder_path.to_path_buf();
            handle_signaling_error_with_fallback(e, || async move {
                crate::webrtc_offline_sender::send_folder_offline(&path).await
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
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    let result = transfer_data_webrtc_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::Folder,
        custom_relays,
        use_default_relays,
        use_pin,
    )
    .await;

    // Clear cleanup path
    cleanup_path.lock().await.take();

    result
}
