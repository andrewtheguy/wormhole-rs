//! Hybrid transport sender: WebRTC with Nostr signaling + relay fallback
//!
//! This module implements the hybrid transport which:
//! 1. Uses Nostr for WebRTC signaling (replacing PeerJS)
//! 2. Attempts direct P2P connection via STUN
//! 3. Falls back to Nostr relay mode if WebRTC fails

use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::crypto::{encrypt_chunk, generate_key, CHUNK_SIZE};
use crate::folder::{create_tar_archive, print_tar_creation_info};
use crate::nostr_protocol::MAX_NOSTR_FILE_SIZE;
// Re-export TransferResult for public API
pub use crate::nostr_sender::TransferResult;
use crate::nostr_sender;
use crate::nostr_signaling::{create_sender_signaling, NostrSignaling, SignalingMessage};
use crate::transfer::{format_bytes, num_chunks, FileHeader, TransferType};
use crate::webrtc_common::{setup_data_channel_handlers, WebRtcPeer};
use crate::wormhole::generate_hybrid_code;

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
    setup_data_channel_handlers(&data_channel, message_tx, Some(open_tx));

    // Start listening for signaling messages
    let (mut signal_rx, signal_handle) = signaling.start_message_receiver();

    // Wait for receiver's "ready" signal and offer
    println!("Waiting for receiver to connect via Nostr signaling...");
    let mut receiver_pubkey = None;

    let offer_result = timeout(WEBRTC_CONNECTION_TIMEOUT, async {
        loop {
            match signal_rx.recv().await {
                Some(SignalingMessage::Ready { sender_pubkey }) => {
                    println!("Receiver ready: {}", sender_pubkey.to_hex());
                    receiver_pubkey = Some(sender_pubkey);
                }
                Some(SignalingMessage::Offer { sender_pubkey, sdp }) => {
                    println!("Received offer from: {}", sender_pubkey.to_hex());
                    receiver_pubkey = Some(sender_pubkey);

                    // Set remote description
                    let offer_sdp = RTCSessionDescription::offer(sdp.sdp)
                        .context("Failed to create offer SDP")?;
                    rtc_peer.set_remote_description(offer_sdp).await?;

                    return Ok::<_, anyhow::Error>(());
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
                    return Err(anyhow::anyhow!("Signaling channel closed"));
                }
            }
        }
    })
    .await;

    if offer_result.is_err() {
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(
            "Timeout waiting for receiver offer".to_string(),
        ));
    }

    if let Err(e) = offer_result.unwrap() {
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(format!("Failed to receive offer: {}", e)));
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

    tokio::spawn(async move {
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

    tokio::spawn(async move {
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
        signal_handle.abort();
        return Ok(WebRtcResult::Failed(
            "Timeout waiting for data channel".to_string(),
        ));
    }

    if open_result.unwrap().is_err() {
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

    // Wait for ACK from receiver
    println!("Waiting for receiver to confirm...");
    let ack_result = timeout(Duration::from_secs(30), async {
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
    signal_handle.abort();

    Ok(WebRtcResult::Success)
}

/// Internal helper for hybrid transfer logic.
async fn transfer_data_hybrid_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    force_relay: bool,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<TransferResult> {
    // Generate encryption key (always required)
    let key = generate_key();
    println!("Encryption enabled for transfer");

    // If force relay mode, we need to set up signaling just for credentials
    // then immediately use relay mode
    if force_relay {
        // Check file size limit for relay mode BEFORE generating wormhole code
        if file_size > MAX_NOSTR_FILE_SIZE {
            anyhow::bail!(
                "File size ({}) exceeds Nostr relay limit ({}).\n\
                 Remove --force-relay to use WebRTC for larger files.",
                format_bytes(file_size),
                format_bytes(MAX_NOSTR_FILE_SIZE)
            );
        }

        println!("Force relay mode enabled, using Nostr relay transport");

        // Create signaling to get credentials
        println!("Connecting to Nostr relays for signaling...");
        let signaling = create_sender_signaling(custom_relays.clone(), use_default_relays).await?;

        println!("Sender pubkey: {}", signaling.public_key().to_hex());
        println!("Transfer ID: {}", signaling.transfer_id());

        // Generate wormhole code
        let code = generate_hybrid_code(
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

        println!("\nWormhole code:\n{}\n", code);
        println!("On the receiving end, run:");
        println!("  wormhole-rs receive\n");
        println!("Then enter the code above when prompted.\n");

        // Go directly to relay mode
        let result = nostr_sender::send_relay_fallback(
            file,
            file_size,
            signaling.keys.clone(),
            signaling.transfer_id().to_string(),
            key,
            signaling.relay_urls().to_vec(),
        )
        .await;

        signaling.disconnect().await;
        return result;
    }

    // Create Nostr signaling client
    println!("Connecting to Nostr relays for signaling...");
    let signaling = create_sender_signaling(custom_relays.clone(), use_default_relays).await?;

    println!("Sender pubkey: {}", signaling.public_key().to_hex());
    println!("Transfer ID: {}", signaling.transfer_id());

    // Generate wormhole code
    let code = generate_hybrid_code(
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

    println!("\nWormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive\n");
    println!("Then enter the code above when prompted.\n");

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
            return Ok(TransferResult::Confirmed);
        }
        WebRtcResult::Failed(reason) => {
            println!("\nWebRTC connection failed: {}", reason);
            println!("Falling back to Nostr relay mode...\n");
        }
    }

    // Fallback to Nostr relay mode using existing credentials
    // Reset file position
    file.rewind().await.context("Failed to reset file position")?;

    let result = nostr_sender::send_relay_fallback(
        file,
        file_size,
        signaling.keys.clone(),
        signaling.transfer_id().to_string(),
        key,
        signaling.relay_urls().to_vec(),
    )
    .await;

    signaling.disconnect().await;
    result
}

/// Send a file via hybrid transport (WebRTC + Nostr fallback)
pub async fn send_file_hybrid(
    file_path: &Path,
    force_relay: bool,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<TransferResult> {
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
    let file = File::open(file_path)
        .await
        .context("Failed to open file")?;

    // Transfer using hybrid transport
    transfer_data_hybrid_internal(
        file,
        filename,
        file_size,
        TransferType::File,
        force_relay,
        custom_relays,
        use_default_relays,
    )
    .await
}

/// Send a folder as a tar archive via hybrid transport
pub async fn send_folder_hybrid(
    folder_path: &Path,
    force_relay: bool,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<TransferResult> {
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

    println!("Archive created: {} ({})", tar_filename, format_bytes(file_size));

    // Open tar file
    let file = File::open(temp_tar.path())
        .await
        .context("Failed to open tar file")?;

    // Transfer using hybrid transport
    let result = transfer_data_hybrid_internal(
        file,
        tar_filename,
        file_size,
        TransferType::Folder,
        force_relay,
        custom_relays,
        use_default_relays,
    )
    .await;

    // Clear cleanup path
    cleanup_path.lock().await.take();

    result
}
