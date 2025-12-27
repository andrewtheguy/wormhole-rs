//! ICE transport sender - sends files using ICE for NAT traversal.
//!
//! Uses webrtc-ice for connection establishment, then runs the unified
//! transfer protocol on top of the TCP-based ICE connection.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::fs::File;

use super::agent::IceTransport;
use super::signaling::{create_sender_signaling, IceSignalingMessage, IceSignalingPayload};
use wormhole_common::auth::spake2::handshake_as_responder;
use wormhole_common::core::transfer::{
    format_bytes, prepare_file_for_send, prepare_folder_for_send, run_sender_transfer,
    setup_temp_file_cleanup_handler, FileHeader, TransferResult, TransferType,
};

/// Send a file via ICE transport.
///
/// Establishes an ICE connection using Nostr for signaling, then transfers
/// the file using the unified protocol.
pub async fn send_file_ice(
    file_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_via_ice(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        prepared.checksum,
        TransferType::File,
        custom_relays,
        use_default_relays,
    )
    .await
}

/// Send a folder as a tar archive via ICE transport.
///
/// Creates a tar archive of the folder, establishes an ICE connection using
/// Nostr for signaling, then transfers the archive using the unified protocol.
pub async fn send_folder_ice(
    folder_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler for temp file
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_path = setup_temp_file_cleanup_handler(temp_path);

    let result = transfer_via_ice(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        0, // Folders are not resumable
        TransferType::Folder,
        custom_relays,
        use_default_relays,
    )
    .await;

    // Clear cleanup path (file will be dropped with temp_file)
    cleanup_path.lock().await.take();

    result
}

/// Internal transfer logic using ICE transport.
async fn transfer_via_ice(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<()> {
    eprintln!("Setting up ICE transport...");

    // Create ICE transport
    let mut ice = IceTransport::new().await?;
    let local_creds = ice.get_local_credentials().await;

    // Start gathering candidates
    ice.gather_candidates().await?;
    eprintln!("Gathering ICE candidates...");

    // Collect candidates (blocking until complete)
    let candidates = ice.collect_candidates().await;
    eprintln!("Gathered {} ICE candidates", candidates.len());

    if candidates.is_empty() {
        anyhow::bail!("Failed to gather any ICE candidates");
    }

    // Create signaling client
    eprintln!("Connecting to Nostr relays for signaling...");
    let signaling = create_sender_signaling(custom_relays, use_default_relays).await?;

    // Display receiver instructions
    eprintln!("\n--- Receiver Instructions ---");
    eprintln!("Run: wormhole-rs-webrtc receive-ice \\");
    eprintln!("       --transfer-id {} \\", signaling.transfer_id());
    eprintln!(
        "       --relay {}",
        signaling.relay_urls().first().unwrap_or(&"".to_string())
    );
    eprintln!("       --sender-pubkey {}", signaling.public_key().to_hex());
    eprintln!();
    eprintln!("Transfer ID: {}", signaling.transfer_id());
    eprintln!("Filename: {}", filename);
    eprintln!("Size: {}", format_bytes(file_size));
    eprintln!("\nWaiting for receiver to connect...");

    // Wait for receiver's answer (contains their credentials + candidates)
    let answer = match signaling.wait_for_message(120).await? {
        Some(IceSignalingMessage::Answer {
            sender_pubkey,
            payload,
        }) => {
            eprintln!("Received answer from: {}", sender_pubkey.to_hex());

            // Publish our offer now that we know the receiver's pubkey
            let offer = IceSignalingPayload::new(&local_creds, candidates);
            signaling.publish_offer(&sender_pubkey, &offer).await?;
            eprintln!("Published ICE offer");

            (sender_pubkey, payload)
        }
        Some(IceSignalingMessage::Offer { .. }) => {
            anyhow::bail!("Unexpected ICE offer (we are the sender)");
        }
        None => {
            anyhow::bail!("Timeout waiting for receiver to connect");
        }
    };

    let (_receiver_pubkey, receiver_payload) = answer;

    eprintln!(
        "Received {} remote candidates from receiver",
        receiver_payload.candidates.len()
    );

    // Set remote credentials
    ice.set_remote_credentials(&super::agent::IceCredentials {
        ufrag: receiver_payload.ufrag.clone(),
        pwd: receiver_payload.pwd.clone(),
    })
    .await?;

    // Connect as controlling agent (dialer)
    eprintln!("Establishing ICE connection...");
    let mut conn = ice
        .dial(&receiver_payload.ufrag, &receiver_payload.pwd)
        .await?;
    eprintln!("ICE connection established!");

    // Perform SPAKE2 handshake using transfer ID as shared context
    eprintln!("Performing key exchange...");
    let key = handshake_as_responder(&mut conn, signaling.transfer_id(), signaling.transfer_id())
        .await
        .context("SPAKE2 handshake failed")?;
    eprintln!("Key exchange successful!");

    // Create header and run unified transfer
    let header = FileHeader::new(transfer_type, filename, file_size, checksum);
    let result = run_sender_transfer(&mut file, &mut conn, &key, &header).await?;

    if result == TransferResult::Aborted {
        anyhow::bail!("Transfer cancelled by receiver");
    }

    // Cleanup signaling
    signaling.disconnect().await;

    eprintln!("Transfer complete!");
    Ok(())
}
