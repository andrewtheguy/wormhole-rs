//! ICE transport receiver - receives files using ICE for NAT traversal.
//!
//! Uses webrtc-ice for connection establishment, then runs the unified
//! transfer protocol on top of the TCP-based ICE connection.

use anyhow::{Context, Result};
use std::path::PathBuf;

use super::agent::IceTransport;
use super::signaling::{create_receiver_signaling, IceSignalingMessage, IceSignalingPayload};
use wormhole_common::auth::spake2::handshake_as_initiator;
use wormhole_common::core::transfer::run_receiver_transfer;

/// Receive a file via ICE transport.
///
/// Connects to a sender using ICE with Nostr for signaling, then receives
/// the file using the unified protocol.
pub async fn receive_ice(
    transfer_id: &str,
    relay_urls: Vec<String>,
    sender_pubkey_hex: &str,
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<()> {
    eprintln!("Setting up ICE transport...");

    // Parse sender's public key
    let sender_pubkey =
        nostr_sdk::PublicKey::from_hex(sender_pubkey_hex).context("Invalid sender public key")?;

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
    let signaling = create_receiver_signaling(transfer_id, relay_urls).await?;

    // Publish our answer (our credentials + candidates)
    let answer = IceSignalingPayload::new(&local_creds, candidates);
    signaling.publish_answer(&sender_pubkey, &answer).await?;
    eprintln!("Published ICE answer to sender");

    // Wait for sender's offer (their credentials + candidates)
    eprintln!("Waiting for sender's offer...");
    let offer = match signaling.wait_for_message(60).await? {
        Some(IceSignalingMessage::Offer { payload, .. }) => {
            eprintln!("Received ICE offer from sender");
            payload
        }
        Some(IceSignalingMessage::Answer { .. }) => {
            anyhow::bail!("Unexpected ICE answer (we are the receiver)");
        }
        None => {
            anyhow::bail!("Timeout waiting for sender's offer");
        }
    };

    eprintln!(
        "Received {} remote candidates from sender",
        offer.candidates.len()
    );

    // Set remote credentials
    ice.set_remote_credentials(&super::agent::IceCredentials {
        ufrag: offer.ufrag.clone(),
        pwd: offer.pwd.clone(),
    })
    .await?;

    // Connect as controlled agent (acceptor)
    eprintln!("Establishing ICE connection...");
    let mut conn = ice.accept(&offer.ufrag, &offer.pwd).await?;
    eprintln!("ICE connection established!");

    // Perform SPAKE2 handshake using transfer ID as shared context
    eprintln!("Performing key exchange...");
    let key = handshake_as_initiator(&mut conn, transfer_id, transfer_id)
        .await
        .context("SPAKE2 handshake failed")?;
    eprintln!("Key exchange successful!");

    // Run unified receiver transfer
    let (_path, _conn) = run_receiver_transfer(conn, key, output_dir, no_resume).await?;

    // Cleanup signaling
    signaling.disconnect().await;

    eprintln!("Transfer complete!");
    Ok(())
}
