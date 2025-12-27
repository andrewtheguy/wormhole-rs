//! ICE transport receiver - receives files using ICE for NAT traversal.
//!
//! Uses webrtc-ice for connection establishment, then runs the unified
//! transfer protocol on top of the TCP-based ICE connection.

use anyhow::{Context, Result};
use std::path::PathBuf;

use super::agent::IceTransport;
use super::signaling::{create_receiver_signaling, IceSignalingMessage, IceSignalingPayload};
use wormhole_common::core::transfer::run_receiver_transfer;
use wormhole_common::core::wormhole::{decode_key, parse_code, PROTOCOL_WEBRTC};

/// Receive a file via ICE transport.
///
/// Parses the wormhole code to extract transfer metadata and encryption key,
/// then establishes an ICE connection using Nostr for signaling.
pub async fn receive_ice(code: &str, output_dir: Option<PathBuf>, no_resume: bool) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    // Verify it's a webrtc protocol code
    if token.protocol != PROTOCOL_WEBRTC {
        anyhow::bail!(
            "Invalid protocol '{}'. This receiver requires '{}' protocol.",
            token.protocol,
            PROTOCOL_WEBRTC
        );
    }

    // Extract encryption key from wormhole code
    let key = decode_key(&token.key).context("Failed to decode encryption key from wormhole code")?;

    // Extract webrtc-specific fields
    let sender_pubkey_hex = token
        .webrtc_sender_pubkey
        .context("Missing sender pubkey in wormhole code")?;
    let transfer_id = token
        .webrtc_transfer_id
        .context("Missing transfer ID in wormhole code")?;
    let relay_urls = token
        .webrtc_relays
        .unwrap_or_default();

    if relay_urls.is_empty() {
        anyhow::bail!("No relay URLs in wormhole code");
    }

    let filename = token.webrtc_filename.as_deref().unwrap_or("unknown");
    eprintln!("Receiving: {}", filename);

    eprintln!("Setting up ICE transport...");

    // Parse sender's public key
    let sender_pubkey =
        nostr_sdk::PublicKey::from_hex(&sender_pubkey_hex).context("Invalid sender public key")?;

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
    let signaling = create_receiver_signaling(&transfer_id, relay_urls).await?;

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

    // Add remote candidates
    ice.add_remote_candidates(&offer.candidates)?;

    // Connect as controlled agent (acceptor)
    eprintln!("Establishing ICE connection...");
    let conn = ice.accept(&offer.ufrag, &offer.pwd).await?;
    eprintln!("ICE connection established!");

    // Run unified receiver transfer (key from wormhole code)
    let (_path, _conn) = run_receiver_transfer(conn, key, output_dir, no_resume).await?;

    // Cleanup signaling
    signaling.disconnect().await;

    eprintln!("Transfer complete!");
    Ok(())
}
