//! Nostr relay transport for hybrid fallback
//!
//! This module provides relay-based file transfer when WebRTC direct connection fails.
//! It uses the same credentials (keys, transfer_id, key) from the hybrid signaling.

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use nostr_sdk::prelude::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

use crate::crypto::encrypt_chunk;
use crate::nostr_protocol::{
    create_chunk_event, get_transfer_id, is_ack_event, parse_ack_event, DEFAULT_NOSTR_RELAYS,
    MAX_NOSTR_FILE_SIZE, NOSTR_CHUNK_SIZE,
};
use crate::transfer::format_bytes;

const COMPLETION_ACK_TIMEOUT_SECS: u64 = 60;
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3;
const CONCURRENT_CHUNKS: usize = 5;

/// Send file data via Nostr relay as fallback for hybrid transport.
///
/// This function uses existing credentials from the hybrid signaling,
/// so the receiver can use the same wormhole code that was already displayed.
///
/// # Arguments
/// * `file` - Open file handle to send
/// * `file_size` - Size of the file in bytes
/// * `sender_keys` - Sender's Nostr keys (from hybrid signaling)
/// * `transfer_id` - Transfer ID (from hybrid signaling)
/// * `encryption_key` - AES-256-GCM key (from hybrid signaling)
/// * `relay_urls` - Relay URLs to use (from hybrid signaling)
pub async fn send_relay_fallback(
    mut file: File,
    file_size: u64,
    sender_keys: Keys,
    transfer_id: String,
    encryption_key: [u8; 32],
    relay_urls: Vec<String>,
) -> Result<()> {
    // Validate file size
    if file_size > MAX_NOSTR_FILE_SIZE {
        anyhow::bail!(
            "File size ({}) exceeds Nostr relay limit ({})\n\
             WebRTC connection is required for larger files.",
            format_bytes(file_size),
            format_bytes(MAX_NOSTR_FILE_SIZE)
        );
    }

    let sender_pubkey = sender_keys.public_key();
    println!("Using existing credentials for relay fallback");
    println!("   Sender: {}", sender_pubkey.to_hex());
    println!("   Transfer ID: {}", transfer_id);

    // Use provided relays or fall back to defaults
    let relay_urls = if relay_urls.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        relay_urls
    };

    println!("Connecting to {} Nostr relays...", relay_urls.len());
    for url in &relay_urls {
        println!("   - {}", url);
    }

    // Create Nostr client and connect to relays
    let client = Client::new(sender_keys.clone());
    for relay_url in &relay_urls {
        if let Err(e) = client.add_relay(relay_url).await {
            eprintln!("Warning: Failed to add relay {}: {}", relay_url, e);
        }
    }

    client.connect().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check connection status
    let relay_statuses = client.relays().await;
    let mut connected_count = 0;
    let mut failed_relays = Vec::new();

    for relay_url_str in &relay_urls {
        if let Ok(relay_url) = RelayUrl::parse(relay_url_str) {
            if let Some(relay) = relay_statuses.get(&relay_url) {
                if relay.is_connected() {
                    connected_count += 1;
                } else {
                    failed_relays.push(relay_url_str.clone());
                }
            } else {
                failed_relays.push(relay_url_str.clone());
            }
        } else {
            failed_relays.push(relay_url_str.clone());
        }
    }

    if !failed_relays.is_empty() {
        for failed in &failed_relays {
            eprintln!("Warning: Failed to connect to relay: {}", failed);
        }
    }

    if connected_count < MIN_RELAYS_REQUIRED {
        anyhow::bail!(
            "Failed to connect to enough relays ({}/{} connected, need {}+)",
            connected_count,
            relay_urls.len(),
            MIN_RELAYS_REQUIRED
        );
    }

    println!("Connected to {} relays", connected_count);

    // Calculate total chunks
    let total_chunks = ((file_size + NOSTR_CHUNK_SIZE as u64 - 1) / NOSTR_CHUNK_SIZE as u64) as u32;
    println!("Data will be sent in {} chunks", total_chunks);

    // Subscribe to ACK events
    let mut notifications = client.notifications();

    let filter = Filter::new()
        .kind(crate::nostr_protocol::nostr_file_transfer_kind())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::T),
            transfer_id.clone(),
        )
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            sender_pubkey.to_hex(),
        );

    if let Err(e) = client.subscribe(filter, None).await {
        anyhow::bail!(
            "Failed to subscribe to ACK events: {}\n\
             Without subscription, receiver ACKs cannot be received.",
            e
        );
    }

    tokio::time::sleep(Duration::from_secs(SUBSCRIPTION_SETUP_DELAY_SECS)).await;

    println!("Waiting for receiver to connect via relay...");

    // Wait for first ACK to confirm receiver is ready
    let mut receiver_ready = false;
    let ready_timeout = Duration::from_secs(300);
    let start_time = tokio::time::Instant::now();

    while !receiver_ready && start_time.elapsed() < ready_timeout {
        match timeout(Duration::from_secs(5), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_ack_event(&event) && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    println!("Receiver connected and ready!");
                    receiver_ready = true;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    if !receiver_ready {
        anyhow::bail!("Timeout waiting for receiver to connect (5 minutes)");
    }

    // Read and encrypt all chunks
    println!("Reading and encrypting {} chunks...", total_chunks);
    let mut all_data = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut all_data)
        .await
        .context("Failed to read file data")?;

    // Prepare all chunk events
    let mut chunk_events = Vec::with_capacity(total_chunks as usize);
    for seq in 0..total_chunks {
        let start = (seq as usize) * NOSTR_CHUNK_SIZE;
        let end = std::cmp::min(start + NOSTR_CHUNK_SIZE, all_data.len());
        let chunk_data = &all_data[start..end];

        let encrypted_chunk = encrypt_chunk(&encryption_key, seq as u64, chunk_data)
            .context("Failed to encrypt chunk")?;

        let chunk_event = create_chunk_event(
            &sender_keys,
            &transfer_id,
            seq,
            total_chunks,
            &encrypted_chunk,
        )?;

        chunk_events.push((seq, chunk_event));
    }

    // Send chunks concurrently
    println!(
        "Sending {} chunks ({} concurrent)...",
        total_chunks, CONCURRENT_CHUNKS
    );
    let chunks_sent = Arc::new(AtomicU32::new(0));
    let client = Arc::new(client);

    let send_results: Vec<Result<u32, anyhow::Error>> = stream::iter(chunk_events)
        .map(|(seq, chunk_event)| {
            let client = Arc::clone(&client);
            let chunks_sent = Arc::clone(&chunks_sent);
            async move {
                client
                    .send_event(&chunk_event)
                    .await
                    .context(format!("Failed to send chunk {}", seq))?;

                let sent = chunks_sent.fetch_add(1, Ordering::SeqCst) + 1;
                let percent = (sent as f64 / total_chunks as f64 * 100.0) as u32;
                println!(
                    "   Progress: {}% - Chunk {}/{} sent",
                    percent, sent, total_chunks
                );

                Ok(seq)
            }
        })
        .buffer_unordered(CONCURRENT_CHUNKS)
        .collect()
        .await;

    for result in send_results {
        result?;
    }

    let client = Arc::try_unwrap(client).unwrap_or_else(|arc| (*arc).clone());
    println!("All chunks sent successfully!");

    // Wait for final completion ACK
    println!("Waiting for receiver to confirm completion...");
    let final_ack_timeout = Duration::from_secs(COMPLETION_ACK_TIMEOUT_SECS);
    let final_ack_deadline = tokio::time::Instant::now() + final_ack_timeout;
    let mut final_ack_received = false;

    while tokio::time::Instant::now() < final_ack_deadline {
        match timeout(Duration::from_secs(1), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_ack_event(&event) && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    if let Ok(ack_seq) = parse_ack_event(&event) {
                        if ack_seq == -1 {
                            final_ack_received = true;
                            break;
                        }
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    if !final_ack_received {
        eprintln!("Warning: Did not receive final completion ACK from receiver");
    } else {
        println!("Receiver confirmed completion!");
    }

    client.disconnect().await;
    println!("Disconnected from Nostr relays.");

    Ok(())
}
