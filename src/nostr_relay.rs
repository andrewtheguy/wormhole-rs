//! Nostr relay transport for webrtc fallback
//!
//! This module provides relay-based file transfer (both sending and receiving)
//! when WebRTC direct connection fails. It uses credentials from the Webrtc/Hybrid
//! signaling or token.

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use crate::crypto::{decrypt_chunk, encrypt_chunk};
use crate::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
};
use crate::nostr_protocol::{
    create_ack_event, create_chunk_event, create_retry_event, get_transfer_id, is_ack_event,
    is_chunk_event, is_retry_event, parse_ack_event, parse_chunk_event, parse_retry_event,
    DEFAULT_NOSTR_RELAYS, MAX_NOSTR_FILE_SIZE, NOSTR_CHUNK_SIZE,
};
use crate::transfer::format_bytes;
use crate::wormhole::{WormholeToken, PROTOCOL_WEBRTC};

// --- Shared Constants ---
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3;

// --- Sender Constants ---
/// Timeout for completion ACK (extended to handle retries)
const COMPLETION_ACK_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour
const CONCURRENT_CHUNKS: usize = 5;

// --- Receiver Constants ---
const CHUNK_RECEIVE_TIMEOUT_SECS: u64 = 300;
/// How often to resend ready ACK (ephemeral events may be missed due to timing)
const READY_ACK_INTERVAL_SECS: u64 = 5;
/// How long to wait with no activity before requesting retry (seconds)
const STAGNATION_TIMEOUT_SECS: u64 = 8;
/// Maximum number of missing chunks to request in a single retry
const MAX_RETRY_BATCH_SIZE: usize = 50;

// --- Sender Types ---

/// Result of a relay transfer indicating whether completion was confirmed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    /// Transfer completed and receiver confirmed receipt
    Confirmed,
    /// All data sent but receiver did not confirm receipt
    /// (could be ACK lost due to ephemeral event timing)
    Unconfirmed,
}

// --- Receiver Types ---

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

// --- Sender Implementation ---

/// Send file data via Nostr relay as fallback for webrtc transport.
///
/// This function uses existing credentials from the webrtc signaling,
/// so the receiver can use the same wormhole code that was already displayed.
///
/// # Arguments
/// * `file` - Open file handle to send
/// * `file_size` - Size of the file in bytes
/// * `sender_keys` - Sender's Nostr keys (from webrtc signaling)
/// * `transfer_id` - Transfer ID (from webrtc signaling)
/// * `encryption_key` - AES-256-GCM key (from webrtc signaling)
/// * `relay_urls` - Relay URLs to use (from webrtc signaling)
pub async fn send_relay_fallback(
    mut file: File,
    file_size: u64,
    sender_keys: Keys,
    transfer_id: String,
    encryption_key: [u8; 32],
    relay_urls: Vec<String>,
) -> Result<TransferResult> {
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

    // Wait for final completion ACK or handle retry requests
    println!("Waiting for receiver to confirm completion...");
    let final_ack_timeout = Duration::from_secs(COMPLETION_ACK_TIMEOUT_SECS);
    let final_ack_deadline = tokio::time::Instant::now() + final_ack_timeout;
    let mut final_ack_received = false;

    while tokio::time::Instant::now() < final_ack_deadline {
        match timeout(Duration::from_secs(2), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                // Check for completion ACK
                if is_ack_event(&event) && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    if let Ok(ack_seq) = parse_ack_event(&event) {
                        if ack_seq == -1 {
                            final_ack_received = true;
                            break;
                        }
                    }
                }

                // Check for retry request
                if is_retry_event(&event)
                    && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    if let Ok(missing_seqs) = parse_retry_event(&event) {
                        println!(
                            "Received retry request for {} chunks, resending...",
                            missing_seqs.len()
                        );

                        // Resend missing chunks
                        for seq in missing_seqs {
                            if seq >= total_chunks {
                                continue; // Invalid sequence number
                            }

                            let start = (seq as usize) * NOSTR_CHUNK_SIZE;
                            let end = std::cmp::min(start + NOSTR_CHUNK_SIZE, all_data.len());
                            let chunk_data = &all_data[start..end];

                            match encrypt_chunk(&encryption_key, seq as u64, chunk_data) {
                                Ok(encrypted_chunk) => {
                                    match create_chunk_event(
                                        &sender_keys,
                                        &transfer_id,
                                        seq,
                                        total_chunks,
                                        &encrypted_chunk,
                                    ) {
                                        Ok(chunk_event) => {
                                            if let Err(e) = client.send_event(&chunk_event).await {
                                                eprintln!(
                                                    "Warning: Failed to resend chunk {}: {}",
                                                    seq, e
                                                );
                                            } else {
                                                println!("   Resent chunk {}", seq);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Warning: Failed to create chunk event {}: {}",
                                                seq, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Warning: Failed to encrypt chunk {}: {}", seq, e);
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    client.disconnect().await;
    println!("Disconnected from Nostr relays.");

    if final_ack_received {
        println!("Receiver confirmed completion!");
        Ok(TransferResult::Confirmed)
    } else {
        eprintln!("Warning: Did not receive final completion ACK from receiver");
        Ok(TransferResult::Unconfirmed)
    }
}

// --- Receiver Implementation ---

/// Receive a file via Nostr relays using a webrtc WormholeToken (for fallback).
pub async fn receive_nostr_with_token(
    token: &WormholeToken,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    // Only support webrtc tokens
    if token.protocol != PROTOCOL_WEBRTC {
        anyhow::bail!(
            "receive_nostr_with_token only supports webrtc protocol, got: {}",
            token.protocol
        );
    }

    println!("Receiving via Nostr relay mode...");

    // Extract fields from webrtc token
    let sender_pubkey_hex = token
        .webrtc_sender_pubkey
        .clone()
        .context("Missing sender pubkey in wormhole code")?;
    let transfer_id = token
        .webrtc_transfer_id
        .clone()
        .context("Missing transfer ID in wormhole code")?;
    let relay_urls = token
        .webrtc_relays
        .clone()
        .context("Missing relays in wormhole code")?;
    let transfer_type = token
        .webrtc_transfer_type
        .clone()
        .context("Missing transfer type in wormhole code")?;

    // Use filename from token if available, otherwise use default
    let filename = if let Some(name) = &token.webrtc_filename {
        name.clone()
    } else {
        // Fallback or error
        "downloaded_file".to_string()
    };

    let sender_pubkey =
        PublicKey::from_hex(&sender_pubkey_hex).context("Invalid sender public key")?;

    let encryption_key = crate::wormhole::decode_key(
        token
            .key
            .as_ref()
            .context("Missing encryption key in token")?,
    )
    .context("Failed to decode encryption key")?;

    println!("Sender pubkey: {}", sender_pubkey_hex);
    println!("Transfer ID: {}", transfer_id);

    if relay_urls.is_empty() {
        anyhow::bail!("Empty relay list");
    }

    println!("Connecting to {} Nostr relays...", relay_urls.len());
    for url in &relay_urls {
        println!("   - {}", url);
    }

    // Generate ephemeral keypair for this receive session
    let receiver_keys = Keys::generate();
    let receiver_pubkey = receiver_keys.public_key();
    println!("Receiver key: {}", receiver_pubkey.to_hex());

    // Create Nostr client and connect to relays
    let client = Client::new(receiver_keys.clone());
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

    for relay_url_str in &relay_urls {
        if let Ok(relay_url) = RelayUrl::parse(relay_url_str) {
            if let Some(relay) = relay_statuses.get(&relay_url) {
                if relay.is_connected() {
                    connected_count += 1;
                }
            }
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

    let mut notifications = client.notifications();

    // Subscribe to chunk events from sender
    let filter = Filter::new()
        .kind(crate::nostr_protocol::nostr_file_transfer_kind())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::T),
            transfer_id.clone(),
        )
        .author(sender_pubkey);

    client.subscribe(filter, None).await?;
    println!("Subscribed to transfer events");

    tokio::time::sleep(Duration::from_secs(SUBSCRIPTION_SETUP_DELAY_SECS)).await;

    // Send initial ACK to signal readiness
    let ack_event = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, 0)?;
    client.send_event(&ack_event).await?;
    println!("Sent ready signal to sender");

    // Collect chunks
    let mut received_chunks: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut total_chunks: Option<u32> = None;
    let mut last_activity_time = tokio::time::Instant::now();
    let mut last_ack_time = tokio::time::Instant::now();
    let mut last_retry_time = tokio::time::Instant::now();
    let mut first_chunk_received = false;

    println!("Receiving chunks...");

    loop {
        if last_activity_time.elapsed() > Duration::from_secs(CHUNK_RECEIVE_TIMEOUT_SECS) {
            if let Some(total) = total_chunks {
                let missing: Vec<u32> = (0..total)
                    .filter(|seq| !received_chunks.contains_key(seq))
                    .collect();
                if !missing.is_empty() {
                    anyhow::bail!("Transfer incomplete: missing chunks {:?}", missing);
                }
            }
            break;
        }

        // Periodically resend ready ACK until first chunk is received
        // (ephemeral events may be missed due to timing when both sides create new clients)
        if !first_chunk_received
            && last_ack_time.elapsed() > Duration::from_secs(READY_ACK_INTERVAL_SECS)
        {
            let ack_event = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, 0)?;
            if let Err(e) = client.send_event(&ack_event).await {
                eprintln!("Warning: Failed to resend ready ACK: {}", e);
            }
            last_ack_time = tokio::time::Instant::now();
        }

        // Check for stagnation and request retry for missing chunks
        if first_chunk_received
            && last_activity_time.elapsed() > Duration::from_secs(STAGNATION_TIMEOUT_SECS)
            && last_retry_time.elapsed() > Duration::from_secs(STAGNATION_TIMEOUT_SECS)
        {
            if let Some(total) = total_chunks {
                if received_chunks.len() < total as usize {
                    // Identify missing chunks (limit batch size)
                    let missing: Vec<u32> = (0..total)
                        .filter(|seq| !received_chunks.contains_key(seq))
                        .take(MAX_RETRY_BATCH_SIZE)
                        .collect();

                    if !missing.is_empty() {
                        println!("Requesting {} missing chunks...", missing.len());
                        let retry_event =
                            create_retry_event(&receiver_keys, &sender_pubkey, &transfer_id, &missing)?;
                        if let Err(e) = client.send_event(&retry_event).await {
                            eprintln!("Warning: Failed to send retry request: {}", e);
                        }
                        last_retry_time = tokio::time::Instant::now();
                    }
                }
            }
        }

        match timeout(Duration::from_secs(2), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if !is_chunk_event(&event) {
                    continue;
                }
                if get_transfer_id(&event).as_deref() != Some(&transfer_id) {
                    continue;
                }

                match parse_chunk_event(&event) {
                    Ok((seq, total, encrypted_chunk)) => {
                        if !first_chunk_received {
                            first_chunk_received = true;
                        }

                        if total_chunks.is_none() {
                            total_chunks = Some(total);
                            println!("Transfer consists of {} chunks", total);
                        }

                        if received_chunks.contains_key(&seq) {
                            continue;
                        }

                        received_chunks.insert(seq, encrypted_chunk);
                        last_activity_time = tokio::time::Instant::now();

                        let progress = (received_chunks.len() as f64 / total as f64 * 100.0) as u32;
                        println!(
                            "   Progress: {}% ({}/{})",
                            progress,
                            received_chunks.len(),
                            total
                        );

                        if received_chunks.len() == total as usize {
                            println!("All chunks received!");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse chunk event: {}", e);
                        continue;
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    // Verify we have all chunks
    let total = total_chunks.context("No chunks received")?;
    if received_chunks.len() != total as usize {
        anyhow::bail!(
            "Incomplete transfer: received {}/{} chunks",
            received_chunks.len(),
            total
        );
    }

    println!("Decrypting and reassembling...");

    // Decrypt and reassemble chunks
    let mut decrypted_data = Vec::new();
    for seq in 0..total {
        let encrypted_chunk = received_chunks
            .get(&seq)
            .context(format!("Missing chunk {}", seq))?;

        let decrypted_chunk = decrypt_chunk(&encryption_key, seq as u64, encrypted_chunk)
            .context(format!("Failed to decrypt chunk {}", seq))?;

        decrypted_data.extend_from_slice(&decrypted_chunk);
    }

    let data_size = decrypted_data.len() as u64;
    println!("Data size: {}", format_bytes(data_size));

    // Handle file vs folder
    if transfer_type == "folder" {
        println!("Extracting folder archive...");
        print_tar_extraction_info();

        let extract_dir = get_extraction_dir(output_dir);
        std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;
        println!("Extracting to: {}", extract_dir.display());

        let cursor = std::io::Cursor::new(decrypted_data);
        let skipped_entries = extract_tar_archive(cursor, &extract_dir)?;
        print_skipped_entries(&skipped_entries);

        println!("\nFolder received successfully!");
        println!("Extracted to: {}", extract_dir.display());
    } else {
        println!("Filename: {}", filename);

        let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
        let output_path = output_dir.join(&filename);

        // Check if file already exists
        if output_path.exists() {
            let prompt_path = output_path.display().to_string();
            let should_overwrite = tokio::task::spawn_blocking(move || {
                print!("File already exists: {}. Overwrite? [y/N] ", prompt_path);
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                Ok::<bool, std::io::Error>(input.trim().eq_ignore_ascii_case("y"))
            })
            .await
            .context("Prompt task panicked")??;

            if !should_overwrite {
                anyhow::bail!("Transfer cancelled - file exists");
            }

            tokio::fs::remove_file(&output_path)
                .await
                .context("Failed to remove existing file")?;
        }

        let temp_file =
            NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
        let temp_path = temp_file.path().to_path_buf();

        let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
        setup_cleanup_handler(cleanup_path.clone());

        let mut temp_file = temp_file;
        temp_file
            .write_all(&decrypted_data)
            .context("Failed to write to file")?;

        cleanup_path.lock().await.take();

        temp_file.flush().context("Failed to flush file")?;
        temp_file
            .persist(&output_path)
            .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

        println!("\nFile received successfully!");
        println!("Saved to: {}", output_path.display());
    }

    // Send final completion ACK
    let final_ack = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, -1)?;
    client.send_event(&final_ack).await?;
    println!("Sent completion confirmation to sender");

    client.disconnect().await;
    println!("Disconnected from Nostr relays.");

    Ok(())
}
