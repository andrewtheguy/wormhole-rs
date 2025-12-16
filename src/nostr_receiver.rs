//! Nostr relay transport receiver for hybrid fallback
//!
//! This module provides relay-based file receiving when WebRTC direct connection fails.
//! It uses credentials from the hybrid token that was already displayed to the user.

use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use crate::crypto::decrypt_chunk;
use crate::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
};
use crate::nostr_protocol::{
    create_ack_event, get_transfer_id, is_chunk_event, parse_chunk_event,
};
use crate::transfer::format_bytes;
use crate::wormhole::{WormholeToken, PROTOCOL_HYBRID};

const CHUNK_RECEIVE_TIMEOUT_SECS: u64 = 300;
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3;

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

/// Receive a file via Nostr relays using a hybrid WormholeToken (for fallback).
pub async fn receive_nostr_with_token(
    token: &WormholeToken,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    // Only support hybrid tokens
    if token.protocol != PROTOCOL_HYBRID {
        anyhow::bail!(
            "receive_nostr_with_token only supports hybrid protocol, got: {}",
            token.protocol
        );
    }

    println!("Receiving via Nostr relay mode...");

    // Extract fields from hybrid token
    let sender_pubkey_hex = token
        .hybrid_sender_pubkey
        .clone()
        .context("Missing sender pubkey in hybrid token")?;
    let transfer_id = token
        .hybrid_transfer_id
        .clone()
        .context("Missing transfer ID in hybrid token")?;
    let relay_urls = token
        .hybrid_relays
        .clone()
        .context("Missing relay list in hybrid token")?;
    let transfer_type = token
        .hybrid_transfer_type
        .clone()
        .unwrap_or_else(|| "file".to_string());

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
    let mut last_chunk_time = tokio::time::Instant::now();

    println!("Receiving chunks...");

    loop {
        if last_chunk_time.elapsed() > Duration::from_secs(CHUNK_RECEIVE_TIMEOUT_SECS) {
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

        match timeout(Duration::from_secs(5), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if !is_chunk_event(&event) {
                    continue;
                }
                if get_transfer_id(&event).as_deref() != Some(&transfer_id) {
                    continue;
                }

                match parse_chunk_event(&event) {
                    Ok((seq, total, encrypted_chunk)) => {
                        if total_chunks.is_none() {
                            total_chunks = Some(total);
                            println!("Transfer consists of {} chunks", total);
                        }

                        if received_chunks.contains_key(&seq) {
                            continue;
                        }

                        received_chunks.insert(seq, encrypted_chunk);
                        last_chunk_time = tokio::time::Instant::now();

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
        // Get filename from hybrid_filename
        let filename = token.hybrid_filename.clone().unwrap_or_else(|| {
            let truncated_id = transfer_id.chars().take(8).collect::<String>();
            format!("received_file_{}.bin", truncated_id)
        });

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
