use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::time::{timeout, Duration};

use crate::crypto::decrypt_chunk;
use crate::nostr_protocol::{
    create_ack_event, get_best_relays, get_transfer_id, is_chunk_event, parse_chunk_event,
};
use crate::transfer::format_bytes;
use crate::wormhole::{parse_code, PROTOCOL_NOSTR};

const CHUNK_RECEIVE_TIMEOUT_SECS: u64 = 60;
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3; // Wait for subscription to propagate

/// Receive a file via Nostr relays
pub async fn receive_file_nostr(
    code: &str,
    output_dir: Option<PathBuf>,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<()> {
    println!("🔮 Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    // Validate this is a Nostr transfer
    if token.protocol != PROTOCOL_NOSTR {
        anyhow::bail!(
            "This is not a Nostr wormhole code (protocol: {})\n\
             Use 'receive' command for iroh transfers.",
            token.protocol
        );
    }

    // Extract Nostr-specific fields
    let sender_pubkey_hex = token
        .nostr_sender_pubkey
        .context("Missing sender pubkey in wormhole code")?;
    let sender_pubkey =
        PublicKey::from_hex(&sender_pubkey_hex).context("Invalid sender public key")?;

    let transfer_id = token
        .nostr_transfer_id
        .context("Missing transfer ID in wormhole code")?;

    let encryption_key = token
        .key
        .context("Missing encryption key in wormhole code")?;

    println!("🔐 AES-256-GCM encryption detected");
    println!("🔑 Sender pubkey: {}", sender_pubkey_hex);
    println!("🆔 Transfer ID: {}", transfer_id);

    // Determine which relays to use
    // Priority: custom CLI flag > use-default-relays flag > fetch from nostr.watch
    // Note: We ignore relays from wormhole code to avoid ambiguity
    let relay_urls = if let Some(relays) = custom_relays {
        println!("📡 Using custom relays");
        relays
    } else if use_default_relays {
        println!("📡 Using default hardcoded relays");
        crate::nostr_protocol::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        // Always fetch best relays for receiver, ignore wormhole code relays
        get_best_relays().await
    };

    println!("📡 Connecting to {} Nostr relays...", relay_urls.len());
    for url in &relay_urls {
        println!("   - {}", url);
    }

    // Generate ephemeral keypair for this receive session
    let receiver_keys = Keys::generate();
    let receiver_pubkey = receiver_keys.public_key();
    println!("🔑 Generated ephemeral receiver key: {}", receiver_pubkey.to_hex());

    // Create Nostr client and connect to relays
    let client = Client::new(receiver_keys.clone());
    let mut connected_count = 0;
    for relay_url in &relay_urls {
        match client.add_relay(relay_url).await {
            Ok(_) => {
                connected_count += 1;
            }
            Err(e) => {
                eprintln!("⚠️  Failed to add relay {}: {}", relay_url, e);
            }
        }
    }

    // Connect to all relays
    client.connect().await;

    // Wait a moment for connections to establish
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check if we have enough relays
    if connected_count < MIN_RELAYS_REQUIRED {
        anyhow::bail!(
            "Failed to connect to enough relays ({}/{} connected, need {}+)\n\
             Check network connectivity or try custom relays with --nostr-relay",
            connected_count,
            relay_urls.len(),
            MIN_RELAYS_REQUIRED
        );
    }

    println!("✅ Connected to {} relays", connected_count);

    // Subscribe to chunk events from sender
    let filter = Filter::new()
        .kind(crate::nostr_protocol::nostr_file_transfer_kind())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::T),
            transfer_id.clone(),
        )
        .author(sender_pubkey);

    let _ = client.subscribe(filter, None).await;
    println!("📥 Subscribed to transfer events");

    // Wait for subscription to propagate to relays before signaling ready
    tokio::time::sleep(Duration::from_secs(SUBSCRIPTION_SETUP_DELAY_SECS)).await;

    // Send initial ACK to signal readiness (seq = 0)
    let ack_event = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, 0)?;
    client.send_event(&ack_event).await?;
    println!("✅ Sent ready signal to sender");

    // Collect chunks
    let mut received_chunks: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut total_chunks: Option<u32> = None;
    let mut last_chunk_time = tokio::time::Instant::now();

    println!("📥 Receiving chunks...");

    loop {
        // Check for timeout
        if last_chunk_time.elapsed() > Duration::from_secs(CHUNK_RECEIVE_TIMEOUT_SECS) {
            // Check if we have all chunks
            if let Some(total) = total_chunks {
                let missing: Vec<u32> = (0..total)
                    .filter(|seq| !received_chunks.contains_key(seq))
                    .collect();

                if !missing.is_empty() {
                    anyhow::bail!(
                        "Transfer incomplete: missing chunks {:?}\n\
                         Network issue or sender disconnected.",
                        missing
                    );
                }
            }
            break;
        }

        // Wait for events
        let mut notifications = client.notifications();
        match timeout(Duration::from_secs(5), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                // Check if this is a chunk event for our transfer
                if !is_chunk_event(&event) {
                    continue;
                }

                if get_transfer_id(&event).as_deref() != Some(&transfer_id) {
                    continue;
                }

                // Parse chunk event
                match parse_chunk_event(&event) {
                    Ok((seq, total, encrypted_chunk)) => {
                        // Update total chunks if not set
                        if total_chunks.is_none() {
                            total_chunks = Some(total);
                            println!("📊 Transfer consists of {} chunks", total);
                        }

                        // Check if we already have this chunk
                        if received_chunks.contains_key(&seq) {
                            continue; // Duplicate, ignore
                        }

                        // Store encrypted chunk
                        received_chunks.insert(seq, encrypted_chunk);
                        last_chunk_time = tokio::time::Instant::now();

                        // Send ACK for this chunk
                        let ack_event =
                            create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, seq as i32)?;
                        client.send_event(&ack_event).await?;

                        // Progress update
                        let progress = (received_chunks.len() as f64 / total as f64 * 100.0) as u32;
                        if received_chunks.len() % 5 == 0 || received_chunks.len() == total as usize {
                            println!(
                                "   Progress: {}% ({}/{})",
                                progress,
                                received_chunks.len(),
                                total
                            );
                        }

                        // Check if we have all chunks
                        if received_chunks.len() == total as usize {
                            println!("✅ All chunks received!");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to parse chunk event: {}", e);
                        continue;
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue, // Timeout, continue waiting
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

    println!("🔓 Decrypting and reassembling file...");

    // Decrypt and reassemble chunks in order
    let mut decrypted_data = Vec::new();
    for seq in 0..total {
        let encrypted_chunk = received_chunks
            .get(&seq)
            .context(format!("Missing chunk {}", seq))?;

        let decrypted_chunk = decrypt_chunk(&encryption_key, seq as u64, encrypted_chunk)
            .context(format!("Failed to decrypt chunk {}", seq))?;

        decrypted_data.extend_from_slice(&decrypted_chunk);
    }

    let file_size = decrypted_data.len() as u64;
    println!("📁 File size: {}", format_bytes(file_size));

    // Extract filename from wormhole code, or use default if missing
    let filename = token
        .nostr_filename
        .unwrap_or_else(|| format!("received_file_{}.bin", transfer_id[..8].to_string()));

    println!("📄 Filename: {}", filename);

    // Determine output directory and final path
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&filename);

    // Check if file already exists
    if output_path.exists() {
        print!(
            "⚠️  File already exists: {}. Overwrite? [y/N] ",
            output_path.display()
        );
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("Transfer cancelled - file exists");
        }

        // Remove existing file
        std::fs::remove_file(&output_path).context("Failed to remove existing file")?;
    }

    // Create temp file in same directory (ensures rename works, auto-deletes on drop)
    let mut temp_file =
        NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;

    // Write decrypted data to temp file
    temp_file
        .write_all(&decrypted_data)
        .context("Failed to write to file")?;

    // Flush and persist temp file to final path (atomic move)
    temp_file.flush().context("Failed to flush file")?;
    temp_file
        .persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

    println!("✅ File received successfully!");
    println!("📁 Saved to: {}", output_path.display());

    // Send final completion ACK (seq = -1)
    let final_ack = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, -1)?;
    client.send_event(&final_ack).await?;
    println!("✅ Sent completion confirmation to sender");

    // Disconnect from relays
    client.disconnect().await;
    println!("👋 Disconnected from Nostr relays.");

    Ok(())
}
