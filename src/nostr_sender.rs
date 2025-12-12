use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

use crate::crypto::{encrypt_chunk, generate_key};
use crate::nostr_protocol::{
    create_chunk_event, generate_transfer_id, get_best_relays, get_transfer_id, is_ack_event,
    parse_ack_event, MAX_NOSTR_FILE_SIZE, NOSTR_CHUNK_SIZE,
};
use crate::transfer::format_bytes;
use crate::wormhole::generate_nostr_code;

const ACK_TIMEOUT_SECS: u64 = 30; // Increased from 10s to 30s for better reliability
const MAX_RETRIES: u32 = 3;
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3; // Wait for subscription to propagate

/// Get connected relay URLs from the client
async fn get_connected_relays(client: &Client) -> Vec<String> {
    let relay_statuses = client.relays().await;
    relay_statuses
        .iter()
        .filter(|(_, relay)| relay.is_connected())
        .map(|(url, _)| url.to_string())
        .collect()
}

/// Send a file via Nostr relays
pub async fn send_file_nostr(
    file_path: &Path,
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<()> {
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

    // Validate file size
    if file_size > MAX_NOSTR_FILE_SIZE {
        anyhow::bail!(
            "File size ({}) exceeds Nostr limit ({})\n\
             Use regular 'send' command for larger files via iroh.",
            format_bytes(file_size),
            format_bytes(MAX_NOSTR_FILE_SIZE)
        );
    }

    println!(
        "📁 Preparing to send via Nostr: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Generate ephemeral keypair for this transfer
    let sender_keys = Keys::generate();
    let sender_pubkey = sender_keys.public_key();
    println!(
        "🔑 Generated ephemeral sender key: {}",
        sender_pubkey.to_hex()
    );

    // Generate transfer ID
    let transfer_id = generate_transfer_id();
    println!("🆔 Transfer ID: {}", transfer_id);

    // Generate encryption key (always required for Nostr)
    let encryption_key = generate_key();
    println!("🔐 AES-256-GCM encryption enabled (mandatory for Nostr)");

    // Determine which relays to use
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
        get_best_relays().await
    };

    println!("📡 Connecting to {} Nostr relays...", relay_urls.len());
    for url in &relay_urls {
        println!("   - {}", url);
    }

    // Create Nostr client and connect to relays (clone keys for client)
    let client = Client::new(sender_keys.clone());
    for relay_url in &relay_urls {
        match client.add_relay(relay_url).await {
            Ok(_) => {
                // Relay added to client
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

    // Check actual connection status
    let relay_statuses = client.relays().await;
    let mut connected_count = 0;
    let mut failed_relays = Vec::new();

    for relay_url_str in &relay_urls {
        // Parse string to RelayUrl for lookup
        if let Ok(relay_url) = RelayUrl::parse(relay_url_str) {
            if let Some(relay) = relay_statuses.get(&relay_url) {
                if relay.is_connected() {
                    connected_count += 1;
                } else {
                    failed_relays.push(relay_url_str.as_str());
                }
            } else {
                failed_relays.push(relay_url_str.as_str());
            }
        } else {
            failed_relays.push(relay_url_str.as_str());
        }
    }

    // Log failed relays
    if !failed_relays.is_empty() {
        for failed in &failed_relays {
            eprintln!("⚠️  Failed to connect to relay: {}", failed);
        }
    }

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

    // Generate and display wormhole code
    let code = generate_nostr_code(
        &encryption_key,
        sender_pubkey.to_hex(),
        transfer_id.clone(),
        relay_urls.clone(),
        filename.clone(),
    )?;

    println!("\n🔮 Wormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive-nostr\n");
    println!("Then enter the code above when prompted.\n");

    // Calculate total chunks
    let total_chunks = ((file_size + NOSTR_CHUNK_SIZE as u64 - 1) / NOSTR_CHUNK_SIZE as u64) as u32;
    println!("📊 File will be sent in {} chunks", total_chunks);

    // Single notifications stream to avoid dropping events between polls
    let mut notifications = client.notifications();

    // Subscribe to ACK events from any receiver for this transfer
    // ACK events will have: kind=24242, t=<transfer_id>, p=<sender_pubkey>, type=ack
    let filter = Filter::new()
        .kind(crate::nostr_protocol::nostr_file_transfer_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::T), transfer_id.clone())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            sender_pubkey.to_hex(),
        );

    let _ = client.subscribe(filter, None).await;

    // Wait for subscription to propagate to relays
    tokio::time::sleep(Duration::from_secs(SUBSCRIPTION_SETUP_DELAY_SECS)).await;

    println!("⏳ Waiting for receiver to connect...");

    // Wait for first ACK to confirm receiver is ready
    let mut receiver_ready = false;
    let ready_timeout = Duration::from_secs(300); // 5 minutes
    let start_time = tokio::time::Instant::now();

    while !receiver_ready && start_time.elapsed() < ready_timeout {
        match timeout(Duration::from_secs(5), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_ack_event(&event) && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    println!("✅ Receiver connected and ready!");
                    receiver_ready = true;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue, // Timeout, keep waiting
        }
    }

    if !receiver_ready {
        anyhow::bail!("Timeout waiting for receiver to connect (5 minutes)");
    }

    // Open file and send chunks
    let mut file = File::open(file_path).await.context("Failed to open file")?;
    let mut buffer = vec![0u8; NOSTR_CHUNK_SIZE];
    let mut bytes_sent = 0u64;
    let mut ack_tracker: HashMap<u32, bool> = HashMap::new();

    // Get list of connected relays for round-robin distribution
    let connected_relays = get_connected_relays(&client).await;
    if connected_relays.is_empty() {
        anyhow::bail!("No connected relays available to send chunks");
    }
    println!(
        "📤 Sending {} chunks (round-robin across {} relays)...",
        total_chunks,
        connected_relays.len()
    );

    for seq in 0..total_chunks {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .context("Failed to read file")?;
        if bytes_read == 0 {
            break;
        }

        let chunk_data = &buffer[..bytes_read];

        // Encrypt chunk
        let encrypted_chunk = encrypt_chunk(&encryption_key, seq as u64, chunk_data)
            .context("Failed to encrypt chunk")?;

        // Try sending chunk with retries
        let mut attempt = 0;
        let mut ack_received = false;

        while attempt < MAX_RETRIES && !ack_received {
            attempt += 1;

            // Select relay for this attempt using round-robin
            let relay_index = ((seq as usize) + (attempt as usize - 1)) % connected_relays.len();
            let target_relay = &connected_relays[relay_index];

            // Create and publish chunk event
            let chunk_event = create_chunk_event(
                &sender_keys,
                &transfer_id,
                seq,
                total_chunks,
                &encrypted_chunk,
            )?;

            // Send to specific relay (round-robin distribution)
            client
                .send_event_to([target_relay.as_str()], &chunk_event)
                .await
                .context("Failed to send chunk event")?;

            // Wait for ACK
            let ack_deadline = tokio::time::Instant::now() + Duration::from_secs(ACK_TIMEOUT_SECS);

            while tokio::time::Instant::now() < ack_deadline {
                match timeout(Duration::from_secs(1), notifications.recv()).await {
                    Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                        if is_ack_event(&event)
                            && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                        {
                            if let Ok(ack_seq) = parse_ack_event(&event) {
                                if ack_seq == seq as i32 {
                                    ack_received = true;
                                    ack_tracker.insert(seq, true);
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

            if !ack_received && attempt < MAX_RETRIES {
                let relay_host = target_relay
                    .replace("wss://", "")
                    .replace("ws://", "")
                    .trim_end_matches('/')
                    .to_string();
                eprintln!(
                    "⚠️  Chunk {} ACK timeout via {}, retrying on next relay ({}/{})",
                    seq, relay_host, attempt, MAX_RETRIES
                );
            }
        }

        if !ack_received {
            anyhow::bail!("❌ Chunk {} failed after {} retries", seq, MAX_RETRIES);
        }

        bytes_sent += bytes_read as u64;

        // Progress update for every chunk (show which relay was used)
        let percent = (bytes_sent as f64 / file_size as f64 * 100.0) as u32;
        // Extract just the host from the relay URL for cleaner output
        let relay_index = ((seq as usize) + (attempt as usize - 1)) % connected_relays.len();
        let relay_host = connected_relays[relay_index]
            .replace("wss://", "")
            .replace("ws://", "")
            .trim_end_matches('/')
            .to_string();
        println!(
            "   Progress: {}% ({}/{}) - Chunk {}/{} → {}",
            percent,
            format_bytes(bytes_sent),
            format_bytes(file_size),
            seq + 1,
            total_chunks,
            relay_host
        );

        // Small delay between chunks to avoid overwhelming relays
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ All chunks sent successfully!");

    // Wait for final completion ACK (seq = -1)
    println!("⏳ Waiting for receiver to confirm completion...");
    let final_ack_timeout = Duration::from_secs(30);
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
        eprintln!("⚠️  Did not receive final completion ACK from receiver");
    } else {
        println!("✅ Receiver confirmed completion!");
    }

    // Disconnect from relays
    client.disconnect().await;
    println!("👋 Disconnected from Nostr relays.");

    Ok(())
}
