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
use crate::nostr_pin::{
    compute_pin_hint, decrypt_wormhole_code, parse_pin_exchange_event, pin_exchange_kind,
    PIN_LENGTH,
};
use crate::nostr_protocol::{
    create_ack_event, discover_sender_relays, get_transfer_id, is_chunk_event, parse_chunk_event,
    DEFAULT_NOSTR_RELAYS,
};
use crate::transfer::format_bytes;
use crate::wormhole::{parse_code, WormholeToken, PROTOCOL_HYBRID, PROTOCOL_NOSTR};

const CHUNK_RECEIVE_TIMEOUT_SECS: u64 = 300; // 5 minutes to allow for slow/unreliable relays
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3; // Wait for subscription to propagate

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
///
/// Note: Spawns a task that lives until Ctrl+C or program exit. This is appropriate
/// for CLI tools but would accumulate tasks if called repeatedly in a long-running process.
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

/// Receive a file via Nostr relays
pub async fn receive_file_nostr(
    code: &str,
    output_dir: Option<PathBuf>,
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

    let encryption_key = crate::wormhole::decode_key(
        token
            .key
            .as_ref()
            .context("Missing encryption key in wormhole code")?,
    )
    .context("Failed to decode encryption key")?;

    println!("🔐 AES-256-GCM encryption detected");
    println!("🔑 Sender pubkey: {}", sender_pubkey_hex);
    println!("🆔 Transfer ID: {}", transfer_id);

    // Determine which relays to use
    let relay_urls = if token.nostr_use_outbox.unwrap_or(false) {
        // NIP-65 Outbox model: discover sender's relays from well-known bridge relays
        println!("📡 Discovering sender's relay list via NIP-65 Outbox model...");

        let relays = discover_sender_relays(&sender_pubkey)
            .await
            .context("Failed to discover sender's relays via NIP-65")?;

        if relays.is_empty() {
            anyhow::bail!("No relays found in sender's NIP-65 relay list event");
        }

        println!("✅ Discovered {} relays from sender's NIP-65 event", relays.len());
        relays
    } else {
        // Legacy mode: use relays from wormhole code directly
        println!("📡 Using relays from wormhole code (same as sender)");
        let relays = token
            .nostr_relays
            .context("Missing relay list in wormhole code")?;

        if relays.is_empty() {
            anyhow::bail!("Wormhole code contains empty relay list");
        }

        relays
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

    // Single notifications stream to avoid dropping events between polls
    let mut notifications = client.notifications();

    // Subscribe to chunk events from sender
    let filter = Filter::new()
        .kind(crate::nostr_protocol::nostr_file_transfer_kind())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::T),
            transfer_id.clone(),
        )
        .author(sender_pubkey);

    if let Err(e) = client.subscribe(filter, None).await {
        anyhow::bail!(
            "Failed to subscribe to chunk events (transfer_id: {}, sender: {}): {}\n\
             Without subscription, file chunks cannot be received.",
            transfer_id,
            sender_pubkey.to_hex(),
            e
        );
    }
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

                        // Store encrypted chunk (no per-chunk ACK, fire-and-forget from sender)
                        received_chunks.insert(seq, encrypted_chunk);
                        last_chunk_time = tokio::time::Instant::now();

                        // Progress update for every chunk
                        let progress = (received_chunks.len() as f64 / total as f64 * 100.0) as u32;
                        println!(
                            "   Progress: {}% ({}/{})",
                            progress,
                            received_chunks.len(),
                            total
                        );

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

    let data_size = decrypted_data.len() as u64;
    println!("Data size: {}", format_bytes(data_size));

    // Check transfer type
    let transfer_type = token.nostr_transfer_type.as_deref().unwrap_or("file");

    if transfer_type == "folder" {
        // Extract tar archive from memory
        println!("Extracting folder archive...");
        print_tar_extraction_info();

        // Determine output directory using shared logic (same as iroh/tor)
        let extract_dir = get_extraction_dir(output_dir);
        std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;
        println!("Extracting to: {}", extract_dir.display());

        // Extract tar from in-memory data
        let cursor = std::io::Cursor::new(decrypted_data);
        let skipped_entries = extract_tar_archive(cursor, &extract_dir)?;
        print_skipped_entries(&skipped_entries);

        println!("\nFolder received successfully!");
        println!("Extracted to: {}", extract_dir.display());
    } else {
        // File transfer (existing logic)
        // Extract filename from wormhole code, or use default if missing
        let filename = token.nostr_filename.unwrap_or_else(|| {
            // Safely truncate transfer_id to 8 characters
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

            // Remove existing file
            tokio::fs::remove_file(&output_path).await.context("Failed to remove existing file")?;
        }

        // Create temp file in same directory (ensures rename works, auto-deletes on drop)
        let temp_file =
            NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
        let temp_path = temp_file.path().to_path_buf();

        // Set up cleanup handler for Ctrl+C
        let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
        setup_cleanup_handler(cleanup_path.clone());

        let mut temp_file = temp_file;

        // Write decrypted data to temp file
        temp_file
            .write_all(&decrypted_data)
            .context("Failed to write to file")?;

        // Clear cleanup path before persist (transfer succeeded)
        cleanup_path.lock().await.take();

        // Flush and persist temp file to final path (atomic move)
        temp_file.flush().context("Failed to flush file")?;
        temp_file
            .persist(&output_path)
            .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

        println!("\nFile received successfully!");
        println!("Saved to: {}", output_path.display());
    }

    // Send final completion ACK (seq = -1)
    let final_ack = create_ack_event(&receiver_keys, &sender_pubkey, &transfer_id, -1)?;
    client.send_event(&final_ack).await?;
    println!("✅ Sent completion confirmation to sender");

    // Disconnect from relays
    client.disconnect().await;
    println!("👋 Disconnected from Nostr relays.");

    Ok(())
}

/// Receive a file via Nostr using PIN-based wormhole code exchange.
///
/// Prompts the user to enter a PIN, then queries Nostr relays for the
/// corresponding PIN exchange event, decrypts the wormhole code, and
/// proceeds with the normal file transfer.
pub async fn receive_with_pin(output_dir: Option<PathBuf>) -> Result<()> {
    // Prompt for PIN input (visible, not masked)
    // Use spawn_blocking to avoid stalling the Tokio worker
    let pin = tokio::task::spawn_blocking(|| {
        print!("Enter PIN: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok::<String, std::io::Error>(input.trim().to_string())
    })
    .await
    .context("PIN input task panicked")??;

    // Validate PIN format
    if pin.len() != PIN_LENGTH {
        anyhow::bail!(
            "Invalid PIN length: expected {} characters, got {}",
            PIN_LENGTH,
            pin.len()
        );
    }

    println!("\n🔢 Using PIN: {}", pin);

    // Compute PIN hint for filtering
    let pin_hint = compute_pin_hint(&pin);
    println!("🔍 Searching for PIN exchange event...");

    // Connect to bridge relays
    let client = Client::default();
    for relay in DEFAULT_NOSTR_RELAYS {
        let _ = client.add_relay(relay.to_string()).await;
    }
    client.connect().await;

    // Wait for connections to establish
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Query for PIN exchange events matching hint
    let filter = Filter::new()
        .kind(pin_exchange_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), pin_hint.clone())
        .since(Timestamp::now() - 3600) // Last hour
        .limit(10);

    let events = client
        .fetch_events(filter, Duration::from_secs(15))
        .await
        .context("Failed to fetch PIN exchange events")?;

    if events.is_empty() {
        client.disconnect().await;
        anyhow::bail!(
            "No PIN exchange event found.\n\
             Make sure the sender has started the transfer and the PIN is correct."
        );
    }

    println!("📥 Found {} potential PIN exchange event(s)", events.len());

    // Try decrypting each matching event
    let mut wormhole_code: Option<String> = None;

    for event in events.iter() {
        match parse_pin_exchange_event(event) {
            Ok((encrypted, salt)) => {
                println!("🔑 Deriving decryption key from PIN (this may take a moment)...");
                match decrypt_wormhole_code(&encrypted, &pin, &salt) {
                    Ok(code) => {
                        println!("✅ Found and decrypted wormhole code!");
                        wormhole_code = Some(code);
                        break;
                    }
                    Err(_) => {
                        // Wrong PIN or corrupted, try next event
                        continue;
                    }
                }
            }
            Err(_) => continue,
        }
    }

    client.disconnect().await;

    let code = wormhole_code.context(
        "No valid PIN exchange event found.\n\
         Check PIN and try again.",
    )?;

    // Continue with normal receive flow using the decrypted wormhole code
    receive_file_nostr(&code, output_dir).await
}

/// Receive a file via Nostr relays using an already-parsed WormholeToken.
/// Supports both PROTOCOL_NOSTR and PROTOCOL_HYBRID tokens (for fallback).
pub async fn receive_nostr_with_token(
    token: &WormholeToken,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!("Receiving via Nostr relay mode...");

    // Extract fields based on protocol type
    let (sender_pubkey_hex, transfer_id, relay_urls, transfer_type) =
        if token.protocol == PROTOCOL_HYBRID {
            // Hybrid token: use hybrid_* fields
            let sender = token
                .hybrid_sender_pubkey
                .clone()
                .context("Missing sender pubkey in hybrid token")?;
            let tid = token
                .hybrid_transfer_id
                .clone()
                .context("Missing transfer ID in hybrid token")?;
            let relays = token
                .hybrid_relays
                .clone()
                .context("Missing relay list in hybrid token")?;
            let ttype = token.hybrid_transfer_type.clone().unwrap_or_else(|| "file".to_string());
            (sender, tid, relays, ttype)
        } else {
            // Nostr token: use nostr_* fields
            let sender = token
                .nostr_sender_pubkey
                .clone()
                .context("Missing sender pubkey in nostr token")?;
            let tid = token
                .nostr_transfer_id
                .clone()
                .context("Missing transfer ID in nostr token")?;

            let relays = if token.nostr_use_outbox.unwrap_or(false) {
                // Discover relays via NIP-65
                let sender_pk = PublicKey::from_hex(&sender).context("Invalid sender public key")?;
                discover_sender_relays(&sender_pk)
                    .await
                    .context("Failed to discover sender's relays via NIP-65")?
            } else {
                token
                    .nostr_relays
                    .clone()
                    .context("Missing relay list in nostr token")?
            };

            let ttype = token.nostr_transfer_type.clone().unwrap_or_else(|| "file".to_string());
            (sender, tid, relays, ttype)
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
            eprintln!("Failed to add relay {}: {}", relay_url, e);
        }
    }

    client.connect().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check actual connection status
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
        // Get filename from nostr_filename (used by both nostr and hybrid)
        let filename = token.nostr_filename.clone().unwrap_or_else(|| {
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
