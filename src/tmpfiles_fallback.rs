//! tmpfiles.org fallback transport for WebRTC
//!
//! This module provides tmpfiles.org-based file transfer when WebRTC direct
//! connection fails. It uses:
//! - Nostr for signaling (ready/URL/completion events)
//! - tmpfiles.org for actual file data transfer
//!
//! Flow:
//! 1. Sender waits for receiver ready signal via Nostr
//! 2. Sender encrypts file and uploads to tmpfiles.org
//! 3. Sender sends download URL to receiver via Nostr
//! 4. Receiver downloads and decrypts file
//! 5. Receiver sends completion signal via Nostr

use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use std::io::Write;
use std::path::PathBuf;
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
    create_completion_event, create_ready_event, create_tmpfile_url_event, get_transfer_id,
    is_completion_event, is_ready_event, is_tmpfile_url_event, parse_tmpfile_url_event,
    DEFAULT_NOSTR_RELAYS,
};
use crate::tmpfiles::{self, MAX_TMPFILES_SIZE};
use crate::transfer::format_bytes;
use crate::wormhole::{WormholeToken, PROTOCOL_WEBRTC};

// --- Constants ---
const MIN_RELAYS_REQUIRED: usize = 2;
const SUBSCRIPTION_SETUP_DELAY_SECS: u64 = 3;
const READY_SIGNAL_TIMEOUT_SECS: u64 = 300; // 5 minutes
const COMPLETION_TIMEOUT_SECS: u64 = 300; // 5 minutes
const URL_RECEIVE_TIMEOUT_SECS: u64 = 600; // 10 minutes (upload can take time)
const READY_SIGNAL_INTERVAL_SECS: u64 = 5;

/// Result of a fallback transfer indicating whether completion was confirmed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    /// Transfer completed and receiver confirmed receipt
    Confirmed,
    /// All data sent but receiver did not confirm receipt
    Unconfirmed,
}

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

/// Connect to Nostr relays and return client + connected count
async fn connect_to_relays(keys: Keys, relay_urls: &[String]) -> Result<(Client, usize)> {
    let client = Client::new(keys);
    for relay_url in relay_urls {
        if let Err(e) = client.add_relay(relay_url).await {
            eprintln!("Warning: Failed to add relay {}: {}", relay_url, e);
        }
    }

    client.connect().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check connection status
    let relay_statuses = client.relays().await;
    let mut connected_count = 0;

    for relay_url_str in relay_urls {
        if let Ok(relay_url) = RelayUrl::parse(relay_url_str) {
            if let Some(relay) = relay_statuses.get(&relay_url) {
                if relay.is_connected() {
                    connected_count += 1;
                }
            }
        }
    }

    Ok((client, connected_count))
}

// --- Sender Implementation ---

/// Send file data via tmpfiles.org with Nostr signaling as fallback for WebRTC.
///
/// This function uses existing credentials from the WebRTC signaling,
/// so the receiver can use the same wormhole code that was already displayed.
///
/// # Arguments
/// * `file` - Open file handle to send
/// * `file_size` - Size of the file in bytes
/// * `sender_keys` - Sender's Nostr keys (from WebRTC signaling)
/// * `transfer_id` - Transfer ID (from WebRTC signaling)
/// * `encryption_key` - AES-256-GCM key (from WebRTC signaling)
/// * `relay_urls` - Relay URLs to use (from WebRTC signaling)
pub async fn send_tmpfiles_fallback(
    mut file: File,
    file_size: u64,
    sender_keys: Keys,
    transfer_id: String,
    encryption_key: [u8; 32],
    relay_urls: Vec<String>,
) -> Result<TransferResult> {
    // Validate file size
    if file_size > MAX_TMPFILES_SIZE {
        anyhow::bail!(
            "File size ({}) exceeds tmpfiles.org limit ({})\n\
             WebRTC connection is required for larger files.",
            format_bytes(file_size),
            format_bytes(MAX_TMPFILES_SIZE)
        );
    }

    let sender_pubkey = sender_keys.public_key();
    println!("Using tmpfiles.org fallback");
    println!("   Sender: {}", sender_pubkey.to_hex());
    println!("   Transfer ID: {}", transfer_id);

    // Use provided relays or fall back to defaults
    let relay_urls: Vec<String> = if relay_urls.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        relay_urls
    };

    println!("Connecting to {} Nostr relays for signaling...", relay_urls.len());

    let (client, connected_count) = connect_to_relays(sender_keys.clone(), &relay_urls).await?;

    if connected_count < MIN_RELAYS_REQUIRED {
        anyhow::bail!(
            "Failed to connect to enough relays ({}/{} connected, need {}+)",
            connected_count,
            relay_urls.len(),
            MIN_RELAYS_REQUIRED
        );
    }

    println!("Connected to {} relays", connected_count);

    // Subscribe to events from receiver
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
        anyhow::bail!("Failed to subscribe to events: {}", e);
    }

    tokio::time::sleep(Duration::from_secs(SUBSCRIPTION_SETUP_DELAY_SECS)).await;

    println!("Waiting for receiver to connect...");

    // Wait for ready signal from receiver
    let mut receiver_pubkey: Option<PublicKey> = None;
    let ready_timeout = Duration::from_secs(READY_SIGNAL_TIMEOUT_SECS);
    let start_time = tokio::time::Instant::now();

    while receiver_pubkey.is_none() && start_time.elapsed() < ready_timeout {
        match timeout(Duration::from_secs(5), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_ready_event(&event)
                    && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    receiver_pubkey = Some(event.pubkey);
                    println!("Receiver connected and ready!");
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    let receiver_pubkey = receiver_pubkey
        .context("Timeout waiting for receiver to connect (5 minutes)")?;

    // Read and encrypt entire file
    println!("Reading and encrypting file...");
    let mut file_data = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut file_data)
        .await
        .context("Failed to read file data")?;

    // Encrypt entire file as a single "chunk" with sequence 1
    let encrypted_data = encrypt_chunk(&encryption_key, 1, &file_data)
        .context("Failed to encrypt file")?;

    println!("Encrypted size: {}", format_bytes(encrypted_data.len() as u64));

    // Upload to tmpfiles.org
    println!("Uploading to tmpfiles.org...");
    let download_url = tmpfiles::upload_bytes(&encrypted_data, "transfer.enc").await?;
    println!("Upload complete!");

    // Send download URL to receiver via Nostr
    println!("Sending download URL to receiver...");
    let url_event = create_tmpfile_url_event(
        &sender_keys,
        &receiver_pubkey,
        &transfer_id,
        &download_url,
    )?;
    client.send_event(&url_event).await?;

    // Wait for completion signal from receiver
    println!("Waiting for receiver to confirm completion...");
    let completion_timeout = Duration::from_secs(COMPLETION_TIMEOUT_SECS);
    let completion_deadline = tokio::time::Instant::now() + completion_timeout;
    let mut completion_received = false;

    while tokio::time::Instant::now() < completion_deadline {
        match timeout(Duration::from_secs(2), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_completion_event(&event)
                    && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    completion_received = true;
                    break;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    client.disconnect().await;

    if completion_received {
        println!("Receiver confirmed completion!");
        Ok(TransferResult::Confirmed)
    } else {
        eprintln!("Warning: Did not receive completion confirmation from receiver");
        Ok(TransferResult::Unconfirmed)
    }
}

// --- Receiver Implementation ---

/// Receive a file via tmpfiles.org with Nostr signaling using a WebRTC WormholeToken.
pub async fn receive_tmpfiles_with_token(
    token: &WormholeToken,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    // Only support webrtc tokens
    if token.protocol != PROTOCOL_WEBRTC {
        anyhow::bail!(
            "receive_tmpfiles_with_token only supports webrtc protocol, got: {}",
            token.protocol
        );
    }

    println!("Receiving via tmpfiles.org fallback...");

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

    let filename = token
        .webrtc_filename
        .clone()
        .unwrap_or_else(|| "downloaded_file".to_string());

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

    println!("Connecting to {} Nostr relays for signaling...", relay_urls.len());

    // Generate ephemeral keypair for this receive session
    let receiver_keys = Keys::generate();
    let (client, connected_count) = connect_to_relays(receiver_keys.clone(), &relay_urls).await?;

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

    // Subscribe to events from sender
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

    // Send ready signal to sender
    let ready_event = create_ready_event(&receiver_keys, &sender_pubkey, &transfer_id)?;
    client.send_event(&ready_event).await?;
    println!("Sent ready signal to sender");

    // Wait for tmpfile URL event from sender
    println!("Waiting for download URL from sender...");
    let mut download_url: Option<String> = None;
    let url_timeout = Duration::from_secs(URL_RECEIVE_TIMEOUT_SECS);
    let start_time = tokio::time::Instant::now();
    let mut last_ready_time = tokio::time::Instant::now();

    while download_url.is_none() && start_time.elapsed() < url_timeout {
        // Periodically resend ready signal (ephemeral events may be missed)
        if last_ready_time.elapsed() > Duration::from_secs(READY_SIGNAL_INTERVAL_SECS) {
            let ready_event = create_ready_event(&receiver_keys, &sender_pubkey, &transfer_id)?;
            if let Err(e) = client.send_event(&ready_event).await {
                eprintln!("Warning: Failed to resend ready signal: {}", e);
            }
            last_ready_time = tokio::time::Instant::now();
        }

        match timeout(Duration::from_secs(2), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if is_tmpfile_url_event(&event)
                    && get_transfer_id(&event).as_deref() == Some(&transfer_id)
                {
                    match parse_tmpfile_url_event(&event) {
                        Ok(url) => {
                            download_url = Some(url);
                            println!("Received download URL!");
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to parse URL event: {}", e);
                        }
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    let download_url = download_url
        .context("Timeout waiting for download URL from sender")?;

    // Download from tmpfiles.org
    println!("Downloading from tmpfiles.org...");
    let encrypted_data = tmpfiles::download_file(&download_url).await?;
    println!("Download complete: {}", format_bytes(encrypted_data.len() as u64));

    // Decrypt file (encrypted as single "chunk" with sequence 1)
    println!("Decrypting...");
    let decrypted_data = decrypt_chunk(&encryption_key, 1, &encrypted_data)
        .context("Failed to decrypt file")?;

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

    // Send completion signal to sender
    let completion_event = create_completion_event(&receiver_keys, &sender_pubkey, &transfer_id)?;
    client.send_event(&completion_event).await?;
    println!("Sent completion confirmation to sender");

    client.disconnect().await;

    Ok(())
}
