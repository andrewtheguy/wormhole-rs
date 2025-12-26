use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::io::Write;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

use crate::core::crypto::{generate_key, CHUNK_SIZE};
use crate::cli::instructions::print_receiver_command;
use crate::core::transfer::{
    format_bytes, num_chunks, prepare_file_for_send, prepare_folder_for_send,
    recv_control, send_encrypted_chunk, send_encrypted_header, ControlSignal,
    FileHeader, TransferType,
};
use crate::core::wormhole::generate_tor_code;

/// Internal helper for common Tor transfer logic.
/// Handles Tor bootstrap, onion service, connection, data transfer, and acknowledgment.
async fn transfer_data_tor_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    use_pin: bool,
) -> Result<()> {
    // Always generate encryption key for application-layer encryption
    let key = generate_key();

    // Bootstrap Tor client (ephemeral mode - new keys each run)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    eprintln!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    eprintln!("Tor client bootstrapped!");

    // Generate a random nickname for ephemeral service
    let random_suffix: u64 = rand::thread_rng().gen();
    let nickname = format!("wh_{:016x}", random_suffix);

    // Configure onion service
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse()?)
        .build()?;

    // Launch service
    let (onion_service, rend_requests) = tor_client
        .launch_onion_service(hs_config)?
        .ok_or_else(|| anyhow::anyhow!("Failed to launch onion service"))?;

    // Get .onion address
    let onion_addr = onion_service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("No onion address available yet"))?;

    let onion_addr_str = format!("{}", onion_addr.display_unredacted());

    // Generate wormhole code
    let code = generate_tor_code(onion_addr_str.clone(), &key)?;

    if use_pin {
        print_receiver_command("wormhole-rs receive --pin");
    } else {
        print_receiver_command("wormhole-rs receive");
    }

    println!("\nWormhole code:\n{}\n", code);

    if use_pin {
        // Generate ephemeral keys for PIN exchange
        let keys = nostr_sdk::Keys::generate();
        let pin = crate::auth::nostr_pin::publish_wormhole_code_via_pin(
            &keys,
            &code,
            "tor-transfer", // Transfer id not critical for tor bootstrap, just needs to be non-empty
        ).await?;

        println!("🔢 PIN: {}\n", pin);
        println!("Then enter the PIN above when prompted.\n");
    } else {
        println!("Then enter the code above when prompted.\n");
    }

    eprintln!("Waiting for receiver to connect via Tor...");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Wait for incoming stream request
    if let Some(stream_req) = stream_requests.next().await {
        eprintln!("Receiver connected! Accepting stream...");

        // Accept the stream request
        let mut stream = stream_req.accept(Connected::new_empty()).await?;

        // Send file header
        let header = FileHeader::new(transfer_type, filename, file_size);
        send_encrypted_header(&mut stream, &key, &header)
            .await
            .context("Failed to send header")?;

        // Wait for receiver confirmation before sending data
        // This allows receiver to check if file exists and prompt user
        eprintln!("Waiting for receiver to confirm...");
        match recv_control(&mut stream, &key).await? {
            ControlSignal::Proceed => {
                eprintln!("Receiver ready, starting transfer...");
            }
            ControlSignal::Abort => {
                eprintln!("Receiver declined transfer");
                anyhow::bail!("Transfer cancelled by receiver");
            }
            ControlSignal::Ack => {
                anyhow::bail!("Unexpected ACK signal during confirmation");
            }
        }

        // Send chunks
        let total_chunks = num_chunks(file_size);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut chunk_num = 1u64; // Start at 1, header used 0
        let mut bytes_sent = 0u64;

        eprintln!("Sending {} chunks...", total_chunks);

        loop {
            let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
            if bytes_read == 0 {
                break;
            }

            send_encrypted_chunk(&mut stream, &key, chunk_num, &buffer[..bytes_read])
                .await
                .context("Failed to send chunk")?;

            chunk_num += 1;
            bytes_sent += bytes_read as u64;

            // Progress update every 10 chunks or on last chunk
            if chunk_num % 10 == 0 || bytes_sent == file_size {
                let percent = if file_size == 0 {
                    100 // Empty file is 100% complete
                } else {
                    (bytes_sent as f64 / file_size as f64 * 100.0) as u32
                };
                print!(
                    "\r   Progress: {}% ({}/{})",
                    percent,
                    format_bytes(bytes_sent),
                    format_bytes(file_size)
                );
                let _ = std::io::stdout().flush();
            }
        }

        // Flush the stream
        stream.flush().await.context("Failed to flush stream")?;

        eprintln!("Transfer complete!");

        // Wait for receiver ACK (best-effort, Tor streams may close abruptly)
        eprintln!("Waiting for receiver to confirm...");
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            recv_control(&mut stream, &key),
        )
        .await
        {
            Ok(Ok(ControlSignal::Ack)) => {
                eprintln!("Receiver confirmed!");
            }
            Ok(Ok(_)) => {
                eprintln!("Received unexpected signal (transfer likely succeeded)");
            }
            Ok(Err(_)) | Err(_) => {
                // Tor streams may close without proper END cell - this is normal
                eprintln!("Connection closed (transfer completed)");
            }
        }
        eprintln!("Done.");
    } else {
        anyhow::bail!("No connection received");
    }

    Ok(())
}

/// Send a file via Tor hidden service
pub async fn send_file_tor(file_path: &Path, use_pin: bool) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_data_tor_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::File,
        use_pin,
    )
    .await
}

/// Send a folder via Tor hidden service (as tar archive)
pub async fn send_folder_tor(folder_path: &Path, use_pin: bool) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Note: prepared.temp_file is kept alive until this function returns, ensuring the file exists
    transfer_data_tor_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::Folder,
        use_pin,
    )
    .await
}
