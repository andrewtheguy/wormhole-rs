use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

use crate::cli::instructions::print_receiver_command;
use crate::core::crypto::generate_key;
use crate::core::transfer::{
    format_resume_progress, handle_receiver_response, prepare_file_for_send,
    prepare_folder_for_send, recv_control, send_encrypted_header, send_file_data,
    setup_temp_file_cleanup_handler, ControlSignal, FileHeader, ResumeResponse, TransferType,
};
use crate::core::wormhole::generate_tor_code;

/// Internal helper for common Tor transfer logic.
/// Handles Tor bootstrap, onion service, connection, data transfer, and acknowledgment.
async fn transfer_data_tor_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
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
        )
        .await?;

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

        // Send file header with checksum for resume support
        let header = FileHeader::new(transfer_type, filename, file_size, checksum);
        send_encrypted_header(&mut stream, &key, &header)
            .await
            .context("Failed to send header")?;

        // Wait for receiver confirmation before sending data
        eprintln!("Waiting for receiver to confirm...");
        let response = handle_receiver_response(&mut stream, &key).await?;

        let start_offset = match response {
            ResumeResponse::Fresh => {
                eprintln!("Receiver ready, starting transfer...");
                0
            }
            ResumeResponse::Resume { offset, .. } => {
                eprintln!("{}", format_resume_progress(offset, file_size));
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                offset
            }
            ResumeResponse::Aborted => {
                eprintln!("Receiver declined transfer");
                anyhow::bail!("Transfer cancelled by receiver");
            }
        };

        // Send file data using shared component
        send_file_data(&mut stream, &mut file, &key, file_size, start_offset, 10).await?;

        // Flush the stream
        stream.flush().await.context("Failed to flush stream")?;

        eprintln!("\nTransfer complete!");

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
        prepared.checksum,
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

    // Set up cleanup handler
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_path = setup_temp_file_cleanup_handler(temp_path.clone());

    let result = transfer_data_tor_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        0, // Folders are not resumable
        TransferType::Folder,
        use_pin,
    )
    .await;

    // Clean up temp file
    cleanup_path.lock().await.take();
    let _ = tokio::fs::remove_file(&temp_path).await;

    result
}
