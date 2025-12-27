use anyhow::Result;
use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::path::Path;
use tokio::fs::File;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

use crate::cli::instructions::print_receiver_command;
use wormhole_common::core::crypto::generate_key;
use wormhole_common::core::transfer::{
    prepare_file_for_send, prepare_folder_for_send, run_sender_transfer_with_timeout,
    setup_temp_file_cleanup_handler, FileHeader, TransferResult, TransferType,
};
use wormhole_common::core::wormhole::generate_tor_code;

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
        let pin = wormhole_common::auth::nostr_pin::publish_wormhole_code_via_pin(
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

        // Create header and run unified transfer logic with 10s ACK timeout
        // Tor streams may close abruptly, so timeout is considered successful
        let header = FileHeader::new(transfer_type, filename, file_size, checksum);
        let result = run_sender_transfer_with_timeout(
            &mut file,
            &mut stream,
            &key,
            &header,
            Some(std::time::Duration::from_secs(10)),
        )
        .await?;

        if result == TransferResult::Aborted {
            anyhow::bail!("Transfer cancelled by receiver");
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
    let cleanup_handler = setup_temp_file_cleanup_handler(temp_path.clone());

    // Run transfer with interrupt handling
    let result = tokio::select! {
        result = transfer_data_tor_internal(
            prepared.file,
            prepared.filename,
            prepared.file_size,
            0, // Folders are not resumable
            TransferType::Folder,
            use_pin,
        ) => result,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - exit with interrupt code
            std::process::exit(130);
        }
    };

    // Clean up temp file
    cleanup_handler.cleanup_path.lock().await.take();
    let _ = tokio::fs::remove_file(&temp_path).await;

    result
}
