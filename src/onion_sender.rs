use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::folder::{create_tar_archive, print_tar_creation_info};
use crate::transfer::{
    format_bytes, num_chunks, send_chunk, send_encrypted_chunk, send_encrypted_header,
    send_header, FileHeader, TransferType,
};
use crate::wormhole::generate_tor_code;

/// Send a file via Tor hidden service
pub async fn send_file_tor(file_path: &Path, extra_encrypt: bool) -> Result<()> {
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

    println!(
        "Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Generate encryption key only if extra encryption is enabled
    let key = if extra_encrypt {
        println!("Extra AES-256-GCM encryption enabled");
        Some(generate_key())
    } else {
        println!("Using Tor's built-in end-to-end encryption");
        None
    };

    // Bootstrap Tor client (ephemeral mode - new keys each run)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    println!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    println!("Tor client bootstrapped!");

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
    let code = generate_tor_code(onion_addr_str.clone(), extra_encrypt, key.as_ref())?;

    println!("\nWormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive-tor\n");
    println!("Then enter the code above when prompted.\n");
    println!("Waiting for receiver to connect via Tor...");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Wait for incoming stream request
    if let Some(stream_req) = stream_requests.next().await {
        println!("Receiver connected! Accepting stream...");

        // Accept the stream request
        let mut stream = stream_req.accept(Connected::new_empty()).await?;

        // Send file header
        let header = FileHeader::new(TransferType::File, filename.clone(), file_size);
        if let Some(ref k) = key {
            send_encrypted_header(&mut stream, k, &header)
                .await
                .context("Failed to send header")?;
        } else {
            send_header(&mut stream, &header)
                .await
                .context("Failed to send header")?;
        }

        // Open file and send chunks
        let mut file = File::open(file_path).await.context("Failed to open file")?;
        let total_chunks = num_chunks(file_size);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut chunk_num = 1u64; // Start at 1, header used 0
        let mut bytes_sent = 0u64;

        println!("Sending {} chunks...", total_chunks);

        loop {
            let bytes_read = file.read(&mut buffer).await.context("Failed to read file")?;
            if bytes_read == 0 {
                break;
            }

            if let Some(ref k) = key {
                send_encrypted_chunk(&mut stream, k, chunk_num, &buffer[..bytes_read])
                    .await
                    .context("Failed to send chunk")?;
            } else {
                send_chunk(&mut stream, &buffer[..bytes_read])
                    .await
                    .context("Failed to send chunk")?;
            }

            chunk_num += 1;
            bytes_sent += bytes_read as u64;

            // Progress update every 10 chunks or on last chunk
            if chunk_num % 10 == 0 || bytes_sent == file_size {
                let percent = (bytes_sent as f64 / file_size as f64 * 100.0) as u32;
                print!(
                    "\r   Progress: {}% ({}/{})",
                    percent,
                    format_bytes(bytes_sent),
                    format_bytes(file_size)
                );
            }
        }

        // Flush the stream
        stream.flush().await.context("Failed to flush stream")?;

        println!("\nFile sent successfully!");

        // Wait for receiver ACK (best-effort, Tor streams may close abruptly)
        println!("Waiting for receiver to confirm...");
        let mut ack_buf = [0u8; 3];
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut ack_buf),
        )
        .await
        {
            Ok(Ok(_)) if &ack_buf == b"ACK" => {
                println!("Receiver confirmed!");
            }
            Ok(Ok(_)) => {
                println!("Received unexpected response (transfer likely succeeded)");
            }
            Ok(Err(_)) | Err(_) => {
                // Tor streams may close without proper END cell - this is normal
                println!("Connection closed (transfer completed)");
            }
        }
        println!("Done.");
    } else {
        anyhow::bail!("No connection received");
    }

    Ok(())
}

/// Send a folder via Tor hidden service (as tar archive)
pub async fn send_folder_tor(folder_path: &Path, extra_encrypt: bool) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("Creating tar archive of: {}", folder_name);
    print_tar_creation_info();

    // Create tar archive using shared folder logic
    let tar_archive = create_tar_archive(folder_path)?;
    let temp_tar = tar_archive.temp_file;
    let tar_filename = tar_archive.filename;
    let file_size = tar_archive.file_size;

    println!(
        "Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

    // Generate encryption key only if extra encryption is enabled
    let key = if extra_encrypt {
        println!("Extra AES-256-GCM encryption enabled");
        Some(generate_key())
    } else {
        println!("Using Tor's built-in end-to-end encryption");
        None
    };

    // Bootstrap Tor client (ephemeral mode)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    println!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    println!("Tor client bootstrapped!");

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
    let code = generate_tor_code(onion_addr_str.clone(), extra_encrypt, key.as_ref())?;

    println!("\nWormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive-tor\n");
    println!("Then enter the code above when prompted.\n");
    println!("Waiting for receiver to connect via Tor...");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Wait for incoming stream request
    if let Some(stream_req) = stream_requests.next().await {
        println!("Receiver connected! Accepting stream...");

        // Accept the stream request
        let mut stream = stream_req.accept(Connected::new_empty()).await?;

        // Send header with Folder transfer type
        let header = FileHeader::new(TransferType::Folder, tar_filename.clone(), file_size);
        if let Some(ref k) = key {
            send_encrypted_header(&mut stream, k, &header)
                .await
                .context("Failed to send header")?;
        } else {
            send_header(&mut stream, &header)
                .await
                .context("Failed to send header")?;
        }

        // Open tar file and send chunks
        let mut file = File::open(temp_tar.path())
            .await
            .context("Failed to open tar file")?;
        let total_chunks = num_chunks(file_size);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut chunk_num = 1u64;
        let mut bytes_sent = 0u64;

        println!("Sending {} chunks...", total_chunks);

        loop {
            let bytes_read = file
                .read(&mut buffer)
                .await
                .context("Failed to read tar file")?;
            if bytes_read == 0 {
                break;
            }

            if let Some(ref k) = key {
                send_encrypted_chunk(&mut stream, k, chunk_num, &buffer[..bytes_read])
                    .await
                    .context("Failed to send chunk")?;
            } else {
                send_chunk(&mut stream, &buffer[..bytes_read])
                    .await
                    .context("Failed to send chunk")?;
            }

            chunk_num += 1;
            bytes_sent += bytes_read as u64;

            // Progress update every 10 chunks or on last chunk
            if chunk_num % 10 == 0 || bytes_sent == file_size {
                let percent = (bytes_sent as f64 / file_size as f64 * 100.0) as u32;
                print!(
                    "\r   Progress: {}% ({}/{})",
                    percent,
                    format_bytes(bytes_sent),
                    format_bytes(file_size)
                );
            }
        }

        // Flush the stream
        stream.flush().await.context("Failed to flush stream")?;

        println!("\nFolder sent successfully!");

        // Wait for receiver ACK (best-effort, Tor streams may close abruptly)
        println!("Waiting for receiver to confirm...");
        let mut ack_buf = [0u8; 3];
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut ack_buf),
        )
        .await
        {
            Ok(Ok(_)) if &ack_buf == b"ACK" => {
                println!("Receiver confirmed!");
            }
            Ok(Ok(_)) => {
                println!("Received unexpected response (transfer likely succeeded)");
            }
            Ok(Err(_)) | Err(_) => {
                // Tor streams may close without proper END cell - this is normal
                println!("Connection closed (transfer completed)");
            }
        }
        println!("Done.");
    } else {
        anyhow::bail!("No connection received");
    }

    Ok(())
}
