use anyhow::{Context, Result};
use iroh::Watcher;
use std::path::PathBuf;

use crate::core::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
    StreamingReader,
};
use crate::core::transfer::{
    finalize_file_receiver, find_available_filename, format_bytes, prepare_file_receiver,
    prompt_file_exists, receive_file_data, recv_encrypted_header, send_abort, send_ack,
    send_proceed, send_resume, setup_dir_cleanup_handler, setup_resumable_cleanup_handler,
    ControlSignal, FileExistsChoice, TransferType,
};
use crate::core::wormhole::parse_code;
use crate::iroh::common::{create_receiver_endpoint, ALPN};

/// Receive a file or folder using a wormhole code.
/// Auto-detects whether it's a file or folder transfer based on the header.
pub async fn receive(
    code: &str,
    output_dir: Option<PathBuf>,
    relay_urls: Vec<String>,
    no_resume: bool,
) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;
    let key =
        crate::core::wormhole::decode_key(&token.key).context("Failed to decode encryption key")?;
    let addr = token
        .addr
        .context("No iroh endpoint address in wormhole code")?
        .to_endpoint_addr()
        .context("Failed to parse endpoint address")?;

    eprintln!("Code valid. Connecting to sender...");

    // Create iroh endpoint
    let endpoint = create_receiver_endpoint(relay_urls).await?;

    // Connect to sender
    let conn = endpoint.connect(addr, ALPN).await.map_err(|e| {
        let err_str = e.to_string().to_lowercase();
        let is_relay_error = err_str.contains("relay")
            || err_str.contains("alpn")
            || err_str.contains("no route")
            || err_str.contains("unreachable");

        if is_relay_error {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Relay connection failed. Try Tor mode instead:\n  \
                 Sender:   wormhole-rs send-tor <file>\n  \
                 Receiver: wormhole-rs receive <code>",
                e
            )
        } else {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Troubleshooting:\n  \
                 - Verify the wormhole code is correct\n  \
                 - Ensure the sender is still running\n  \
                 - Check network connectivity and firewall settings\n  \
                 - If issues persist, try Tor mode: wormhole-rs send-tor <file>",
                e
            )
        }
    })?;

    // Print connection info
    let remote_id = conn.remote_id();
    eprintln!("Connected!");
    eprintln!("Remote ID: {}", remote_id);

    // Get connection type (Direct, Relay, Mixed, None)
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        eprintln!("Connection type: {:?}", conn_type);
    }

    // Accept bi-directional stream
    let (mut send_stream, mut recv_stream) =
        conn.accept_bi().await.context("Failed to accept stream")?;

    // Read header (determines file vs folder)
    let header = recv_encrypted_header(&mut recv_stream, &key)
        .await
        .context("Failed to read header")?;

    eprintln!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            // Determine final output path, handling file existence
            let output_path = output_dir.join(&header.filename);
            let final_output_path = if output_path.exists() {
                // Prompt user in blocking context
                let path_clone = output_path.clone();
                let choice = tokio::task::spawn_blocking(move || prompt_file_exists(&path_clone))
                    .await
                    .context("Prompt task panicked")??;

                match choice {
                    FileExistsChoice::Overwrite => {
                        tokio::fs::remove_file(&output_path)
                            .await
                            .context("Failed to remove existing file")?;
                        output_path
                    }
                    FileExistsChoice::Rename => {
                        let new_path = find_available_filename(&output_path);
                        eprintln!("Will save as: {}", new_path.display());
                        new_path
                    }
                    FileExistsChoice::Cancel => {
                        // Send ABORT signal to sender
                        send_abort(&mut send_stream, &key)
                            .await
                            .context("Failed to send abort signal")?;
                        anyhow::bail!("Transfer cancelled by user");
                    }
                }
            } else {
                output_path
            };

            // Prepare file receiver (checks for resume)
            let (mut receiver, control_signal) =
                prepare_file_receiver(&final_output_path, &header, no_resume)?;

            // Set up cleanup handler (keeps temp file for resumable transfers on interrupt)
            let is_resumable = !no_resume && header.checksum != 0;
            let cleanup_path =
                setup_resumable_cleanup_handler(receiver.temp_path.clone(), is_resumable);

            // Send control signal to sender (PROCEED or RESUME)
            match &control_signal {
                ControlSignal::Proceed => {
                    send_proceed(&mut send_stream, &key)
                        .await
                        .context("Failed to send proceed signal")?;
                    eprintln!("Ready to receive data...");
                }
                ControlSignal::Resume(offset) => {
                    send_resume(&mut send_stream, &key, *offset)
                        .await
                        .context("Failed to send resume signal")?;
                    eprintln!("Resuming from offset {}...", format_bytes(*offset));
                }
                _ => unreachable!(),
            }

            // Receive file data
            receive_file_data(
                &mut recv_stream,
                &mut receiver,
                &key,
                header.file_size,
                10,  // progress_interval
                100, // metadata_update_interval
            )
            .await?;

            // Clear cleanup path before finalize (transfer succeeded)
            cleanup_path.lock().await.take();

            // Finalize transfer (strip metadata header, rename to final path)
            finalize_file_receiver(receiver)?;

            eprintln!("File received successfully!");
            eprintln!("Saved to: {}", final_output_path.display());
        }
        TransferType::Folder => {
            // Send confirmation to sender that we're ready to receive data
            send_proceed(&mut send_stream, &key)
                .await
                .context("Failed to send proceed signal")?;
            eprintln!("Ready to receive data...");

            receive_folder_impl(recv_stream, &header, key, Some(output_dir)).await?;
        }
    }

    // Send acknowledgment to sender
    send_ack(&mut send_stream, &key)
        .await
        .context("Failed to send acknowledgment")?;
    send_stream
        .finish()
        .context("Failed to finish send stream")?;

    // Close connection gracefully
    conn.closed().await;
    endpoint.close().await;

    eprintln!("Connection closed.");

    Ok(())
}


/// Internal implementation for receiving a folder (tar archive)
async fn receive_folder_impl<R>(
    recv_stream: R,
    header: &crate::core::transfer::FileHeader,
    key: [u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()>
where
    R: tokio::io::AsyncReadExt + Unpin + Send + 'static,
{
    eprintln!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory using shared logic
    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    // Set up cleanup handler for Ctrl+C
    let cleanup_path = setup_dir_cleanup_handler(extract_dir.clone());

    eprintln!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Get runtime handle for blocking in Read impl
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader that feeds tar extractor
    let reader = StreamingReader::new(recv_stream, key, header.file_size, runtime_handle);

    // Use spawn_blocking to run tar extraction in a blocking context
    let extract_dir_clone = extract_dir.clone();
    let skipped_entries =
        tokio::task::spawn_blocking(move || extract_tar_archive(reader, &extract_dir_clone))
            .await
            .context("Extraction task panicked")??;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    // Clear cleanup path before success (transfer succeeded)
    cleanup_path.lock().await.take();

    eprintln!("\nFolder received successfully!");
    eprintln!("Extracted to: {}", extract_dir.display());

    Ok(())
}
