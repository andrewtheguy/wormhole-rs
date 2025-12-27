use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, ErrorKind, HasKind, TorClient};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use wormhole_common::core::folder::{
    extract_tar_archive_returning_reader, get_extraction_dir, print_skipped_entries,
    print_tar_extraction_info, StreamingReader,
};
use wormhole_common::core::transfer::{
    finalize_file_receiver, find_available_filename, format_bytes, format_resume_progress,
    prepare_file_receiver, prompt_file_exists, receive_file_data, recv_encrypted_header,
    send_abort, send_ack, send_proceed, send_resume, setup_resumable_cleanup_handler,
    ControlSignal, FileExistsChoice, TransferType,
};
use wormhole_common::core::wormhole::{decode_key, parse_code, PROTOCOL_TOR};

const MAX_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 5;

/// Check if error is retryable (timeout, temporary network issues)
fn is_retryable(e: &arti_client::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::TorNetworkTimeout
            | ErrorKind::RemoteNetworkTimeout
            | ErrorKind::TransientFailure
            | ErrorKind::LocalNetworkError
    )
}

/// Receive a file via Tor hidden service
pub async fn receive_file_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    // Validate protocol
    if token.protocol != PROTOCOL_TOR {
        anyhow::bail!(
            "Expected Tor protocol, got '{}'. Use the appropriate receive command.",
            token.protocol
        );
    }

    let key = decode_key(&token.key).context("Failed to decode encryption key")?;

    let onion_addr = token
        .onion_address
        .context("No onion address in wormhole code")?;

    eprintln!("Code valid. Connecting to sender via Tor...");

    // Bootstrap Tor client (ephemeral mode - allows multiple concurrent receivers)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    eprintln!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;
    eprintln!("Tor client bootstrapped!");

    // Retry connection for temporary errors
    let mut stream = None;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        eprintln!(
            "Connecting to {} (attempt {}/{})...",
            onion_addr, attempt, MAX_RETRIES
        );

        match tor_client.connect((onion_addr.as_str(), 80)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);

                if !is_retryable(&e) {
                    return Err(e.into());
                }

                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    eprintln!("Retrying in {} seconds...", RETRY_DELAY_SECS);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }

    let mut stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect after {} attempts: {}",
            MAX_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;

    eprintln!("Connected!");

    // Read file header
    let header = recv_encrypted_header(&mut stream, &key)
        .await
        .context("Failed to read file header")?;

    eprintln!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    // Check file existence and get final output path (for files only)
    // This happens BEFORE data transfer, so user can cancel without wasting bandwidth
    let final_output_path = if header.transfer_type == TransferType::File {
        let output_path = output_dir.join(&header.filename);

        if output_path.exists() {
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
                    // Send encrypted ABORT signal to sender
                    send_abort(&mut stream, &key)
                        .await
                        .context("Failed to send abort signal")?;
                    anyhow::bail!("Transfer cancelled by user");
                }
            }
        } else {
            output_path
        }
    } else {
        // For folders, we extract to a directory - handled separately
        output_dir.clone()
    };

    // Check transfer type
    if header.transfer_type == TransferType::Folder {
        // Folders are not resumable, send proceed immediately
        send_proceed(&mut stream, &key)
            .await
            .context("Failed to send proceed signal")?;
        eprintln!("Ready to receive data...");

        // Handle as folder transfer
        return receive_folder_stream(stream, header, key, Some(final_output_path)).await;
    }

    // File transfer with resume support
    let (mut receiver, control_signal) =
        prepare_file_receiver(&final_output_path, &header, false)?;

    // Set up cleanup handler (resumable if checksum is present)
    let is_resumable = header.checksum != 0;
    let cleanup_path = setup_resumable_cleanup_handler(receiver.temp_path.clone(), is_resumable);

    // Send appropriate control signal to sender
    match &control_signal {
        ControlSignal::Proceed => {
            send_proceed(&mut stream, &key)
                .await
                .context("Failed to send proceed signal")?;
            eprintln!("Ready to receive data...");
        }
        ControlSignal::Resume(offset) => {
            send_resume(&mut stream, &key, *offset)
                .await
                .context("Failed to send resume signal")?;
            eprintln!("{}", format_resume_progress(*offset, header.file_size));
        }
        ControlSignal::Abort => {
            send_abort(&mut stream, &key)
                .await
                .context("Failed to send abort signal")?;
            anyhow::bail!("Transfer cancelled by user");
        }
        // prepare_file_receiver only returns Proceed or Resume, but handle other variants defensively
        other => anyhow::bail!("Unexpected control signal from prepare_file_receiver: {:?}", other),
    }

    // Receive file data using shared component
    receive_file_data(&mut stream, &mut receiver, &key, header.file_size, 10, 100).await?;

    // Clear cleanup and finalize
    cleanup_path.lock().await.take();
    finalize_file_receiver(receiver)?;

    eprintln!("\nFile received successfully!");
    eprintln!("Saved to: {}", final_output_path.display());

    // Send encrypted ACK
    send_ack(&mut stream, &key)
        .await
        .context("Failed to send acknowledgment")?;

    eprintln!("Connection closed.");

    Ok(())
}

/// Handle folder transfer after header is received
async fn receive_folder_stream<S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static>(
    stream: S,
    header: wormhole_common::core::transfer::FileHeader,
    key: [u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    eprintln!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory using shared logic
    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    eprintln!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Get runtime handle for blocking in Read impl
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader using shared folder logic
    let reader = StreamingReader::new(stream, key, header.file_size, runtime_handle);

    // Use spawn_blocking to run tar extraction in a blocking context
    // Returns both skipped entries and the StreamingReader for ACK sending
    let extract_dir_clone = extract_dir.clone();
    let (skipped_entries, streaming_reader) = tokio::task::spawn_blocking(move || {
        extract_tar_archive_returning_reader(reader, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    eprintln!("\nFolder received successfully!");
    eprintln!("Extracted to: {}", extract_dir.display());

    // Get the underlying stream back and send encrypted ACK (consistent with file transfers)
    let mut stream = streaming_reader.into_inner();
    send_ack(&mut stream, &key)
        .await
        .context("Failed to send ACK")?;

    eprintln!("Sent ACK to sender.");

    Ok(())
}

/// Receive a file or folder via Tor (auto-detects type)
pub async fn receive_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    receive_file_tor(code, output_dir).await
}
