use anyhow::{Context, Result};
use iroh::Watcher;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;

use crate::core::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
    StreamingReader,
};
use crate::core::transfer::{
    find_available_filename, format_bytes, num_chunks, prompt_file_exists, recv_encrypted_chunk,
    recv_encrypted_header, send_abort, send_ack, send_proceed, FileExistsChoice, TransferType,
};
use crate::core::wormhole::parse_code;
use crate::iroh::common::{create_receiver_endpoint, ALPN};

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for extraction directory cleanup on interrupt
type ExtractDirCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
///
/// # Task Lifecycle
/// This spawns a task that waits for Ctrl+C and lives until the signal is received
/// or the program exits. This design is appropriate for CLI tools where `receive()`
/// is called once per process. If `receive()` were called multiple times in a
/// long-running process, these tasks would accumulate (though they're lightweight).
/// For such use cases, consider using `tokio::select!` or a global signal handler
/// with registration/unregistration.
fn setup_file_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                log::error!("Interrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}

/// Set up Ctrl+C handler to clean up extraction directory.
/// See [`setup_file_cleanup_handler`] for task lifecycle notes.
fn setup_dir_cleanup_handler(cleanup_path: ExtractDirCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_dir_all(&path).await;
                log::error!("Interrupted. Cleaned up extraction directory.");
            }
            std::process::exit(130);
        }
    });
}

/// Receive a file or folder using a wormhole code.
/// Auto-detects whether it's a file or folder transfer based on the header.
pub async fn receive(
    code: &str,
    output_dir: Option<PathBuf>,
    relay_urls: Vec<String>,
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
                    // Send ABORT signal to sender
                    send_abort(&mut send_stream, &key)
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

    // Send confirmation to sender that we're ready to receive data
    send_proceed(&mut send_stream, &key)
        .await
        .context("Failed to send proceed signal")?;
    eprintln!("Ready to receive data...");

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            receive_file_impl(&mut recv_stream, &header, key, final_output_path).await?;
        }
        TransferType::Folder => {
            receive_folder_impl(recv_stream, &header, key, Some(final_output_path)).await?;
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

/// Internal implementation for receiving a file
/// output_path is the final destination path (file existence already checked)
async fn receive_file_impl<R>(
    recv_stream: &mut R,
    header: &crate::core::transfer::FileHeader,
    key: [u8; 32],
    output_path: PathBuf,
) -> Result<()>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    // Get output directory from path
    let output_dir = output_path.parent().unwrap_or(std::path::Path::new("."));

    // Create temp file in same directory (ensures rename works, auto-deletes on drop)
    let temp_file =
        NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
    let temp_path = temp_file.path().to_path_buf();

    // Set up cleanup handler for Ctrl+C
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_file_cleanup_handler(cleanup_path.clone());

    let mut temp_file = temp_file;

    // Receive chunks (starting at chunk_num 1)
    let total_chunks = num_chunks(header.file_size);
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_received = 0u64;

    eprintln!("Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = recv_encrypted_chunk(recv_stream, &key)
            .await
            .context("Failed to receive chunk")?;

        // Write synchronously (tempfile uses std::fs::File)
        temp_file
            .write_all(&chunk)
            .context("Failed to write to file")?;

        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_received == header.file_size {
            let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_received),
                format_bytes(header.file_size)
            );
            let _ = std::io::stdout().flush();
        }
    }

    // Clear cleanup path before persist (transfer succeeded)
    cleanup_path.lock().await.take();

    // Flush and persist temp file to final path (atomic move)
    temp_file.flush().context("Failed to flush file")?;
    temp_file
        .persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

    eprintln!("\nFile received successfully!");
    eprintln!("Saved to: {}", output_path.display());

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
    let cleanup_path: ExtractDirCleanup = Arc::new(Mutex::new(Some(extract_dir.clone())));
    setup_dir_cleanup_handler(cleanup_path.clone());

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
