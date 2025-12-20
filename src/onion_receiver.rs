use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, ErrorKind, HasKind, TorClient};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::folder::{
    extract_tar_archive_returning_reader, get_extraction_dir, print_skipped_entries,
    print_tar_extraction_info, StreamingReader,
};
use crate::transfer::{
    format_bytes, num_chunks, recv_encrypted_chunk, recv_encrypted_header, TransferType,
};
use crate::wormhole::{decode_key, parse_code, PROTOCOL_TOR};

const MAX_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 5;
/// Number of chunks to buffer before flushing to disk via spawn_blocking
const WRITE_BATCH_SIZE: usize = 10;

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
            std::process::exit(130); // Standard exit code for Ctrl+C
        }
    });
}

/// Receive a file via Tor hidden service
pub async fn receive_file_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    println!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    // Validate protocol
    if token.protocol != PROTOCOL_TOR {
        anyhow::bail!(
            "Expected Tor protocol, got '{}'. Use the appropriate receive command.",
            token.protocol
        );
    }

    let key = decode_key(&token.key)
        .context("Failed to decode encryption key")?;

    let onion_addr = token
        .onion_address
        .context("No onion address in wormhole code")?;

    println!("Code valid. Connecting to sender via Tor...");

    // Bootstrap Tor client (ephemeral mode - allows multiple concurrent receivers)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    println!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;
    println!("Tor client bootstrapped!");

    // Retry connection for temporary errors
    let mut stream = None;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        println!(
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
                    println!("Retrying in {} seconds...", RETRY_DELAY_SECS);
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

    println!("Connected!");

    // Read file header
    let header = recv_encrypted_header(&mut stream, &key)
        .await
        .context("Failed to read file header")?;

    // Check transfer type
    if header.transfer_type == TransferType::Folder {
        // Handle as folder transfer
        return receive_folder_stream(stream, header, key, output_dir).await;
    }

    println!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory and final path
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&header.filename);

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

        tokio::fs::remove_file(&output_path).await.context("Failed to remove existing file")?;
    }

    // Create temp file in same directory
    let temp_file =
        NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
    let temp_path = temp_file.path().to_path_buf();

    // Set up cleanup handler for Ctrl+C
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_cleanup_handler(cleanup_path.clone());

    // Wrap temp_file in Arc<StdMutex> for spawn_blocking access
    let temp_file = Arc::new(StdMutex::new(temp_file));

    // Receive chunks
    let total_chunks = num_chunks(header.file_size);
    let mut chunk_num = 1u64;
    let mut bytes_received = 0u64;

    // Buffer for batching writes to avoid blocking async runtime
    let mut chunk_buffer: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH_SIZE);

    println!("Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = recv_encrypted_chunk(&mut stream, &key, chunk_num)
            .await
            .context("Failed to receive chunk")?;

        bytes_received += chunk.len() as u64;
        chunk_num += 1;
        chunk_buffer.push(chunk);

        // Write batch to file using spawn_blocking when buffer is full or transfer complete
        if chunk_buffer.len() >= WRITE_BATCH_SIZE || bytes_received == header.file_size {
            let buffer = std::mem::take(&mut chunk_buffer);
            let file = Arc::clone(&temp_file);
            tokio::task::spawn_blocking(move || {
                let mut guard = file
                    .lock()
                    .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
                for chunk in buffer {
                    guard.write_all(&chunk)?;
                }
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("Write task panicked")??;
        }

        // Progress update
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

    // Extract file from Arc<StdMutex> for persist
    let temp_file = Arc::try_unwrap(temp_file)
        .map_err(|_| anyhow::anyhow!("Failed to unwrap Arc - file still in use"))?
        .into_inner()
        .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

    // Persist temp file using spawn_blocking to avoid blocking async runtime
    let output_path_for_persist = output_path.clone();
    tokio::task::spawn_blocking(move || {
        let mut file = temp_file;
        file.flush().context("Failed to flush file")?;
        file.persist(&output_path_for_persist)
            .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))
    })
    .await
    .context("Persist task panicked")??;

    println!("\nFile received successfully!");
    println!("Saved to: {}", output_path.display());

    // Send ACK
    stream
        .write_all(b"ACK")
        .await
        .context("Failed to send acknowledgment")?;
    stream.flush().await.context("Failed to flush stream")?;

    println!("Connection closed.");

    Ok(())
}

/// Handle folder transfer after header is received
async fn receive_folder_stream<S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static>(
    stream: S,
    header: crate::transfer::FileHeader,
    key: [u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory using shared logic
    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    println!("Extracting to: {}", extract_dir.display());
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

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    // Get the underlying stream back and send explicit ACK (consistent with file transfers)
    let mut stream = streaming_reader.into_inner();
    stream
        .write_all(b"ACK")
        .await
        .context("Failed to send ACK")?;

    println!("Sent ACK to sender.");

    Ok(())
}

/// Receive a file or folder via Tor (auto-detects type)
pub async fn receive_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    receive_file_tor(code, output_dir).await
}
