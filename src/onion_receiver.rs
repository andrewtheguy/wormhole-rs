use anyhow::{Context, Result};
use arti_client::{ErrorKind, HasKind, TorClient, TorClientConfig};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::folder::{
    extract_tar_archive, print_skipped_entries, print_tar_extraction_info, StreamingReader,
};
use crate::transfer::{
    format_bytes, num_chunks, recv_chunk, recv_encrypted_chunk, recv_encrypted_header, recv_header,
    TransferType,
};
use crate::wormhole::{decode_key, parse_code, PROTOCOL_TOR};

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

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file
fn setup_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = std::fs::remove_file(&path);
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

    if token.extra_encrypt {
        println!("Extra AES-256-GCM encryption detected");
    } else {
        println!("Using Tor's built-in end-to-end encryption");
    }

    let key = token
        .key
        .as_ref()
        .map(|k| decode_key(k))
        .transpose()
        .context("Failed to decode encryption key")?;

    let onion_addr = token
        .onion_address
        .context("No onion address in wormhole code")?;

    println!("Code valid. Connecting to sender via Tor...");

    // Bootstrap Tor client
    println!("Bootstrapping Tor client...");
    let config = TorClientConfig::default();
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
    let header = if let Some(ref k) = key {
        recv_encrypted_header(&mut stream, k)
            .await
            .context("Failed to read file header")?
    } else {
        recv_header(&mut stream)
            .await
            .context("Failed to read file header")?
    };

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
        print!(
            "File already exists: {}. Overwrite? [y/N] ",
            output_path.display()
        );
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("Transfer cancelled - file exists");
        }

        std::fs::remove_file(&output_path).context("Failed to remove existing file")?;
    }

    // Create temp file in same directory
    let temp_file =
        NamedTempFile::new_in(&output_dir).context("Failed to create temporary file")?;
    let temp_path = temp_file.path().to_path_buf();

    // Set up cleanup handler for Ctrl+C
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_cleanup_handler(cleanup_path.clone());

    // Keep temp_file handle for writing
    let mut temp_file = temp_file;

    // Receive chunks
    let total_chunks = num_chunks(header.file_size);
    let mut chunk_num = 1u64;
    let mut bytes_received = 0u64;

    println!("Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = if let Some(ref k) = key {
            recv_encrypted_chunk(&mut stream, k, chunk_num)
                .await
                .context("Failed to receive chunk")?
        } else {
            recv_chunk(&mut stream)
                .await
                .context("Failed to receive chunk")?
        };

        temp_file
            .write_all(&chunk)
            .context("Failed to write to file")?;

        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        // Progress update
        if chunk_num % 10 == 0 || bytes_received == header.file_size {
            let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_received),
                format_bytes(header.file_size)
            );
        }
    }

    // Clear cleanup path before persist (transfer succeeded)
    cleanup_path.lock().await.take();

    // Persist temp file
    temp_file.flush().context("Failed to flush file")?;
    temp_file
        .persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

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
async fn receive_folder_stream<S: AsyncReadExt + Unpin + Send + 'static>(
    stream: S,
    header: crate::transfer::FileHeader,
    key: Option<[u8; 32]>,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let extract_dir = match output_dir {
        Some(dir) => dir,
        None => {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let random_id: u32 = rand::random();
            PathBuf::from(format!("wormhole_{}_{:08x}", timestamp, random_id))
        }
    };

    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    println!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Get runtime handle for blocking in Read impl
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader using shared folder logic
    let reader = StreamingReader::new(stream, key, header.file_size, runtime_handle);

    // Use spawn_blocking to run tar extraction in a blocking context
    let extract_dir_clone = extract_dir.clone();
    let skipped_entries = tokio::task::spawn_blocking(move || {
        extract_tar_archive(reader, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    // Note: ACK is sent in the streaming reader's last chunk handling
    // For folder transfers, we need to send ACK after extraction
    // But the stream is consumed by the reader, so we handle this differently
    // The sender will detect connection close as implicit ACK for Tor transfers

    println!("Connection closed.");

    Ok(())
}

/// Receive a file or folder via Tor (auto-detects type)
pub async fn receive_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    receive_file_tor(code, output_dir).await
}
