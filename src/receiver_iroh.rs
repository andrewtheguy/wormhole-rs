use anyhow::{Context, Result};
use iroh::Watcher;
use std::cmp;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tar::Archive;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;

use crate::iroh_common::{create_receiver_endpoint, ALPN};
use crate::transfer::{
    format_bytes, num_chunks, recv_chunk, recv_encrypted_chunk, recv_encrypted_header, recv_header,
    TransferType,
};
use crate::wormhole::parse_code;

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for extraction directory cleanup on interrupt
type ExtractDirCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file
fn setup_file_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = std::fs::remove_file(&path);
                eprintln!("\nInterrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}

/// Set up Ctrl+C handler to clean up extraction directory
fn setup_dir_cleanup_handler(cleanup_path: ExtractDirCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = std::fs::remove_dir_all(&path);
                eprintln!("\nInterrupted. Cleaned up extraction directory.");
            }
            std::process::exit(130);
        }
    });
}

/// Wrapper to bridge async chunk receiving with sync tar reading.
/// Implements std::io::Read by fetching chunks on demand.
/// Supports both encrypted and unencrypted modes.
struct StreamingReader<R> {
    recv_stream: R,
    key: Option<[u8; 32]>,
    chunk_num: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    bytes_remaining: u64,
    runtime_handle: tokio::runtime::Handle,
}

impl<R> StreamingReader<R> {
    fn new(
        recv_stream: R,
        key: Option<[u8; 32]>,
        file_size: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            recv_stream,
            key,
            chunk_num: 1, // Chunks start at 1, header was 0
            buffer: Vec::new(),
            buffer_pos: 0,
            bytes_remaining: file_size,
            runtime_handle,
        }
    }
}

impl<R: tokio::io::AsyncReadExt + Unpin + Send> Read for StreamingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If buffer is exhausted and there's more data, fetch next chunk
        if self.buffer_pos >= self.buffer.len() && self.bytes_remaining > 0 {
            // Block on async chunk receive
            let chunk_result = self.runtime_handle.block_on(async {
                if let Some(ref key) = self.key {
                    recv_encrypted_chunk(&mut self.recv_stream, key, self.chunk_num).await
                } else {
                    recv_chunk(&mut self.recv_stream).await
                }
            });

            match chunk_result {
                Ok(chunk) => {
                    self.bytes_remaining -= chunk.len() as u64;
                    self.chunk_num += 1;
                    self.buffer = chunk;
                    self.buffer_pos = 0;
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to receive chunk: {}", e),
                    ));
                }
            }
        }

        // Return data from buffer
        if self.buffer_pos >= self.buffer.len() {
            return Ok(0); // EOF
        }

        let available = self.buffer.len() - self.buffer_pos;
        let to_copy = cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;

        Ok(to_copy)
    }
}

/// Receive a file or folder using a wormhole code.
/// Auto-detects whether it's a file or folder transfer based on the header.
pub async fn receive(code: &str, output_dir: Option<PathBuf>, relay_urls: Vec<String>) -> Result<()> {
    println!("🔮 Parsing wormhole code...");

    // Parse the wormhole code (auto-detects encryption mode)
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    if token.extra_encrypt {
        println!("🔐 Extra AES-256-GCM encryption detected");
    }

    let key = token
        .key
        .as_ref()
        .map(|k| crate::wormhole::decode_key(k))
        .transpose()
        .context("Failed to decode encryption key")?;
    let addr = token
        .addr
        .context("No iroh endpoint address in wormhole code")?
        .to_endpoint_addr()
        .context("Failed to parse endpoint address")?;

    println!("✅ Code valid. Connecting to sender...");

    // Create iroh endpoint
    let endpoint = create_receiver_endpoint(relay_urls).await?;

    // Connect to sender
    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .context("Failed to connect to sender")?;

    // Print connection info
    let remote_id = conn.remote_id();
    println!("✅ Connected!");
    println!("   📡 Remote ID: {}", remote_id);

    // Get connection type (Direct, Relay, Mixed, None)
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        println!("   🔗 Connection: {:?}", conn_type);
    }

    // Accept bi-directional stream
    let (mut send_stream, mut recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream")?;

    // Read header (determines file vs folder)
    let header = if let Some(ref k) = key {
        recv_encrypted_header(&mut recv_stream, k)
            .await
            .context("Failed to read header")?
    } else {
        recv_header(&mut recv_stream)
            .await
            .context("Failed to read header")?
    };

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            receive_file_impl(
                &mut recv_stream,
                &header,
                key,
                output_dir,
            )
            .await?;
        }
        TransferType::Folder => {
            receive_folder_impl(
                recv_stream,
                &header,
                key,
                output_dir,
            )
            .await?;
        }
    }

    // Send acknowledgment to sender
    send_stream
        .write_all(b"ACK")
        .await
        .context("Failed to send acknowledgment")?;
    send_stream
        .finish()
        .context("Failed to finish send stream")?;

    // Close connection gracefully
    conn.closed().await;
    endpoint.close().await;

    println!("👋 Connection closed.");

    Ok(())
}

/// Internal implementation for receiving a file
async fn receive_file_impl<R>(
    recv_stream: &mut R,
    header: &crate::transfer::FileHeader,
    key: Option<[u8; 32]>,
    output_dir: Option<PathBuf>,
) -> Result<()>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    println!(
        "📁 Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory and final path
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&header.filename);

    // Check if file already exists
    if output_path.exists() {
        print!(
            "⚠️  File already exists: {}. Overwrite? [y/N] ",
            output_path.display()
        );
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("Transfer cancelled - file exists");
        }

        // Remove existing file
        std::fs::remove_file(&output_path).context("Failed to remove existing file")?;
    }

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

    println!("📥 Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = if let Some(ref k) = key {
            recv_encrypted_chunk(recv_stream, k, chunk_num)
                .await
                .context("Failed to receive chunk")?
        } else {
            recv_chunk(recv_stream)
                .await
                .context("Failed to receive chunk")?
        };

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
        }
    }

    // Clear cleanup path before persist (transfer succeeded)
    cleanup_path.lock().await.take();

    // Flush and persist temp file to final path (atomic move)
    temp_file.flush().context("Failed to flush file")?;
    temp_file
        .persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

    println!("\n✅ File received successfully!");
    println!("📁 Saved to: {}", output_path.display());

    Ok(())
}

/// Internal implementation for receiving a folder (tar archive)
async fn receive_folder_impl<R>(
    recv_stream: R,
    header: &crate::transfer::FileHeader,
    key: Option<[u8; 32]>,
    output_dir: Option<PathBuf>,
) -> Result<()>
where
    R: tokio::io::AsyncReadExt + Unpin + Send + 'static,
{
    println!(
        "📁 Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Determine output directory
    let extract_dir = match output_dir {
        Some(dir) => dir, // Use provided directory directly
        None => {
            // Generate random folder in current directory with timestamp for sorting
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let random_id: u32 = rand::random();
            PathBuf::from(format!("wormhole_{}_{:08x}", timestamp, random_id))
        }
    };

    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    // Set up cleanup handler for Ctrl+C
    let cleanup_path: ExtractDirCleanup = Arc::new(Mutex::new(Some(extract_dir.clone())));
    setup_dir_cleanup_handler(cleanup_path.clone());

    println!("📂 Extracting to: {}", extract_dir.display());
    #[cfg(unix)]
    println!("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    {
        println!("   Note: Unix file modes are not supported on Windows.");
        println!("   Symlinks require admin privileges and may be skipped.");
    }
    println!("   Special files (devices, FIFOs) will be skipped if present.");

    // Get runtime handle for blocking in Read impl
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader that feeds tar extractor
    let reader = StreamingReader::new(recv_stream, key, header.file_size, runtime_handle);

    // Extract tar archive while streaming
    let mut archive = Archive::new(reader);
    // Preserve file mode (0755, etc.) but not owner/group (UID/GID mismatch across machines)
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(false);

    // Use spawn_blocking to run tar extraction in a blocking context
    let extract_dir_clone = extract_dir.clone();
    let skipped_entries = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
        let mut skipped = Vec::new();

        for entry in archive.entries().context("Failed to read tar entries")? {
            let mut entry = entry.context("Failed to read tar entry")?;
            let path = entry.path().context("Failed to get entry path")?.into_owned();

            // Check entry type
            let entry_type = entry.header().entry_type();

            // On Windows, symlinks require special privileges and may fail
            #[cfg(windows)]
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                skipped.push(format!("{} (symlink/hardlink)", path.display()));
                continue;
            }

            // Skip special files that can't be extracted
            if entry_type.is_block_special()
                || entry_type.is_character_special()
                || entry_type.is_fifo()
            {
                skipped.push(format!("{} (special file)", path.display()));
                continue;
            }

            // Extract the entry
            entry
                .unpack_in(&extract_dir_clone)
                .with_context(|| format!("Failed to extract: {}", path.display()))?;
        }

        Ok(skipped)
    })
    .await
    .context("Extraction task panicked")??;

    // Report skipped entries
    if !skipped_entries.is_empty() {
        println!(
            "\n⚠️  Skipped {} entries (not supported on this platform):",
            skipped_entries.len()
        );
        for entry in &skipped_entries {
            println!("   - {}", entry);
        }
    }

    // Clear cleanup path before success (transfer succeeded)
    cleanup_path.lock().await.take();

    println!("\n✅ Folder received successfully!");
    println!("📂 Extracted to: {}", extract_dir.display());

    Ok(())
}
