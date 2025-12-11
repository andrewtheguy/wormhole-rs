use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint, Watcher,
};
use std::cmp;
use std::io::Read;
use std::path::PathBuf;
use tar::Archive;

use crate::transfer::{
    format_bytes, recv_chunk, recv_encrypted_chunk, recv_encrypted_header, recv_header,
    TransferType,
};
use crate::wormhole::parse_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

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

/// Receive a folder (tar archive) using a wormhole code.
///
/// Note: File permissions may not be fully preserved in cross-platform transfers,
/// especially when receiving from Unix on Windows or vice versa. Windows does not
/// support Unix permission modes (rwx), so files may have different permissions
/// after extraction.
pub async fn receive_folder(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    println!("🔮 Parsing wormhole code...");

    // Parse the wormhole code (auto-detects encryption mode)
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    if token.extra_encrypt {
        println!("🔐 Extra AES-256-GCM encryption detected");
    }

    let key = token.key;
    let addr = token.addr;

    println!("✅ Code valid. Connecting to sender...");

    // Create iroh endpoint with N0 discovery + local mDNS
    let endpoint = Endpoint::empty_builder(RelayMode::Default)
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

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

    // Read header
    let header = if let Some(ref k) = key {
        recv_encrypted_header(&mut recv_stream, k)
            .await
            .context("Failed to read header")?
    } else {
        recv_header(&mut recv_stream)
            .await
            .context("Failed to read header")?
    };

    // Validate transfer type
    if header.transfer_type != TransferType::Folder {
        anyhow::bail!(
            "Expected folder transfer, got file transfer. Use 'receive' command instead."
        );
    }

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

    println!("\n✅ Folder received successfully!");
    println!("📂 Extracted to: {}", extract_dir.display());

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
