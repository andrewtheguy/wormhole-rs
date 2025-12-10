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

use crate::transfer::{format_bytes, recv_encrypted_chunk, recv_encrypted_header, TransferType};
use crate::wormhole::parse_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

/// Wrapper to bridge async chunk receiving with sync tar reading.
/// Implements std::io::Read by fetching and decrypting chunks on demand.
struct DecryptingReader<R> {
    recv_stream: R,
    key: [u8; 32],
    chunk_num: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    bytes_remaining: u64,
    runtime_handle: tokio::runtime::Handle,
}

impl<R> DecryptingReader<R> {
    fn new(recv_stream: R, key: [u8; 32], file_size: u64, runtime_handle: tokio::runtime::Handle) -> Self {
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

impl<R: tokio::io::AsyncReadExt + Unpin + Send> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If buffer is exhausted and there's more data, fetch next chunk
        if self.buffer_pos >= self.buffer.len() && self.bytes_remaining > 0 {
            // Block on async chunk receive
            let chunk_result = self.runtime_handle.block_on(async {
                recv_encrypted_chunk(&mut self.recv_stream, &self.key, self.chunk_num).await
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

/// Receive a folder (tar archive) using a wormhole code
pub async fn receive_folder(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    println!("🔮 Parsing wormhole code...");

    // Parse the wormhole code
    let (key, addr) = parse_code(code).context("Failed to parse wormhole code")?;

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
    let (send_stream, mut recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream")?;

    // Read encrypted header (uses chunk_num 0)
    let header = recv_encrypted_header(&mut recv_stream, &key)
        .await
        .context("Failed to read header")?;

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

    // Create random output folder
    let random_id: u32 = rand::random();
    let base_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let extract_dir = base_dir.join(format!("wormhole_{:08x}", random_id));

    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    println!("📂 Extracting to: {}", extract_dir.display());

    // Get runtime handle for blocking in Read impl
    let runtime_handle = tokio::runtime::Handle::current();

    // Create decrypting reader that feeds tar extractor
    let reader = DecryptingReader::new(recv_stream, key, header.file_size, runtime_handle);

    // Extract tar archive while streaming
    let mut archive = Archive::new(reader);
    archive.set_preserve_permissions(true);

    // Use spawn_blocking to run tar extraction in a blocking context
    let extract_dir_clone = extract_dir.clone();
    tokio::task::spawn_blocking(move || {
        archive
            .unpack(&extract_dir_clone)
            .context("Failed to extract tar archive")
    })
    .await
    .context("Extraction task panicked")??;

    println!("\n✅ Folder received successfully!");
    println!("📂 Extracted to: {}", extract_dir.display());

    // Close connection gracefully
    drop(send_stream);
    conn.closed().await;
    endpoint.close().await;

    println!("👋 Connection closed.");

    Ok(())
}
