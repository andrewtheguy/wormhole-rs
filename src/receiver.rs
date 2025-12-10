use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint,
};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::transfer::{format_bytes, num_chunks, recv_encrypted_chunk, recv_encrypted_header};
use crate::wormhole::parse_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

/// Receive a file using a wormhole code
pub async fn receive_file(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    println!("🔮 Parsing wormhole code...");

    // Parse the wormhole code
    let (key, addr) = parse_code(code).context("Failed to parse wormhole code")?;

    println!("✅ Code valid. Connecting to sender...");

    // Create iroh endpoint with N0 discovery
    let endpoint = Endpoint::empty_builder(RelayMode::Default)
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    // Connect to sender
    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .context("Failed to connect to sender")?;

    println!("✅ Connected!");

    // Accept bi-directional stream
    let (send_stream, mut recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream")?;

    // Read encrypted file header (uses chunk_num 0)
    let header = recv_encrypted_header(&mut recv_stream, &key)
        .await
        .context("Failed to read file header")?;

    println!("📁 Receiving: {} ({})", header.filename, format_bytes(header.file_size));

    // Determine output path
    let output_path = match output_dir {
        Some(dir) => dir.join(&header.filename),
        None => PathBuf::from(&header.filename),
    };

    // Check if file already exists
    if output_path.exists() {
        anyhow::bail!("File already exists: {}", output_path.display());
    }

    // Create output file
    let mut file = File::create(&output_path)
        .await
        .context("Failed to create output file")?;

    // Receive chunks (starting at chunk_num 1)
    let total_chunks = num_chunks(header.file_size);
    let mut chunk_num = 1u64;  // Start at 1, header used 0
    let mut bytes_received = 0u64;

    println!("📥 Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = recv_encrypted_chunk(&mut recv_stream, &key, chunk_num)
            .await
            .context("Failed to receive chunk")?;

        file.write_all(&chunk)
            .await
            .context("Failed to write to file")?;

        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_received == header.file_size {
            let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
            print!("\r   Progress: {}% ({}/{})", percent, format_bytes(bytes_received), format_bytes(header.file_size));
        }
    }

    // Ensure file is flushed
    file.flush().await.context("Failed to flush file")?;
    drop(file);

    println!("\n✅ File received successfully!");
    println!("📁 Saved to: {}", output_path.display());

    // Close connection gracefully
    drop(send_stream);
    drop(recv_stream);
    conn.closed().await;
    endpoint.close().await;

    println!("👋 Connection closed.");

    Ok(())
}
