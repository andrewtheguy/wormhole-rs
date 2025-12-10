use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint, Watcher,
};
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

use crate::transfer::{format_bytes, num_chunks, recv_encrypted_chunk, recv_encrypted_header};
use crate::wormhole::parse_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

/// Receive a file using a wormhole code
pub async fn receive_file(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
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

    // Read encrypted file header (uses chunk_num 0)
    let header = recv_encrypted_header(&mut recv_stream, &key)
        .await
        .context("Failed to read file header")?;

    println!("📁 Receiving: {} ({})", header.filename, format_bytes(header.file_size));

    // Determine output directory and final path
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&header.filename);

    // Check if file already exists
    if output_path.exists() {
        print!("⚠️  File already exists: {}. Overwrite? [y/N] ", output_path.display());
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("Transfer cancelled - file exists");
        }
        
        // Remove existing file
        std::fs::remove_file(&output_path)
            .context("Failed to remove existing file")?;
    }

    // Create temp file in same directory (ensures rename works, auto-deletes on drop)
    let mut temp_file = NamedTempFile::new_in(&output_dir)
        .context("Failed to create temporary file")?;

    // Receive chunks (starting at chunk_num 1)
    let total_chunks = num_chunks(header.file_size);
    let mut chunk_num = 1u64;  // Start at 1, header used 0
    let mut bytes_received = 0u64;

    println!("📥 Receiving {} chunks...", total_chunks);

    while bytes_received < header.file_size {
        let chunk = recv_encrypted_chunk(&mut recv_stream, &key, chunk_num)
            .await
            .context("Failed to receive chunk")?;

        // Write synchronously (tempfile uses std::fs::File)
        temp_file.write_all(&chunk)
            .context("Failed to write to file")?;

        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_received == header.file_size {
            let percent = (bytes_received as f64 / header.file_size as f64 * 100.0) as u32;
            print!("\r   Progress: {}% ({}/{})", percent, format_bytes(bytes_received), format_bytes(header.file_size));
        }
    }

    // Flush and persist temp file to final path (atomic move)
    temp_file.flush().context("Failed to flush file")?;
    temp_file.persist(&output_path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file: {}", e))?;

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
