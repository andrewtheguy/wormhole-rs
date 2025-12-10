use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint,
};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::transfer::{format_bytes, num_chunks, send_encrypted_chunk, send_encrypted_header, FileHeader};
use crate::wormhole::generate_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

/// Send a file and return the wormhole code
pub async fn send_file(file_path: &Path) -> Result<()> {
    // Get file metadata
    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?
        .to_string();

    println!("📁 Preparing to send: {} ({})", filename, format_bytes(file_size));

    // Generate encryption key
    let key = generate_key();

    // Create iroh endpoint with N0 discovery + local mDNS
    let endpoint = Endpoint::empty_builder(RelayMode::Default)
        .alpns(vec![ALPN.to_vec()])
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    // Wait for endpoint to be online (connected to relay)
    endpoint.online().await;

    // Get our address
    let addr = endpoint.addr();

    // Generate wormhole code
    let code = generate_code(&key, &addr)?;

    println!("\n🔮 Wormhole code:\n{}\n", code);
    println!("On the receiving end, run:");
    println!("  wormhole-rs receive\n");
    println!("Then enter the code above when prompted.\n");
    println!("⏳ Waiting for receiver to connect...");

    // Wait for connection
    let conn = endpoint
        .accept()
        .await
        .context("No incoming connection")?
        .await
        .context("Failed to accept connection")?;

    println!("✅ Receiver connected!");

    // Open bi-directional stream
    let (mut send_stream, _recv_stream) = conn
        .open_bi()
        .await
        .context("Failed to open stream")?;

    // Send encrypted file header (uses chunk_num 0)
    let header = FileHeader::new(filename.clone(), file_size);
    send_encrypted_header(&mut send_stream, &key, &header)
        .await
        .context("Failed to send header")?;

    // Open file and send chunks (starting at chunk_num 1)
    let mut file = File::open(file_path).await.context("Failed to open file")?;
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64;  // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    println!("📤 Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read file")?;
        if bytes_read == 0 {
            break;
        }

        send_encrypted_chunk(&mut send_stream, &key, chunk_num, &buffer[..bytes_read])
            .await
            .context("Failed to send chunk")?;

        chunk_num += 1;
        bytes_sent += bytes_read as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_sent == file_size {
            let percent = (bytes_sent as f64 / file_size as f64 * 100.0) as u32;
            print!("\r   Progress: {}% ({}/{})", percent, format_bytes(bytes_sent), format_bytes(file_size));
        }
    }

    println!("\n✅ File sent successfully!");

    // Finish the stream
    send_stream.finish().context("Failed to finish stream")?;
    
    // Wait a moment for the receiver to process
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    println!("👋 Connection closed.");

    Ok(())
}
