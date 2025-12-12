use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint, RelayUrl,
};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::transfer::{
    format_bytes, num_chunks, send_chunk, send_encrypted_chunk, send_encrypted_header,
    send_header, FileHeader, TransferType,
};
use crate::wormhole::generate_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

fn parse_relay_mode(relay_url: Option<String>) -> Result<RelayMode> {
    match relay_url {
        Some(url) => {
            let relay_url: RelayUrl = url.parse().context("Invalid relay URL")?;
            Ok(RelayMode::Custom(relay_url.into()))
        }
        None => Ok(RelayMode::Default),
    }
}

/// Send a file and return the wormhole code
pub async fn send_file(file_path: &Path, extra_encrypt: bool, relay_url: Option<String>) -> Result<()> {
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

    println!(
        "📁 Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Generate encryption key only if extra encryption is enabled
    let key = if extra_encrypt {
        println!("🔐 Extra AES-256-GCM encryption enabled");
        Some(generate_key())
    } else {
        None
    };

    // Parse relay mode
    let relay_mode = parse_relay_mode(relay_url)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    if using_custom_relay {
        println!("Using custom relay server");
    }

    // Create iroh endpoint with N0 discovery + local mDNS
    let endpoint = Endpoint::empty_builder(relay_mode)
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
    let code = generate_code(&addr, extra_encrypt, key.as_ref())?;

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
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

    // Send file header
    let header = FileHeader::new(TransferType::File, filename.clone(), file_size);
    if let Some(ref k) = key {
        send_encrypted_header(&mut send_stream, k, &header)
            .await
            .context("Failed to send header")?;
    } else {
        send_header(&mut send_stream, &header)
            .await
            .context("Failed to send header")?;
    }

    // Open file and send chunks
    let mut file = File::open(file_path).await.context("Failed to open file")?;
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    println!("📤 Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read file")?;
        if bytes_read == 0 {
            break;
        }

        if let Some(ref k) = key {
            send_encrypted_chunk(&mut send_stream, k, chunk_num, &buffer[..bytes_read])
                .await
                .context("Failed to send chunk")?;
        } else {
            send_chunk(&mut send_stream, &buffer[..bytes_read])
                .await
                .context("Failed to send chunk")?;
        }

        chunk_num += 1;
        bytes_sent += bytes_read as u64;

        // Progress update every 10 chunks or on last chunk
        if chunk_num % 10 == 0 || bytes_sent == file_size {
            let percent = (bytes_sent as f64 / file_size as f64 * 100.0) as u32;
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_sent),
                format_bytes(file_size)
            );
        }
    }

    println!("\n✅ File sent successfully!");

    // Finish the send stream to signal we're done sending
    send_stream.finish().context("Failed to finish stream")?;

    // Wait for receiver to acknowledge completion
    println!("⏳ Waiting for receiver to confirm...");
    let mut ack_buf = [0u8; 3];
    recv_stream
        .read_exact(&mut ack_buf)
        .await
        .context("Failed to receive acknowledgment from receiver")?;

    if &ack_buf != b"ACK" {
        anyhow::bail!("Invalid acknowledgment from receiver");
    }

    println!("✅ Receiver confirmed!");

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    println!("👋 Connection closed.");

    Ok(())
}
