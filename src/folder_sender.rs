use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint,
};
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::transfer::{
    format_bytes, num_chunks, send_encrypted_chunk, send_encrypted_header, FileHeader,
    TransferType,
};
use crate::wormhole::generate_code;

const ALPN: &[u8] = b"wormhole-transfer/1";

/// Send a folder as a tar archive
pub async fn send_folder(folder_path: &Path) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    let parent_dir = folder_path
        .parent()
        .unwrap_or(Path::new("."));

    println!("📁 Creating tar archive of: {}", folder_name);

    // Create tar archive to temp file (must complete before sending)
    let temp_tar = NamedTempFile::new().context("Failed to create temporary file")?;

    let status = Command::new("tar")
        .arg("-cf")
        .arg(temp_tar.path())
        .arg("-C")
        .arg(parent_dir)
        .arg(folder_name)
        .status()
        .context("Failed to run tar command. Is tar installed?")?;

    if !status.success() {
        anyhow::bail!("Failed to create tar archive (tar exited with error)");
    }

    // Get tar file size
    let file_size = std::fs::metadata(temp_tar.path())
        .context("Failed to read tar file metadata")?
        .len();

    let tar_filename = format!("{}.tar", folder_name);

    println!(
        "📦 Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

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
    println!("  wormhole-rs receive-folder\n");
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

    // Send encrypted header with Folder transfer type (uses chunk_num 0)
    let header = FileHeader::new(TransferType::Folder, tar_filename.clone(), file_size);
    send_encrypted_header(&mut send_stream, &key, &header)
        .await
        .context("Failed to send header")?;

    // Open tar file and send chunks (starting at chunk_num 1)
    let mut file = File::open(temp_tar.path())
        .await
        .context("Failed to open tar file")?;
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    println!("📤 Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .context("Failed to read tar file")?;
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
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_sent),
                format_bytes(file_size)
            );
        }
    }

    println!("\n✅ Folder sent successfully!");

    // Finish the stream
    send_stream.finish().context("Failed to finish stream")?;

    // Wait a moment for the receiver to process
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    println!("👋 Connection closed.");

    // Temp file is automatically cleaned up when NamedTempFile is dropped

    Ok(())
}
