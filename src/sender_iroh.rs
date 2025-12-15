use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::Builder;
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use walkdir::WalkDir;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::iroh_common::create_sender_endpoint;
use crate::transfer::{
    format_bytes, num_chunks, send_chunk, send_encrypted_chunk, send_encrypted_header,
    send_header, FileHeader, TransferType,
};
use crate::wormhole::generate_code;

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
            std::process::exit(130);
        }
    });
}

/// Send a file and return the wormhole code
pub async fn send_file(file_path: &Path, extra_encrypt: bool, relay_urls: Vec<String>) -> Result<()> {
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

    // Create iroh endpoint
    let endpoint = create_sender_endpoint(relay_urls).await?;

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

/// Send a folder as a tar archive.
///
/// Note: File permissions may not be fully preserved in cross-platform transfers,
/// especially when sending from Unix to Windows or vice versa. Windows does not
/// support Unix permission modes (rwx), so files may have different permissions
/// after extraction on Windows.
pub async fn send_folder(folder_path: &Path, extra_encrypt: bool, relay_urls: Vec<String>) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("📁 Creating tar archive of: {}", folder_name);
    #[cfg(unix)]
    println!("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    println!("   Note: Windows does not support Unix file modes.");
    println!("   Symlinks are included; special files (devices, FIFOs) are skipped.");

    // Create tar archive to temp file using Rust tar crate (no system dependency)
    let temp_tar = NamedTempFile::new().context("Failed to create temporary file")?;
    let temp_path = temp_tar.path().to_path_buf();

    // Set up cleanup handler for Ctrl+C
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    // Build tar archive
    {
        let tar_file = fs::File::create(temp_tar.path()).context("Failed to create tar file")?;
        let mut builder = Builder::new(tar_file);

        // Walk the directory and add all entries
        for entry in WalkDir::new(folder_path) {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Calculate relative path from folder root
            let rel_path = path
                .strip_prefix(folder_path)
                .context("Failed to calculate relative path")?;

            // Skip the root folder itself
            if rel_path.as_os_str().is_empty() {
                continue;
            }

            // Create archive path with folder name as root
            let archive_path = Path::new(folder_name).join(rel_path);

            if path.is_dir() {
                builder
                    .append_dir(&archive_path, path)
                    .with_context(|| format!("Failed to add directory: {}", path.display()))?;
            } else if path.is_file() || path.is_symlink() {
                // append_path_with_name handles both regular files and symlinks
                builder
                    .append_path_with_name(path, &archive_path)
                    .with_context(|| format!("Failed to add file: {}", path.display()))?;
            }
            // Other special files (devices, sockets, etc.) are skipped
        }

        builder.finish().context("Failed to finalize tar archive")?;
    }

    // Get tar file size
    let file_size = fs::metadata(temp_tar.path())
        .context("Failed to read tar file metadata")?
        .len();

    let tar_filename = format!("{}.tar", folder_name);

    println!(
        "📦 Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

    // Generate encryption key only if extra encryption is enabled
    let key = if extra_encrypt {
        println!("🔐 Extra AES-256-GCM encryption enabled");
        Some(generate_key())
    } else {
        None
    };

    // Create iroh endpoint
    let endpoint = create_sender_endpoint(relay_urls).await?;

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

    // Send header with Folder transfer type
    let header = FileHeader::new(TransferType::Folder, tar_filename.clone(), file_size);
    if let Some(ref k) = key {
        send_encrypted_header(&mut send_stream, k, &header)
            .await
            .context("Failed to send header")?;
    } else {
        send_header(&mut send_stream, &header)
            .await
            .context("Failed to send header")?;
    }

    // Open tar file and send chunks
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

    println!("\n✅ Folder sent successfully!");

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

    // Clear cleanup path (transfer succeeded, temp file no longer needed)
    cleanup_path.lock().await.take();

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    println!("👋 Connection closed.");

    // Temp file is automatically cleaned up when NamedTempFile is dropped

    Ok(())
}
