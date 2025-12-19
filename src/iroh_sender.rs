use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::folder::{create_tar_archive, print_tar_creation_info};
use crate::iroh_common::{create_sender_endpoint, wait_for_direct_connection, DirectConnectionResult};
use crate::transfer::{
    format_bytes, num_chunks, send_chunk, send_encrypted_chunk, send_encrypted_header,
    send_header, FileHeader, TransferType,
};
use crate::wormhole::generate_code;

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Set up Ctrl+C handler to clean up temp file.
///
/// Note: Spawns a task that lives until Ctrl+C or program exit. This is appropriate
/// for CLI tools but would accumulate tasks if called repeatedly in a long-running process.
fn setup_cleanup_handler(cleanup_path: TempFileCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                eprintln!("\nInterrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}

/// Internal helper for common transfer logic.
/// Handles encryption setup, endpoint creation, connection, data transfer, and acknowledgment.
async fn transfer_data_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    extra_encrypt: bool,
    relay_urls: Vec<String>,
    use_pin: bool,
) -> Result<()> {
    // Generate encryption key only if extra encryption is enabled
    let key = if extra_encrypt {
        println!("🔐 Extra AES-256-GCM encryption enabled");
        Some(generate_key())
    } else {
        None
    };

    // Create iroh endpoint
    let (endpoint, using_custom_relay) = create_sender_endpoint(relay_urls).await?;

    // Get our address
    let addr = endpoint.addr();

    // Generate wormhole code
    let code = generate_code(&addr, extra_encrypt, key.as_ref())?;

    println!("\n🔮 Wormhole code:\n{}\n", code);

    if use_pin {
        // Generate ephemeral keys for PIN exchange
        let keys = nostr_sdk::Keys::generate();
        let pin = crate::nostr_pin::publish_wormhole_code_via_pin(
            &keys,
            &code,
            "iroh-transfer", // Transfer id not critical for iroh, just needs to be non-empty
        ).await?;

        println!("🔢 PIN: {}\n", pin);
        println!("On the receiving end, run:");
        println!("  wormhole-rs receive --pin\n");
        println!("Then enter the PIN above when prompted.\n");
    } else {
        println!("On the receiving end, run:");
        println!("  wormhole-rs receive\n");
        println!("Then enter the code above when prompted.\n");
    }

    println!("⏳ Waiting for receiver to connect...");

    // Wait for connection
    let conn = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!(
            "No incoming connection.\n\n\
             If relay connection fails, try Tor mode: wormhole-rs send tor <file>"
        ))?
        .await
        .map_err(|e| anyhow::anyhow!(
            "Failed to accept connection: {}\n\n\
             If relay connection fails, try Tor mode: wormhole-rs send tor <file>",
            e
        ))?;

    let remote_id = conn.remote_id();
    println!("✅ Receiver connected!");

    // When using default public relay (not custom), reject relay-only connections
    // The default relay is rate-limited and not suitable for data transfer
    if !using_custom_relay {
        if wait_for_direct_connection(&endpoint, remote_id).await == DirectConnectionResult::StillRelay {
            conn.close(1u32.into(), b"relay connections not allowed with default relay");
            anyhow::bail!(
                "Connection rejected: relay-only connection not allowed with default public relay.\n\n\
                 The default relay is rate-limited. Try one of these alternatives:\n  \
                 - Use Tor mode: wormhole-rs send tor <file>\n  \
                 - Use a custom relay: wormhole-rs send iroh --relay-url <url> <file>"
            );
        }
        println!("   🔗 Direct P2P connection established");
    }

    // Open bi-directional stream
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

    // Send file header
    let header = FileHeader::new(transfer_type, filename, file_size);
    if let Some(ref k) = key {
        send_encrypted_header(&mut send_stream, k, &header)
            .await
            .context("Failed to send header")?;
    } else {
        send_header(&mut send_stream, &header)
            .await
            .context("Failed to send header")?;
    }

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    println!("📤 Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
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
            let percent = if file_size == 0 {
                100 // Empty file is 100% complete
            } else {
                (bytes_sent as f64 / file_size as f64 * 100.0) as u32
            };
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_sent),
                format_bytes(file_size)
            );
            let _ = std::io::stdout().flush();
        }
    }

    println!("\n✅ Transfer complete!");

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

/// Send a file and return the wormhole code
pub async fn send_file(file_path: &Path, extra_encrypt: bool, relay_urls: Vec<String>, use_pin: bool) -> Result<()> {
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

    // Open file
    let file = File::open(file_path).await.context("Failed to open file")?;

    // Transfer using common logic
    transfer_data_internal(
        file,
        filename,
        file_size,
        TransferType::File,
        extra_encrypt,
        relay_urls,
        use_pin,
    )
    .await
}

/// Send a folder as a tar archive.
///
/// Note: File permissions may not be fully preserved in cross-platform transfers,
/// especially when sending from Unix to Windows or vice versa. Windows does not
/// support Unix permission modes (rwx), so files may have different permissions
/// after extraction on Windows.
pub async fn send_folder(folder_path: &Path, extra_encrypt: bool, relay_urls: Vec<String>, use_pin: bool) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("📁 Creating tar archive of: {}", folder_name);
    print_tar_creation_info();

    // Create tar archive using shared folder logic
    let tar_archive = create_tar_archive(folder_path)?;
    let temp_tar = tar_archive.temp_file;
    let tar_filename = tar_archive.filename;
    let file_size = tar_archive.file_size;

    // Set up cleanup handler for Ctrl+C
    let temp_path = temp_tar.path().to_path_buf();
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    println!(
        "📦 Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

    // Open tar file
    let file = File::open(temp_tar.path())
        .await
        .context("Failed to open tar file")?;

    // Transfer using common logic
    let result = transfer_data_internal(
        file,
        tar_filename,
        file_size,
        TransferType::Folder,
        extra_encrypt,
        relay_urls,
        use_pin,
    )
    .await;

    // Clear cleanup path (transfer succeeded or failed, temp file handled)
    cleanup_path.lock().await.take();

    // Temp file is automatically cleaned up when NamedTempFile is dropped

    result
}
