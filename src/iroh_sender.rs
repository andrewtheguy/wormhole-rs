use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use iroh::Watcher;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::crypto::{generate_key, CHUNK_SIZE};
use crate::cli_instructions::print_receiver_command;
use crate::iroh_common::{create_sender_endpoint};
use crate::transfer::{
    format_bytes, num_chunks, prepare_file_for_send, prepare_folder_for_send,
    send_encrypted_chunk, send_encrypted_header, FileHeader, TransferType,
    ABORT_SIGNAL, PROCEED_SIGNAL,
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
                log::error!("\nInterrupted. Cleaned up temp file.");
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
    relay_urls: Vec<String>,
    use_pin: bool,
) -> Result<()> {
    // Always generate encryption key for application-layer encryption
    let key = generate_key();

    // Create iroh endpoint
    let endpoint = create_sender_endpoint(relay_urls).await?;

    // Get our address
    let addr = endpoint.addr();

    // Generate wormhole code
    let code = generate_code(&addr, &key)?;

    if use_pin {
        print_receiver_command("wormhole-rs receive --pin");
    } else {
        print_receiver_command("wormhole-rs receive");
    }

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
        println!("Then enter the PIN above when prompted.\n");
    } else {
        println!("Then enter the code above when prompted.\n");
    }

    log::info!("⏳ Waiting for receiver to connect...");

    // Wait for connection
    let conn = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!(
            "No incoming connection.\n\n\
             If relay connection fails, try Tor mode: wormhole-rs send-tor <file>"
        ))?
        .await
        .map_err(|e| anyhow::anyhow!(
            "Failed to accept connection: {}\n\n\
             If relay connection fails, try Tor mode: wormhole-rs send-tor <file>",
            e
        ))?;

    let remote_id = conn.remote_id();
    log::info!("✅ Receiver connected!");
    log::info!("   📡 Remote ID: {}", remote_id);

    // Get connection type (Direct, Relay, Mixed, None)
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        log::info!("   🔗 Connection: {:?}", conn_type);
    }

    // Open bi-directional stream
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

    // Send file header
    let header = FileHeader::new(transfer_type, filename, file_size);
    send_encrypted_header(&mut send_stream, &key, &header)
        .await
        .context("Failed to send header")?;

    // Wait for receiver confirmation before sending data
    // This allows receiver to check if file exists and prompt user
    log::info!("⏳ Waiting for receiver to confirm...");
    let mut confirm_buf = [0u8; 7]; // "PROCEED" or "ABORT\0\0"
    recv_stream
        .read_exact(&mut confirm_buf)
        .await
        .context("Failed to receive confirmation from receiver")?;

    if confirm_buf[..5] == ABORT_SIGNAL[..5] {
        log::info!("❌ Receiver declined transfer");
        conn.close(0u32.into(), b"cancelled");
        endpoint.close().await;
        anyhow::bail!("Transfer cancelled by receiver");
    }

    if confirm_buf != *PROCEED_SIGNAL {
        anyhow::bail!("Invalid confirmation signal from receiver");
    }

    log::info!("✅ Receiver ready, starting transfer...");

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64; // Start at 1, header used 0
    let mut bytes_sent = 0u64;

    log::info!("📤 Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
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

    log::info!("\n✅ Transfer complete!");

    // Finish the send stream to signal we're done sending
    send_stream.finish().context("Failed to finish stream")?;

    // Wait for receiver to acknowledge completion
    log::info!("⏳ Waiting for receiver to confirm...");
    let mut ack_buf = [0u8; 3];
    recv_stream
        .read_exact(&mut ack_buf)
        .await
        .context("Failed to receive acknowledgment from receiver")?;

    if &ack_buf != b"ACK" {
        anyhow::bail!("Invalid acknowledgment from receiver");
    }

    log::info!("✅ Receiver confirmed!");

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    log::info!("👋 Connection closed.");

    Ok(())
}

/// Send a file and return the wormhole code
pub async fn send_file(file_path: &Path, relay_urls: Vec<String>, use_pin: bool) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_data_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::File,
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
pub async fn send_folder(folder_path: &Path, relay_urls: Vec<String>, use_pin: bool) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler for Ctrl+C
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    let result = transfer_data_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        TransferType::Folder,
        relay_urls,
        use_pin,
    )
    .await;

    // Clear cleanup path (transfer succeeded or failed, temp file handled)
    cleanup_path.lock().await.take();

    // Temp file is automatically cleaned up when NamedTempFile (prepared.temp_file) is dropped

    result
}
