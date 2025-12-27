use anyhow::{Context, Result};
use iroh::Watcher;
use std::path::Path;
use tokio::fs::File;

use crate::cli::instructions::print_receiver_command;
use super::common::{create_sender_endpoint, IrohDuplex};
use wormhole_common::core::crypto::generate_key;
use wormhole_common::core::transfer::{
    prepare_file_for_send, prepare_folder_for_send, run_sender_transfer,
    setup_temp_file_cleanup_handler, FileHeader, Interrupted, TransferResult, TransferType,
};
use wormhole_common::core::wormhole::generate_code;
use wormhole_common::signaling::nostr_protocol::generate_transfer_id;

/// Internal helper for common transfer logic.
/// Handles encryption setup, endpoint creation, connection, data transfer, and acknowledgment.
async fn transfer_data_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
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
        // Generate unique transfer ID to avoid collisions with concurrent transfers
        let transfer_id = generate_transfer_id();
        let pin = wormhole_common::auth::nostr_pin::publish_wormhole_code_via_pin(
            &keys,
            &code,
            &transfer_id,
        )
        .await?;

        println!("🔢 PIN: {}\n", pin);
        println!("Then enter the PIN above when prompted.\n");
    } else {
        println!("Then enter the code above when prompted.\n");
    }

    eprintln!("Waiting for receiver to connect...");

    // Wait for connection
    let conn = endpoint
        .accept()
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No incoming connection.\n\n\
                 Troubleshooting:\n  \
                 - Ensure the receiver has the correct wormhole code\n  \
                 - Check network connectivity on both ends\n  \
                 - Try Tor mode for better NAT traversal: wormhole-rs send-tor <file>"
            )
        })?
        .await
        .map_err(|e| {
            let err_str = e.to_string().to_lowercase();
            let is_relay_error = err_str.contains("relay")
                || err_str.contains("alpn")
                || err_str.contains("no route")
                || err_str.contains("unreachable");

            if is_relay_error {
                anyhow::anyhow!(
                    "Failed to accept connection: {}\n\n\
                     Relay connection failed. Try Tor mode instead:\n  \
                     wormhole-rs send-tor <file>",
                    e
                )
            } else {
                anyhow::anyhow!(
                    "Failed to accept connection: {}\n\n\
                     Troubleshooting:\n  \
                     - Ensure the receiver has the correct wormhole code\n  \
                     - Check network connectivity and firewall settings\n  \
                     - If issues persist, try Tor mode: wormhole-rs send-tor <file>",
                    e
                )
            }
        })?;

    let remote_id = conn.remote_id();
    eprintln!("Receiver connected!");
    eprintln!("   Remote ID: {}", remote_id);

    // Get connection type (Direct, Relay, Mixed, None)
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        eprintln!("   Connection: {:?}", conn_type);
    }

    // Open bi-directional stream
    let (mut send_stream, mut recv_stream) =
        conn.open_bi().await.context("Failed to open stream")?;

    // Create header and run unified transfer logic
    let header = FileHeader::new(transfer_type, filename, file_size, checksum);
    let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);

    let result = run_sender_transfer(&mut file, &mut duplex, &key, &header).await?;

    if result == TransferResult::Aborted {
        conn.close(0u32.into(), b"cancelled");
        endpoint.close().await;
        anyhow::bail!("Transfer cancelled by receiver");
    }

    // Finish the send stream to signal we're done sending (QUIC-specific)
    send_stream.finish().context("Failed to finish stream")?;

    // Close connection gracefully
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    eprintln!("Connection closed.");

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
        prepared.checksum,
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
    let cleanup_handler = setup_temp_file_cleanup_handler(temp_path.clone());

    // Run transfer with interrupt handling
    let result = tokio::select! {
        result = transfer_data_internal(
            prepared.file,
            prepared.filename,
            prepared.file_size,
            prepared.checksum, // 0 for folders (not resumable)
            TransferType::Folder,
            relay_urls,
            use_pin,
        ) => result,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - clean up and return Interrupted error
            cleanup_handler.cleanup_path.lock().await.take();
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(Interrupted.into());
        }
    };

    // Clear cleanup path (transfer succeeded or failed, temp file handled)
    cleanup_handler.cleanup_path.lock().await.take();

    // Temp file is automatically cleaned up when NamedTempFile (prepared.temp_file) is dropped

    result
}
