//! mDNS transport sender - advertises file transfer via mDNS.
//!
//! This module provides file/folder sending over local network using mDNS
//! for peer discovery and passphrase-based encryption.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::auth::spake2::handshake_as_responder;
use crate::cli::instructions::print_receiver_command;
use crate::core::transfer::{
    format_bytes, handle_receiver_response, prepare_file_for_send, prepare_folder_for_send,
    recv_control, send_encrypted_header, send_file_data, ControlSignal, FileHeader,
    ResumeResponse, TransferType,
};
use crate::mdns::common::{
    generate_pin, generate_transfer_id, PORT_RANGE_END, PORT_RANGE_START, SERVICE_TYPE,
    TXT_FILENAME, TXT_FILE_SIZE, TXT_TRANSFER_ID, TXT_TRANSFER_TYPE,
};

/// Display receiver instructions and PIN to the user.
fn display_receiver_instructions(pin: &str) {
    print_receiver_command("wormhole-rs receive-local");
    eprintln!("PIN: {}", pin);
    eprintln!("Then enter the PIN above when prompted.");
}

/// Find an available TCP port in the configured range.
/// Binds to [::] for dual-stack (IPv4 + IPv6) support.
/// Starts at a random port within the range for unpredictability.
fn find_available_port() -> Result<TcpListener> {
    use rand::Rng;
    let range_size = PORT_RANGE_END - PORT_RANGE_START + 1;
    let start_offset: u16 = rand::thread_rng().gen_range(0..range_size);

    for i in 0..range_size {
        let port = PORT_RANGE_START + ((start_offset + i) % range_size);
        // Try IPv6 dual-stack first (accepts both IPv4 and IPv6)
        if let Ok(listener) = TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port)) {
            return Ok(listener);
        }
        // Fallback to IPv4 only if IPv6 not available
        if let Ok(listener) = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)) {
            return Ok(listener);
        }
    }
    anyhow::bail!(
        "No available ports in range {}-{}",
        PORT_RANGE_START,
        PORT_RANGE_END
    )
}

/// Send a file via mDNS transport.
///
/// Advertises the file via mDNS and waits for a receiver to connect.
/// Generates a random passphrase and displays it to the user.
/// The file is encrypted using a key derived from the passphrase.
pub async fn send_file_mdns(file_path: &Path) -> Result<()> {
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Generate random PIN (key will be derived via SPAKE2 handshake)
    let pin = generate_pin();
    display_receiver_instructions(&pin);

    transfer_data_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        prepared.checksum,
        TransferType::File,
        pin,
    )
    .await
}

/// Send a folder as a tar archive via mDNS transport.
///
/// Creates a tar archive of the folder, advertises via mDNS, and waits for
/// a receiver to connect. Generates a random passphrase and displays it.
/// The archive is encrypted using a key derived from the passphrase.
pub async fn send_folder_mdns(folder_path: &Path) -> Result<()> {
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler for temp file
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_path: Arc<Mutex<Option<std::path::PathBuf>>> =
        Arc::new(Mutex::new(Some(temp_path)));
    setup_cleanup_handler(cleanup_path.clone());

    // Generate random PIN (key will be derived via SPAKE2 handshake)
    let pin = generate_pin();
    display_receiver_instructions(&pin);

    let result = transfer_data_internal(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        0, // Folders are not resumable
        TransferType::Folder,
        pin,
    )
    .await;

    // Clear cleanup path (file will be dropped with temp_file)
    cleanup_path.lock().await.take();

    result
}

/// Internal transfer logic shared between file and folder sends.
async fn transfer_data_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
    pin: String,
) -> Result<()> {
    // Generate transfer ID
    let transfer_id = generate_transfer_id();

    // Start TCP listener
    let listener = find_available_port()?;
    let port = listener.local_addr()?.port();
    eprintln!("Listening on TCP port {}", port);

    // Generate random hostname for mDNS (don't expose real hostname)
    let random_host = format!("wormhole-{}", &transfer_id[..8]);
    let instance_name = random_host.clone();

    // Create mDNS service daemon
    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;

    // Build TXT records (no salt needed - key derived via SPAKE2)
    let mut properties = HashMap::new();
    properties.insert(TXT_TRANSFER_ID.to_string(), transfer_id.clone());
    properties.insert(TXT_FILENAME.to_string(), filename.clone());
    properties.insert(TXT_FILE_SIZE.to_string(), file_size.to_string());
    properties.insert(
        TXT_TRANSFER_TYPE.to_string(),
        match transfer_type {
            TransferType::File => "file".to_string(),
            TransferType::Folder => "folder".to_string(),
        },
    );

    // Register service with auto address discovery
    let my_hostname = format!("{}.local.", random_host);
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &my_hostname,
        (),
        port,
        properties,
    )
    .context("Failed to create service info")?
    .enable_addr_auto();

    let fullname = service_info.get_fullname().to_string();
    mdns.register(service_info)
        .context("Failed to register mDNS service")?;

    eprintln!("mDNS service registered: {}", instance_name);
    eprintln!("Transfer ID: {}", transfer_id);
    eprintln!("Filename: {}", filename);
    eprintln!("Size: {}", format_bytes(file_size));
    eprintln!("Waiting for receiver to connect...");

    // Accept connection (using tokio's TcpListener for async)
    // We need to convert std TcpListener to tokio TcpListener
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;

    // Loop to handle invalid connections gracefully
    loop {
        let (mut stream, peer_addr) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;

        eprintln!("Connection from: {}", peer_addr);

        use tokio::time::timeout;

        // Perform SPAKE2 handshake (includes transfer ID validation)
        // Wait up to 10 seconds for handshake
        let handshake_result = timeout(
            std::time::Duration::from_secs(10),
            handshake_as_responder(&mut stream, &pin, &transfer_id),
        )
        .await;

        match handshake_result {
            Ok(Ok(key)) => {
                eprintln!("SPAKE2 handshake successful with: {}", peer_addr);
                // Send data over TCP using SPAKE2-derived key
                send_data_over_tcp(
                    stream,
                    &mut file,
                    filename.clone(),
                    file_size,
                    checksum,
                    transfer_type,
                    &key,
                )
                .await?;
                break;
            }
            Ok(Err(e)) => {
                eprintln!("SPAKE2 handshake failed from {}: {}", peer_addr, e);
                drop(stream);
                continue;
            }
            Err(_) => {
                eprintln!("Handshake timeout from {}, closing connection", peer_addr);
                drop(stream);
                continue;
            }
        }
    }

    // Unregister service
    let _ = mdns.unregister(&fullname);
    let _ = mdns.shutdown();

    eprintln!("Transfer complete!");
    Ok(())
}

/// Send encrypted file data over TCP stream.
async fn send_data_over_tcp(
    mut stream: TcpStream,
    file: &mut File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
    key: &[u8; 32],
) -> Result<()> {
    // Send encrypted header with checksum
    let header = FileHeader::new(transfer_type, filename, file_size, checksum);
    send_encrypted_header(&mut stream, key, &header)
        .await
        .context("Failed to send header")?;

    eprintln!("Sent file header");

    // Wait for receiver confirmation before sending data
    eprintln!("Waiting for receiver to confirm...");
    let response = handle_receiver_response(&mut stream, key).await?;

    let start_offset = match response {
        ResumeResponse::Fresh => {
            eprintln!("Receiver ready, starting transfer...");
            0
        }
        ResumeResponse::Resume { offset, .. } => {
            eprintln!(
                "Resuming transfer from {} ({:.1}%)...",
                format_bytes(offset),
                offset as f64 / file_size as f64 * 100.0
            );
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            offset
        }
        ResumeResponse::Aborted => {
            eprintln!("Receiver declined transfer");
            anyhow::bail!("Transfer cancelled by receiver");
        }
    };

    // Send file data using shared component
    send_file_data(&mut stream, file, key, file_size, start_offset, 10).await?;

    eprintln!("\nAll data sent!");

    // Wait for encrypted ACK with timeout (same as handshake timeout)
    eprintln!("Waiting for receiver confirmation...");
    use tokio::time::timeout;

    let ack_result = timeout(
        std::time::Duration::from_secs(10),
        recv_control(&mut stream, key),
    )
    .await;

    match ack_result {
        Ok(Ok(ControlSignal::Ack)) => {
            eprintln!("Receiver confirmed!");
        }
        Ok(Ok(_)) => {
            anyhow::bail!("Unexpected control signal, expected ACK");
        }
        Ok(Err(e)) => {
            return Err(e).context("Failed to receive ACK from receiver");
        }
        Err(_) => {
            anyhow::bail!("Timed out waiting for receiver confirmation (10s)");
        }
    }

    Ok(())
}

/// Set up Ctrl+C handler for cleanup.
fn setup_cleanup_handler(cleanup_path: Arc<Mutex<Option<std::path::PathBuf>>>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_file(&path).await;
                log::error!("Interrupted. Cleaned up temp file.");
            }
            std::process::exit(130);
        }
    });
}
