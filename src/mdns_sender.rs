//! mDNS transport sender - advertises file transfer via mDNS.
//!
//! This module provides file/folder sending over local network using mDNS
//! for peer discovery and passphrase-based encryption.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::crypto::CHUNK_SIZE;
use crate::folder::{create_tar_archive, print_tar_creation_info, TarArchive};
use crate::mdns_common::{
    derive_key_from_passphrase, generate_passphrase, generate_transfer_id, PORT_RANGE_END,
    PORT_RANGE_START, SERVICE_TYPE, TXT_FILENAME, TXT_FILE_SIZE, TXT_TRANSFER_ID,
    TXT_TRANSFER_TYPE,
};
use crate::transfer::{
    format_bytes, num_chunks, send_encrypted_chunk, send_encrypted_header, FileHeader,
    TransferType,
};

/// Find an available TCP port in the configured range.
/// Binds to [::] for dual-stack (IPv4 + IPv6) support.
fn find_available_port() -> Result<TcpListener> {
    for port in PORT_RANGE_START..=PORT_RANGE_END {
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

    println!("Preparing to send: {} ({})", filename, format_bytes(file_size));

    // Generate random passphrase
    let passphrase = generate_passphrase();
    println!("\nPassphrase: {}\n", passphrase);
    println!("Share this passphrase with the receiver.\n");

    // Derive encryption key from passphrase
    let key = derive_key_from_passphrase(&passphrase)?;

    // Open file
    let file = File::open(file_path)
        .await
        .context("Failed to open file")?;

    // Transfer using common logic
    transfer_data_internal(file, filename, file_size, TransferType::File, key).await
}

/// Send a folder as a tar archive via mDNS transport.
///
/// Creates a tar archive of the folder, advertises via mDNS, and waits for
/// a receiver to connect. Generates a random passphrase and displays it.
/// The archive is encrypted using a key derived from the passphrase.
pub async fn send_folder_mdns(folder_path: &Path) -> Result<()> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("Creating tar archive of: {}", folder_name);
    print_tar_creation_info();

    // Create tar archive (blocking operation)
    let folder_path_owned = folder_path.to_owned();
    let tar_archive: TarArchive =
        tokio::task::spawn_blocking(move || create_tar_archive(&folder_path_owned))
            .await
            .context("Failed to spawn blocking task")??;

    let tar_filename = tar_archive.filename;
    let file_size = tar_archive.file_size;
    let temp_path = tar_archive.temp_file.path().to_path_buf();

    // Set up cleanup handler for temp file
    let cleanup_path: Arc<Mutex<Option<std::path::PathBuf>>> =
        Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_cleanup_handler(cleanup_path.clone());

    println!(
        "Archive created: {} ({})",
        tar_filename,
        format_bytes(file_size)
    );

    // Generate random passphrase
    let passphrase = generate_passphrase();
    println!("\nPassphrase: {}\n", passphrase);
    println!("Share this passphrase with the receiver.\n");

    // Derive encryption key from passphrase
    let key = derive_key_from_passphrase(&passphrase)?;

    // Open tar file
    let file = File::open(&temp_path)
        .await
        .context("Failed to open tar file")?;

    // Transfer
    let result = transfer_data_internal(file, tar_filename, file_size, TransferType::Folder, key).await;

    // Clear cleanup path (file will be dropped with temp_file)
    cleanup_path.lock().await.take();

    result
}

/// Internal transfer logic shared between file and folder sends.
async fn transfer_data_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    key: [u8; 32],
) -> Result<()> {
    // Generate transfer ID
    let transfer_id = generate_transfer_id();

    // Start TCP listener
    let listener = find_available_port()?;
    let port = listener.local_addr()?.port();
    println!("Listening on TCP port {}", port);

    // Generate random hostname for mDNS (don't expose real hostname)
    let random_host = format!("wormhole-{}", &transfer_id[..8]);
    let instance_name = random_host.clone();

    // Create mDNS service daemon
    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;

    // Build TXT records
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

    println!("\nmDNS service registered: {}", instance_name);
    println!("Transfer ID: {}", transfer_id);
    println!("Filename: {}", filename);
    println!("Size: {}", format_bytes(file_size));
    println!("\nWaiting for receiver to connect...");
    println!("Receiver should run: wormhole-rs receive --transport mdns\n");

    // Accept connection (using tokio's TcpListener for async)
    // We need to convert std TcpListener to tokio TcpListener
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;

    let (stream, peer_addr) = listener
        .accept()
        .await
        .context("Failed to accept connection")?;

    println!("Receiver connected from: {}", peer_addr);

    // Send data over TCP
    send_data_over_tcp(stream, &mut file, filename, file_size, transfer_type, &key).await?;

    // Unregister service
    let _ = mdns.unregister(&fullname);
    let _ = mdns.shutdown();

    println!("Transfer complete!");
    Ok(())
}

/// Send encrypted file data over TCP stream.
async fn send_data_over_tcp(
    mut stream: TcpStream,
    file: &mut File,
    filename: String,
    file_size: u64,
    transfer_type: TransferType,
    key: &[u8; 32],
) -> Result<()> {
    // Send encrypted header (chunk_num = 0)
    let header = FileHeader::new(transfer_type, filename, file_size);
    send_encrypted_header(&mut stream, key, &header)
        .await
        .context("Failed to send header")?;

    println!("Sent file header");

    // Send chunks
    let total_chunks = num_chunks(file_size);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_num = 1u64;
    let mut bytes_sent = 0u64;

    println!("Sending {} chunks...", total_chunks);

    loop {
        let bytes_read = file.read(&mut buffer).await.context("Failed to read data")?;
        if bytes_read == 0 {
            break;
        }

        // Send encrypted chunk
        send_encrypted_chunk(&mut stream, key, chunk_num, &buffer[..bytes_read])
            .await
            .context("Failed to send chunk")?;

        chunk_num += 1;
        bytes_sent += bytes_read as u64;

        // Progress update
        if chunk_num % 10 == 0 || bytes_sent == file_size {
            let percent = if file_size == 0 {
                100
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

    println!("\nAll data sent!");

    // Wait for ACK
    println!("Waiting for receiver confirmation...");
    let mut ack_buf = [0u8; 3];
    use tokio::io::AsyncReadExt;
    stream
        .read_exact(&mut ack_buf)
        .await
        .context("Failed to receive ACK")?;

    if &ack_buf != b"ACK" {
        anyhow::bail!("Invalid acknowledgment from receiver");
    }

    println!("Receiver confirmed!");
    Ok(())
}

/// Set up Ctrl+C handler for cleanup.
fn setup_cleanup_handler(cleanup_path: Arc<Mutex<Option<std::path::PathBuf>>>) {
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
