//! mDNS transport receiver - browses for available senders.
//!
//! This module provides file/folder receiving over local network using mDNS
//! for peer discovery. Users browse available senders, select one, and enter
//! a passphrase to decrypt the transfer.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::folder::{
    extract_tar_archive, get_extraction_dir, print_skipped_entries, print_tar_extraction_info,
};
use crate::mdns_common::{
    derive_key_from_passphrase, MdnsServiceInfo, SERVICE_TYPE, TXT_FILENAME, TXT_FILE_SIZE,
    TXT_TRANSFER_ID, TXT_TRANSFER_TYPE,
};
use crate::transfer::{format_bytes, num_chunks, recv_encrypted_chunk, recv_encrypted_header, TransferType};

/// Timeout for mDNS browsing (seconds)
const BROWSE_TIMEOUT_SECS: u64 = 30;

/// Shared state for temp file cleanup on interrupt
type TempFileCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Shared state for extraction directory cleanup on interrupt
type ExtractDirCleanup = Arc<Mutex<Option<PathBuf>>>;

/// Browse for available wormhole senders and let user select.
///
/// Discovers senders advertising via mDNS, displays them to the user,
/// prompts for selection and passphrase, then receives the file.
pub async fn receive_mdns(output_dir: Option<PathBuf>) -> Result<()> {
    println!("Browsing for wormhole senders on local network...\n");

    // Create mDNS daemon
    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
    let receiver = mdns
        .browse(SERVICE_TYPE)
        .context("Failed to start mDNS browsing")?;

    let mut services: HashMap<String, MdnsServiceInfo> = HashMap::new();
    let browse_start = std::time::Instant::now();

    println!(
        "Searching for senders (timeout: {}s)...\n",
        BROWSE_TIMEOUT_SECS
    );

    // Browse for services
    loop {
        // Check timeout
        if browse_start.elapsed() > Duration::from_secs(BROWSE_TIMEOUT_SECS) {
            break;
        }

        // Stop early if we found at least one sender and haven't received updates for a while
        if !services.is_empty() && browse_start.elapsed() > Duration::from_secs(5) {
            break;
        }

        // Try to receive service events with timeout
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    // Extract TXT records
                    let properties = info.get_properties();

                    let transfer_id = properties
                        .get(TXT_TRANSFER_ID)
                        .map(|v| v.val_str().to_string())
                        .unwrap_or_default();
                    let filename = properties
                        .get(TXT_FILENAME)
                        .map(|v| v.val_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let file_size: u64 = properties
                        .get(TXT_FILE_SIZE)
                        .and_then(|v| v.val_str().parse().ok())
                        .unwrap_or(0);
                    let transfer_type = properties
                        .get(TXT_TRANSFER_TYPE)
                        .map(|v| v.val_str().to_string())
                        .unwrap_or_else(|| "file".to_string());

                    // Filter and deduplicate addresses: prefer IPv4 and non-link-local IPv6
                    let all_addrs: Vec<IpAddr> = info.get_addresses().iter().map(|s| s.to_ip_addr()).collect();
                    let filtered: HashSet<IpAddr> = all_addrs
                        .into_iter()
                        .filter(|addr| match addr {
                            IpAddr::V4(_) => true,
                            IpAddr::V6(v6) => !v6.is_unicast_link_local() && !v6.is_loopback(),
                        })
                        .collect();
                    let addresses: Vec<IpAddr> = filtered.into_iter().collect();

                    let service_info = MdnsServiceInfo {
                        instance_name: info.get_fullname().to_string(),
                        hostname: info.get_hostname().to_string(),
                        port: info.get_port(),
                        transfer_id: transfer_id.clone(),
                        filename,
                        file_size,
                        transfer_type,
                        addresses,
                    };

                    if !transfer_id.is_empty() {
                        let is_new = !services.contains_key(&transfer_id);

                        // Merge addresses with existing if already known
                        let final_addresses = if let Some(existing) = services.get(&transfer_id) {
                            let mut merged: HashSet<IpAddr> = existing.addresses.iter().cloned().collect();
                            merged.extend(service_info.addresses.iter().cloned());
                            merged.into_iter().collect()
                        } else {
                            service_info.addresses.clone()
                        };

                        let service_info = MdnsServiceInfo {
                            addresses: final_addresses,
                            ..service_info
                        };

                        if is_new {
                            let addrs: Vec<_> = service_info.addresses.iter().map(|a| a.to_string()).collect();
                            let addr_str = if addrs.is_empty() { "discovering...".to_string() } else { addrs.join(", ") };
                            println!(
                                "Found sender: {} ({}) - {} ({})",
                                service_info.hostname.trim_end_matches('.'),
                                addr_str,
                                service_info.filename,
                                format_bytes(service_info.file_size)
                            );
                        }
                        services.insert(transfer_id, service_info);
                    }
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    // Remove service if it goes away
                    services.retain(|_, v| v.instance_name != fullname);
                }
                _ => {}
            },
            Err(_) => {
                // Timeout, continue browsing
            }
        }
    }

    // Stop browsing
    let _ = mdns.stop_browse(SERVICE_TYPE);
    let _ = mdns.shutdown();

    if services.is_empty() {
        println!("\nNo wormhole senders found on the network.");
        println!("Make sure the sender is running: wormhole-rs send --transport mdns <file> --passphrase <phrase>");
        return Ok(());
    }

    println!("\n--- Available Senders ---");
    let service_list: Vec<_> = services.values().collect();
    for (i, service) in service_list.iter().enumerate() {
        let addrs: Vec<_> = service.addresses.iter().map(|a| a.to_string()).collect();
        let addr_str = if addrs.is_empty() { "no routable addr".to_string() } else { addrs.join(", ") };
        println!(
            "[{}] {} - {} ({}) from {} ({})",
            i + 1,
            service.filename,
            format_bytes(service.file_size),
            service.transfer_type,
            service.hostname.trim_end_matches('.'),
            addr_str,
        );
    }

    // Prompt user to select
    let selection = prompt_selection(service_list.len())?;
    let selected = service_list[selection].clone();

    println!("\nSelected: {}", selected.filename);

    // Prompt for passphrase
    let passphrase = prompt_passphrase()?;

    // Derive key
    println!("Deriving encryption key...");
    let key = derive_key_from_passphrase(&passphrase)?;

    // Connect to sender
    let addr = selected
        .addresses
        .first()
        .context("No addresses found for sender")?;
    let socket_addr = std::net::SocketAddr::new(*addr, selected.port);

    println!("Connecting to {}...", socket_addr);
    let mut stream = TcpStream::connect(socket_addr)
        .await
        .context("Failed to connect to sender")?;

    println!("Connected!");

    // Send handshake: "WORMHOLE:<transfer_id>"
    let handshake = format!("WORMHOLE:{}", selected.transfer_id);
    use tokio::io::AsyncWriteExt;
    stream.write_all(handshake.as_bytes()).await
        .context("Failed to send handshake")?;

    // Receive file
    receive_data_over_tcp(stream, &key, output_dir).await
}

/// Receive encrypted file data over TCP.
async fn receive_data_over_tcp(
    mut stream: TcpStream,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    // Receive header
    let header = recv_encrypted_header(&mut stream, key)
        .await
        .context("Failed to receive header - wrong passphrase?")?;

    println!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    );

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            receive_file_impl(&mut stream, &header.filename, header.file_size, key, output_dir)
                .await?;
        }
        TransferType::Folder => {
            receive_folder_impl(&mut stream, &header.filename, header.file_size, key, output_dir)
                .await?;
        }
    }

    // Send ACK
    stream
        .write_all(b"ACK")
        .await
        .context("Failed to send ACK")?;
    stream.flush().await?;
    println!("Sent confirmation to sender");

    Ok(())
}

/// Receive a file implementation.
async fn receive_file_impl(
    stream: &mut TcpStream,
    filename: &str,
    file_size: u64,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(filename);

    // Check if exists
    if output_path.exists() {
        let should_overwrite = prompt_overwrite(&output_path)?;
        if !should_overwrite {
            anyhow::bail!("Transfer cancelled - file exists");
        }
        std::fs::remove_file(&output_path)?;
    }

    // Create temp file
    let temp_file = NamedTempFile::new_in(&output_dir).context("Failed to create temp file")?;
    let temp_path = temp_file.path().to_path_buf();
    let cleanup_path: TempFileCleanup = Arc::new(Mutex::new(Some(temp_path.clone())));
    setup_file_cleanup_handler(cleanup_path.clone());

    // Receive chunks
    let total_chunks = num_chunks(file_size);
    let mut chunk_num = 1u64;
    let mut bytes_received = 0u64;

    // Collect chunks to a buffer, then write to file
    let mut all_data = Vec::with_capacity(file_size as usize);

    println!("Receiving {} chunks...", total_chunks);

    while bytes_received < file_size {
        // Receive encrypted chunk
        let chunk = recv_encrypted_chunk(stream, key, chunk_num)
            .await
            .context("Failed to receive chunk - wrong passphrase?")?;

        all_data.extend_from_slice(&chunk);
        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        // Progress
        if chunk_num % 10 == 0 || bytes_received == file_size {
            let percent = if file_size == 0 {
                100
            } else {
                (bytes_received as f64 / file_size as f64 * 100.0) as u32
            };
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_received),
                format_bytes(file_size)
            );
            let _ = std::io::stdout().flush();
        }
    }

    // Write to temp file
    let temp_path_clone = temp_path.clone();
    let output_path_clone = output_path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::write(&temp_path_clone, &all_data)?;
        std::fs::rename(&temp_path_clone, &output_path_clone)?;
        Ok(())
    })
    .await
    .context("Failed to spawn blocking task")??;

    // Clear cleanup
    cleanup_path.lock().await.take();

    println!("\nFile received successfully!");
    println!("Saved to: {}", output_path.display());

    Ok(())
}

/// Receive a folder implementation.
async fn receive_folder_impl(
    stream: &mut TcpStream,
    filename: &str,
    file_size: u64,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!(
        "Receiving folder archive: {} ({})",
        filename,
        format_bytes(file_size)
    );

    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir)?;

    let cleanup_path: ExtractDirCleanup = Arc::new(Mutex::new(Some(extract_dir.clone())));
    setup_dir_cleanup_handler(cleanup_path.clone());

    println!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    // Collect all data
    let mut tar_data = Vec::with_capacity(file_size as usize);
    let mut chunk_num = 1u64;
    let mut bytes_received = 0u64;
    let total_chunks = num_chunks(file_size);

    println!("Receiving {} chunks...", total_chunks);

    while bytes_received < file_size {
        let chunk = recv_encrypted_chunk(stream, key, chunk_num)
            .await
            .context("Failed to receive chunk")?;

        tar_data.extend_from_slice(&chunk);
        chunk_num += 1;
        bytes_received += chunk.len() as u64;

        if chunk_num % 10 == 0 || bytes_received == file_size {
            let percent = if file_size == 0 {
                100
            } else {
                (bytes_received as f64 / file_size as f64 * 100.0) as u32
            };
            print!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes_received),
                format_bytes(file_size)
            );
            let _ = std::io::stdout().flush();
        }
    }

    // Extract
    let extract_dir_clone = extract_dir.clone();
    let skipped = tokio::task::spawn_blocking(move || {
        let cursor = std::io::Cursor::new(tar_data);
        extract_tar_archive(cursor, &extract_dir_clone)
    })
    .await
    .context("Failed to spawn blocking task")??;

    print_skipped_entries(&skipped);
    cleanup_path.lock().await.take();

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    Ok(())
}

/// Prompt user to select a sender.
fn prompt_selection(max: usize) -> Result<usize> {
    print!("\nSelect sender [1-{}]: ", max);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let selection: usize = input.trim().parse().context("Invalid selection")?;
    if selection < 1 || selection > max {
        anyhow::bail!("Selection out of range");
    }
    Ok(selection - 1)
}

/// Prompt user for passphrase.
fn prompt_passphrase() -> Result<String> {
    print!("Enter passphrase: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let passphrase = input.trim().to_string();
    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty");
    }
    Ok(passphrase)
}

/// Prompt user to overwrite existing file.
fn prompt_overwrite(path: &PathBuf) -> Result<bool> {
    print!("File exists: {}. Overwrite? [y/N] ", path.display());
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Set up Ctrl+C handler for temp file cleanup.
fn setup_file_cleanup_handler(cleanup_path: TempFileCleanup) {
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

/// Set up Ctrl+C handler for extraction directory cleanup.
fn setup_dir_cleanup_handler(cleanup_path: ExtractDirCleanup) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Some(path) = cleanup_path.lock().await.take() {
                let _ = tokio::fs::remove_dir_all(&path).await;
                eprintln!("\nInterrupted. Cleaned up extraction directory.");
            }
            std::process::exit(130);
        }
    });
}
