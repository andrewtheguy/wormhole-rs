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
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::spake2::handshake_as_initiator;
use crate::core::folder::{
    extract_tar_archive_returning_reader, get_extraction_dir, print_skipped_entries,
    print_tar_extraction_info, StreamingReader,
};
use crate::core::transfer::{
    finalize_file_receiver, format_bytes, format_resume_progress, num_chunks,
    prepare_file_receiver, receive_file_data, recv_encrypted_header, send_abort, send_ack,
    send_proceed, send_resume, setup_resumable_cleanup_handler, ControlSignal, TransferType,
};
use crate::mdns::common::{
    MdnsServiceInfo, SERVICE_TYPE, TXT_FILENAME, TXT_FILE_SIZE, TXT_TRANSFER_ID, TXT_TRANSFER_TYPE,
};

/// Timeout for mDNS browsing (seconds)
const BROWSE_TIMEOUT_SECS: u64 = 30;

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

        // Stop early if we found at least one sender with routable addresses
        let has_routable_service = services.values().any(|s| !s.addresses.is_empty());
        if has_routable_service && browse_start.elapsed() > Duration::from_secs(5) {
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
                    let all_addrs: Vec<IpAddr> = info
                        .get_addresses()
                        .iter()
                        .map(|s| s.to_ip_addr())
                        .collect();
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
                            let mut merged: HashSet<IpAddr> =
                                existing.addresses.iter().cloned().collect();
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
                            let addrs: Vec<_> = service_info
                                .addresses
                                .iter()
                                .map(|a| a.to_string())
                                .collect();
                            let addr_str = if addrs.is_empty() {
                                "discovering...".to_string()
                            } else {
                                addrs.join(", ")
                            };
                            // For folders, show the original folder name (strip .tar extension)
                            let display_name = if service_info.transfer_type == "folder" {
                                service_info
                                    .filename
                                    .strip_suffix(".tar")
                                    .unwrap_or(&service_info.filename)
                            } else {
                                &service_info.filename
                            };
                            println!(
                                "Found sender: {} ({}) - {} ({}, {})",
                                service_info.hostname.trim_end_matches('.'),
                                addr_str,
                                display_name,
                                service_info.transfer_type,
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
        println!("Make sure the sender is running: wormhole-rs send-local <path>");
        return Ok(());
    }

    println!("\n--- Available Senders ---");
    let service_list: Vec<_> = services.values().collect();
    for (i, service) in service_list.iter().enumerate() {
        let addrs: Vec<_> = service.addresses.iter().map(|a| a.to_string()).collect();
        let addr_str = if addrs.is_empty() {
            "no routable addr".to_string()
        } else {
            addrs.join(", ")
        };
        // For folders, show the original folder name (strip .tar extension)
        let display_name = if service.transfer_type == "folder" {
            service
                .filename
                .strip_suffix(".tar")
                .unwrap_or(&service.filename)
        } else {
            &service.filename
        };
        println!(
            "[{}] {} - {} ({}) from {} ({})",
            i + 1,
            display_name,
            format_bytes(service.file_size),
            service.transfer_type,
            service.hostname.trim_end_matches('.'),
            addr_str,
        );
    }

    // Prompt user to select
    let selection = match prompt_selection(service_list.len())? {
        Some(idx) => idx,
        None => {
            println!("Cancelled.");
            return Ok(());
        }
    };
    let selected = service_list[selection].clone();

    println!("\nSelected: {}", selected.filename);

    // Prompt for PIN
    let pin = prompt_pin()?;

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

    println!("Connected! Performing SPAKE2 key exchange...");

    // Perform SPAKE2 handshake to derive encryption key
    let key = handshake_as_initiator(&mut stream, &pin, &selected.transfer_id)
        .await
        .context("SPAKE2 handshake failed - wrong PIN?")?;

    println!("Key exchange successful!");

    // Receive file using SPAKE2-derived key
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

    // Determine output directory
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    // Dispatch based on transfer type
    match header.transfer_type {
        TransferType::File => {
            let final_output_path = output_dir.join(&header.filename);

            // Use shared file receiver component (resume enabled by default for mDNS)
            let (mut receiver, control_signal) =
                prepare_file_receiver(&final_output_path, &header, false)?;

            // Set up cleanup handler (resumable if checksum is present)
            let is_resumable = header.checksum != 0;
            let cleanup_path =
                setup_resumable_cleanup_handler(receiver.temp_path.clone(), is_resumable);

            // Send appropriate control signal to sender
            match &control_signal {
                ControlSignal::Proceed => {
                    send_proceed(&mut stream, key)
                        .await
                        .context("Failed to send proceed signal")?;
                    println!("Ready to receive data...");
                }
                ControlSignal::Resume(offset) => {
                    send_resume(&mut stream, key, *offset)
                        .await
                        .context("Failed to send resume signal")?;
                    println!("{}", format_resume_progress(*offset, header.file_size));
                }
                ControlSignal::Abort => {
                    send_abort(&mut stream, key)
                        .await
                        .context("Failed to send abort signal")?;
                    anyhow::bail!("Transfer cancelled by user");
                }
                // prepare_file_receiver only returns Proceed or Resume, but handle other variants defensively
                other => anyhow::bail!("Unexpected control signal from prepare_file_receiver: {:?}", other),
            }

            // Receive file data using shared component
            receive_file_data(&mut stream, &mut receiver, key, header.file_size, 10, 100).await?;

            // Clear cleanup and finalize
            cleanup_path.lock().await.take();
            finalize_file_receiver(receiver)?;

            println!("\nFile received successfully!");
        }
        TransferType::Folder => {
            // Folders are not resumable - always send proceed
            send_proceed(&mut stream, key)
                .await
                .context("Failed to send proceed signal")?;
            println!("Ready to receive data...");

            // Folder impl takes ownership and returns stream after extraction
            let stream = receive_folder_impl(
                stream,
                &header.filename,
                header.file_size,
                key,
                Some(output_dir),
            )
            .await?;

            // Send encrypted ACK
            let mut stream = stream;
            send_ack(&mut stream, key)
                .await
                .context("Failed to send ACK")?;
            println!("Sent confirmation to sender");
            return Ok(());
        }
    }

    // Send encrypted ACK for file transfers
    send_ack(&mut stream, key)
        .await
        .context("Failed to send ACK")?;
    println!("Sent confirmation to sender");

    Ok(())
}


/// Receive a folder implementation (streams directly to tar extractor).
/// Takes ownership of stream and returns it after extraction for ACK.
async fn receive_folder_impl(
    stream: TcpStream,
    filename: &str,
    file_size: u64,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<TcpStream> {
    println!(
        "Receiving folder archive: {} ({})",
        filename,
        format_bytes(file_size)
    );

    let extract_dir = get_extraction_dir(output_dir);
    std::fs::create_dir_all(&extract_dir)?;

    let cleanup_path: ExtractDirCleanup = Arc::new(Mutex::new(Some(extract_dir.clone())));
    let cleanup_cancel = CancellationToken::new();
    let _cleanup_handle = setup_dir_cleanup_handler(cleanup_path.clone(), cleanup_cancel.clone());

    println!("Extracting to: {}", extract_dir.display());
    print_tar_extraction_info();

    let total_chunks = num_chunks(file_size);
    println!(
        "Receiving {} chunks (streaming to extractor)...",
        total_chunks
    );

    // Get runtime handle for blocking in StreamingReader
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader that feeds tar extractor directly
    let reader = StreamingReader::new(stream, *key, file_size, runtime_handle);

    // Run tar extraction in blocking context, returning reader for ACK
    let extract_dir_clone = extract_dir.clone();
    let (skipped, reader) = tokio::task::spawn_blocking(move || {
        extract_tar_archive_returning_reader(reader, &extract_dir_clone)
    })
    .await
    .context("Extraction task panicked")??;

    // Get stream back from reader
    let stream = reader.into_inner();

    print_skipped_entries(&skipped);
    cleanup_path.lock().await.take();
    cleanup_cancel.cancel();

    println!("\nFolder received successfully!");
    println!("Extracted to: {}", extract_dir.display());

    Ok(stream)
}

/// Prompt user to select a sender.
fn prompt_selection(max: usize) -> Result<Option<usize>> {
    loop {
        print!("\nSelect sender [1-{}] or 'q' to quit: ", max);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("q") {
            return Ok(None);
        }

        match input.parse::<usize>() {
            Ok(selection) if selection >= 1 && selection <= max => {
                return Ok(Some(selection - 1));
            }
            _ => {
                println!(
                    "Invalid selection. Please enter a number between 1 and {}, or 'q' to quit.",
                    max
                );
            }
        }
    }
}

/// Prompt user for PIN with checksum validation.
fn prompt_pin() -> Result<String> {
    crate::auth::pin::prompt_pin().context("Failed to read PIN")
}

/// Set up Ctrl+C handler for extraction directory cleanup.
///
/// Returns a JoinHandle that can be aborted when cleanup is no longer needed.
/// The handler uses select! to race between Ctrl+C and cancellation.
/// On Ctrl+C: cleans up the extraction directory and returns (does not exit).
/// On cancellation: returns immediately without cleanup.
fn setup_dir_cleanup_handler(
    cleanup_path: ExtractDirCleanup,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                // Cancelled by caller - cleanup no longer needed
            }
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    if let Some(path) = cleanup_path.lock().await.take() {
                        let _ = tokio::fs::remove_dir_all(&path).await;
                        eprintln!("\nInterrupted. Cleaned up extraction directory.");
                    }
                }
            }
        }
    })
}
