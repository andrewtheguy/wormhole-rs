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
use std::time::Duration;
use tokio::net::TcpStream;

use super::common::{
    MdnsServiceInfo, SERVICE_TYPE, TXT_FILENAME, TXT_FILE_SIZE, TXT_TRANSFER_ID, TXT_TRANSFER_TYPE,
};
use wormhole_common::auth::spake2::handshake_as_initiator;
use wormhole_common::core::transfer::{format_bytes, run_receiver_transfer};

/// Timeout for mDNS browsing (seconds)
const BROWSE_TIMEOUT_SECS: u64 = 30;

/// Check if an IP address is routable (usable for connections).
/// Rejects loopback, link-local, and unspecified addresses.
fn is_routable(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_unicast_link_local() && !v6.is_unspecified()
        }
    }
}

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

                    // Filter and deduplicate addresses: prefer non-loopback IPv4 and non-link-local IPv6
                    let all_addrs: Vec<IpAddr> = info
                        .get_addresses()
                        .iter()
                        .map(|s| s.to_ip_addr())
                        .collect();
                    let filtered: HashSet<IpAddr> = all_addrs
                        .into_iter()
                        .filter(|addr| match addr {
                            IpAddr::V4(v4) => !v4.is_loopback(),
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

    // Filter services to only those with routable addresses
    let service_list: Vec<_> = services
        .values()
        .filter(|s| s.addresses.iter().any(is_routable))
        .collect();

    if service_list.is_empty() {
        println!("\nFound {} sender(s) but none have routable addresses.", services.len());
        println!("This may indicate a network configuration issue.");
        return Ok(());
    }

    println!("\n--- Available Senders ---");
    for (i, service) in service_list.iter().enumerate() {
        let addrs: Vec<_> = service
            .addresses
            .iter()
            .filter(|a| is_routable(a))
            .map(|a| a.to_string())
            .collect();
        let addr_str = addrs.join(", ");
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

    // Connect to sender - use first routable address
    let addr = selected
        .addresses
        .iter()
        .find(|a| is_routable(a))
        .expect("Service was filtered to have routable addresses");
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
    stream: TcpStream,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
) -> Result<()> {
    // Run unified receiver transfer
    let (_path, _stream) = run_receiver_transfer(stream, *key, output_dir, false).await?;

    println!("Sent confirmation to sender");

    Ok(())
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
    wormhole_common::auth::pin::prompt_pin().context("Failed to read PIN")
}
