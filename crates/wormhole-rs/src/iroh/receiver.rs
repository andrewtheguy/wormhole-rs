use anyhow::{Context, Result};
use iroh::endpoint::{ConnectError, ConnectWithOptsError, ConnectingError, ConnectionError};
use iroh::Watcher;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use super::common::{create_receiver_endpoint, OwnedIrohDuplex, ALPN};
use wormhole_common::core::transfer::run_receiver_transfer;
use wormhole_common::core::wormhole::parse_code;

/// Receive a file or folder using a wormhole code.
/// Auto-detects whether it's a file or folder transfer based on the header.
pub async fn receive(
    code: &str,
    output_dir: Option<PathBuf>,
    relay_urls: Vec<String>,
    no_resume: bool,
) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;
    let key = wormhole_common::core::wormhole::decode_key(&token.key)
        .context("Failed to decode encryption key")?;
    let addr = token
        .addr
        .context("No iroh endpoint address in wormhole code")?
        .to_endpoint_addr()
        .context("Failed to parse endpoint address")?;

    eprintln!("Code valid. Connecting to sender...");

    // Create iroh endpoint
    let endpoint = create_receiver_endpoint(relay_urls).await?;

    // Connect to sender
    let conn = endpoint.connect(addr, ALPN).await.map_err(|e| {
        // Determine if this is a relay/network connectivity error by inspecting
        // the structured error types from iroh/quinn
        let is_relay_or_network_error = is_relay_or_network_error(&e);

        if is_relay_or_network_error {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Relay connection failed. Try Tor mode instead:\n  \
                 Sender:   wormhole-rs send-tor <file>\n  \
                 Receiver: wormhole-rs receive <code>",
                e
            )
        } else {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Troubleshooting:\n  \
                 - Verify the wormhole code is correct\n  \
                 - Ensure the sender is still running\n  \
                 - Check network connectivity and firewall settings\n  \
                 - If issues persist, try Tor mode: wormhole-rs send-tor <file>",
                e
            )
        }
    })?;

    // Print connection info
    let remote_id = conn.remote_id();
    eprintln!("Connected!");
    eprintln!("Remote ID: {}", remote_id);

    // Get connection type (Direct, Relay, Mixed, None)
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        eprintln!("Connection type: {:?}", conn_type);
    }

    // Accept bi-directional stream
    let (send_stream, recv_stream) = conn.accept_bi().await.context("Failed to accept stream")?;

    // Create owned duplex for unified transfer logic
    let duplex = OwnedIrohDuplex::new(send_stream, recv_stream);

    // Run unified receiver transfer
    let (_path, duplex) = run_receiver_transfer(duplex, key, output_dir, no_resume).await?;

    // Finish send stream (QUIC-specific)
    duplex
        .into_send_stream()
        .finish()
        .context("Failed to finish send stream")?;

    // Close connection gracefully with timeout to avoid hanging indefinitely
    const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

    // Initiate connection close (non-async, just signals intent to close)
    conn.close(0u32.into(), b"transfer complete");

    // Wait for the connection to fully close, with timeout
    match timeout(CLOSE_TIMEOUT, conn.closed()).await {
        Ok(_) => {}
        Err(_) => {
            log::warn!(
                "Waiting for connection close timed out after {:?}",
                CLOSE_TIMEOUT
            );
        }
    }

    // Always close the endpoint, even if connection close timed out
    match timeout(CLOSE_TIMEOUT, endpoint.close()).await {
        Ok(_) => {}
        Err(_) => {
            log::warn!("Endpoint close timed out after {:?}", CLOSE_TIMEOUT);
        }
    }

    eprintln!("Connection closed.");

    Ok(())
}

/// Determine if a connection error indicates a relay or network connectivity issue.
///
/// This function inspects the structured error types from iroh/quinn to identify
/// errors that suggest relay failures, network unreachability, or similar issues
/// where Tor mode might be a better alternative.
fn is_relay_or_network_error(e: &ConnectError) -> bool {
    // First, try to match on structured error variants
    match e {
        ConnectError::Connect { source, .. } => match source {
            ConnectWithOptsError::NoAddress { .. } => return true,
            ConnectWithOptsError::Quinn { source, .. } => {
                // Quinn's ConnectError doesn't expose network-level issues directly
                // Check if the error message indicates connection failure
                let msg = source.to_string().to_lowercase();
                if msg.contains("no route") || msg.contains("unreachable") {
                    return true;
                }
            }
            _ => {}
        },
        ConnectError::Connecting { source, .. } => match source {
            ConnectingError::ConnectionError { source, .. } => {
                return is_connection_error_network_related(source);
            }
            ConnectingError::HandshakeFailure { .. } => {
                // ALPN mismatch or handshake issues often indicate relay problems
                return true;
            }
            _ => {}
        },
        ConnectError::Connection { source, .. } => {
            return is_connection_error_network_related(source);
        }
        _ => {}
    }

    // Fallback: check error message as a last resort for cases not covered
    // by the structured matching above. This is a best-effort heuristic for
    // error conditions that iroh/quinn don't expose as distinct variants.
    let err_str = e.to_string().to_lowercase();
    err_str.contains("relay")
        || err_str.contains("no route")
        || err_str.contains("unreachable")
        || err_str.contains("network")
}

/// Check if a quinn ConnectionError indicates a network-related issue
fn is_connection_error_network_related(e: &ConnectionError) -> bool {
    match e {
        ConnectionError::TimedOut => true,
        ConnectionError::Reset => true,
        ConnectionError::TransportError(te) => {
            // Transport errors can indicate network issues
            let msg = te.to_string().to_lowercase();
            msg.contains("no route")
                || msg.contains("unreachable")
                || msg.contains("network")
                || msg.contains("connection refused")
        }
        ConnectionError::VersionMismatch => false,
        ConnectionError::ConnectionClosed(_) => false,
        ConnectionError::ApplicationClosed(_) => false,
        ConnectionError::LocallyClosed => false,
        ConnectionError::CidsExhausted => false,
    }
}
