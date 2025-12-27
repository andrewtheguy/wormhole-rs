use anyhow::{Context, Result};
use iroh::Watcher;
use std::path::PathBuf;

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
        let err_str = e.to_string().to_lowercase();
        let is_relay_error = err_str.contains("relay")
            || err_str.contains("alpn")
            || err_str.contains("no route")
            || err_str.contains("unreachable");

        if is_relay_error {
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

    // Close connection gracefully
    conn.closed().await;
    endpoint.close().await;

    eprintln!("Connection closed.");

    Ok(())
}
