use anyhow::{Context, Result};
use arti_client::{config::TorClientConfigBuilder, ErrorKind, HasKind, TorClient};
use std::path::PathBuf;

use wormhole_common::core::transfer::run_receiver_transfer;
use wormhole_common::core::wormhole::{decode_key, parse_code, PROTOCOL_TOR};

const MAX_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 5;

/// Check if error is retryable (timeout, temporary network issues)
fn is_retryable(e: &arti_client::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::TorNetworkTimeout
            | ErrorKind::RemoteNetworkTimeout
            | ErrorKind::TransientFailure
            | ErrorKind::LocalNetworkError
    )
}

/// Receive a file via Tor hidden service
pub async fn receive_file_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    eprintln!("Parsing wormhole code...");

    // Parse the wormhole code
    let token = parse_code(code).context("Failed to parse wormhole code")?;

    // Validate protocol
    if token.protocol != PROTOCOL_TOR {
        anyhow::bail!(
            "Expected Tor protocol, got '{}'. Use the appropriate receive command.",
            token.protocol
        );
    }

    let key = decode_key(&token.key).context("Failed to decode encryption key")?;

    let onion_addr = token
        .onion_address
        .context("No onion address in wormhole code")?;

    eprintln!("Code valid. Connecting to sender via Tor...");

    // Bootstrap Tor client (ephemeral mode - allows multiple concurrent receivers)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    eprintln!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;
    eprintln!("Tor client bootstrapped!");

    // Retry connection for temporary errors
    let mut stream = None;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        eprintln!(
            "Connecting to {} (attempt {}/{})...",
            onion_addr, attempt, MAX_RETRIES
        );

        match tor_client.connect((onion_addr.as_str(), 80)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);

                if !is_retryable(&e) {
                    return Err(e.into());
                }

                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    eprintln!("Retrying in {} seconds...", RETRY_DELAY_SECS);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }

    let stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect after {} attempts: {}",
            MAX_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;

    eprintln!("Connected!");

    // Run unified receiver transfer (no resume for Tor receiver by default)
    let (_path, _stream) = run_receiver_transfer(stream, key, output_dir, false).await?;

    eprintln!("Connection closed.");

    Ok(())
}

/// Receive a file or folder via Tor (auto-detects type)
pub async fn receive_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    receive_file_tor(code, output_dir).await
}
