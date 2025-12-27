use arti_client::{config::TorClientConfigBuilder, ErrorKind, HasKind, TorClient};
use std::io::Write;
use tokio::io::AsyncReadExt;

const MAX_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 5;
/// Maximum allowed message length (4 MB) to prevent malicious allocation attacks
const MAX_MSG_LEN: usize = 4 * 1024 * 1024;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        log::error!("Usage: {} <onion_address.onion>", args[0]);
        std::process::exit(1);
    }

    let onion_addr = &args[1];

    // Create a temporary directory for ephemeral state (avoids conflicts with concurrent instances)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    log::info!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    log::info!("Tor client bootstrapped!");

    // Retry connection only for temporary errors
    let mut stream = None;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        log::info!(
            "Connecting to {} (attempt {}/{})...",
            onion_addr,
            attempt,
            MAX_RETRIES
        );

        match tor_client.connect((onion_addr.as_str(), 80)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                log::error!("Connection failed: {}", e);

                // Only retry on temporary/retryable errors
                if !is_retryable(&e) {
                    return Err(e.into());
                }

                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    log::info!("Retrying in {} seconds...", RETRY_DELAY_SECS);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }

    let mut stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect after {} attempts: {}",
            MAX_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;

    log::info!("Connected!");

    // Read length prefix (4 bytes, big-endian u32)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message length to prevent malicious allocation attacks
    if len == 0 {
        anyhow::bail!("Invalid message: length is zero");
    }
    if len > MAX_MSG_LEN {
        anyhow::bail!(
            "Message too large: {} bytes exceeds maximum of {} bytes",
            len,
            MAX_MSG_LEN
        );
    }

    // Read exact message bytes
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await?;

    let message = String::from_utf8_lossy(&buffer);
    log::info!("\n=== RECEIVED MESSAGE ===");
    log::info!("{}", message);

    Ok(())
}
