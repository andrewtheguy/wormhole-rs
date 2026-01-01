use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    // Create a temporary directory for ephemeral state (new keys each run)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    log::info!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    log::info!("Tor client bootstrapped!");

    // Generate a random nickname for truly ephemeral service (new address each time)
    let random_suffix: u64 = rand::thread_rng().r#gen();
    let nickname = format!("wh_{:016x}", random_suffix);

    // Configure onion service with random nickname
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse()?)
        .build()?;

    // Launch service - returns Option<(RunningOnionService, Stream<RendRequest>)>
    let (onion_service, rend_requests) = tor_client
        .launch_onion_service(hs_config)?
        .ok_or_else(|| anyhow::anyhow!("Failed to launch onion service"))?;

    // Get .onion address
    let onion_addr = onion_service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("No onion address available yet"))?;

    log::info!("\n=== ONION SERVICE READY ===");
    // Display the full .onion address
    log::info!("Address: {}", onion_addr.display_unredacted());
    log::info!("Waiting for receiver...\n");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Single-connection demo: This example accepts one connection and exits.
    // For a production server, wrap this in `while let Some(...) = stream_requests.next().await`
    // to handle multiple sequential connections.
    if let Some(stream_req) = stream_requests.next().await {
        log::info!("Receiver connected! Accepting stream...");

        // Accept the stream request
        let mut stream = stream_req.accept(Connected::new_empty()).await?;

        // Send test message with length prefix
        let message = b"Hello from onion service!";
        let len = message.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(message).await?;
        stream.flush().await?;

        log::info!("Message sent! Waiting for receiver to close connection...");

        // Wait for receiver to close their end (read will return 0 bytes when closed)
        let mut buf = [0u8; 1];
        match stream.read(&mut buf).await {
            Ok(0) => log::info!("Connection closed normally."),
            Ok(_) => log::info!("Received unexpected data before close."),
            Err(e) => log::error!("Read error while waiting for close: {}", e),
        }

        log::info!("Done!");
    }

    Ok(())
}
