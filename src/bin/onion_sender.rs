use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a temporary directory for ephemeral state (new keys each run)
    let temp_dir = tempfile::tempdir()?;
    let state_dir = temp_dir.path().join("state");
    let cache_dir = temp_dir.path().join("cache");

    println!("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    println!("Tor client bootstrapped!");

    // Generate a random nickname for truly ephemeral service (new address each time)
    let random_suffix: u64 = rand::thread_rng().gen();
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

    println!("\n=== ONION SERVICE READY ===");
    // Display the full .onion address
    println!("Address: {}", onion_addr.display_unredacted());
    println!("Waiting for receiver...\n");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Wait for incoming stream request
    if let Some(stream_req) = stream_requests.next().await {
        println!("Receiver connected! Accepting stream...");

        // Accept the stream request
        let mut stream = stream_req.accept(Connected::new_empty()).await?;

        // Send test message
        let message = b"Hello from onion service!";
        stream.write_all(message).await?;
        stream.flush().await?;

        println!("Message sent! Waiting for receiver to close connection...");

        // Wait for receiver to close their end (read will return 0 bytes when closed)
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf).await;

        println!("Connection closed. Done!");
    }

    Ok(())
}
