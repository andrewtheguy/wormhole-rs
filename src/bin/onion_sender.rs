use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Bootstrapping Tor client...");

    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await?;

    println!("Tor client bootstrapped!");

    // Configure onion service
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname("wormhole_test".parse()?)
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
    // Display the full .onion address using Debug format (HsId does not implement Display directly)
    println!("Address: {:?}", onion_addr);
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
        stream.shutdown().await?;

        println!("Message sent successfully!");
    }

    Ok(())
}
