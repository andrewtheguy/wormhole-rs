use arti_client::{TorClient, TorClientConfig};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <onion_address.onion>", args[0]);
        std::process::exit(1);
    }

    let onion_addr = &args[1];

    println!("Bootstrapping Tor client...");

    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await?;

    println!("Tor client bootstrapped!");
    println!("Connecting to {}...", onion_addr);

    // Connect to onion service on port 80 (default)
    let mut stream = tor_client.connect((onion_addr.as_str(), 80)).await?;

    println!("Connected!");

    // Read message
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;

    let message = String::from_utf8_lossy(&buffer);
    println!("\n=== RECEIVED MESSAGE ===");
    println!("{}", message);

    Ok(())
}
