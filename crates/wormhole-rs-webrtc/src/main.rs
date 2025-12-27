//! wormhole-rs-webrtc: ICE transport for NAT traversal
//!
//! This crate provides file transfer using ICE (Interactive Connectivity Establishment)
//! for NAT traversal, with Nostr relays for signaling.
//!
//! Build with: cargo build -p wormhole-rs-webrtc

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod ice;

// Legacy WebRTC modules (not used by ICE transport)
// mod signaling;
// mod webrtc;

#[derive(Parser)]
#[command(name = "wormhole-rs-webrtc")]
#[command(about = "Secure file transfer using ICE for NAT traversal")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Use verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file using ICE transport
    Send {
        /// Path to file or folder to send
        path: PathBuf,

        /// Use default Nostr relays instead of auto-discovery
        #[arg(long)]
        default_relays: bool,

        /// Custom Nostr relay URLs (can be specified multiple times)
        #[arg(long, value_name = "URL")]
        relay: Vec<String>,
    },

    /// Receive a file using ICE transport
    Receive {
        /// Transfer ID from sender
        #[arg(long)]
        transfer_id: String,

        /// Sender's public key (hex)
        #[arg(long)]
        sender_pubkey: String,

        /// Nostr relay URL(s) to use (can be specified multiple times)
        #[arg(long, value_name = "URL")]
        relay: Vec<String>,

        /// Output directory (defaults to current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable resumable transfers (don't save partial downloads)
        #[arg(long)]
        no_resume: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match cli.command {
        Commands::Send {
            path,
            default_relays,
            relay,
        } => {
            let custom_relays = if relay.is_empty() { None } else { Some(relay) };

            if path.is_dir() {
                ice::send_folder_ice(&path, custom_relays, default_relays).await?;
            } else {
                ice::send_file_ice(&path, custom_relays, default_relays).await?;
            }
        }

        Commands::Receive {
            transfer_id,
            sender_pubkey,
            relay,
            output,
            no_resume,
        } => {
            if relay.is_empty() {
                anyhow::bail!("At least one --relay URL is required");
            }

            ice::receive_ice(&transfer_id, relay, &sender_pubkey, output, no_resume).await?;
        }
    }

    Ok(())
}
