//! wormhole-rs-webrtc: WebRTC transport for peer-to-peer file transfer
//!
//! This crate provides file transfer using WebRTC data channels with
//! Nostr relays for signaling. It supports both online (Nostr) and
//! offline (copy/paste) signaling modes.
//!
//! Build with: cargo build -p wormhole-rs-webrtc

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

mod signaling;
mod webrtc;

#[derive(Parser)]
#[command(name = "wormhole-rs-webrtc")]
#[command(about = "Secure file transfer using WebRTC for peer-to-peer connectivity")]
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
    /// Send a file using WebRTC transport
    Send {
        /// Path to file or folder to send
        path: PathBuf,

        /// Use default Nostr relays instead of auto-discovery
        #[arg(long)]
        default_relays: bool,

        /// Custom Nostr relay URLs (can be specified multiple times)
        #[arg(long, value_name = "URL")]
        relay: Vec<String>,

        /// Use PIN-based code exchange (easier to share verbally)
        #[arg(long)]
        pin: bool,

        /// Use manual signaling (copy/paste) instead of Nostr
        #[arg(long)]
        manual_signaling: bool,
    },

    /// Receive a file using WebRTC transport
    Receive {
        /// Wormhole code from sender (will prompt if not provided)
        code: Option<String>,

        /// Output directory (defaults to current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable resumable transfers (don't save partial downloads)
        #[arg(long)]
        no_resume: bool,

        /// Use PIN-based code exchange (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Use manual signaling (copy/paste) instead of Nostr
        #[arg(long)]
        manual_signaling: bool,
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
            pin,
            manual_signaling,
        } => {
            let custom_relays = if relay.is_empty() { None } else { Some(relay) };

            if path.is_dir() {
                webrtc::send_folder_webrtc(
                    &path,
                    custom_relays,
                    default_relays,
                    pin,
                    manual_signaling,
                )
                .await?;
            } else {
                webrtc::send_file_webrtc(
                    &path,
                    custom_relays,
                    default_relays,
                    pin,
                    manual_signaling,
                )
                .await?;
            }
        }

        Commands::Receive {
            code,
            output,
            no_resume,
            pin,
            manual_signaling,
        } => {
            if manual_signaling {
                // Use offline receiver
                webrtc::receive_file_offline(output, no_resume).await?;
            } else {
                // Get wormhole code from PIN, argument, or prompt
                let code = if pin {
                    // Use PIN-based code lookup
                    let pin_str = wormhole_common::auth::pin::prompt_pin()?;
                    eprintln!("Looking up wormhole code via PIN...");
                    wormhole_common::auth::nostr_pin::fetch_wormhole_code_via_pin(&pin_str).await?
                } else if let Some(c) = code {
                    c
                } else {
                    // Prompt for wormhole code
                    print!("Enter wormhole code: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                };

                if code.is_empty() {
                    anyhow::bail!("Wormhole code is required");
                }

                webrtc::receive_webrtc(&code, output, no_resume).await?;
            }
        }
    }

    Ok(())
}
