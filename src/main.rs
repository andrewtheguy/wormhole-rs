use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
#[cfg(feature = "iroh")]
use wormhole_rs::{receiver_iroh, sender_iroh};
use wormhole_rs::wormhole;

#[cfg(feature = "onion")]
use wormhole_rs::{onion_receiver, onion_sender};

#[cfg(feature = "webrtc")]
use wormhole_rs::{hybrid_receiver, hybrid_sender::{self, TransferResult}};

use wormhole_rs::{mdns_receiver, mdns_sender};

#[derive(Parser)]
#[command(name = "wormhole-rs")]
#[command(about = "Secure peer-to-peer file transfer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or folder
    Send {
        #[command(subcommand)]
        transport: SendTransport,
    },

    /// Receive a file or folder using a code
    Receive,

    /// Send via local network (mDNS discovery, passphrase encryption)
    #[command(name = "send-local")]
    SendLocal {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,
    },

    /// Receive via local network (mDNS discovery)
    #[command(name = "receive-local")]
    ReceiveLocal {
        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Send transport options
#[derive(Subcommand)]
enum SendTransport {
    #[cfg(feature = "iroh")]
    /// Send via iroh peer-to-peer network (default)
    Iroh {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,
        /// Add extra AES-256-GCM encryption layer
        #[arg(long)]
        extra_encrypt: bool,

        /// Custom relay server URLs
        #[arg(long)]
        relay_url: Vec<String>,
    },

    #[cfg(feature = "onion")]
    /// Send via Tor hidden service (anonymous)
    Tor {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Add extra AES-256-GCM encryption layer
        #[arg(long)]
        extra_encrypt: bool,
    },

    #[cfg(feature = "webrtc")]
    /// Send via WebRTC with Nostr signaling + relay fallback
    Hybrid {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Custom Nostr relay URLs for signaling/fallback
        #[arg(long = "nostr-relay")]
        nostr_relay: Vec<String>,

        /// Use default hardcoded Nostr relays instead of fetching from nostr.watch
        #[arg(long)]
        use_default_relays: bool,

        /// Force Nostr relay mode (skip WebRTC)
        #[arg(long)]
        force_nostr_relay: bool,
    },
}



/// Validate path exists and matches folder flag
fn validate_path(path: &PathBuf, folder: bool) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path not found: {}", path.display());
    }

    if folder {
        if !path.is_dir() {
            anyhow::bail!(
                "--folder specified but path is not a directory: {}",
                path.display()
            );
        }
    } else if !path.is_file() {
        anyhow::bail!(
            "Path is not a file: {}. Use --folder for directories.",
            path.display()
        );
    }

    Ok(())
}

/// Validate output directory exists
fn validate_output_dir(output: &Option<PathBuf>) -> Result<()> {
    if let Some(ref dir) = output {
        if !dir.is_dir() {
            anyhow::bail!("Output directory does not exist: {}", dir.display());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { transport } => match transport {
            #[cfg(feature = "iroh")]
            SendTransport::Iroh {
                path,
                folder,
                extra_encrypt,
                relay_url,
            } => {
                validate_path(&path, folder)?;
                if folder {
                    sender_iroh::send_folder(&path, extra_encrypt, relay_url).await?;
                } else {
                    sender_iroh::send_file(&path, extra_encrypt, relay_url).await?;
                }
            }

            #[cfg(feature = "onion")]
            SendTransport::Tor {
                path,
                folder,
                extra_encrypt,
            } => {
                validate_path(&path, folder)?;
                if folder {
                    onion_sender::send_folder_tor(&path, extra_encrypt).await?;
                } else {
                    onion_sender::send_file_tor(&path, extra_encrypt).await?;
                }
            }

            #[cfg(feature = "webrtc")]
            SendTransport::Hybrid {
                path,
                folder,
                nostr_relay,
                use_default_relays,
                force_nostr_relay,
            } => {
                validate_path(&path, folder)?;
                let custom_relays = if nostr_relay.is_empty() {
                    None
                } else {
                    Some(nostr_relay)
                };
                let result = if folder {
                    hybrid_sender::send_folder_hybrid(
                        &path,
                        force_nostr_relay,
                        custom_relays,
                        use_default_relays,
                    )
                    .await?
                } else {
                    hybrid_sender::send_file_hybrid(
                        &path,
                        force_nostr_relay,
                        custom_relays,
                        use_default_relays,
                    )
                    .await?
                };
                if result == TransferResult::Unconfirmed {
                    eprintln!(
                        "Note: Transfer may have succeeded but receiver confirmation was not received."
                    );
                }
            }
        },

        Commands::SendLocal { path, folder } => {
            validate_path(&path, folder)?;
            if folder {
                mdns_sender::send_folder_mdns(&path).await?;
            } else {
                mdns_sender::send_file_mdns(&path).await?;
            }
        }

        Commands::ReceiveLocal { output } => {
            validate_output_dir(&output)?;
            mdns_receiver::receive_mdns(output).await?;
        }

        Commands::Receive => {
            // Prompt for code
            print!("Enter wormhole code: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let code = input.trim().to_string();

            receive_with_code(&code, None, vec![]).await?;
        }
    }

    Ok(())
}

/// Receive using a wormhole code (auto-detects transport)
async fn receive_with_code(
    code: &str,
    output: Option<PathBuf>,
    relay_url: Vec<String>,
) -> Result<()> {
    // Validate code format
    wormhole::validate_code_format(code)?;

    // Parse code to determine transport
    let token = wormhole::parse_code(code)?;

    match token.protocol.as_str() {
        #[cfg(feature = "iroh")]
        wormhole::PROTOCOL_IROH => {
            receiver_iroh::receive(code, output, relay_url).await?;
        }
        #[cfg(feature = "onion")]
        wormhole::PROTOCOL_TOR => {
            onion_receiver::receive_tor(code, output).await?;
        }
        #[cfg(feature = "webrtc")]
        wormhole::PROTOCOL_HYBRID => {
            hybrid_receiver::receive_hybrid(code, output).await?;
        }
        proto => {
            #[cfg(not(feature = "iroh"))]
            if proto == wormhole::PROTOCOL_IROH {
                anyhow::bail!(
                    "This wormhole code uses Iroh transport, but Iroh support is disabled.\n\
                     To enable Iroh support, rebuild with: cargo build --features iroh\n\
                     Or run with: cargo run --features iroh -- receive"
                );
            }
            #[cfg(not(feature = "onion"))]
            if proto == wormhole::PROTOCOL_TOR {
                anyhow::bail!(
                    "This wormhole code uses Tor transport, but Tor support is disabled.\n\
                     To enable Tor support, rebuild with: cargo build --features onion\n\
                     Or run with: cargo run --features onion -- receive"
                );
            }
            #[cfg(not(feature = "webrtc"))]
            if proto == wormhole::PROTOCOL_HYBRID {
                anyhow::bail!(
                    "This wormhole code uses hybrid transport, but WebRTC support is disabled.\n\
                     To enable WebRTC support, rebuild with: cargo build --features webrtc\n\
                     Or run with: cargo run --features webrtc -- receive"
                );
            }
            anyhow::bail!("Unknown protocol in wormhole code: {}", proto);
        }
    }

    Ok(())
}
