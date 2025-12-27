use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use wormhole_rs::core::wormhole;

#[cfg(feature = "iroh")]
use wormhole_rs::iroh::{receiver as iroh_receiver, sender as iroh_sender};

#[cfg(feature = "onion")]
use wormhole_rs::onion::{receiver as onion_receiver, sender as onion_sender};

#[cfg(feature = "webrtc")]
use wormhole_rs::webrtc::{
    offline_receiver as webrtc_offline_receiver, receiver as webrtc_receiver,
    sender as webrtc_sender,
};

use wormhole_rs::mdns::{receiver as mdns_receiver, sender as mdns_sender};

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
    #[cfg(feature = "webrtc")]
    /// Send a file or folder via WebRTC (recommended, alias for send-webrtc)
    Send {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Custom Nostr relay URLs for signaling/fallback
        #[arg(long = "nostr-relay")]
        nostr_relay: Vec<String>,

        /// Use default hardcoded Nostr relays instead of running relay discovery
        #[arg(long)]
        use_default_relays: bool,

        /// Use manual copy/paste signaling instead of Nostr relays
        #[arg(long)]
        manual_signaling: bool,
    },

    #[cfg(feature = "webrtc")]
    /// Send a file or folder via WebRTC with Nostr signaling (recommended)
    #[command(name = "send-webrtc")]
    SendWebrtc {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Custom Nostr relay URLs for signaling/fallback
        #[arg(long = "nostr-relay")]
        nostr_relay: Vec<String>,

        /// Use default hardcoded Nostr relays instead of running relay discovery
        #[arg(long)]
        use_default_relays: bool,

        /// Use manual copy/paste signaling instead of Nostr relays
        #[arg(long)]
        manual_signaling: bool,
    },

    #[cfg(feature = "iroh")]
    /// Send a file or folder via iroh peer-to-peer network
    #[command(name = "send-iroh")]
    SendIroh {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,
    },

    #[cfg(feature = "onion")]
    /// Send a file or folder via Tor hidden service (anonymous)
    #[command(name = "send-tor")]
    SendTor {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,
    },

    /// Send via local network (mDNS discovery)
    #[command(name = "send-local")]
    SendLocal {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,
    },

    /// Receive a file or folder using a code
    Receive {
        /// Wormhole code from sender (will prompt if not provided)
        #[arg(short, long)]
        code: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Disable resumable transfers (don't save partial downloads)
        #[arg(long)]
        no_resume: bool,

        /// Use manual copy/paste signaling instead of Nostr relays (WebRTC)
        #[cfg(feature = "webrtc")]
        #[arg(long)]
        manual_signaling: bool,
    },

    /// Receive via local network (mDNS discovery)
    #[command(name = "receive-local")]
    ReceiveLocal {
        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
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

/// Helper to send via WebRTC
#[cfg(feature = "webrtc")]
async fn do_send_webrtc(
    path: PathBuf,
    folder: bool,
    pin: bool,
    nostr_relay: Vec<String>,
    use_default_relays: bool,
    manual_signaling: bool,
) -> Result<()> {
    validate_path(&path, folder)?;
    let custom_relays = if nostr_relay.is_empty() {
        None
    } else {
        Some(nostr_relay)
    };
    if folder {
        webrtc_sender::send_folder_webrtc(
            &path,
            custom_relays,
            use_default_relays,
            pin,
            manual_signaling,
        )
        .await?;
    } else {
        webrtc_sender::send_file_webrtc(
            &path,
            custom_relays,
            use_default_relays,
            pin,
            manual_signaling,
        )
        .await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up tracing subscriber with filters for noisy iroh internals
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            // Suppress noisy iroh internal logs
            .add_directive("iroh=warn".parse().unwrap())
            .add_directive("iroh_net=warn".parse().unwrap())
            .add_directive("iroh_relay=warn".parse().unwrap())
            .add_directive("iroh_quinn=warn".parse().unwrap())
            .add_directive("netwatch=warn".parse().unwrap())
            .add_directive("portmapper=warn".parse().unwrap())
            .add_directive("swarm_discovery=warn".parse().unwrap())
            .add_directive("pkarr=warn".parse().unwrap())
            .add_directive("quinn=warn".parse().unwrap())
            .add_directive("quinn_proto=warn".parse().unwrap())
            // Suppress noisy arti/tor internal logs
            .add_directive("arti=warn".parse().unwrap())
            .add_directive("arti_client=warn".parse().unwrap())
            .add_directive("tor_proto=warn".parse().unwrap())
            .add_directive("tor_chanmgr=warn".parse().unwrap())
            .add_directive("tor_circmgr=off".parse().unwrap()) // Suppress cleanup errors on drop
            .add_directive("tor_guardmgr=warn".parse().unwrap())
            .add_directive("tor_netdir=warn".parse().unwrap())
            .add_directive("tor_dirmgr=warn".parse().unwrap())
            .add_directive("tor_hsservice=warn".parse().unwrap())
            .add_directive("tor_hsclient=warn".parse().unwrap())
            .add_directive("tor_rtcompat=warn".parse().unwrap())
            .add_directive("tor_persist=off".parse().unwrap()) // Suppress state persistence errors
            // Suppress noisy webrtc internal logs
            .add_directive("webrtc=error".parse().unwrap())
            .add_directive("webrtc_ice=error".parse().unwrap())
            .add_directive("webrtc_srtp=off".parse().unwrap()) // Suppress SRTP close warnings
            .add_directive("webrtc_sctp=error".parse().unwrap())
            .add_directive("ice=error".parse().unwrap())
            .add_directive("stun=error".parse().unwrap())
            .add_directive("turn=error".parse().unwrap())
            .add_directive("dtls=error".parse().unwrap())
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "webrtc")]
        Commands::Send {
            path,
            folder,
            pin,
            nostr_relay,
            use_default_relays,
            manual_signaling,
        } => {
            do_send_webrtc(
                path,
                folder,
                pin,
                nostr_relay,
                use_default_relays,
                manual_signaling,
            )
            .await?;
        }

        #[cfg(feature = "webrtc")]
        Commands::SendWebrtc {
            path,
            folder,
            pin,
            nostr_relay,
            use_default_relays,
            manual_signaling,
        } => {
            do_send_webrtc(
                path,
                folder,
                pin,
                nostr_relay,
                use_default_relays,
                manual_signaling,
            )
            .await?;
        }

        #[cfg(feature = "iroh")]
        Commands::SendIroh {
            path,
            folder,
            pin,
            relay_url,
        } => {
            validate_path(&path, folder)?;
            if folder {
                iroh_sender::send_folder(&path, relay_url, pin).await?;
            } else {
                iroh_sender::send_file(&path, relay_url, pin).await?;
            }
        }

        #[cfg(feature = "onion")]
        Commands::SendTor { path, folder, pin } => {
            validate_path(&path, folder)?;
            if folder {
                onion_sender::send_folder_tor(&path, pin).await?;
            } else {
                onion_sender::send_file_tor(&path, pin).await?;
            }
        }

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

        #[cfg(feature = "webrtc")]
        Commands::Receive {
            mut code,
            output,
            relay_url,
            pin,
            no_resume,
            manual_signaling,
        } => {
            // Validate output directory if provided
            validate_output_dir(&output)?;

            // Handle manual signaling mode (WebRTC with copy/paste)
            if manual_signaling {
                webrtc_offline_receiver::receive_file_offline(output).await?;
                return Ok(());
            }

            // Handle PIN mode if requested
            if pin {
                let pin_str = wormhole_rs::auth::pin::prompt_pin()?;

                eprintln!("Searching for wormhole token via Nostr...");

                // Fetch encrypted token from Nostr
                let token_str =
                    wormhole_rs::auth::nostr_pin::fetch_wormhole_code_via_pin(&pin_str).await?;
                eprintln!("Token found and decrypted!");
                code = Some(token_str);
            }

            // Get code from argument or prompt
            let code = match code {
                Some(c) => c,
                None => {
                    print!("Enter wormhole code: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            receive_with_code(&code, output, relay_url, no_resume).await?;
        }

        #[cfg(not(feature = "webrtc"))]
        Commands::Receive {
            mut code,
            output,
            relay_url,
            pin,
            no_resume,
        } => {
            // Validate output directory if provided
            validate_output_dir(&output)?;

            // Handle PIN mode if requested
            if pin {
                let pin_str = wormhole_rs::auth::pin::prompt_pin()?;

                eprintln!("Searching for wormhole token via Nostr...");

                // Fetch encrypted token from Nostr
                let token_str =
                    wormhole_rs::auth::nostr_pin::fetch_wormhole_code_via_pin(&pin_str).await?;
                eprintln!("Token found and decrypted!");
                code = Some(token_str);
            }

            // Get code from argument or prompt
            let code = match code {
                Some(c) => c,
                None => {
                    print!("Enter wormhole code: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            receive_with_code(&code, output, relay_url, no_resume).await?;
        }
    }

    Ok(())
}

/// Receive using a wormhole code (auto-detects transport)
async fn receive_with_code(
    code: &str,
    output: Option<PathBuf>,
    relay_url: Vec<String>,
    no_resume: bool,
) -> Result<()> {
    // Validate code format
    wormhole::validate_code_format(code)?;

    // Parse code to determine transport
    let token = wormhole::parse_code(code)?;

    match token.protocol.as_str() {
        #[cfg(feature = "iroh")]
        wormhole::PROTOCOL_IROH => {
            iroh_receiver::receive(code, output, relay_url, no_resume).await?;
        }
        #[cfg(feature = "onion")]
        wormhole::PROTOCOL_TOR => {
            onion_receiver::receive_tor(code, output).await?;
        }
        #[cfg(feature = "webrtc")]
        wormhole::PROTOCOL_WEBRTC => {
            webrtc_receiver::receive_webrtc(code, output).await?;
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
            if proto == wormhole::PROTOCOL_WEBRTC {
                anyhow::bail!(
                    "This wormhole code uses webrtc transport, but WebRTC support is disabled.\n\
                     To enable WebRTC support, rebuild with: cargo build --features webrtc\n\
                     Or run with: cargo run --features webrtc -- receive"
                );
            }
            anyhow::bail!("Unknown protocol in wormhole code: {}", proto);
        }
    }

    Ok(())
}
