use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use wormhole_common::core::transfer::is_interrupted;
use wormhole_common::core::wormhole;

#[cfg(feature = "iroh")]
mod iroh;
#[cfg(feature = "iroh")]
use iroh::{receiver as iroh_receiver, sender as iroh_sender};

#[cfg(feature = "onion")]
mod onion;
#[cfg(feature = "onion")]
use onion::{receiver as onion_receiver, sender as onion_sender};

mod mdns;
use mdns::{receiver as mdns_receiver, sender as mdns_sender};

mod cli;

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
    #[cfg(feature = "iroh")]
    /// Send a file or folder via iroh (default, recommended)
    Send {
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
            "Path is not a regular file: {}. If you intended a directory, use --folder.",
            path.display()
        );
    }

    Ok(())
}

/// Validate output directory exists and is a directory
fn validate_output_dir(output: &Option<PathBuf>) -> Result<()> {
    if let Some(ref dir) = output {
        if !dir.exists() {
            anyhow::bail!("Output path does not exist: {}", dir.display());
        }
        if !dir.is_dir() {
            anyhow::bail!("Output path is not a directory: {}", dir.display());
        }
    }
    Ok(())
}

fn main() {
    // Run the async main and handle errors
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(async_main());

    if let Err(e) = result {
        // Check if this was an interrupt (Ctrl+C)
        if is_interrupted(&e) {
            // Exit with 128 + SIGINT (2) = 130, standard Unix convention
            std::process::exit(130);
        }
        // Print error and exit with failure code
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<()> {
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
            .add_directive("tor_circmgr=off".parse().unwrap())
            .add_directive("tor_guardmgr=warn".parse().unwrap())
            .add_directive("tor_netdir=warn".parse().unwrap())
            .add_directive("tor_dirmgr=warn".parse().unwrap())
            .add_directive("tor_hsservice=warn".parse().unwrap())
            .add_directive("tor_hsclient=warn".parse().unwrap())
            .add_directive("tor_rtcompat=warn".parse().unwrap())
            .add_directive("tor_persist=off".parse().unwrap())
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "iroh")]
        Commands::Send {
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

        Commands::Receive {
            mut code,
            output,
            relay_url,
            pin,
            no_resume,
        } => {
            // Warn if relay_url is specified but iroh feature is disabled
            #[cfg(not(feature = "iroh"))]
            if !relay_url.is_empty() {
                eprintln!(
                    "Warning: --relay-url has no effect because iroh support is disabled.\n\
                     To use custom relays, rebuild with: cargo build --features iroh"
                );
            }

            // Validate output directory if provided
            validate_output_dir(&output)?;

            // Handle PIN mode if requested
            if pin {
                let pin_str = wormhole_common::auth::pin::prompt_pin()?;

                eprintln!("Searching for wormhole token via Nostr...");

                // Fetch encrypted token from Nostr
                let token_str = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    wormhole_common::auth::nostr_pin::fetch_wormhole_code_via_pin(&pin_str),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Timeout: Failed to retrieve wormhole code from Nostr after 30 seconds"
                    )
                })??;
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
#[allow(unused_variables)] // relay_url and no_resume only used with iroh feature
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
            anyhow::bail!("Unknown protocol in wormhole code: {}", proto);
        }
    }

    Ok(())
}
