use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Write};
use std::path::PathBuf;
use wormhole_rs::{nostr_protocol, nostr_receiver, nostr_sender, receiver_iroh, sender_iroh, wormhole};

#[cfg(feature = "onion")]
use wormhole_rs::{onion_receiver, onion_sender};

/// Transport protocol for file transfer
#[derive(Clone, Debug, ValueEnum)]
enum Transport {
    /// Default: iroh-based peer-to-peer transfer
    Iroh,
    /// Nostr relay-based transfer (max 512KB files)
    Nostr,
    /// Tor hidden service transfer
    #[cfg(feature = "onion")]
    Tor,
}

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
        /// Path to the file or folder to send
        path: PathBuf,

        /// Transport protocol to use
        #[arg(long, value_enum, default_value = "iroh")]
        transport: Transport,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Add extra AES-256-GCM encryption layer
        #[arg(long)]
        extra_encrypt: bool,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,

        /// Custom Nostr relay URLs (for nostr transport)
        #[arg(long = "nostr-relay")]
        nostr_relay: Vec<String>,

        /// Use default hardcoded Nostr relays instead of fetching from nostr.watch
        #[arg(long)]
        use_default_relays: bool,

        /// Disable NIP-65 Outbox model for Nostr (for compatibility with old receivers)
        #[arg(long)]
        no_outbox: bool,
    },

    /// Receive a file or folder (auto-detects transport and type from wormhole code)
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            path,
            transport,
            folder,
            extra_encrypt,
            relay_url,
            nostr_relay,
            use_default_relays,
            no_outbox,
        } => {
            // Validate path exists
            if !path.exists() {
                anyhow::bail!("Path not found: {}", path.display());
            }

            // Validate folder flag matches path type
            if folder {
                if !path.is_dir() {
                    anyhow::bail!("--folder specified but path is not a directory: {}", path.display());
                }
            } else {
                if !path.is_file() {
                    anyhow::bail!("Path is not a file: {}. Use --folder for directories.", path.display());
                }
            }

            match transport {
                Transport::Iroh => {
                    if folder {
                        sender_iroh::send_folder(&path, extra_encrypt, relay_url).await?;
                    } else {
                        sender_iroh::send_file(&path, extra_encrypt, relay_url).await?;
                    }
                }
                Transport::Nostr => {
                    let custom_relays = if nostr_relay.is_empty() {
                        None
                    } else {
                        Some(nostr_relay)
                    };
                    let use_outbox = !no_outbox;
                    if folder {
                        // Folder size is validated inside send_folder_nostr
                        nostr_sender::send_folder_nostr(&path, custom_relays, use_default_relays, use_outbox).await?;
                    } else {
                        // Enforce file size limit for Nostr transfers
                        let metadata = std::fs::metadata(&path)?;
                        let file_size = metadata.len();
                        if file_size > nostr_protocol::MAX_NOSTR_FILE_SIZE {
                            anyhow::bail!(
                                "File too large for Nostr transfer (max 512KB): {} bytes\n\
                                 Use --transport iroh for larger files.",
                                file_size
                            );
                        }
                        nostr_sender::send_file_nostr(&path, custom_relays, use_default_relays, use_outbox).await?;
                    }
                }
                #[cfg(feature = "onion")]
                Transport::Tor => {
                    if folder {
                        onion_sender::send_folder_tor(&path, extra_encrypt).await?;
                    } else {
                        onion_sender::send_file_tor(&path, extra_encrypt).await?;
                    }
                }
            }
        }

        Commands::Receive { code, output, relay_url } => {
            // Validate output directory if provided
            if let Some(ref dir) = output {
                if !dir.is_dir() {
                    anyhow::bail!("Output directory does not exist: {}", dir.display());
                }
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

            // Validate code format
            wormhole::validate_code_format(&code)?;

            // Parse code to determine transport
            let token = wormhole::parse_code(&code)?;

            match token.protocol.as_str() {
                wormhole::PROTOCOL_IROH => {
                    // Iroh transport: auto-detects file vs folder from header
                    receiver_iroh::receive(&code, output, relay_url).await?;
                }
                wormhole::PROTOCOL_NOSTR => {
                    // Nostr transport: auto-detects file vs folder from wormhole code
                    nostr_receiver::receive_file_nostr(&code, output).await?;
                }
                #[cfg(feature = "onion")]
                wormhole::PROTOCOL_TOR => {
                    // Tor transport: auto-detects file vs folder from header
                    onion_receiver::receive_tor(&code, output).await?;
                }
                proto => {
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
        }
    }

    Ok(())
}
