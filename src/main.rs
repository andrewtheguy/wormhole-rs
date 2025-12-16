use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Write};
use std::path::PathBuf;
use wormhole_rs::{nostr_receiver, nostr_sender, receiver_iroh, sender_iroh, wormhole};

#[cfg(feature = "onion")]
use wormhole_rs::{onion_receiver, onion_sender};

#[cfg(feature = "webrtc")]
use wormhole_rs::{webrtc_receiver, webrtc_sender};

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
    /// WebRTC peer-to-peer transfer via PeerJS
    #[cfg(feature = "webrtc")]
    Webrtc,
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

        /// Use PIN-based code exchange for Nostr (displays 8-char PIN instead of full code)
        #[arg(long)]
        nostr_pin: bool,

        /// Custom PeerJS server URL (for webrtc transport)
        #[arg(long = "peerjs-server")]
        peerjs_server: Option<String>,
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

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        nostr_pin: bool,
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
            nostr_pin,
            peerjs_server,
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

            // Suppress unused variable warning when webrtc feature is disabled
            #[cfg(not(feature = "webrtc"))]
            let _ = &peerjs_server;

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
                    // Size validation is handled inside the send functions with better error messages
                    if folder {
                        nostr_sender::send_folder_nostr(&path, custom_relays, use_default_relays, use_outbox, nostr_pin).await?;
                    } else {
                        nostr_sender::send_file_nostr(&path, custom_relays, use_default_relays, use_outbox, nostr_pin).await?;
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
                #[cfg(feature = "webrtc")]
                Transport::Webrtc => {
                    if folder {
                        webrtc_sender::send_folder_webrtc(&path, peerjs_server.as_deref()).await?;
                    } else {
                        webrtc_sender::send_file_webrtc(&path, peerjs_server.as_deref()).await?;
                    }
                }
            }
        }

        Commands::Receive { code, output, relay_url, nostr_pin } => {
            // Validate output directory if provided
            if let Some(ref dir) = output {
                if !dir.is_dir() {
                    anyhow::bail!("Output directory does not exist: {}", dir.display());
                }
            }

            // Check if PIN mode for Nostr
            if nostr_pin {
                return nostr_receiver::receive_with_pin(output).await;
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
                #[cfg(feature = "webrtc")]
                wormhole::PROTOCOL_WEBRTC => {
                    // WebRTC transport: auto-detects file vs folder from header
                    webrtc_receiver::receive_webrtc(&code, output).await?;
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
                    #[cfg(not(feature = "webrtc"))]
                    if proto == wormhole::PROTOCOL_WEBRTC {
                        anyhow::bail!(
                            "This wormhole code uses WebRTC transport, but WebRTC support is disabled.\n\
                             To enable WebRTC support, rebuild with: cargo build --features webrtc\n\
                             Or run with: cargo run --features webrtc -- receive"
                        );
                    }
                    anyhow::bail!("Unknown protocol in wormhole code: {}", proto);
                }
            }
        }
    }

    Ok(())
}
