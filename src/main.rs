use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use wormhole_rs::{folder_receiver, folder_sender, receiver, sender, wormhole};

#[derive(Parser)]
#[command(name = "wormhole-rs")]
#[command(about = "Secure peer-to-peer file transfer using iroh")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file
    Send {
        /// Path to the file to send
        file: PathBuf,

        /// Add extra AES-256-GCM encryption layer (for insecure transports)
        #[arg(long)]
        extra_encrypt: bool,
    },
    /// Receive a file
    Receive {
        /// Wormhole code from sender (will prompt if not provided)
        #[arg(short, long)]
        code: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Expect extra AES-256-GCM encryption layer
        #[arg(long)]
        extra_encrypt: bool,
    },
    /// Send a folder (creates tar archive)
    SendFolder {
        /// Path to the folder to send
        folder: PathBuf,

        /// Add extra AES-256-GCM encryption layer (for insecure transports)
        #[arg(long)]
        extra_encrypt: bool,
    },
    /// Receive a folder (extracts tar archive)
    ReceiveFolder {
        /// Wormhole code from sender (will prompt if not provided)
        #[arg(short, long)]
        code: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Expect extra AES-256-GCM encryption layer
        #[arg(long)]
        extra_encrypt: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { file, extra_encrypt } => {
            if !file.exists() {
                anyhow::bail!("File not found: {}", file.display());
            }
            if !file.is_file() {
                anyhow::bail!("Not a file: {}", file.display());
            }
            sender::send_file(&file, extra_encrypt).await?;
        }
        Commands::Receive {
            code,
            output,
            extra_encrypt,
        } => {
            if let Some(ref dir) = output {
                if !dir.is_dir() {
                    anyhow::bail!("Output directory does not exist: {}", dir.display());
                }
            }
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
            wormhole::validate_code_format(&code)?;
            receiver::receive_file(&code, output, extra_encrypt).await?;
        }
        Commands::SendFolder {
            folder,
            extra_encrypt,
        } => {
            if !folder.exists() {
                anyhow::bail!("Folder not found: {}", folder.display());
            }
            if !folder.is_dir() {
                anyhow::bail!("Not a directory: {}", folder.display());
            }
            folder_sender::send_folder(&folder, extra_encrypt).await?;
        }
        Commands::ReceiveFolder {
            code,
            output,
            extra_encrypt,
        } => {
            if let Some(ref dir) = output {
                if !dir.is_dir() {
                    anyhow::bail!("Output directory does not exist: {}", dir.display());
                }
            }
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
            wormhole::validate_code_format(&code)?;
            folder_receiver::receive_folder(&code, output, extra_encrypt).await?;
        }
    }

    Ok(())
}
