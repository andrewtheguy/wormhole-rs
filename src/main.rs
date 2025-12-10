mod crypto;
mod receiver;
mod sender;
mod transfer;
mod wormhole;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    },
    /// Receive a file
    Receive {
        /// Wormhole code from sender
        code: String,
        
        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { file } => {
            if !file.exists() {
                anyhow::bail!("File not found: {}", file.display());
            }
            if !file.is_file() {
                anyhow::bail!("Not a file: {}", file.display());
            }
            sender::send_file(&file).await?;
        }
        Commands::Receive { code, output } => {
            if let Some(ref dir) = output {
                if !dir.is_dir() {
                    anyhow::bail!("Output directory does not exist: {}", dir.display());
                }
            }
            receiver::receive_file(&code, output).await?;
        }
    }

    Ok(())
}
