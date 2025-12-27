//! wormhole-rs-webrtc: WebRTC transport (isolated, not in workspace)
//!
//! This crate is NOT in the workspace members list and will not be built by default.
//! It can be built manually with: cargo build -p wormhole-rs-webrtc
//!
//! WebRTC transport is deprioritized in favor of iroh transport.
//! Use `wormhole-rs` for file transfers.

fn main() {
    eprintln!("wormhole-rs-webrtc is not yet implemented.");
    eprintln!("WebRTC transport has been deprioritized.");
    eprintln!();
    eprintln!("Use wormhole-rs instead:");
    eprintln!("  wormhole-rs send <file>          # Send via iroh (default)");
    eprintln!("  wormhole-rs send-tor <file>      # Send via Tor");
    eprintln!("  wormhole-rs send-local <file>    # Send via mDNS");
    eprintln!("  wormhole-rs receive <code>       # Receive file");
    std::process::exit(1);
}
