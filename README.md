# wormhole-rs

A secure peer-to-peer file transfer tool with four transport modes:
- **iroh mode** - Direct P2P transfers using [iroh](https://github.com/n0-computer/iroh) with QUIC/TLS (automatic relay fallback)
- **Hybrid mode** - WebRTC transfers with Nostr signaling and relay fallback - requires `webrtc` feature
- **Tor mode** - Anonymous transfers via Tor hidden services (.onion addresses) - requires `onion` feature
- **Local mode** - LAN transfers using mDNS discovery and TCP - no internet required

## Features

- **End-to-end encryption** - All connections use strong encryption (AES-256-GCM / ChaCha20-Poly1305)
- **Four transport modes** - Choose between Iroh P2P, Hybrid (WebRTC+Nostr), Tor, or Local LAN
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Local discovery** - mDNS for same-network transfers
- **NAT traversal** - STUN/TURN for WebRTC, relay fallback for Iroh/Nostr
- **Cross-platform** - Single binary, supports macOS, Linux, and Windows

For detailed protocol flows, wire formats, security model, and implementation details, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installation

### Quick Install (Linux & macOS)

```bash
curl -sSL https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.sh | bash
```

Install with custom release tag:
```bash
curl -sSL https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.sh | bash -s <RELEASE_TAG>
```

### Quick Install (Windows)

```powershell
irm https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.ps1 | iex
```

Install with custom release tag:
```powershell
irm https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.ps1 | iex -Args <RELEASE_TAG>
```

### Manual Build

```bash
# Build with default features (Local mode only)
cargo build --release

# Build with Iroh support
cargo build --release --features iroh

# Build with all features (Iroh + Local + Hybrid + Tor)
cargo build --release --all-features
```

## Usage

### iroh Mode (Default)

Best for large files with direct P2P connections.
> Requires building with `--features iroh`.

```bash
# Send file
wormhole-rs send iroh /path/to/file

# Send folder
wormhole-rs send iroh /path/to/folder --folder

# With extra AES-256-GCM encryption layer
wormhole-rs send iroh /path/to/file --extra-encrypt

# Custom relay server
wormhole-rs send iroh --relay-url https://your-relay.example.com /path/to/file
```

### Hybrid Mode (WebRTC + Nostr)

Browser-compatible P2P transfers. Uses Nostr relays for signaling and falls back to relay transfer if P2P fails.
> Requires building with `--features webrtc`.

```bash
# Send via Hybrid mode
wormhole-rs send hybrid /path/to/file

# Force relay mode (skip WebRTC, go straight to Nostr relay transfer)
wormhole-rs send hybrid /path/to/file --force-nostr-relay
```

### Local Mode (LAN)

Transfer files over the local network using mDNS discovery and TCP. No internet connection required.

```bash
# Send file locally
wormhole-rs send-local /path/to/file

# Send folder locally
wormhole-rs send-local /path/to/folder --folder

# Receive locally
wormhole-rs receive-local
# Or specify output directory
wormhole-rs receive-local --output /path/to/downloads
```

### Tor Mode (Anonymous)

Anonymous transfers via Tor hidden services.
> Requires building with `--features onion`.

```bash
# Send via Tor
wormhole-rs send tor /path/to/file
```

### Receiving

The receiver command is the same for global transfers (Iroh, Hybrid, Tor). It auto-detects the protocol from the code.

```bash
wormhole-rs receive
# Or with code directly
wormhole-rs receive --code <WORMHOLE_CODE>
```

## Security

All modes provide end-to-end encryption. The wormhole code is the key exchange mechanism.

| Mode | Transport Encryption | Application Encryption |
|------|---------------------|------------------------|
| iroh | QUIC/TLS 1.3 | Optional (`--extra-encrypt`) |
| Hybrid | DTLS (WebRTC) / TLS (Relay) | Mandatory AES-256-GCM |
| Local | None (TCP) | Mandatory AES-256-GCM (Passphrase) |
| Tor | Tor circuits | Optional (`--extra-encrypt`) |

Relay servers (iroh, Nostr) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
