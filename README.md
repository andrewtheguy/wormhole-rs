# wormhole-rs

A secure peer-to-peer file transfer tool with four transport modes:
- **iroh mode** - Direct P2P transfers using [iroh](https://github.com/n0-computer/iroh) with QUIC/TLS (default)
- **Nostr mode** - Small file/folder transfers (≤512KB) via [Nostr relays](https://nostr.com) with mandatory AES-256-GCM encryption
- **WebRTC mode** - Browser-compatible P2P transfers via WebRTC data channels - requires `webrtc` feature
- **Tor mode** - Anonymous transfers via Tor hidden services (.onion addresses) - requires `onion` feature

## Features

- End-to-end encryption - All connections use strong encryption; mandatory AES-256-GCM for WebRTC/Nostr
- Four transport modes - Choose between iroh P2P, WebRTC, Nostr relays, or Tor hidden services
- File and folder transfers - Send individual files or entire directories (as tar archives)
- Local discovery - mDNS for same-network transfers (iroh mode)
- NAT traversal - STUN/TURN for WebRTC, relay fallback for iroh
- Custom servers - Use your own relay/PeerJS servers
- Cross-platform - Single binary, supports macOS, Linux, and Windows

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
cargo build --release
```

## Usage

### Basic Usage

**Send a file:**
```bash
wormhole-rs send /path/to/file
```

**Send a folder:**
```bash
wormhole-rs send /path/to/folder --folder
```

**Receive:**
```bash
wormhole-rs receive
# Or with code directly
wormhole-rs receive --code <WORMHOLE_CODE>
```

### iroh Mode (Default)

Best for large files with direct P2P connections.

```bash
# Send file
wormhole-rs send /path/to/file

# With extra AES-256-GCM encryption layer
wormhole-rs send /path/to/file --extra-encrypt

# Custom relay server
wormhole-rs send --relay-url https://your-relay.example.com /path/to/file
```

### Nostr Mode (≤512KB)

Use when iroh is unavailable. Always encrypted with AES-256-GCM.

```bash
# Send via Nostr
wormhole-rs send /path/to/file --transport nostr
```

**PIN mode** - Share a short 8-character PIN instead of the full wormhole code:

```bash
# Sender: displays PIN like "AB#3K7*P"
wormhole-rs send /path/to/file --transport nostr --nostr-pin

# Receiver: prompts for PIN input
wormhole-rs receive --nostr-pin
```

The PIN encrypts the wormhole code using Argon2id + AES-256-GCM. Relays never see the PIN, wormhole code, or encryption keys. See [ARCHITECTURE.md](docs/ARCHITECTURE.md#nostr-mode-with-pin---nostr-pin) for security details.

**Custom relays:**
```bash
wormhole-rs send /path/to/file --transport nostr --nostr-relay wss://relay.damus.io
```

### WebRTC Mode (Browser-Compatible)

> Requires building with `--features webrtc`.

```bash
cargo build --release --features webrtc
wormhole-rs send /path/to/file --transport webrtc
```

### Tor Mode (Anonymous)

> Requires building with `--features onion`.

```bash
cargo build --release --features onion
wormhole-rs send /path/to/file --transport tor
```

## Security

All modes provide end-to-end encryption. The encryption key is embedded in the wormhole code and shared out-of-band (you manually share the code with the receiver).

| Mode | Transport Encryption | Application Encryption |
|------|---------------------|------------------------|
| iroh | QUIC/TLS 1.3 | Optional (`--extra-encrypt`) |
| Nostr | None (relay-based) | Mandatory AES-256-GCM |
| WebRTC | DTLS-SRTP | Mandatory AES-256-GCM |
| Tor | Tor circuits | Optional (`--extra-encrypt`) |

Relay servers (iroh, Nostr, PeerJS) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
