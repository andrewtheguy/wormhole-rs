# wormhole-rs

A secure peer-to-peer file transfer tool with two main transport categories:

**1. Internet Transfers** (Wormhole Code)
- **iroh mode** - Direct P2P transfers using [iroh](https://github.com/n0-computer/iroh) with QUIC/TLS (automatic relay fallback)
- **WebRTC mode** - WebRTC transfers with Nostr signaling and relay fallback - requires `webrtc` feature
- **Tor mode** - Anonymous transfers via Tor hidden services (.onion addresses) - requires `onion` feature

**2. Local Transfers** (Passphrase)
- **Local mode** - LAN transfers using mDNS discovery and TCP - no internet required

## Features

- **End-to-end encryption** - All connections use strong encryption (AES-256-GCM / ChaCha20-Poly1305)
- **Two Transfer Categories**
    - **Internet**: Global P2P via Iroh, WebRTC, or Tor
    - **Local**: Private LAN transfers using mDNS
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Local discovery** - mDNS for same-network transfers
- **NAT traversal** - STUN/TURN for WebRTC, relay fallback for Iroh/Nostr
- **Manual Relay Fallback** - Force fallback to Nostr relay mode by pressing ENTER if WebRTC fails
- **PIN-based Transfers** - Use short 12-digit PINs instead of long wormhole codes for easier typing
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

### From Source

```bash
# Default build (Local mode only - lightweight)
cargo build --release

# With Iroh support (recommended)
cargo build --release --features iroh

# With WebRTC support
cargo build --release --features webrtc

# With Tor support
cargo build --release --features onion

# Full feauture set
cargo build --release --all-features
```

## Usage

### Internet Transfers (`wormhole-rs send`)

Use these modes for transfers over the internet. They all use a **Wormhole Code** for connection.

#### 1. iroh Mode (Default)
*Best for large files. Direct P2P with automatic relay fallback.*
> Requires building with `--features iroh`.

```bash
# Send file
wormhole-rs send iroh /path/to/file

# Send folder
wormhole-rs send iroh /path/to/folder --folder

# With extra AES-256-GCM encryption
wormhole-rs send iroh /path/to/file --extra-encrypt
```

#### 2. WebRTC Mode
*Browser-compatible. Uses WebRTC + Nostr signaling.*
> Requires building with `--features webrtc`.

```bash
# Standard send (displays wormhole code)
wormhole-rs send webrtc /path/to/file

# Send using a 12-digit PIN (Easier to type)
wormhole-rs send --pin webrtc /path/to/file
```

#### 3. Tor Mode
*Anonymous transfers via Tor hidden services.*
> Requires building with `--features onion`.

```bash
wormhole-rs send tor /path/to/file

# Send using PIN
wormhole-rs send --pin tor /path/to/file
```

#### Receiving (Internet)
The receiver auto-detects the protocol from the wormhole code.

```bash
wormhole-rs receive
# Or with code directly
wormhole-rs receive --code <WORMHOLE_CODE>

# Receive using PIN
wormhole-rs receive --pin
```

---

### Local LAN Transfers (`wormhole-rs send-local`)

Use this mode for transfers on the same network (no internet required). Uses a **Passphrase** (not a code).

```bash
# Send locally
wormhole-rs send-local /path/to/file

# Send folder locally
wormhole-rs send-local /path/to/folder --folder

# Receive locally
wormhole-rs receive-local
```

## Security

All modes provide end-to-end encryption.
- **Global Modes (Iroh, WebRTC, Tor)**: The **Wormhole Code** contains the key/address information.
- **Local Mode**: Uses a short **Passphrase** for key derivation.

| Mode | Type | Key Exchange | Transport Encryption |
|------|------|--------------|---------------------|
| iroh | Internet | Wormhole Code | QUIC/TLS 1.3 |
| WebRTC | Internet | Wormhole Code | DTLS (WebRTC) / TLS (Relay) |
| Tor | Internet | Wormhole Code | Tor circuits |
| Local | LAN | **Passphrase** | None (TCP) |

Relay servers (iroh, Nostr) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
