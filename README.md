# wormhole-rs

A secure peer-to-peer file transfer tool with two main transport categories:

**1. Internet Transfers** (Wormhole Code)
- **iroh mode** - Direct P2P transfers using [iroh](https://github.com/n0-computer/iroh) with QUIC/TLS (automatic relay fallback)
- **WebRTC mode** - WebRTC transfers with Nostr signaling (or copy/paste `--manual-signaling`) - requires `webrtc` feature
- **Tor mode** - Anonymous transfers via Tor hidden services (.onion addresses), also serves as relay when P2P fails - requires `onion` feature

**2. Local Transfers** (PIN + SPAKE2)
- **Local mode** - LAN transfers using mDNS discovery, SPAKE2 key exchange from a 12-character PIN, and TCP transport (no internet required)

## Features

- **End-to-end encryption** - All connections use strong encryption (AES-256-GCM / ChaCha20-Poly1305)
- **Two Transfer Categories**
    - **Internet**: Global P2P via Iroh, WebRTC, or Tor
    - **Local**: Private LAN transfers using mDNS
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Local discovery** - mDNS for same-network transfers
- **NAT traversal** - STUN for WebRTC; relay fallback for Iroh; use Tor mode as relay when direct P2P fails
- **PIN-based Transfers** - Use short 12-character PINs (with checksum) instead of long wormhole codes for easier typing
- **Cross-platform** - Single binary, supports macOS, Linux, and Windows

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** (Air-gapped / Local LAN)
- **No Clipboard** (PIN Mode for easy typing)
- **Restricted Networks** (Firewall/NAT traversal)
- **Anonymity** (Tor Mode)
- **Self-Hosted Infrastructure** (Zero third-party dependency)

For detailed protocol flows, wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).



## Installation

### Quick Install (Linux & macOS)

```bash
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash
```

Install with custom release tag:
```bash
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash -s <RELEASE_TAG>
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash -s 20251210172710
```

### Quick Install (Windows)

```powershell
irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex
```

Install with custom release tag:
```powershell
irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex -Args <RELEASE_TAG>
```

By default the PowerShell installer pulls the latest **stable** release. Use `-PreRelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```powershell
# Latest prerelease
irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex -Args -PreRelease

# Pin to a specific tag
irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex -Args 20251210172710
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

##### Custom Iroh Relays
- Default behavior uses iroh's public relay fallback plus direct P2P.
- For self-hosted setups, point both sides at your own DERP relay(s):
    ```bash
    wormhole-rs send iroh --relay-url https://relay1.example.com /path/to/file
    wormhole-rs receive --relay-url https://relay1.example.com
    ```
- Multiple `--relay-url` flags are supported for failover.
- Discovery still relies on iroh's public DNS/pkarr services today; full zero-third-party operation will land with the planned custom DNS server support (see ROADMAP).

#### 2. WebRTC Mode
*Browser-compatible. Uses WebRTC + Nostr signaling; copy/paste signaling works with `--manual-signaling`.*
> Requires building with `--features webrtc`.

```bash
# Standard send (displays wormhole code)
wormhole-rs send webrtc /path/to/file

# Send using a 12-character PIN (checksum-validated)
wormhole-rs send --pin webrtc /path/to/file

# Send with copy/paste manual signaling (no relays)
wormhole-rs send --manual-signaling webrtc /path/to/file
```

##### Custom Nostr Relays
- By default, WebRTC mode discovers the best Nostr relays automatically via NIP-65/NIP-66.
- Use `--nostr-relay` to specify custom Nostr relays for signaling:
    ```bash
    wormhole-rs send webrtc --nostr-relay wss://my-relay.com /path/to/file
    ```
- Use `--use-default-relays` to skip discovery and use hardcoded default relays:
    ```bash
    wormhole-rs send webrtc --use-default-relays /path/to/file
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

# Receive with copy/paste manual signaling (WebRTC)
wormhole-rs receive --manual-signaling
```

---

### Local LAN Transfers (`wormhole-rs send-local`)

Use this mode for transfers on the same network (no internet required). A **PIN** is shown and fed into a SPAKE2 PAKE to derive the AES key (not a wormhole code).

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
- **Global Modes (Iroh, WebRTC, Tor)**: The **Wormhole Code** carries the key/address information.
- **Local Mode**: Uses a 12-character PIN that feeds a SPAKE2 PAKE to derive the AES key (no wormhole code).

| Mode | Type | Key Exchange | Transport Encryption |
|------|------|--------------|---------------------|
| iroh | Internet | Wormhole Code | QUIC/TLS 1.3 |
| WebRTC | Internet | Wormhole Code | DTLS (WebRTC) / TLS (Relay) |
| Tor | Internet | Wormhole Code | Tor circuits |
| Local | LAN | SPAKE2 (PIN + transfer_id) | AES-256-GCM over TCP |

Relay servers (iroh, Tor) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
