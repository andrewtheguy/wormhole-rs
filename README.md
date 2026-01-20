# wormhole-rs

A secure peer-to-peer file transfer tool with direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable transfers** - Interrupted transfers can resume from where they left off
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Multiple transport modes** - iroh (recommended), Tor, WebRTC, and local LAN
- **Local discovery** - mDNS for same-network transfers without internet
- **NAT traversal** - Automatic relay fallback for iroh; STUN for WebRTC; Tor as manual fallback
- **Cross-platform** - Standalone binary for macOS, Linux, and Windows

## Installation

The release installers fetch a native, standalone executable. You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS)

```bash
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash
```

To install the WebRTC binary instead:

```bash
curl -sSL https://andrewtheguy.github.io/wormhole-rs/install.sh | bash -s -- --webrtc
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

To install the WebRTC binary instead (single line):

```powershell
$env:WORMHOLE_INSTALL_ARGS='-WebRTC'; irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex
```

By default the PowerShell installer pulls the latest **stable** release. Use `-PreRelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples (args-only parser):

```powershell
# Latest prerelease
$env:WORMHOLE_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex

# Pin to a specific tag
$env:WORMHOLE_INSTALL_ARGS='20251210172710'; irm https://andrewtheguy.github.io/wormhole-rs/install.ps1 | iex
```

### From Source

```bash
# Default build (iroh + Tor + local; default features)
cargo build --release

# Local-only (no iroh/tor)
cargo build --release --no-default-features

# iroh only
cargo build --release --no-default-features --features iroh

# Tor only
cargo build --release --no-default-features --features onion

# WebRTC binary (separate crate)
cargo build --release -p wormhole-rs-webrtc

# Full feature set
cargo build --release --all-features
```

## Usage

### Internet Transfers

Use these modes for transfers over the internet. They all use a **Wormhole Code** for connection.

#### 1. iroh Mode (Recommended) - `send`
*Direct P2P transport using QUIC/TLS with automatic relay fallback. Most reliable for both small and large files.*
> Requires building with `--features iroh`.

```bash
# Send file
wormhole-rs send /path/to/file

# Send folder
wormhole-rs send /path/to/folder --folder
```

##### Custom Iroh Relays
- Default behavior uses iroh's public relay fallback plus direct P2P.
- For self-hosted setups, point both sides at your own DERP relay(s):
    ```bash
    wormhole-rs send --relay-url https://relay1.example.com /path/to/file
    wormhole-rs receive --relay-url https://relay1.example.com
    ```
- Multiple `--relay-url` flags are supported for failover.
- Discovery still relies on iroh's public DNS/pkarr services today; full zero-third-party operation will land with the planned custom DNS server support (see ROADMAP).

#### 2. Tor Mode - `send-tor`
*Anonymous transfers via Tor hidden services.*
> Requires building with `--features onion`.

```bash
wormhole-rs send-tor /path/to/file

# Send using PIN
wormhole-rs send-tor --pin /path/to/file
```

#### 3. WebRTC Mode - `wormhole-rs-webrtc send`
*WebRTC transfers with Nostr signaling for NAT traversal.*
> Built as a separate binary in this workspace: `cargo build -p wormhole-rs-webrtc`.

```bash
# Send with default Nostr relays
wormhole-rs-webrtc send /path/to/file

# Send with custom relay
wormhole-rs-webrtc send --relay wss://my-relay.com /path/to/file

# Receive (sender displays transfer-id, pubkey, relay)
wormhole-rs-webrtc receive \
    --transfer-id <TRANSFER_ID> \
    --sender-pubkey <SENDER_PUBKEY_HEX> \
    --relay wss://relay.example.com
```

##### Manual Mode (Copy/Paste SDP)
For air-gapped or restricted environments where Nostr relays are unavailable:

```bash
# Sender
wormhole-rs-webrtc send-manual /path/to/file

# Receiver
wormhole-rs-webrtc receive-manual
```

Manual mode exchanges SDP offers/answers via copy-paste. The codes contain the encryption key, so only share them through secure channels (SSH, remote desktop, encrypted chat).

If WebRTC connection fails (e.g., both peers behind symmetric NAT), use Tor mode as a relay fallback.

#### Receiving (Internet)
`wormhole-rs receive` auto-detects iroh vs Tor from the wormhole code. WebRTC codes are handled by `wormhole-rs-webrtc receive` (or `receive-manual`).

```bash
wormhole-rs receive
# Or with code directly
wormhole-rs receive --code <WORMHOLE_CODE>

# Receive using PIN
wormhole-rs receive --pin
```

---

### Local / Offline Transfers

There are **two** ways to transfer without relying on the public internet:

1) **LAN discovery (recommended when both devices share a network)**
   - Uses mDNS discovery + SPAKE2 PIN
   - Fast, zero copy/paste, no internet required

2) **Manual WebRTC (when mDNS is blocked or devices are on different networks but you can copy/paste)**
   - Uses WebRTC DataChannels with **manual** SDP exchange
   - Works even when Nostr relays are unavailable

> **Note**: Tor mode requires internet access. iroh mode can be air‑gapped **only if** you self‑host both the relay **and** discovery services on the same network; the default public relay/discovery endpoints require internet access.

#### LAN discovery (`wormhole-rs send-local`)

Use this mode for transfers on the same network (no internet required). A **PIN** is shown and fed into a SPAKE2 PAKE to derive the AES key (not a wormhole code).

```bash
# Send locally
wormhole-rs send-local /path/to/file

# Send folder locally
wormhole-rs send-local /path/to/folder --folder

# Receive locally
wormhole-rs receive-local
```

#### Manual WebRTC (`wormhole-rs-webrtc send-manual`)

```bash
# Sender
wormhole-rs-webrtc send-manual /path/to/file

# Receiver
wormhole-rs-webrtc receive-manual
```

Manual mode exchanges SDP offers/answers via copy-paste. The codes contain the encryption key, so only share them through secure channels (SSH, remote desktop, encrypted chat).

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** - Air-gapped / Local LAN transfers
- **Restricted Networks** - Firewall/NAT traversal options
- **Anonymity** - Tor mode for anonymous transfers
- **Self-Hosted** - Zero third-party dependency setups

For protocol details and wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

All modes provide end-to-end encryption.
- **Internet Modes (iroh, Tor, WebRTC)**: The **Wormhole Code** carries the key/address information.
- **Local Mode**: Uses a 12-character PIN that feeds a SPAKE2 PAKE to derive the AES key (no wormhole code).

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Wormhole Code | QUIC/TLS 1.3 | AES-256-GCM |
| Tor | Internet | Wormhole Code | Tor circuits | AES-256-GCM |
| WebRTC | Internet | Wormhole Code | DTLS (WebRTC) | AES-256-GCM |
| Local | LAN | SPAKE2 (PIN + transfer_id) | None (raw TCP) | AES-256-GCM |

Internet modes use dual-layer encryption (transport + content). Local mode uses single-layer AES-256-GCM over raw TCP, which is sufficient for trusted LANs.

Relay servers (iroh, Tor) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
