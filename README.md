# wormhole-rs

A secure peer-to-peer file transfer tool with three transport modes:
- **iroh mode** - Direct P2P transfers using [iroh](https://github.com/n0-computer/iroh) with QUIC/TLS (default)
- **Nostr mode** - Small file/folder transfers (≤512KB) via [Nostr relays](https://nostr.com) with mandatory AES-256-GCM encryption
- **Tor mode** - Anonymous transfers via Tor hidden services (.onion addresses) - requires `onion` feature

## Features

- 🔐 **End-to-end encryption** - All connections use strong encryption; optional AES-256-GCM layer
- 🌐 **Three transport modes** - Choose between iroh P2P, Nostr relays, or Tor hidden services
- 📁 **File and folder transfers** - Send individual files or entire directories (as tar archives)
- 🏠 **Local discovery** - mDNS for same-network transfers (iroh mode)
- 📡 **Connection info** - Shows if transfer is Direct, Relay, or Mixed (iroh mode)
- 🧅 **Tor anonymity** - Optional anonymous transfers via .onion addresses (Tor mode)
- 🔧 **Custom relay servers** - Use your own private relays with automatic failover
- 📊 **Progress display** - Real-time transfer progress for all modes
- 💻 **Cross-platform** - Single binary with no dependencies, supports macOS, Linux, and Windows

## Installation

### Quick Install (Linux & macOS)

**One-line installation using the automated script:**

```bash
curl -sSL https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.sh | bash
```

**Install with custom release tag:**

```bash
curl -sSL https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.sh | bash -s <RELEASE_TAG>
```

**Using environment variable:**

```bash
RELEASE_TAG=latest curl -sSL https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.sh | bash
```

The installer will:
- Detect your OS (Linux/macOS) and architecture (amd64/arm64)
- Download the appropriate binary from GitHub releases
- Test the binary before installation
- Install to `~/.local/bin/wormhole-rs`
- Provide PATH setup guidance

### Quick Install (Windows)

**One-line installation using PowerShell:**

```powershell
irm https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.ps1 | iex
```

**Install with custom release tag:**

```powershell
irm https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.ps1 | iex -Args <RELEASE_TAG>
```

**Using environment variable:**

```powershell
$env:RELEASE_TAG="latest"; irm https://raw.githubusercontent.com/andrewtheguy/wormhole-rs/main/install.ps1 | iex
```

The installer will:
- Detect your architecture (amd64/arm64)
- Download the appropriate Windows binary from GitHub releases
- Test the binary before installation
- Install to `$env:LOCALAPPDATA\Programs\wormhole-rs\wormhole-rs.exe`
- Automatically add to your user PATH

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

This will display a wormhole code to share with the receiver.

**Send a folder:**

```bash
wormhole-rs send /path/to/folder --folder
```

Folders are transferred as tar archives. The receiver automatically extracts them.

**Receive (auto-detects transport and type):**

```bash
wormhole-rs receive
```

You will be prompted to enter the wormhole code. The receiver automatically detects the transport protocol (iroh, Nostr, or Tor) and transfer type (file or folder) from the wormhole code.

```bash
# Provide code directly
wormhole-rs receive --code <WORMHOLE_CODE>

# Specify output directory
wormhole-rs receive --output /path/to/dir
```

### iroh Mode (Default)

iroh mode uses direct P2P connections with QUIC/TLS encryption. Best for large files.

```bash
# Send file (iroh is default)
wormhole-rs send /path/to/file

# Send folder
wormhole-rs send /path/to/folder --folder

# With extra AES-256-GCM encryption layer
wormhole-rs send /path/to/file --extra-encrypt
```

**Custom Relay Server:**

By default, wormhole-rs uses iroh's public relay servers. For production use or private networks, you can run your own relay server.

```bash
# Send with custom relay
wormhole-rs send --relay-url https://your-relay.example.com /path/to/file

# Receive with custom relay
wormhole-rs receive --relay-url https://your-relay.example.com

# Multiple relays for failover
wormhole-rs send --relay-url https://relay1.example.com --relay-url https://relay2.example.com /path/to/file
```

### Nostr Mode (Small Files/Folders ≤512KB)

Use Nostr mode when iroh is unavailable or blocked. Nostr transfers are always encrypted with AES-256-GCM.

```bash
# Send file via Nostr
wormhole-rs send /path/to/file --transport nostr

# Send folder via Nostr (tar archive must be ≤512KB)
wormhole-rs send /path/to/folder --folder --transport nostr
```

By default, wormhole-rs uses the **NIP-65 Outbox model** which allows sender and receiver to use different relays.

**Custom relays:**

```bash
wormhole-rs send /path/to/file --transport nostr --nostr-relay wss://relay.damus.io --nostr-relay wss://nos.lol
```

**Use default hardcoded relays:**

```bash
wormhole-rs send /path/to/file --transport nostr --use-default-relays
```

**Legacy mode (disable NIP-65 Outbox):**

```bash
wormhole-rs send /path/to/file --transport nostr --no-outbox
```

### Tor Mode (Anonymous Transfers)

> **Note:** Requires building with `--features onion`. Tor mode uses Arti (Tor's Rust implementation).

Tor mode provides anonymous transfers via .onion hidden services. Both sender and receiver are hidden behind Tor.

```bash
# Build with Tor support
cargo build --release --features onion

# Send file via Tor
wormhole-rs send /path/to/file --transport tor

# Send folder via Tor
wormhole-rs send /path/to/folder --folder --transport tor

# With extra AES-256-GCM encryption (on top of Tor's encryption)
wormhole-rs send /path/to/file --transport tor --extra-encrypt
```

The sender bootstraps an ephemeral Tor client and creates a temporary .onion service. The wormhole code contains the .onion address for the receiver to connect.

**Receive via Tor:**

```bash
wormhole-rs receive --code <WORMHOLE_CODE>
```

The receiver automatically detects Tor protocol from the wormhole code and connects via Tor.

## How It Works

### iroh Mode - Connection Flow

```
                    ┌──────────┐
                    │  Relay   │  (discovery + fallback)
                    └────┬─────┘
                         │
   1. Publish addr       │        2. Discover sender
         ┌───────────────┴───────────────┐
         ▼                               ▼
    ┌────────┐                      ┌──────────┐
    │ Sender │◄────────────────────►│ Receiver │
    └────────┘   3. Direct P2P      └──────────┘
                 (if possible)
```

**Direct connection (same network or hole-punch success):**
```
Sender ◄──── TLS 1.3 encrypted ────► Receiver
              (relay not involved)
```

**Relay fallback (strict NAT/firewall):**
```
Sender ◄──── TLS 1.3 encrypted ────► Receiver
                    │
               iroh Relay
            (forwards packets,
             cannot decrypt)
```

Both connection types use the same QUIC/TLS 1.3 encryption. The TLS handshake is always performed end-to-end between sender and receiver.

### Nostr Mode - Transfer Flow

**NIP-65 Outbox Model (Default):**

```
    ┌────────┐         ┌───────────────┐         ┌──────────┐
    │ Sender │────────►│ Bridge Relays │◄────────│ Receiver │
    └────────┘         │ (NIP-65 event)│         └──────────┘
         │             └───────────────┘               │
         │                                             │
         │  1. Publish NIP-65 relay list               │  2. Query NIP-65
         │     to bridge relays                        │     to discover
         │                                             │     sender's relays
         │                                             │
         ▼                                             ▼
    ┌────────┐         ┌───────────────┐         ┌──────────┐
    │ Sender │────────►│Sender's Relays│◄────────│ Receiver │
    └────────┘         │ (file chunks) │         └──────────┘
                       └───────────────┘
```

**Transfer Phase:**

```
    ┌────────┐           ┌─────────────┐           ┌──────────┐
    │ Sender │──────────►│Nostr Relays │◄──────────│ Receiver │
    └────────┘           └─────────────┘           └──────────┘
         │                                               │
         │  1. Generate ephemeral keys                  │
         │  2. Publish encrypted chunks                  │
         │     (kind 24242, ephemeral events)            │
         │                                               │
         │                                               │  3. Subscribe to
         │                                               │     transfer events
         │                                               │
         │  4. Wait for ACK events                       │
         │  ◄────────────────────────────────────────────┤
         │  5. Retry failed chunks (up to 3 times)       │
```

**Nostr Protocol:**
- **NIP-65 Outbox model** - Sender publishes their relay list to well-known bridge relays; receiver discovers relays automatically
- Each file chunk is published as a separate Nostr event (kind 24242)
- Receiver sends ACK events for each received chunk
- Sender retries unacknowledged chunks up to 3 times
- All chunks are AES-256-GCM encrypted before publishing
- Ephemeral events are not stored permanently by relays
- Legacy mode (`--no-outbox`) requires sender and receiver to use the same relays

## Security & Encryption Model

### iroh Mode

**Key Exchange (Out-of-Band):**

The 32-byte AES-256 encryption key is:
1. **Generated randomly** by the sender
2. **Embedded in the wormhole code** (base64-encoded along with endpoint address)
3. **Shared out-of-band** - you manually share the code with the receiver

**The iroh relay server never sees the encryption key.**

**What Each Party Sees:**

| Party | Sees |
|-------|------|
| Sender | Plaintext file, encryption key |
| Receiver | Encryption key (from wormhole code), decrypted file |
| Relay Server | Only encrypted blobs + routing info |

**Encryption Layers:**

| Layer | Protection |
|-------|------------|
| AES-256-GCM | File content encryption (application layer, optional with `--extra-encrypt`) |
| QUIC/TLS 1.3 | Transport encryption (network layer, always enabled for all connection types) |

**Note:** QUIC/TLS 1.3 encryption is applied to **all** connections - both direct P2P and relay-assisted. The TLS handshake happens end-to-end between sender and receiver; relay servers only forward encrypted packets they cannot read.

**Nonce Handling:**

Each 16KB chunk uses a unique nonce derived from the chunk number, preventing nonce reuse attacks.

**Connection Types:**

The receiver displays the current connection type:

| Type | Description |
|------|-------------|
| `Direct(addr)` | Direct P2P via UDP hole-punching (fastest) |
| `Relay(url)` | Via relay server (works through firewalls) |
| `Mixed(addr, url)` | Both available, upgrading to direct |
| `None` | No verified connection path |

**Priority:** Local mDNS → Direct UDP → Relay fallback

### Nostr Mode

**Mandatory Encryption:**

Nostr mode always uses AES-256-GCM encryption - it cannot be disabled. This is required because:
- Nostr relays can read all event content
- Events may be cached or forwarded by relays
- No transport-layer encryption between sender and receiver

**Key Exchange:**

The 32-byte AES-256 encryption key is:
1. **Generated randomly** by the sender
2. **Embedded in the wormhole code** along with sender pubkey, transfer ID, relay list, and filename
3. **Shared out-of-band** - you manually share the code with the receiver

**What Each Party Sees:**

| Party | Sees |
|-------|------|
| Sender | Plaintext file, encryption key, ephemeral keypair |
| Receiver | Encryption key (from wormhole code), decrypted file, ephemeral keypair |
| Nostr Relays | Only encrypted chunks (base64-encoded ciphertext), event metadata, signatures |

**Nonce Handling:**

Each 16KB chunk uses a unique nonce derived from the chunk sequence number, preventing nonce reuse.

**Event Structure:**

```json
{
  "kind": 24242,
  "pubkey": "<sender_ephemeral_pubkey>",
  "tags": [
    ["t", "<transfer_id>"],
    ["seq", "<chunk_number>"],
    ["total", "<total_chunks>"],
    ["type", "chunk"]
  ],
  "content": "<base64_encrypted_chunk>"
}
```

**Security Guarantees:**

- Nostr relays cannot decrypt file content (only sender and receiver have the key)
- Each transfer uses ephemeral Nostr keypairs (not linked to user identity)
- Events are ephemeral (kind 20000-29999 range, not permanently stored)
- Unique transfer ID per session prevents cross-transfer confusion

## Wire Protocol Format

### iroh Mode

**Wormhole Code (Version 2):**
```json
{
  "version": 2,
  "protocol": "iroh",
  "extra_encrypt": true,
  "key": "<base64-encoded-32-bytes>",
  "addr": <EndpointAddr>
}
```
Base64url-encoded JSON token.

**Encrypted Header (chunk_num = 0):**
```
┌──────────────┬─────────────────────────────────────────────────────┐
│  header_len  │              encrypted header data                  │
│  (4 bytes)   │  nonce(12) + encrypted(filename_len + name + size)  │
└──────────────┴─────────────────────────────────────────────────────┘
```

**Encrypted Chunk (chunk_num = 1, 2, 3...):**
```
┌──────────────┬──────────┬─────────────────┬─────────────┐
│  chunk_len   │  nonce   │   ciphertext    │   GCM tag   │
│  (4 bytes)   │(12 bytes)│    (≤16KB)      │  (16 bytes) │
└──────────────┴──────────┴─────────────────┴─────────────┘
```

> **Note:** All data sent over the network is encrypted. The relay server only sees encrypted blobs.

### Nostr Mode

**Wormhole Code - File Transfer (Outbox Mode):**
```json
{
  "version": 2,
  "protocol": "nostr",
  "extra_encrypt": true,
  "key": "<base64-encoded-32-bytes>",
  "nostr_sender_pubkey": "<hex_pubkey>",
  "nostr_transfer_id": "<hex_transfer_id>",
  "nostr_filename": "example.txt",
  "nostr_transfer_type": "file",
  "nostr_use_outbox": true
}
```

**Wormhole Code - Folder Transfer:**
```json
{
  "version": 2,
  "protocol": "nostr",
  "extra_encrypt": true,
  "key": "<base64-encoded-32-bytes>",
  "nostr_sender_pubkey": "<hex_pubkey>",
  "nostr_transfer_id": "<hex_transfer_id>",
  "nostr_filename": "myfolder.tar",
  "nostr_transfer_type": "folder",
  "nostr_use_outbox": true
}
```
For folder transfers, `nostr_transfer_type` is `"folder"` and the data is a tar archive. Receiver extracts automatically.

**Wormhole Code - Legacy Mode (`--no-outbox`):**
```json
{
  "version": 2,
  "protocol": "nostr",
  "extra_encrypt": true,
  "key": "<base64-encoded-32-bytes>",
  "nostr_sender_pubkey": "<hex_pubkey>",
  "nostr_relays": ["wss://relay1.com", "wss://relay2.com"],
  "nostr_transfer_id": "<hex_transfer_id>",
  "nostr_filename": "example.txt",
  "nostr_transfer_type": "file"
}
```
In legacy mode, the relay list is embedded and both parties must use the same relays. In outbox mode, the relay list is omitted - receiver discovers relays via NIP-65.

Base64url-encoded JSON token.

**NIP-65 Relay List Event (Outbox Mode):**
```json
{
  "kind": 10002,
  "pubkey": "<sender_ephemeral_pubkey>",
  "created_at": <unix_timestamp>,
  "tags": [
    ["r", "wss://relay1.com"],
    ["r", "wss://relay2.com"]
  ],
  "content": "",
  "sig": "<signature>"
}
```
Published to well-known bridge relays (damus.io, nos.lol, nostr.wine) for receiver discovery.

**Chunk Event:**
```json
{
  "kind": 24242,
  "pubkey": "<sender_ephemeral_pubkey>",
  "created_at": <unix_timestamp>,
  "tags": [
    ["t", "<transfer_id>"],
    ["seq", "<chunk_number>"],
    ["total", "<total_chunks>"],
    ["type", "chunk"]
  ],
  "content": "<base64(encrypted_chunk)>",
  "sig": "<signature>"
}
```

**ACK Event:**
```json
{
  "kind": 24242,
  "pubkey": "<receiver_ephemeral_pubkey>",
  "tags": [
    ["p", "<sender_pubkey>"],
    ["t", "<transfer_id>"],
    ["seq", "<chunk_number>"],
    ["type", "ack"]
  ],
  "content": "",
  "sig": "<signature>"
}
```

**Encrypted Chunk Format (before base64 encoding):**
```
┌──────────┬─────────────────┬─────────────┐
│  nonce   │   ciphertext    │   GCM tag   │
│(12 bytes)│    (≤16KB)      │  (16 bytes) │
└──────────┴─────────────────┴─────────────┘
```

## Tor Mode Details

> **Warning:** Tor mode uses Arti (Tor's Rust implementation), which is not yet as secure as C-Tor. Do not use for highly security-sensitive purposes.

### How Tor Mode Works

```
    ┌────────┐                                      ┌──────────┐
    │ Sender │                                      │ Receiver │
    └────┬───┘                                      └────┬─────┘
         │                                               │
         │  1. Bootstrap Tor client                      │
         │  2. Create ephemeral .onion service           │
         │  3. Generate wormhole code with               │
         │     .onion address                            │
         │                                               │
         │  ─────── Share wormhole code ───────────►     │
         │                                               │
         │                                               │  4. Bootstrap Tor client
         │                                               │  5. Connect to .onion
         │                                               │
         │  ◄──────── Tor Circuit ────────────────►     │
         │            (end-to-end encrypted)             │
         │                                               │
         │  6. Send file/folder chunks                   │
         │  ◄──────────────────────────────────────►     │
         │  7. Receive ACK                               │
```

**Key properties:**
- **Anonymity** - Both sender and receiver are hidden behind Tor
- **NAT traversal** - Works through any firewall without port forwarding
- **Ephemeral services** - New .onion address generated for each transfer
- **End-to-end encryption** - Tor provides built-in encryption; optional AES-256-GCM layer available

### Building with Tor Support

```bash
cargo build --release --features onion
```

### Tor Wire Protocol

**Wormhole Code:**
```json
{
  "version": 2,
  "protocol": "tor",
  "extra_encrypt": false,
  "onion_address": "abc123...xyz.onion"
}
```

If `extra_encrypt` is true, an AES-256-GCM key is also included for an additional encryption layer on top of Tor's encryption.

### Example Binaries

The `examples/` directory contains standalone Tor sender/receiver examples:

```bash
# Run example sender
cargo run --example onion_sender --features onion

# Run example receiver
cargo run --example onion_receiver --features onion -- <address.onion>
```

### Limitations

- **Slow startup** - Tor bootstrapping and onion service publication takes 30-60 seconds
- **Connection timeouts** - Tor circuits can be slow; receiver retries up to 5 times
- **Experimental** - Arti's onion services are still maturing

### Dependencies (onion feature)

- `arti-client` v0.37 - Tor client implementation
- `tor-hsservice` v0.37 - Hidden service support
- `tor-cell` v0.37 - Tor protocol cells
- `safelog` v0.7 - Redacted logging for .onion addresses

## Project Structure

```
src/
├── main.rs              # CLI entry point (unified send/receive commands)
├── lib.rs               # Library exports
├── crypto.rs            # AES-256-GCM encryption/decryption
├── wormhole.rs          # Wormhole code generation/parsing (v2 tokens)
├── transfer.rs          # Wire protocol (headers, chunks)
├── folder.rs            # Shared folder logic (tar creation/extraction)
├── iroh_common.rs       # Common iroh endpoint setup and relay configuration
├── sender_iroh.rs       # iroh mode file/folder sender
├── receiver_iroh.rs     # iroh mode file/folder receiver
├── nostr_protocol.rs    # Nostr event structures and protocol logic
├── nostr_sender.rs      # Nostr mode file/folder sender
├── nostr_receiver.rs    # Nostr mode file/folder receiver
├── onion_sender.rs      # Tor mode file/folder sender (requires onion feature)
└── onion_receiver.rs    # Tor mode file/folder receiver (requires onion feature)

examples/
├── onion_sender.rs      # Standalone Tor sender example
└── onion_receiver.rs    # Standalone Tor receiver example
```

## Dependencies

### Core
- `iroh` v0.95.1 - P2P connectivity (iroh mode)
- `nostr-sdk` v0.44.1 - Nostr protocol (Nostr mode)
- `aes-gcm` - AES-256-GCM encryption
- `clap` - CLI parsing
- `tokio` - Async runtime
- `serde` + `serde_json` - Serialization

### Additional
- `reqwest` - HTTP client (nostr.watch API)
- `base64` - Encoding
- `hex` - Hex encoding
- `rand` - Random generation
- `tempfile` - Atomic file writing
- `tar` - Folder archiving

## License

MIT
