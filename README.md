# wormhole-rs

A secure peer-to-peer file transfer tool using [iroh](https://github.com/n0-computer/iroh) for direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- 🔐 **End-to-end encryption** - AES-256-GCM with unique nonces per 16KB chunk
- 🌐 **Peer-to-peer** - Direct connections when possible, relay fallback when needed
- 🏠 **Local discovery** - mDNS for same-network transfers without relay
- 📡 **Connection info** - Shows if transfer is Direct, Relay, or Mixed
- 📊 **Progress display** - Real-time transfer progress

## Installation

```bash
cargo build --release
```

## Usage

### Send a file

```bash
./target/release/wormhole-rs send /path/to/file
```

This will display a wormhole code to share with the receiver.

### Receive a file

```bash
./target/release/wormhole-rs receive <WORMHOLE_CODE>
```

Optionally specify an output directory:

```bash
./target/release/wormhole-rs receive <WORMHOLE_CODE> --output /path/to/dir
```

## How It Works

### Connection Flow

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

### Data Transfer

**Direct connection (same network or hole-punch success):**
```
Sender ◄──── encrypted chunks ────► Receiver
         (relay not involved)
```

**Relay fallback (strict NAT/firewall):**
```
Sender ──► Relay ──► Receiver
       (encrypted, relay can't read)
```

## Security & Encryption Model

### Key Exchange (Out-of-Band)

The 32-byte AES-256 encryption key is:
1. **Generated randomly** by the sender
2. **Embedded in the wormhole code** (base64-encoded along with endpoint address)
3. **Shared out-of-band** - you manually share the code with the receiver

**The iroh relay server never sees the encryption key.**

### What Each Party Sees

| Party | Sees |
|-------|------|
| Sender | Plaintext file, encryption key |
| Receiver | Encryption key (from wormhole code), decrypted file |
| Relay Server | Only encrypted blobs + routing info |

### Encryption Layers

| Layer | Protection |
|-------|------------|
| AES-256-GCM | File content encryption (application layer) |
| iroh QUIC/TLS | Transport encryption (network layer) |

### Nonce Handling

Each 16KB chunk uses a unique nonce derived from the chunk number, preventing nonce reuse attacks.

### Connection Types

The receiver displays the current connection type:

| Type | Description |
|------|-------------|
| `Direct(addr)` | Direct P2P via UDP hole-punching (fastest) |
| `Relay(url)` | Via relay server (works through firewalls) |
| `Mixed(addr, url)` | Both available, upgrading to direct |
| `None` | No verified connection path |

**Priority:** Local mDNS → Direct UDP → Relay fallback

## Wire Protocol Format

### Wormhole Code
```
base64( postcard( [32-byte AES key] + [EndpointAddr] ) )
```

### Encrypted Header (chunk_num = 0)
```
┌──────────────┬─────────────────────────────────────────────────────┐
│  header_len  │              encrypted header data                  │
│  (4 bytes)   │  nonce(12) + encrypted(filename_len + name + size)  │
└──────────────┴─────────────────────────────────────────────────────┘
```

### Encrypted Chunk (chunk_num = 1, 2, 3...)
```
┌──────────────┬──────────┬─────────────────┬─────────────┐
│  chunk_len   │  nonce   │   ciphertext    │   GCM tag   │
│  (4 bytes)   │(12 bytes)│    (≤16KB)      │  (16 bytes) │
└──────────────┴──────────┴─────────────────┴─────────────┘
```

> **Note:** All data sent over the network is encrypted. The relay server only sees encrypted blobs.

## Project Structure

```
src/
├── main.rs       # CLI entry point
├── crypto.rs     # AES-256-GCM encryption/decryption
├── wormhole.rs   # Wormhole code generation/parsing
├── transfer.rs   # Wire protocol (headers, chunks)
├── sender.rs     # Send file logic
└── receiver.rs   # Receive file logic
```

## Dependencies

- `iroh` v0.95.1 - P2P connectivity
- `aes-gcm` - AES-256-GCM encryption
- `clap` - CLI parsing
- `tokio` - Async runtime
- `postcard` + `serde` - Binary serialization

## License

MIT
