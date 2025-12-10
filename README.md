# wormhole-rs

A magic-wormhole-style secure file transfer tool using [iroh](https://github.com/n0-computer/iroh) for peer-to-peer connectivity and AES-256-GCM encryption.

## Features

- 🔐 **End-to-end encryption** - AES-256-GCM with unique nonces per 16KB chunk
- 🌐 **Peer-to-peer** - Direct connections via iroh's QUIC relay network
- 🔮 **Human-readable codes** - Easy to share wormhole codes like `42-guitar-piano-...`
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

```
┌────────┐                          ┌──────────┐                         ┌──────────┐
│ Sender │                          │  Relay   │                         │ Receiver │
└───┬────┘                          └────┬─────┘                         └────┬─────┘
    │  1. Connect & publish addr         │                                    │
    ├───────────────────────────────────►│                                    │
    │                                    │                                    │
    │  2. Generate AES-256 key           │                                    │
    │  3. Create wormhole code           │                                    │
    │     (key + addr encoded)           │                                    │
    │                                    │                                    │
    │                                    │  4. Parse code, connect            │
    │◄───────────────────────────────────┼────────────────────────────────────┤
    │                                    │                                    │
    │  5. Send file header               │                                    │
    ├────────────────────────────────────┼───────────────────────────────────►│
    │                                    │                                    │
    │  6. Stream encrypted 16KB chunks   │                                    │
    ├────────────────────────────────────┼───────────────────────────────────►│
    │                                    │                                    │
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
