# wormhole-rs-webrtc

WebRTC transport for wormhole-rs file transfers.

> **Note**: This is a legacy/experimental transport. For new users, we recommend using **iroh mode** (`send-iroh`) which provides better reliability, automatic relay fallback, and simpler setup.

## Features

- WebRTC Data Channels for P2P file transfer
- Nostr relay signaling (auto-discovers best relays)
- Manual signaling mode for air-gapped networks
- PIN mode for easy code sharing

## Usage

### Standard WebRTC Transfer

```bash
# Sender
wormhole-rs send-webrtc /path/to/file

# Receiver
wormhole-rs receive --code <WORMHOLE_CODE>
```

### With PIN (easier to type)

```bash
# Sender
wormhole-rs send-webrtc --pin /path/to/file

# Receiver
wormhole-rs receive --pin
```

### Manual Signaling (no relays needed)

```bash
# Sender
wormhole-rs send-webrtc --manual-signaling /path/to/file

# Receiver
wormhole-rs receive --manual-signaling
```

### Custom Nostr Relays

```bash
# Use specific relay
wormhole-rs send-webrtc --nostr-relay wss://my-relay.com /path/to/file

# Skip discovery, use defaults
wormhole-rs send-webrtc --use-default-relays /path/to/file
```

## When to Use WebRTC

WebRTC mode may still be useful in specific scenarios:

1. **Manual signaling** - When you need to exchange signaling data out-of-band (copy/paste) without any relay servers
2. **Custom Nostr infrastructure** - If you already run Nostr relays for other purposes

For most use cases, **iroh mode** is recommended instead.

## Documentation

- [Architecture & Protocol](docs/ARCHITECTURE.md) - Detailed protocol flows and wire formats
