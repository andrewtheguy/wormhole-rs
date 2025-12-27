# wormhole-rs-webrtc

WebRTC transport for wormhole-rs file transfers with NAT traversal.

> **Note**: This crate is NOT in the main workspace. Build with: `cargo build -p wormhole-rs-webrtc`

## Features

- WebRTC ICE (Interactive Connectivity Establishment) for NAT traversal
- TCP candidates for reliable, ordered byte streams
- Nostr relay signaling for credential/candidate exchange
- Uses unified transfer protocol (same as iroh, Tor, mDNS transports)
- SPAKE2 key exchange for authenticated encryption

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Signaling Layer                       │
│  (Nostr relays - exchange ICE credentials & candidates) │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   webrtc-ice Agent                       │
│  - ICE negotiation (TCP candidates only)                │
│  - NAT traversal via STUN                               │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│               IceConn → AsyncRead/AsyncWrite            │
│  - TCP gives ordered, reliable bytes                    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Unified Transfer Protocol                   │
│  - run_sender_transfer() / run_receiver_transfer()      │
│  - Same as iroh, Tor, mDNS                              │
└─────────────────────────────────────────────────────────┘
```

## Usage

### Send a File

```bash
# With default Nostr relays
wormhole-rs-webrtc send /path/to/file

# With custom relay
wormhole-rs-webrtc send --relay wss://my-relay.com /path/to/file

# Use default relays (skip auto-discovery)
wormhole-rs-webrtc send --default-relays /path/to/file
```

### Receive a File

```bash
wormhole-rs-webrtc receive \
    --transfer-id <TRANSFER_ID> \
    --sender-pubkey <SENDER_PUBKEY_HEX> \
    --relay wss://relay.example.com
```

The sender displays the transfer ID, sender pubkey, and relay URL for the receiver to use.

## How It Works

1. **Sender** creates ICE agent, gathers TCP candidates via STUN
2. **Sender** publishes to Nostr relay and waits for receiver
3. **Receiver** creates ICE agent, gathers candidates, sends answer via Nostr
4. **Sender** receives answer, publishes offer with credentials
5. ICE connection established (TCP-based, NAT-traversed)
6. SPAKE2 key exchange using transfer ID
7. Unified transfer protocol runs over encrypted connection

## Comparison with Other Transports

| Transport | NAT Traversal | Relay | Protocol |
|-----------|---------------|-------|----------|
| **WebRTC** | STUN/TURN | Nostr signaling | Unified |
| iroh | STUN + relay | iroh network | Unified |
| mDNS | LAN only | None | Unified |
| Tor | .onion | Tor network | Unified |

## Documentation

- [Architecture & Protocol](docs/ARCHITECTURE.md) - Detailed protocol flows

## Future Enhancements

- [ ] Offline/manual signaling mode (copy-paste credentials)
- [ ] TURN relay support for restricted networks
