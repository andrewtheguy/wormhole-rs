# wormhole-rs-webrtc

WebRTC transport for wormhole-rs file transfers with NAT traversal.

> **Note**: This crate is NOT in the main workspace. Build with: `cargo build -p wormhole-rs-webrtc`

## Features

- Full WebRTC stack with RTCPeerConnection and RTCDataChannel
- ICE (Interactive Connectivity Establishment) for NAT traversal
- Nostr relay signaling for SDP/candidate exchange
- Uses unified transfer protocol (same as iroh, Tor, mDNS transports)
- SPAKE2 key exchange for authenticated encryption

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Signaling Layer                       │
│  (Nostr relays - exchange SDP offers/answers + ICE)     │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  RTCPeerConnection                       │
│  - SDP offer/answer negotiation                         │
│  - ICE candidate gathering via STUN                     │
│  - DTLS encryption                                      │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│        RTCDataChannel → DataChannelStream               │
│  - AsyncRead/AsyncWrite adapter                         │
│  - Ordered, reliable message delivery                   │
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

1. **Sender** creates RTCPeerConnection and data channel
2. **Sender** creates SDP offer and gathers ICE candidates via STUN
3. **Sender** publishes offer to Nostr relay and waits for receiver
4. **Receiver** creates RTCPeerConnection, receives offer via Nostr
5. **Receiver** creates SDP answer and publishes to Nostr
6. **Sender** receives answer, WebRTC connection established
7. SPAKE2 key exchange using transfer ID
8. Unified transfer protocol runs over encrypted data channel

## Comparison with Other Transports

| Transport | NAT Traversal | Relay | Protocol |
|-----------|---------------|-------|----------|
| **WebRTC** | STUN/TURN | Nostr signaling | Unified |
| iroh | STUN + relay | iroh network | Unified |
| mDNS | LAN only | None | Unified |
| Tor | .onion | Tor network | Unified |

## Documentation

- [Architecture & Protocol](docs/ARCHITECTURE.md) - Detailed protocol flows

## Fallback

If WebRTC connection fails (e.g., both peers behind symmetric NAT), use Tor mode from the main `wormhole-rs` program as a relay fallback.
