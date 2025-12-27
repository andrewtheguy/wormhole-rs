# wormhole-rs-webrtc

WebRTC transport for wormhole-rs file transfers with NAT traversal.

> **Note**: This crate is NOT in the main workspace. Build with: `cargo build -p wormhole-rs-webrtc`

## Features

- Full WebRTC stack with RTCPeerConnection and RTCDataChannel
- ICE (Interactive Connectivity Establishment) for NAT traversal
- Nostr relay signaling for SDP/candidate exchange (or manual copy-paste)
- Uses unified transfer protocol (same as iroh, Tor, mDNS transports)
- SPAKE2 key exchange for authenticated encryption

## Usage

### Send a File

```bash
# With default Nostr relays
wormhole-rs-webrtc send /path/to/file

# With custom relay
wormhole-rs-webrtc send --relay wss://my-relay.com /path/to/file
```

### Receive a File

```bash
wormhole-rs-webrtc receive \
    --transfer-id <TRANSFER_ID> \
    --sender-pubkey <SENDER_PUBKEY_HEX> \
    --relay wss://relay.example.com
```

The sender displays the transfer ID, sender pubkey, and relay URL for the receiver to use.

## Documentation

See [main ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for detailed protocol flows, security model, and wire format.

## Fallback

If WebRTC connection fails (e.g., both peers behind symmetric NAT), use Tor mode from the main `wormhole-rs` program as a relay fallback.
