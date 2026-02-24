# Common Use Cases & Scenarios

This guide describes common scenarios where `wormhole-rs` shines and which mode to use for each.

## 1. No Internet Access (LAN / Air-gapped)
**Scenario**: You need to transfer files without using the public internet: either both machines are on the same LAN, or you are fully air‑gapped and can only copy/paste text.

**Solution A**: **Local Mode** (`wormhole-rs-local`)
- **Why**: Uses mDNS discovery and direct TCP. No data leaves your local network. Relies on a short 12‑character PIN instead of a long code.
- **Command**:
  ```bash
  # Sender
  wormhole-rs-local send /path/to/file

  # Receiver
  wormhole-rs-local receive
  ```
- **Experience**: The sender is shown a random 12‑character PIN. The receiver finds the sender automatically and is prompted for that PIN.

**Solution B**: **WebRTC Manual Mode** (`wormhole-rs-webrtc send-manual` / `receive-manual`)  
- **Why**: Works when mDNS is blocked or the devices are on different networks, as long as you can copy/paste text between them. No Nostr relay required.
- **Command**:
  ```bash
  # Sender
  wormhole-rs-webrtc send-manual /path/to/file

  # Receiver
  wormhole-rs-webrtc receive-manual
  ```
- **Experience**: Sender copy/pastes an SDP offer, receiver replies with an SDP answer. The exchanged text includes the encryption key, so use a secure channel.

> **Note**: Tor Mode requires internet access. iroh Mode can be used in air‑gapped environments **only if** you self‑host the relay **and** discovery services on the same network; the default public relay/discovery endpoints require internet access.

---

## 2. Cross-Subnet / VPN Discovery Issues
**Scenario**: mDNS discovery doesn't work because peers are on different subnets, across VPNs, or on networks that block multicast.

**Solution**: **iroh Mode**
- **Why**: iroh discovers peers across network boundaries using DNS/pkarr discovery plus relay infrastructure—no manual IP input required. Requires internet access.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send /path/to/file

  # Receiver (auto-detects iroh vs Tor from code)
  wormhole-rs receive --code <WORMHOLE_CODE>
  ```
- **Experience**: Share the wormhole code via any channel (chat, paper, verbal). iroh handles peer discovery and NAT traversal automatically without needing IP addresses.

---

## 3. Cannot Copy-Paste (Cross-device / Remote Terminal)
**Scenario**: You are sending a file from a laptop to a friend's phone, or to a remote server console where you cannot easily copy and paste the long "Wormhole Code". Typing a huge base64 string is impossible.

**Solution A**: **Local Mode** (Recommended for same network)
- **Why**: Uses a short 12-character PIN with mDNS discovery. No code copying needed.
- **Command**:
  ```bash
  # Sender
  wormhole-rs-local send /path/to/file

  # Receiver
  wormhole-rs-local receive
  ```
- **Experience**:
  1. Sender sees: `PIN: A1b2C3d4E5f6` (example)
  2. Receiver runs `wormhole-rs-local receive` and types `A1b2C3d4E5f6`.

**Solution B**: **PIN Mode** (For internet transfers)
- **Why**: Uses a short 12-character PIN instead of a long code. The PIN is exchanged via Nostr relays, while the actual file transfer uses either iroh or Tor transport.
- **Command**:
  ```bash
  # Sender (iroh transport with PIN exchange)
  wormhole-rs send --pin /path/to/file

  # Or sender (Tor transport with PIN exchange, for anonymity)
  wormhole-rs send-tor --pin /path/to/file

  # Receiver (unified command, prompts for PIN)
  wormhole-rs receive --pin
  ```

---

## 4. Strict Firewalls / Restricted Networks
**Scenario**: You are on a corporate or university network that blocks UDP, non-standard ports, and direct P2P connections. Standard transfers hang or fail.

**Solution A**: **iroh Mode** (Recommended)
- **Why**: iroh uses QUIC with automatic relay fallback. It tries direct P2P first, then falls back to iroh's relay servers if needed.
- **Command**:
  ```bash
  wormhole-rs send /path/to/file
  ```

**Solution B**: **Tor Mode** (if iroh fails)
- **Why**: If direct P2P connection fails completely, Tor mode provides a reliable relay path through the Tor network with better privacy than any third-party relay.
- **Command**:
  ```bash
  wormhole-rs send-tor /path/to/file
  ```

---

## 5. Maximum Anonymity
**Scenario**: You want to transfer a file without revealing your IP address to the peer or any relay servers.

**Solution**: **Tor Mode** (`send-tor`)
- **Why**: Creates a Tor Hidden Service for the transfer. Traffic is routed through the Tor network, masking locations of both parties.
- **Command**:
  ```bash
  wormhole-rs send-tor --pin /path/to/file
  ```

---

## 6. Large File Transfer
**Scenario**: Transferring a massive dataset (GBs) over the internet.

**Solution**: **iroh Mode** (Recommended)
- **Why**: Uses QUIC, optimized for high throughput and congestion control. Automatic relay fallback ensures reliable delivery.
  ```bash
  wormhole-rs send /path/to/large-video.mp4
  ```

---

## 7. Self-Hosted Infrastructure (Zero Third-Party Dependency)
**Scenario**: You require complete control over the network infrastructure and cannot rely on public relays or discovery servers due to policy or privacy concerns.

**Solution A**: **iroh Mode + Custom DERP Relays** (Recommended)
- **Why**: iroh allows you to run your own lightweight relay (DERP). By pointing `wormhole-rs` to your own infrastructure, you achieve a true peer-to-peer connection where no third-party relays are involved.
- **Current Status**: Custom relays are supported today via `--relay-url`, but peer discovery still uses iroh's public DNS/pkarr services. See [ROADMAP.md](ROADMAP.md) for updates on custom DNS/discovery support. For a fully zero-third-party option today, use:
  - **Local Mode** (`wormhole-rs-local`) when both peers share a LAN and can rely on mDNS.
- **Resources**: Implementation for the relay server is available in the [iroh repository](https://github.com/n0-computer/iroh).
- **Command**:
  ```bash
  wormhole-rs send --relay-url https://my-private-relay.com /path/to/file
  ```

**Solution B**: **Local Mode** (Same network)
- **Why**: Uses mDNS discovery with no external dependencies. Works completely offline.
- **Command**:
  ```bash
  wormhole-rs-local send /path/to/file
  ```

---

## 8. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.

---

## WebRTC Mode

WebRTC mode provides P2P transfers with Nostr signaling for NAT traversal, plus a manual copy/paste path for offline or relay‑blocked environments. See [main README](../README.md#3-webrtc-mode---wormhole-rs-webrtc-send) for usage details.
