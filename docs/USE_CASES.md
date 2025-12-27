# Common Use Cases & Scenarios

This guide describes common scenarios where `wormhole-rs` shines and which mode to use for each.

## 1. No Internet Access (LAN / Air-gapped)
**Scenario**: You need to transfer files between two computers on the same Wi-Fi or Ethernet network, but the internet is down, slow, or you are in an isolated environment (air-gapped).

**Solution A**: **Local Mode** (`send-local` / `receive-local`)
- **Why**: Uses mDNS for discovery and direct TCP connections. No data leaves your local network. Relies on a short passphrase instead of a long code.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send-local /path/to/file

  # Receiver
  wormhole-rs receive-local
  ```
- **Experience**: The sender sets a passphrase (e.g., "secret"). The receiver finds the sender automatically and prompts for that passphrase.

**Solution B**: **iroh Mode** (Cross-subnet discovery)
- **Why**: When mDNS discovery doesn't work (different subnets, VPN issues), iroh mode automatically discovers peers across network boundaries using iroh's distributed hash table (DHT) and relay infrastructure—no manual IP input required.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send-iroh /path/to/file

  # Receiver
  wormhole-rs receive --code <WORMHOLE_CODE>
  ```
- **Experience**: Share the wormhole code via any channel (chat, paper, verbal). iroh handles peer discovery and NAT traversal automatically without needing IP addresses.

---

## 2. Cannot Copy-Paste (Cross-device / Remote Terminal)
**Scenario**: You are sending a file from a laptop to a friend's phone, or to a remote server console where you cannot easily copy and paste the long "Wormhole Code". Typing a huge base64 string is impossible.

**Solution A**: **Local Mode** (Recommended for same network)
- **Why**: Uses a short 12-character PIN with mDNS discovery. No code copying needed.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send-local /path/to/file

  # Receiver
  wormhole-rs receive-local
  ```
- **Experience**:
  1. Sender sees: `PIN: A1b2C3d4E5f6` (example)
  2. Receiver runs `receive-local` and types `A1b2C3d4E5f6`.

**Solution B**: **Tor Mode with PIN** (For internet transfers)
- **Why**: Uses a short 12-character PIN via Nostr relays.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send-tor --pin /path/to/file

  # Receiver
  wormhole-rs receive --pin
  ```

---

## 3. Strict Firewalls / Restricted Networks
**Scenario**: You are on a corporate or university network that blocks UDP, non-standard ports, and direct P2P connections. Standard transfers hang or fail.

**Solution A**: **iroh Mode** (Recommended)
- **Why**: iroh uses QUIC with automatic relay fallback. It tries direct P2P first, then falls back to iroh's relay servers if needed.
- **Command**:
  ```bash
  wormhole-rs send-iroh /path/to/file
  ```

**Solution B**: **Tor Mode** (if iroh fails)
- **Why**: If direct P2P connection fails completely, Tor mode provides a reliable relay path through the Tor network with better privacy than any third-party relay.
- **Command**:
  ```bash
  wormhole-rs send-tor /path/to/file
  ```

---

## 4. Maximum Anonymity
**Scenario**: You want to transfer a file without revealing your IP address to the peer or any relay servers.

**Solution**: **Tor Mode** (`send-tor`)
- **Why**: Creates a Tor Hidden Service for the transfer. Traffic is routed through the Tor network, masking locations of both parties.
- **Command**:
  ```bash
  wormhole-rs send-tor --pin /path/to/file
  ```

---

## 5. Large File Transfer
**Scenario**: Transferring a massive dataset (GBs) over the internet.

**Solution**: **iroh Mode** (Recommended)
- **Why**: Uses QUIC, optimized for high throughput and congestion control. Automatic relay fallback ensures reliable delivery.
  ```bash
  wormhole-rs send-iroh /path/to/large-video.mp4
  ```

---

## 6. Self-Hosted Infrastructure (Zero Third-Party Dependency)
**Scenario**: You require complete control over the network infrastructure and cannot rely on public relays or discovery servers due to policy or privacy concerns.

**Solution A**: **iroh Mode + Custom DERP Relays** (Recommended)
- **Why**: iroh allows you to run your own lightweight relay (DERP). By pointing `wormhole-rs` to your own infrastructure, you achieve a true peer-to-peer connection where no third-party relays are involved.
- **Current Status**: Custom relays are supported today via `--relay-url`, but peer discovery still uses iroh's public DNS/pkarr services. Until custom DNS support lands (see ROADMAP: Support Custom Iroh DNS Server), the fully zero-third-party option is:
  - **Local Mode** (`send-local` / `receive-local`) when both peers share a LAN and can rely on mDNS.
- **Resources**: Implementation for the relay server is available in the [iroh repository](https://github.com/n0-computer/iroh).
- **Command**:
  ```bash
  wormhole-rs send-iroh --relay-url https://my-private-relay.com /path/to/file
  ```

**Solution B**: **Local Mode** (Same network)
- **Why**: Uses mDNS discovery with no external dependencies. Works completely offline.
- **Command**:
  ```bash
  wormhole-rs send-local /path/to/file
  ```

---

## 7. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.

---

## Legacy: WebRTC Mode

WebRTC mode is still available for specific use cases. See [WebRTC crate documentation](../crates/wormhole-rs-webrtc/README.md) for details.
