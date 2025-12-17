# Common Use Cases & Scenarios

This guide describes common scenarios where `wormhole-rs` shines and which mode to use for each.

## 1. No Internet Access (LAN / Air-gapped)
**Scenario**: You need to transfer files between two computers on the same Wi-Fi or Ethernet network, but the internet is down, slow, or you are in an isolated environment (air-gapped).

**Solution**: **Local Mode** (`send-local` / `receive-local`)
- **Why**: It uses mDNS for discovery and direct TCP connections. No data leaves your local network. It relies on a short passphrase instead of a long code.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send-local /path/to/file
  
  # Receiver
  wormhole-rs receive-local
  ```
- **Experience**: The sender sets a passphrase (e.g., "secret"). The receiver finds the sender automatically and prompts for that passphrase.

---

## 2. Cannot Copy-Paste (Cross-device / Remote Terminal)
**Scenario**: You are sending a file from a laptop to a friend's phone, or to a remote server console where you cannot easily copy and paste the long "Wormhole Code". Typing a huge base64 string is impossible.

**Solution**: **PIN Mode** (`--pin`)
- **Why**: Instead of a massive code string, you only need to type a **12-character PIN**.
- **Command**:
  ```bash
  # Sender (using WebRTC for compatibility, or Iroh/Tor)
  wormhole-rs send --pin webrtc /path/to/file
  
  # Receiver
  wormhole-rs receive --pin
  ```
- **Experience**: 
  1. Sender sees: `PIN: A1b2C3d4E5f6` (example)
  2. Receiver runs `receive --pin` and types `A1b2C3d4E5f6`.
  3. The app handles the complex key exchange automatically behind the scenes using Nostr.

---

## 3. Strict Firewalls / Restricted Networks
**Scenario**: You are on a corporate or university network that blocks UDP, non-standard ports, and direct P2P connections. Standard transfers hang or fail.

**Solution**: **WebRTC Mode + Relay Fallback**
- **Why**: WebRTC tries to punch through NATs. If direct connection fails (firewall blocks UDP), `wormhole-rs` can fall back to using Nostr relays to store-and-forward encrypted chunks (over standard HTTPS/WS).
- **Manual Fallback**: If the connection hangs, the sender can press **ENTER** to force the relay mode immediately.
- **Command**:
  ```bash
  wormhole-rs send --pin webrtc /path/to/file
  ```

---

## 4. Maximum Anonymity
**Scenario**: You want to transfer a file without revealing your IP address to the peer or any relay servers.

**Solution**: **Tor Mode** (`onion`)
- **Why**: Creates a Tor Hidden Service for the transfer. Traffic is routed through the Tor network, masking locations of both parties.
- **Command**:
  ```bash
  wormhole-rs send --pin tor /path/to/file
  ```

---

## 5. Large File Transfer (Maximum Efficiency)
**Scenario**: Transferring a massive dataset (GBs) over the internet where speed is critical.

**Solution**: **Iroh Mode** (Default)
- **Why**: Uses `iroh` (QUIC), which is optimized for high throughput and congestion control. It utilizes multiple streams and handles packet loss efficiently, making it the fastest option for large files.
- **Command**:
  ```bash
  wormhole-rs send iroh /path/to/large-video.mp4
  ```

---

## 6. Self-Hosted Infrastructure (Zero Third-Party Dependency)
**Scenario**: You require complete control over the network infrastructure and cannot rely on public relays or discovery servers due to policy or privacy concerns.

**Solution**: **Iroh Mode + Custom Relays**
- **Why**: Iroh allows you to run your own lightweight relay (DERP). By pointing `wormhole-rs` to your own infrastructure, you achieve a true peer-to-peer connection where no third-party relays are involved.
- **Resources**: Implementation for the relay server allows for independence and is available in the [Iroh repository](https://github.com/n0-computer/iroh).
- **Command**:
  ```bash
  wormhole-rs send iroh --relay-url http://my-private-relay.com:3340 /path/to/file
  ```

---

## 7. Planned / Future Scenarios (Roadmap)
*These features are currently in development or planned. See [ROADMAP.md](ROADMAP.md) for details.*

### A. Fully Air-gapped P2P Discovery
**Scenario**: You want to use P2P discovery in a completely offline or private network (like a high-security corporate Intranet) without even reaching out to public DNS servers.
- **Solution**: **Custom Iroh DNS Server**
- **Benefit**: Allows `wormhole-rs` to discover peers globally within a private network using a self-hosted DNS/Discovery server.

### B. Download without CLI (Tor Browser)
**Scenario**: The receiver is on a restricted machine where they cannot install the CLI, but they have the Tor Browser.
- **Solution**: **Browser-Accessible Tor Downloads**
- **Benefit**: The sender creates an onion service that serves the file over HTTP. The receiver simply pastes the `.onion` link into Tor Browser to download.

### C. VPN / Complex Subnet Transfers
**Scenario**: You are connected via WireGuard or Tailscale, but mDNS auto-discovery doesn't work across the VPN interface.
- **Solution**: **Manual IP/Port Entry** (Local Mode)
- **Benefit**: Sender shares `IP:PORT` (e.g., `10.0.0.2:4000`) manually. Receiver connects directly, bypassing discovery issues.
