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

**Solution B**: **WebRTC Manual Signaling** (`--manual-signaling`)
- **Why**: When mDNS discovery doesn't work (different subnets, VPN issues), manual signaling allows WebRTC P2P transfer by exchanging codes out-of-band.
- **Command**:
  ```bash
  # Sender
  wormhole-rs send webrtc --manual-signaling /path/to/file

  # Receiver
  wormhole-rs receive --manual-signaling
  ```
- **Experience**: Exchange base64 codes via any channel (chat, paper, verbal). No internet or relay servers needed.

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
- **Why**: WebRTC tries to punch through NATs. If direct connection fails (firewall blocks UDP), `wormhole-rs` can fall back to using tmpfiles.org to upload/download encrypted files (100MB limit, 60 min retention).
- **Manual Fallback**: If the connection hangs, the sender can use `--force-relay` to skip WebRTC and use tmpfiles.org directly.
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

## 7. No Nostr Relays Available (Manual Signaling)
**Scenario**: You want to use WebRTC for P2P transfer but cannot access Nostr relays (blocked network, air-gapped with internet for STUN only, or privacy concerns about relay metadata).

**Solution**: **Manual Signaling Mode** (`--manual-signaling`)
- **Why**: Bypasses Nostr relays entirely. You manually copy/paste signaling data between sender and receiver via any out-of-band channel (chat, email, paper).
- **Features**:
  - Step-by-step instructions guide both parties
  - CRC32 checksum validates copy/paste integrity
  - Magic trailer enables automatic end-of-input detection
  - 30-minute TTL prevents stale session attacks
- **Command**:
  ```bash
  # Sender
  wormhole-rs send webrtc --manual-signaling /path/to/file

  # Receiver
  wormhole-rs receive --manual-signaling
  ```
- **Experience**:
  1. Sender generates offer code (base64) and displays it with clear START/END markers
  2. Sender shares the code via any channel (Signal, email, read aloud, etc.)
  3. Receiver pastes the code and generates a response code
  4. Receiver shares the response back to sender
  5. WebRTC connection establishes directly between peers

---

## 8. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.
