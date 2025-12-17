# Project Roadmap

---

## Backlog

Ideas and feature requests for future consideration.

### Manual IP/Port Entry for Local Mode
**Priority:** Low, because there are many other ways to transfer files locally.
**Domain:** Local Connection
- **Problem:** mDNS discovery often fails to discover routable IPs (e.g., VPN interfaces like WireGuard/Tailscale) or works poorly across subnets.
  - **Feature:** 
  - Sender displays a list of available local IPs and the listening port.
  - Receiver has a CLI option to manually enter `ip:port` instead of waiting for mDNS discovery.
  - Provides a fallback for LAN/VPN transfers when auto-discovery fails.

### Browser-Accessible Tor Downloads
**Domain:** Tor Mode
- **Feature:** Enable `wormhole-rs send tor` to serve files via standard HTTP over the Onion network.
- **Benefit:** Allows receivers to download files using just the **Tor Browser**, eliminating the need to install the `wormhole-rs` CLI on the receiving machine.


### Tor as Default Relay for WebRTC (will cause heavy dependency for WebRTC mode)
**Goal:** Improve privacy and reliability for WebRTC fallback scenarios.

- **Current State:** 
  - WebRTC uses Nostr for signaling.
  - If direct P2P fails, it falls back to Nostr relays (store-and-forward) for data transfer.
- **Proposal:**
  - Promote **Tor Onion Services** to be the default fallback relay mechanism when direct WebRTC fails.
  - Nostr data relaying should be demoted to a secondary, non-recommended option (or kept only for signaling).
  - This leverages the existing Tor feature flag to provide a robust, anonymous relay path.


### Make Nostr an Opt-In Feature
**Domain:** Core / Feature Flags
- **Feature:** Decouple Nostr dependencies completely.
- **Benefit:** Users who only want to use Iroh or Tor (or Local mode) shouldn't be required to build/include the Nostr stack.
- This aligns with the move to make Tor the primary relay for WebRTC, potentially allowing Nostr to be strictly optional.

### Transfer Resumability
**Domain:** Core / Transfer Logic
- **Feature:** Ability to resume interrupted transfers (especially for large files) from where they left off.
- **Benefit:** Prevents data loss and wasted bandwidth on unstable connections.
- **Implementation:** Needs tracking of received chunks and a handshake to negotiate resume offset.

### Support Custom Iroh DNS Server
**Domain:** Iroh Mode
- **Priority:** Low, because Iroh's infrastructure is pretty reliable as of now.
- **Feature:** Allow configuring a custom Iroh DNS / Discovery server.
- **Benefit:** Enables fully air-gapped or private P2P discovery without relying on global Iroh DNS servers, completing the self-hosted story.
- **Current State:** Only custom Relay (DERP) servers are supported via `--relay-url`.