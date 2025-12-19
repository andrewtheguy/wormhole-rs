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


### Make Nostr an Opt-In Feature
**Domain:** Core / Feature Flags
- **Feature:** Decouple Nostr dependencies completely.
- **Benefit:** Users who only want to use Iroh or Tor (or Local mode) shouldn't be required to build/include the Nostr stack.

### Transfer Resumability
**Domain:** Core / Transfer Logic
- **Feature:** Ability to resume interrupted transfers (especially for large files) from where they left off.
- **Benefit:** Prevents data loss and wasted bandwidth on unstable connections.
- **Implementation:** Needs tracking of received chunks and a handshake to negotiate resume offset.

### Support Custom Iroh DNS Server
**Domain:** Iroh Mode
- **Priority:** Low (public Iroh DNS/pkarr is stable today).
- **Goal:** Let `wormhole-rs` point at a self-hosted Iroh DNS / discovery endpoint instead of the default n0 services.
- **Benefit:** Completes the fully self-hosted stack (air-gapped or private P2P discovery) when combined with custom DERP relays.
- **Current State:** CLI already supports custom DERP relays via `--relay-url`; discovery still depends on Iroh's public DNS/pkarr at https://dns.iroh.link/pkarr. Custom DNS wiring to point at your own server is not yet implemented.