# Project Roadmap

## Backlog

Ideas and feature requests for future consideration.

### Manual IP/Port Entry for Local Mode
**Priority:** Low, because there are many other ways to transfer files locally.
**Domain:** Local Connection
- **Problem:** mDNS discovery often fails to discover routable IPs (e.g., VPN interfaces like WireGuard/Tailscale) or works poorly across subnets.
- **Feature:** Sender displays a list of available local IPs and the listening port.
- **Feature:** Receiver has a CLI option to manually enter `ip:port` instead of waiting for mDNS discovery.
- **Benefit:** Provides a fallback for LAN/VPN transfers when auto-discovery fails.

### Browser-Accessible Tor Downloads
**Domain:** Tor Mode
- **Feature:** Enable `wormhole-rs-tor send` to serve files via standard HTTP over the Onion network.
- **Benefit:** Allows receivers to download files using just the **Tor Browser**, eliminating the need to install the `wormhole-rs` CLI on the receiving machine.


### Make Nostr an Opt-In Feature
**Domain:** Core / Feature Flags
- **Feature:** Decouple Nostr dependencies completely (currently used for WebRTC signaling and PIN-based code exchange).
- **Benefit:** Users who only want iroh/Tor/Local transfers without PIN exchange shouldn't be required to build/include the Nostr stack.

