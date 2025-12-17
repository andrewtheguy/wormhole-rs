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
**Goal:** Improve privacy and reliability for WebRTC fallback scenarios because Tor network should be more reliable and private than tmpfiles.org uploads.

- **Current State:**
  - WebRTC uses Nostr for signaling only.
  - If direct P2P fails, it falls back to tmpfiles.org for data transfer (100MB limit, 60 min retention).
- **Proposal:**
  - Promote **Tor Onion Services** to be the default fallback relay mechanism when direct WebRTC fails.
  - tmpfiles.org fallback should be demoted to a secondary option.
  - This leverages the existing Tor feature flag to provide a robust, anonymous relay path.


### Make Nostr an Opt-In Feature
**Domain:** Core / Feature Flags
- **Feature:** Decouple Nostr dependencies completely.
- **Benefit:** Users who only want to use Iroh or Tor (or Local mode) shouldn't be required to build/include the Nostr stack.
- This aligns with the move to make Tor the primary relay for WebRTC, potentially allowing Nostr to be strictly optional.

### Streaming Encrypt/Upload for tmpfiles.org Fallback
**Domain:** WebRTC / tmpfiles.org Fallback
- **Current State:**
  - Sender encrypts file in 16KB chunks to a temp file, then streams upload from temp file.
  - Requires knowing encrypted size upfront for HTTP Content-Length header.
- **Potential Optimization:**
  - If tmpfiles.org accepts chunked transfer encoding (no Content-Length required), we could stream encrypt directly to HTTP upload.
  - Would eliminate temp file entirely: `Read → Encrypt → Stream Upload` in one pass.
- **Investigation Needed:** Test if `multipart::Part::stream()` (without size) works with tmpfiles.org API.
- **Benefit:** Eliminates disk I/O for temp file, reduces latency.

### Investigate Alternative Temp File Upload Services
**Domain:** WebRTC / Fallback Options
- **Current State:** Using tmpfiles.org (100MB limit, 60 min retention).
- **Alternatives to Investigate:**
  - **temp.sh** - https://temp.sh/
  - **termbin.com** - https://termbin.com/
  - **uguu.se** - https://uguu.se/
- **Evaluation Criteria:**
  - Max file size limit
  - Retention period
  - API simplicity (curl-friendly)
  - Reliability and uptime
  - Support for streaming uploads (chunked transfer encoding)
  - Geographic availability
- **Potential Benefit:** Fallback redundancy, better limits, or improved reliability.

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