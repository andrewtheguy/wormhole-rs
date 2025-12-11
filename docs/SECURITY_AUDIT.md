# Security Audit: iroh v0.95.1 End-to-End Encryption

## Audit Summary

**Audited Version**: iroh v0.95.1 (from Cargo.lock)
**Audit Date**: December 2025
**Finding**: iroh provides zero-knowledge end-to-end encryption at the transport layer, making application-level AES-256-GCM encryption **redundant** for the default use case.

## Key Finding

The custom AES-256-GCM encryption layer in wormhole-rs was found to be unnecessary for security purposes when using iroh's default transport. iroh already provides three layers of encryption that prevent relay servers from reading transferred data.

## iroh's Security Architecture (v0.95.1)

### Source Code Analysis

The following files were analyzed from `~/.cargo/registry/src/index.crates.io-*/iroh-0.95.1/`:

| File | Purpose |
|------|---------|
| `src/key.rs` | Ed25519 key generation, SharedSecret derivation |
| `src/tls.rs` | TLS 1.3 configuration with raw public keys |
| `src/tls/verifier.rs` | RFC 7250 raw public key certificate verification |
| `src/magicsock.rs` | Discovery message encryption (ChaCha20-Poly1305) |

### Three Encryption Layers

#### Layer 1: Discovery Encryption (ChaCha20-Poly1305)

```rust
// From iroh-0.95.1/src/magicsock.rs
// Discovery messages are encrypted using NaCl Secretbox (ChaCha20-Poly1305)
// with keys derived from Ed25519 → Curve25519 ECDH key agreement
```

- Sender's Ed25519 SecretKey is converted to Curve25519 for key agreement
- Discovery messages (addresses, routing info) are encrypted
- Relay servers cannot read discovery metadata

#### Layer 2: TLS 1.3 Transport (RFC 7250)

```rust
// From iroh-0.95.1/src/tls.rs
// Uses TLS 1.3 with raw public key certificates
CryptoProvider::builder()
    .with_cipher_suites(&[
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
    ])
```

- TLS 1.3 handshake authenticated by Ed25519 public keys
- Raw public key certificates (RFC 7250) - no CA required
- Cipher suites: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305

#### Layer 3: QUIC AEAD Encryption

- All QUIC packets are encrypted with session keys derived from TLS handshake
- AEAD (Authenticated Encryption with Associated Data)
- Packet numbers and payload are encrypted

### EndpointAddr Structure Analysis

```rust
// From iroh-base-0.29.0/src/node_addr.rs
pub struct NodeAddr {
    pub node_id: PublicKey,  // 32-byte Ed25519 public key
    pub info: AddrInfo,      // Network addresses (relay URLs, socket addrs)
}
```

**Critical Finding**: The `EndpointAddr` (now `NodeAddr`) contains ONLY:
- **PublicKey** (32 bytes) - The Ed25519 public key
- **AddrInfo** - Network addresses for routing

The `SecretKey` is **never** included in the address and **never** transmitted over the network.

### Key Exchange Flow

```
Sender                                          Receiver
  |                                                 |
  | 1. Generate Ed25519 keypair locally             |
  |    SecretKey stays on sender                    |
  |                                                 |
  | 2. Wormhole code = base64(EndpointAddr)         |
  |    Contains: PublicKey + addresses              |
  |    Does NOT contain: SecretKey                  |
  |                                                 |
  | -------- Out-of-band code sharing ---------->   |
  |                                                 |
  |                   3. Receiver creates endpoint  |
  |                      with own keypair           |
  |                                                 |
  | <--- TLS 1.3 handshake (authenticated) ----     |
  |      Server: Sender's PublicKey                 |
  |      Client: Receiver's PublicKey               |
  |                                                 |
  | 4. Shared session keys derived                  |
  |    from TLS handshake                           |
  |                                                 |
  | <==== Encrypted QUIC stream data ====>          |
```

### Why the Relay Server Cannot Read Data

The critical security property is that the **Ed25519 SecretKey never leaves the sender's machine**:

1. **Key Generation**: The sender generates an Ed25519 keypair locally
   - `SecretKey` - 32 bytes, stays on sender's machine forever
   - `PublicKey` - 32 bytes, shared in wormhole code

2. **Wormhole Code Contents**: Only contains `PublicKey + network addresses`
   - The `SecretKey` is **never** serialized or transmitted
   - Even if an attacker intercepts the wormhole code, they only get public info

3. **TLS Handshake Authentication**: Requires the `SecretKey` to sign
   - The sender proves identity by signing with `SecretKey`
   - Without the `SecretKey`, no one can impersonate the sender
   - The relay server cannot forge this signature

4. **Session Key Derivation**: TLS 1.3 derives session keys from the handshake
   - Session keys are ephemeral and unique per connection
   - The relay server is not part of the TLS handshake
   - Therefore, the relay server never has access to session keys

**Result**: The relay server only sees encrypted QUIC packets that it cannot decrypt.

### Proof: SecretKey Never Transmitted

From `iroh-0.95.1/src/key.rs`:

```rust
impl SecretKey {
    /// Generate a new secret key using the OS random number generator.
    pub fn generate() -> Self { ... }

    /// Create a public key from this secret key.
    pub fn public(&self) -> PublicKey { ... }

    // NOTE: No serialize/transmit methods for SecretKey
    // The secret key stays local to the endpoint
}
```

From `iroh-0.95.1/src/endpoint.rs`:

```rust
// EndpointAddr only contains public info
pub fn addr(&self) -> EndpointAddr {
    EndpointAddr {
        node_id: self.secret_key.public(),  // Only public key
        info: self.my_addr_info(),          // Only network addresses
    }
}
```

## Current Implementation

Based on this audit, wormhole-rs now:

1. **Default mode**: Relies on iroh's QUIC/TLS 1.3 encryption
   - Wormhole code: `base64(postcard(EndpointAddr))`
   - Shorter codes, same security

2. **`--extra-encrypt` mode**: Adds AES-256-GCM layer
   - Wormhole code: `base64(postcard(AES_key + EndpointAddr))`
   - Useful for future insecure transports (e.g., TURN servers for WebRTC)
   - Defense-in-depth for paranoid users

## Wire Format

### Default (Unencrypted Application Layer)

```
Header: [4-byte len][transfer_type(1)][filename_len(2)][filename][file_size(8)]
Chunk:  [4-byte len][data]
```

Security: Protected by QUIC/TLS 1.3

### With --extra-encrypt

```
Header: [4-byte len][nonce(12)][encrypted header data][tag(16)]
Chunk:  [4-byte len][nonce(12)][encrypted chunk data][tag(16)]
```

Security: Double encryption (AES-256-GCM + QUIC/TLS 1.3)

## Recommendations

1. **For standard use**: Use default mode (no `--extra-encrypt`)
   - Simpler, shorter codes
   - iroh's encryption is sufficient

2. **For high-security needs**: Use `--extra-encrypt`
   - Defense-in-depth
   - Protects against potential iroh vulnerabilities

3. **For future insecure transports**: Always use `--extra-encrypt`
   - Required if adding TURN/WebRTC support
   - Required if using untrusted relay servers

## References

- iroh source code: `~/.cargo/registry/src/index.crates.io-*/iroh-0.95.1/`
- iroh-base source: `~/.cargo/registry/src/index.crates.io-*/iroh-base-0.29.0/`
- RFC 7250: Using Raw Public Keys in TLS
- QUIC RFC 9000: QUIC Transport Protocol
- TLS 1.3 RFC 8446
