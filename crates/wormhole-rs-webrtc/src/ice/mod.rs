//! ICE transport module.
//!
//! Uses webrtc-ice for NAT traversal with TCP candidates,
//! then runs the unified transfer protocol on top.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Signaling Layer                       │
//! │  (Nostr relays - exchange ICE credentials & candidates) │
//! └─────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                   IceTransport (agent.rs)                │
//! │  - ICE negotiation (TCP candidates only)                │
//! │  - NAT traversal via STUN                               │
//! │  - Returns IceConn on successful connection             │
//! └─────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │               IceConn (conn.rs)                          │
//! │  - Implements AsyncRead + AsyncWrite                    │
//! │  - TCP gives ordered, reliable bytes                    │
//! └─────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Unified Transfer Protocol                   │
//! │  - run_sender_transfer() / run_receiver_transfer()      │
//! │  - Same as iroh, Tor, mDNS transports                   │
//! └─────────────────────────────────────────────────────────┘
//! ```

mod agent;
mod conn;
mod receiver;
mod sender;
mod signaling;

#[allow(unused_imports)]
pub use agent::{IceCandidateInfo, IceCredentials, IceTransport, DEFAULT_STUN_SERVERS};
pub use conn::IceConn;
pub use receiver::receive_ice;
pub use sender::{send_file_ice, send_folder_ice};
