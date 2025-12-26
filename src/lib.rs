// Core modules - always available
pub mod auth;
pub mod cli;
pub mod core;

// Signaling - webrtc feature gates specific modules
#[cfg(feature = "webrtc")]
pub mod signaling;

// Transport modules - feature gated
#[cfg(feature = "iroh")]
pub mod iroh;

pub mod mdns;

#[cfg(feature = "onion")]
pub mod onion;

#[cfg(feature = "webrtc")]
pub mod webrtc;
