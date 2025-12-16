pub mod crypto;
pub mod folder;
#[cfg(feature = "iroh")]
pub mod iroh_common;
pub mod nostr_protocol;
#[cfg(feature = "iroh")]
pub mod receiver_iroh;
#[cfg(feature = "iroh")]
pub mod sender_iroh;
pub mod transfer;
pub mod wormhole;

// Internal modules for hybrid fallback (only needed with webrtc feature)
#[cfg(feature = "webrtc")]
pub(crate) mod nostr_receiver;
#[cfg(feature = "webrtc")]
pub(crate) mod nostr_sender;


#[cfg(feature = "onion")]
pub mod onion_receiver;
#[cfg(feature = "onion")]
pub mod onion_sender;

pub mod mdns_common;
pub mod mdns_receiver;
pub mod mdns_sender;

#[cfg(feature = "webrtc")]
pub mod hybrid_receiver;
#[cfg(feature = "webrtc")]
pub mod hybrid_sender;
#[cfg(feature = "webrtc")]
pub mod nostr_signaling;
#[cfg(feature = "webrtc")]
pub mod webrtc_common;

#[cfg(test)]
mod crypto_tests;
#[cfg(test)]
#[cfg(test)]
mod nostr_protocol_tests;

#[cfg(all(test, feature = "webrtc"))]
mod hybrid_receiver_tests;
