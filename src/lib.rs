pub mod crypto;
pub mod folder;
pub mod iroh_common;
pub mod nostr_protocol;
pub mod receiver_iroh;
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
mod nostr_protocol_tests;
