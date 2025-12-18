pub mod crypto;
pub mod folder;
#[cfg(feature = "iroh")]
pub mod iroh_common;
pub mod nostr_protocol;
#[cfg(feature = "iroh")]
pub mod iroh_receiver;
#[cfg(feature = "iroh")]
pub mod iroh_sender;
pub mod transfer;
pub mod wormhole;

// Internal modules for webrtc fallback (only needed with webrtc feature)
#[cfg(feature = "webrtc")]
pub(crate) mod tmpfiles;
#[cfg(feature = "webrtc")]
pub(crate) mod tmpfiles_fallback;
pub mod nostr_pin;


#[cfg(feature = "onion")]
pub mod onion_receiver;
#[cfg(feature = "onion")]
pub mod onion_sender;

pub mod mdns_common;
pub mod mdns_receiver;
pub mod mdns_sender;

#[cfg(feature = "webrtc")]
pub mod webrtc_sender;
#[cfg(feature = "webrtc")]
pub mod webrtc_receiver;
#[cfg(feature = "webrtc")]
pub mod webrtc_common;
#[cfg(feature = "webrtc")]
pub mod nostr_signaling;
#[cfg(feature = "webrtc")]
pub mod webrtc_offline_signaling;
#[cfg(feature = "webrtc")]
pub mod webrtc_offline_sender;
#[cfg(feature = "webrtc")]
pub mod webrtc_offline_receiver;

#[cfg(test)]
mod crypto_tests;
#[cfg(test)]
mod nostr_protocol_tests;

#[cfg(test)]
#[cfg(feature = "webrtc")]
mod webrtc_receiver_tests;
