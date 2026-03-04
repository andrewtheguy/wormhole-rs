#[cfg(feature = "nostr")]
pub mod nostr_protocol;

#[cfg(all(test, feature = "nostr"))]
mod nostr_protocol_test;
