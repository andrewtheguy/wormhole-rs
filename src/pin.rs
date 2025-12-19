//! Common PIN utilities for wormhole transfers.
//!
//! Provides PIN generation with an unambiguous character set
//! for use across all transport modes (mDNS, Nostr PIN exchange, etc.).

use rand::Rng;

/// Length of the PIN code in characters
pub const PIN_LENGTH: usize = 12;

/// Character set for PIN generation (alphanumeric + safe symbols).
/// Excludes easily confused characters: 0/O, 1/I/l
pub const PIN_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz$#@+";

/// Generate a random 12-character PIN using unambiguous characters.
///
/// Uses a character set that excludes easily confused characters (0/O, 1/I/l)
/// and includes uppercase, lowercase, digits, and symbols for high entropy.
pub fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    (0..PIN_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..PIN_CHARSET.len());
            PIN_CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_generation() {
        let pin = generate_pin();
        assert_eq!(pin.len(), PIN_LENGTH);
        // Verify all chars are from charset
        for c in pin.chars() {
            assert!(PIN_CHARSET.contains(&(c as u8)));
        }
    }

    #[test]
    fn test_pin_generation_uniqueness() {
        let pin1 = generate_pin();
        let pin2 = generate_pin();
        // Very unlikely to be the same
        assert_ne!(pin1, pin2);
    }
}
