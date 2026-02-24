//! Common PIN utilities for wormhole transfers.
//!
//! Provides PIN generation with an unambiguous character set
//! for use across all transport modes (mDNS, Nostr PIN exchange, etc.).
//!
//! PIN format: 11 random characters + 1 checksum character (12 total).
//! The checksum allows early detection of typos before attempting connection.

use rand::Rng;

/// Length of the PIN code in characters (11 random + 1 checksum)
pub const PIN_LENGTH: usize = 12;

/// Character set for PIN generation (alphanumeric + safe symbols).
/// Excludes easily confused characters: 0/O, 1/I/l
pub const PIN_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz$#@+";

/// Compute checksum character for a PIN prefix.
///
/// The checksum is computed by summing the charset index of each character,
/// then taking modulo charset length to get the checksum character index.
pub fn compute_checksum(pin_prefix: &str) -> Option<char> {
    let mut sum: usize = 0;
    for c in pin_prefix.chars() {
        let idx = PIN_CHARSET.iter().position(|&ch| ch == c as u8)?;
        sum += idx;
    }
    Some(PIN_CHARSET[sum % PIN_CHARSET.len()] as char)
}

/// Validate PIN format and checksum.
///
/// Returns true if the PIN has correct length, uses only valid characters,
/// and has a valid checksum as the last character.
pub fn validate_pin(pin: &str) -> bool {
    if pin.len() != PIN_LENGTH {
        return false;
    }
    // All chars must be from charset
    if !pin.chars().all(|c| PIN_CHARSET.contains(&(c as u8))) {
        return false;
    }
    // Verify checksum (last char)
    let prefix = &pin[..PIN_LENGTH - 1];
    let expected_checksum = compute_checksum(prefix);
    let actual_checksum = pin.chars().last();
    expected_checksum == actual_checksum
}

/// Generate a random 12-character PIN with checksum.
///
/// Uses a character set that excludes easily confused characters (0/O, 1/I/l)
/// and includes uppercase, lowercase, digits, and symbols for high entropy.
/// The last character is a checksum for early typo detection.
pub fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    let prefix: String = (0..PIN_LENGTH - 1)
        .map(|_| {
            let idx = rng.gen_range(0..PIN_CHARSET.len());
            PIN_CHARSET[idx] as char
        })
        .collect();
    let checksum = compute_checksum(&prefix).unwrap();
    format!("{}{}", prefix, checksum)
}

/// Prompt user for PIN with checksum validation.
///
/// Loops on invalid PIN, pre-filling with the previous input so user can edit it.
/// Returns the validated PIN or an error if input fails.
pub fn prompt_pin() -> std::io::Result<String> {
    use rustyline::DefaultEditor;

    let mut rl = DefaultEditor::new().map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut last_input: Option<String> = None;

    loop {
        let readline = if let Some(ref prev) = last_input {
            rl.readline_with_initial("Enter corrected PIN: ", (prev, ""))
        } else {
            rl.readline("Enter PIN: ")
        };

        match readline {
            Ok(line) => {
                let pin = line.trim().to_string();

                if pin.is_empty() {
                    println!("PIN cannot be empty.");
                    continue;
                }

                if !validate_pin(&pin) {
                    println!("Invalid PIN format or checksum.");
                    last_input = Some(pin);
                    continue;
                }

                return Ok(pin);
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Interrupted",
                ));
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF",
                ));
            }
            Err(e) => {
                return Err(std::io::Error::other(e.to_string()));
            }
        }
    }
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

    #[test]
    fn test_generated_pin_has_valid_checksum() {
        // Generate multiple PINs and verify they all pass validation
        for _ in 0..100 {
            let pin = generate_pin();
            assert!(validate_pin(&pin), "Generated PIN should be valid: {}", pin);
        }
    }

    #[test]
    fn test_checksum_computation() {
        let prefix = "AAAAAAAAAAA"; // 11 chars
        let checksum = compute_checksum(prefix);
        assert!(checksum.is_some());
        // Consistent checksum for same input
        assert_eq!(checksum, compute_checksum(prefix));
    }

    #[test]
    fn test_validate_pin_wrong_length() {
        assert!(!validate_pin("short"));
        assert!(!validate_pin("this_is_way_too_long_to_be_a_pin"));
    }

    #[test]
    fn test_validate_pin_invalid_chars() {
        // Contains '0' which is not in charset
        assert!(!validate_pin("000000000000"));
        // Contains 'O' which is not in charset
        assert!(!validate_pin("OOOOOOOOOOOO"));
    }

    #[test]
    fn test_validate_pin_wrong_checksum() {
        let pin = generate_pin();
        // Corrupt the checksum (last character)
        let mut chars: Vec<char> = pin.chars().collect();
        let last_idx = chars.len() - 1;
        // Change checksum to a different valid character
        chars[last_idx] = if chars[last_idx] == '2' { '3' } else { '2' };
        let corrupted: String = chars.into_iter().collect();
        assert!(!validate_pin(&corrupted), "Corrupted PIN should be invalid");
    }

    #[test]
    fn test_validate_pin_typo_detection() {
        let pin = generate_pin();
        // Corrupt a character in the middle
        let mut chars: Vec<char> = pin.chars().collect();
        chars[5] = if chars[5] == '2' { '3' } else { '2' };
        let typo: String = chars.into_iter().collect();
        assert!(!validate_pin(&typo), "PIN with typo should be invalid");
    }
}
