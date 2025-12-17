//! PIN-based wormhole code exchange for Nostr transport.
//!
//! This module provides functions for:
//! - Generating random 12-character PINs from unambiguous characters
//! - Deriving encryption keys from PINs using Argon2id
//! - Creating and parsing PIN exchange events (kind 24243)
//! - Encrypting/decrypting wormhole codes with PIN-derived keys

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use argon2::{Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr_sdk::prelude::*;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::time::Duration;
use crate::nostr_protocol::DEFAULT_NOSTR_RELAYS;

/// Nostr event kind for PIN exchange (24243)
pub const PIN_EXCHANGE_KIND: u16 = 24243;

/// Salt length for Argon2id
pub const ARGON2_SALT_LEN: usize = 16;

/// AES-GCM nonce length
const AES_NONCE_LEN: usize = 12;

// Argon2id parameters
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
const ARGON2_PARALLELISM: u32 = 4;

/// Length of the PIN code in characters
pub const PIN_LENGTH: usize = 12;

/// Character set for PIN generation (alphanumeric + safe symbols)
/// Removed similar characters (0/O, 1/I/l) to reduce ambiguity
const PIN_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz$#@+";

/// Generate a random 12-char PIN
pub fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    (0..PIN_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..PIN_CHARSET.len());
            PIN_CHARSET[idx] as char
        })
        .collect()
}

/// PIN exchange event expiration (1 hour)
const PIN_EVENT_EXPIRATION_SECS: u64 = 3600;

/// Compute PIN hint for event filtering (first 8 hex chars of SHA256).
pub fn compute_pin_hint(pin: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..4]) // First 4 bytes = 8 hex chars
}

/// Derive a 256-bit key from PIN using Argon2id.
pub fn derive_key_from_pin(pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(output)
}

/// Generate a random salt for Argon2id.
pub fn generate_salt() -> [u8; ARGON2_SALT_LEN] {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Encrypt wormhole code with PIN-derived key.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt_wormhole_code(wormhole_code: &str, pin: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_from_pin(pin, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // Generate random nonce
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, wormhole_code.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: nonce || ciphertext || tag (tag is included in ciphertext by aes-gcm)
    let mut result = Vec::with_capacity(AES_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt wormhole code with PIN-derived key.
///
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt_wormhole_code(encrypted: &[u8], pin: &str, salt: &[u8]) -> Result<String> {
    if encrypted.len() < AES_NONCE_LEN + 16 {
        anyhow::bail!("Encrypted data too short");
    }

    let key = derive_key_from_pin(pin, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let nonce = Nonce::from_slice(&encrypted[..AES_NONCE_LEN]);
    let ciphertext = &encrypted[AES_NONCE_LEN..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed - invalid PIN or corrupted data"))?;

    String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")
}

/// Nostr event kind for PIN exchange.
pub fn pin_exchange_kind() -> Kind {
    Kind::from_u16(PIN_EXCHANGE_KIND)
}

/// Create a PIN exchange event containing the encrypted wormhole code.
///
/// Event structure:
/// - kind: 24243
/// - content: base64(encrypted_wormhole_code)
/// - tags:
///   - ["h", "<pin_hint>"] - First 8 hex chars of SHA256(PIN) for filtering
///   - ["s", "<base64(salt)>"] - Argon2id salt
///   - ["t", "<transfer_id>"] - Transfer ID
///   - ["type", "pin_exchange"] - Event type marker
///   - ["expiration", "<unix_timestamp>"] - NIP-40 expiration
pub fn create_pin_exchange_event(
    keys: &Keys,
    wormhole_code: &str,
    transfer_id: &str,
    pin: &str,
) -> Result<Event> {
    // Generate salt and encrypt wormhole code
    let salt = generate_salt();
    let encrypted = encrypt_wormhole_code(wormhole_code, pin, &salt)?;

    // Compute PIN hint for filtering
    let pin_hint = compute_pin_hint(pin);

    // Base64 encode encrypted data and salt
    let content = STANDARD.encode(&encrypted);
    let salt_b64 = STANDARD.encode(&salt);

    // Calculate expiration timestamp
    let expiration = Timestamp::now().as_secs() + PIN_EVENT_EXPIRATION_SECS;

    // Build event
    let event = EventBuilder::new(pin_exchange_kind(), content)
        .tags(vec![
            Tag::custom(TagKind::Custom("h".into()), vec![pin_hint]),
            Tag::custom(TagKind::Custom("s".into()), vec![salt_b64]),
            Tag::custom(TagKind::Custom("t".into()), vec![transfer_id.to_string()]),
            Tag::custom(TagKind::Custom("type".into()), vec!["pin_exchange".to_string()]),
            Tag::expiration(Timestamp::from(expiration)),
        ])
        .sign_with_keys(keys)
        .context("Failed to sign PIN exchange event")?;

    Ok(event)
}

/// Parse a PIN exchange event and extract encrypted data and salt.
///
/// Returns: (encrypted_data, salt)
pub fn parse_pin_exchange_event(event: &Event) -> Result<(Vec<u8>, Vec<u8>)> {
    // Validate event kind
    if event.kind != pin_exchange_kind() {
        anyhow::bail!(
            "Invalid event kind: expected {}, got {}",
            PIN_EXCHANGE_KIND,
            event.kind.as_u16()
        );
    }

    // Validate event type tag
    let event_type = event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "type")
        .and_then(|t| t.content())
        .context("Missing type tag")?;

    if event_type != "pin_exchange" {
        anyhow::bail!("Invalid event type: expected pin_exchange, got {}", event_type);
    }

    // Extract salt from "s" tag
    let salt_b64 = event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "s")
        .and_then(|t| t.content())
        .context("Missing salt tag")?;

    let salt = STANDARD
        .decode(salt_b64)
        .context("Failed to decode salt")?;

    if salt.len() != ARGON2_SALT_LEN {
        anyhow::bail!("Invalid salt length: expected {}, got {}", ARGON2_SALT_LEN, salt.len());
    }

    // Decode encrypted content
    let encrypted = STANDARD
        .decode(&event.content)
        .context("Failed to decode encrypted content")?;

    Ok((encrypted, salt))
}

/// Extract PIN hint from a PIN exchange event.
pub fn get_pin_hint(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "h")
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

/// Publish a wormhole code via PIN exchange.
///
/// Generates a PIN, encrypts the code, publishes the exchange event to default relays,
/// and returns the generated PIN.
pub async fn publish_wormhole_code_via_pin(
    keys: &Keys,
    wormhole_code: &str,
    transfer_id: &str,
) -> Result<String> {
    // Generate PIN
    let pin = generate_pin();
    
    // Create event
    let event = create_pin_exchange_event(keys, wormhole_code, transfer_id, &pin)
        .context("Failed to create PIN exchange event")?;

    println!("Connecting to Nostr relays for PIN exchange...");
    
    // Connect to relays
    let client = Client::new(keys.clone());
    for relay in DEFAULT_NOSTR_RELAYS {
        let _ = client.add_relay(relay.to_string()).await;
    }
    client.connect().await;
    
    // Publish event
    client.send_event(&event).await.context("Failed to publish PIN exchange event")?;
    
    // Give it a moment to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Disconnect
    let _ = client.disconnect().await;
    
    Ok(pin)
}

/// Fetch a wormhole code using a PIN.
///
/// Queries default relays for PIN exchange events matching the PIN,
/// and attempts to decrypt them.
pub async fn fetch_wormhole_code_via_pin(pin: &str) -> Result<String> {
    if pin.len() != PIN_LENGTH {
        anyhow::bail!("Invalid PIN length");
    }

    let pin_hint = compute_pin_hint(pin);
    
    println!("Connecting to Nostr relays...");
    let client = Client::default();
    for relay in DEFAULT_NOSTR_RELAYS {
        let _ = client.add_relay(relay.to_string()).await;
    }
    client.connect().await;
    
    // Wait for connection
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Query
    let filter = Filter::new()
        .kind(pin_exchange_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), pin_hint.clone())
        .since(Timestamp::now() - 3600)
        .limit(10);
        
    let events = client.fetch_events(filter, Duration::from_secs(10)).await
        .context("Failed to fetch events")?;
        
    let _ = client.disconnect().await;
    
    if events.is_empty() {
        anyhow::bail!("No PIN exchange event found. Check if sender is ready.");
    }
    
    // Try decrypting
    for event in events {
        if let Ok((encrypted, salt)) = parse_pin_exchange_event(&event) {
            if let Ok(code) = decrypt_wormhole_code(&encrypted, pin, &salt) {
                return Ok(code);
            }
        }
    }
    
    anyhow::bail!("Failed to decrypt wormhole code with the provided PIN.")
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
    fn test_pin_hint_consistency() {
        let pin = "ABC123456789";
        let hint1 = compute_pin_hint(pin);
        let hint2 = compute_pin_hint(pin);
        assert_eq!(hint1, hint2);
        assert_eq!(hint1.len(), 8);
    }

    #[test]
    fn test_pin_hint_different_pins() {
        let hint1 = compute_pin_hint("ABC123456789");
        let hint2 = compute_pin_hint("XYZ987654321");
        assert_ne!(hint1, hint2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pin = "Te$t12345678";
        let salt = generate_salt();
        let wormhole_code = "eyJ2ZXJzaW9uIjoyLCJwcm90b2NvbCI6Im5vc3RyIn0";

        let encrypted = encrypt_wormhole_code(wormhole_code, pin, &salt).unwrap();
        let decrypted = decrypt_wormhole_code(&encrypted, pin, &salt).unwrap();

        assert_eq!(wormhole_code, decrypted);
    }

    #[test]
    fn test_wrong_pin_fails() {
        let pin = "Te$t12345678";
        let wrong_pin = "Wr0ng!234567";
        let salt = generate_salt();
        let wormhole_code = "eyJ2ZXJzaW9uIjoyLCJwcm90b2NvbCI6Im5vc3RyIn0";

        let encrypted = encrypt_wormhole_code(wormhole_code, pin, &salt).unwrap();
        let result = decrypt_wormhole_code(&encrypted, wrong_pin, &salt);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_salt_fails() {
        let pin = "Te$t12345678";
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let wormhole_code = "iroh-wormhole-code-123";

        let encrypted = encrypt_wormhole_code(wormhole_code, pin, &salt1).unwrap();
        let result = decrypt_wormhole_code(&encrypted, pin, &salt2);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let pin = "Te$t12345678";
        let salt = [1u8; ARGON2_SALT_LEN];

        let key1 = derive_key_from_pin(pin, &salt).unwrap();
        let key2 = derive_key_from_pin(pin, &salt).unwrap();

        assert_eq!(key1, key2);
    }
}
