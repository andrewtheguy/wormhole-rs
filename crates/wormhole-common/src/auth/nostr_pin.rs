//! PIN-based wormhole code exchange for Nostr transport.
//!
//! This module provides functions for:
//! - Deriving encryption keys from PINs using Argon2id
//! - Creating and parsing PIN exchange events (kind 24243)
//! - Encrypting/decrypting wormhole codes with PIN-derived keys
//!
//! # Security Notes
//!
//! ## PIN Hint Design
//!
//! The PIN hint (first 32 bits of SHA-256(PIN)) is published with events to enable
//! efficient relay filtering. This design is secure because:
//!
//! - **Ephemeral nature**: Events expire after 1 hour (NIP-40 TTL), not persistent identity
//! - **Strong PIN entropy**: 12-char PIN has ~65 bits of entropy
//! - **One-way hash**: SHA-256 cannot be reversed; attacker must brute-force 2^65 hashes
//! - **Argon2id protection**: Even with PIN, attacker needs per-event salt + expensive KDF
//! - **Single-use**: Each transfer generates a new PIN, no rainbow table benefit
//!
//! The 32-bit hint provides ~4 billion buckets for efficient relay filtering while
//! the PIN's entropy and Argon2id KDF (64 MiB memory, 3 iterations) provide the
//! actual security. Brute-forcing 2^65 SHA-256 hashes to find the PIN would take
//! ~117 years on modern GPUs, making the hint size irrelevant to security.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use nostr_sdk::prelude::*;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use crate::auth::pin::{PIN_LENGTH, generate_pin};

/// Default public Nostr relays for PIN exchange
/// These should match the relays used in signaling for consistency
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    //"wss://relay.damus.io", // acceptable for index queries; not recommended for high-volume operations due to rate limiting
    //"wss://relay.nostr.band",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

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

/// PIN exchange event expiration (1 hour)
const PIN_EVENT_EXPIRATION_SECS: u64 = 3600;

/// Timeout for waiting for relay connections
const RELAY_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to Nostr relays for PIN operations.
///
/// Creates a client, adds the default relays, connects, and waits for at least
/// one successful connection. Returns the connected client or an error.
///
/// # Arguments
/// * `keys` - Optional signing keys. If provided, client is created with these keys.
///   If None, a default client is created.
/// * `purpose` - Description for log messages (e.g., "PIN exchange", "PIN lookup")
async fn connect_to_relays(keys: Option<&Keys>, purpose: &str) -> Result<Client> {
    let client = match keys {
        Some(k) => Client::new(k.clone()),
        None => Client::default(),
    };

    let mut relays_added = 0;
    for relay in DEFAULT_NOSTR_RELAYS {
        match client.add_relay(relay.to_string()).await {
            Ok(_) => {
                relays_added += 1;
                log::debug!("Added relay: {}", relay);
            }
            Err(e) => {
                log::warn!("Failed to add relay {}: {}", relay, e);
            }
        }
    }

    if relays_added == 0 {
        anyhow::bail!("Failed to add any relays for {}", purpose);
    }

    // Initiate connections to all added relays
    client.connect().await;

    // Wait for at least one relay to establish connection
    client.wait_for_connection(RELAY_CONNECTION_TIMEOUT).await;

    // Check connection status for each relay
    let relay_statuses = client.relays().await;
    let mut connected_relays = Vec::new();
    let mut failed_relays = Vec::new();

    for (url, relay) in &relay_statuses {
        if relay.is_connected() {
            connected_relays.push(url.to_string());
        } else {
            failed_relays.push(url.to_string());
        }
    }

    if connected_relays.is_empty() {
        client.disconnect().await;
        anyhow::bail!(
            "Failed to connect to any relays after {:?}. Tried: {}",
            RELAY_CONNECTION_TIMEOUT,
            failed_relays.join(", ")
        );
    }

    log::debug!(
        "Connected to {}/{} relays for {}: {}",
        connected_relays.len(),
        relays_added,
        purpose,
        connected_relays.join(", ")
    );

    if !failed_relays.is_empty() {
        log::debug!("Failed to connect to: {}", failed_relays.join(", "));
    }

    Ok(client)
}

/// Timeout for verifying event was published
const EVENT_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval for polling event verification
const EVENT_VERIFICATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Compute PIN hint for event filtering (first 8 hex chars of SHA-256).
///
/// Uses 32 bits (4 bytes) for efficient relay filtering (~4 billion buckets).
/// This is safe because PIN events are ephemeral (1-hour TTL) and the PIN's
/// ~65-bit entropy makes brute-forcing SHA-256 infeasible. See module docs.
pub fn compute_pin_hint(pin: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..4]) // First 4 bytes = 8 hex chars = 32 bits
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
///   - ["h", "<pin_hint>"] - First 8 hex chars of SHA-256(PIN) for filtering (32 bits)
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
    let salt_b64 = STANDARD.encode(salt);

    // Calculate expiration timestamp
    let expiration = Timestamp::now().as_secs() + PIN_EVENT_EXPIRATION_SECS;

    // Build event
    let event = EventBuilder::new(pin_exchange_kind(), content)
        .tags(vec![
            Tag::custom(TagKind::Custom("h".into()), vec![pin_hint]),
            Tag::custom(TagKind::Custom("s".into()), vec![salt_b64]),
            Tag::custom(TagKind::Custom("t".into()), vec![transfer_id.to_string()]),
            Tag::custom(
                TagKind::Custom("type".into()),
                vec!["pin_exchange".to_string()],
            ),
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
        anyhow::bail!(
            "Invalid event type: expected pin_exchange, got {}",
            event_type
        );
    }

    // Extract salt from "s" tag
    let salt_b64 = event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "s")
        .and_then(|t| t.content())
        .context("Missing salt tag")?;

    let salt = STANDARD.decode(salt_b64).context("Failed to decode salt")?;

    if salt.len() != ARGON2_SALT_LEN {
        anyhow::bail!(
            "Invalid salt length: expected {}, got {}",
            ARGON2_SALT_LEN,
            salt.len()
        );
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

    eprintln!("Connecting to Nostr relays for PIN exchange...");

    // Connect to relays
    let client = connect_to_relays(Some(keys), "PIN exchange").await?;

    // Publish event
    let send_result = client.send_event(&event).await;

    // Handle send result before verification
    let output = match send_result {
        Ok(o) => o,
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!(
                "Failed to publish PIN exchange event: {}",
                e
            ));
        }
    };

    // Verify event was published by querying for it
    let event_id = event.id;
    let pin_hint = compute_pin_hint(&pin);
    let verification_filter = Filter::new()
        .kind(pin_exchange_kind())
        .id(event_id)
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), pin_hint);

    let start = std::time::Instant::now();
    let mut verified = false;

    while start.elapsed() < EVENT_VERIFICATION_TIMEOUT {
        match client
            .fetch_events(verification_filter.clone(), Duration::from_secs(2))
            .await
        {
            Ok(events) if !events.is_empty() => {
                verified = true;
                log::debug!("PIN exchange event verified on relay");
                break;
            }
            _ => {
                tokio::time::sleep(EVENT_VERIFICATION_POLL_INTERVAL).await;
            }
        }
    }

    client.disconnect().await;

    if !verified {
        // Even though relays acknowledged the event, we couldn't verify it's actually
        // retrievable. This means the receiver likely won't be able to find it.
        anyhow::bail!(
            "PIN exchange event was acknowledged by {} relay(s) but could not be verified. \
             The receiver may not be able to retrieve the code. Please try again.",
            output.success.len()
        );
    }

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

    eprintln!("Connecting to Nostr relays...");

    // Connect to relays
    let client = connect_to_relays(None, "PIN lookup").await?;

    // Query
    let filter = Filter::new()
        .kind(pin_exchange_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), pin_hint.clone())
        .since(Timestamp::now() - 3600)
        .limit(10);

    let events_res = client.fetch_events(filter, Duration::from_secs(10)).await;

    // Disconnect (always, regardless of fetch result)
    client.disconnect().await;

    // Handle fetch result
    let events = events_res.context("Failed to fetch events")?;

    if events.is_empty() {
        anyhow::bail!("No PIN exchange event found. Check if sender is ready.");
    }

    // Try decrypting each event
    for (index, event) in events.iter().enumerate() {
        let event_id = event.id.to_hex();
        match parse_pin_exchange_event(event) {
            Ok((encrypted, salt)) => match decrypt_wormhole_code(&encrypted, pin, &salt) {
                Ok(code) => return Ok(code),
                Err(e) => {
                    log::debug!(
                        "Failed to decrypt event {} (index {}): {}",
                        event_id,
                        index,
                        e
                    );
                }
            },
            Err(e) => {
                log::debug!(
                    "Failed to parse event {} (index {}): {}",
                    event_id,
                    index,
                    e
                );
            }
        }
    }

    anyhow::bail!("Failed to decrypt wormhole code with the provided PIN.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_hint_consistency() {
        let pin = "ABC123456789";
        let hint1 = compute_pin_hint(pin);
        let hint2 = compute_pin_hint(pin);
        assert_eq!(hint1, hint2);
        // 8 hex chars = 32 bits for efficient filtering (safe for ephemeral events)
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
