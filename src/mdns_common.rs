//! Common utilities for mDNS transport.
//!
//! Provides shared constants, key derivation, and data structures for
//! mDNS-based local network file transfers.

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use std::net::IpAddr;

/// Unambiguous character set for passphrase generation.
/// Excludes easily confused characters: 0/O, 1/l/I
/// Includes: uppercase (no I,O), lowercase (no l,o), digits (no 0,1), symbols
const PASSPHRASE_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*+-=?";

/// Default passphrase length
const PASSPHRASE_LENGTH: usize = 12;

/// mDNS service type for wormhole file transfers
pub const SERVICE_TYPE: &str = "_wormhole._tcp.local.";

/// TCP port range for file transfer (dynamic/private port range)
pub const PORT_RANGE_START: u16 = 49152;
pub const PORT_RANGE_END: u16 = 65535;

/// TXT record keys
pub const TXT_TRANSFER_ID: &str = "transfer_id";
pub const TXT_FILENAME: &str = "filename";
pub const TXT_FILE_SIZE: &str = "file_size";
pub const TXT_TRANSFER_TYPE: &str = "transfer_type";
pub const TXT_SALT: &str = "salt";

/// Salt length in bytes (128 bits)
pub const SALT_LENGTH: usize = 16;

/// Generate a cryptographically secure random salt.
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    rand::thread_rng().gen()
}

/// Derive a 256-bit encryption key from a passphrase and salt using Argon2id.
///
/// Parameters match the documented security settings:
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4 lanes
///
/// # Arguments
/// * `passphrase` - User-provided passphrase
/// * `salt` - Per-transfer random salt (must be SALT_LENGTH bytes)
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() != SALT_LENGTH {
        anyhow::bail!(
            "Invalid salt length: expected {} bytes, got {}",
            SALT_LENGTH,
            salt.len()
        );
    }

    let params = Params::new(
        65536, // m_cost: 64 MiB memory (in KiB)
        3,     // t_cost: 3 iterations
        4,     // p_cost: 4 lanes (parallelism)
        Some(32),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;

    Ok(key)
}

/// Generate a unique transfer ID for this session.
pub fn generate_transfer_id() -> String {
    let bytes: [u8; 8] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Generate a random passphrase using unambiguous characters.
///
/// Uses a character set that excludes easily confused characters (0/O, 1/l/I)
/// and includes uppercase, lowercase, digits, and symbols for high entropy.
pub fn generate_passphrase() -> String {
    let mut rng = rand::thread_rng();
    (0..PASSPHRASE_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..PASSPHRASE_CHARS.len());
            PASSPHRASE_CHARS[idx] as char
        })
        .collect()
}

/// Service info discovered via mDNS.
#[derive(Debug, Clone)]
pub struct MdnsServiceInfo {
    pub instance_name: String,
    pub hostname: String,
    pub port: u16,
    pub transfer_id: String,
    pub filename: String,
    pub file_size: u64,
    pub transfer_type: String,
    pub addresses: Vec<IpAddr>,
    /// Per-transfer random salt for key derivation (hex-encoded in TXT record)
    pub salt: [u8; SALT_LENGTH],
}
