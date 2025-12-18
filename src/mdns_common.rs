//! Common utilities for mDNS transport.
//!
//! Provides shared constants and data structures for mDNS-based local
//! network file transfers. Key derivation is handled by SPAKE2 PAKE.

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
}
