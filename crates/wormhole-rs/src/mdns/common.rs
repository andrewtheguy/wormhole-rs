//! Common utilities for mDNS transport.
//!
//! Provides shared constants and data structures for mDNS-based local
//! network file transfers. Key derivation is handled by SPAKE2 PAKE.

use std::net::IpAddr;

// Re-export PIN utilities from common pin module
pub use wormhole_common::auth::pin::generate_pin;

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
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().r#gen();
    hex::encode(bytes)
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
