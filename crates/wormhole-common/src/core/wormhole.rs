use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(feature = "iroh-addr")]
use iroh::{EndpointAddr, RelayUrl};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current token format version
pub const CURRENT_VERSION: u8 = 4;

/// TTL for wormhole codes in seconds (30 minutes)
pub const CODE_TTL_SECS: u64 = 30 * 60;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Protocol identifier for tor transport
pub const PROTOCOL_TOR: &str = "tor";

/// Protocol identifier for webrtc transport (WebRTC + Nostr signaling)
pub const PROTOCOL_WEBRTC: &str = "webrtc";

/// Validate a Tor v3 onion address format.
///
/// A valid v3 onion address:
/// - Ends with ".onion"
/// - Has exactly 56 base32 characters before the ".onion" suffix
/// - Uses only lowercase letters a-z and digits 2-7 (base32 alphabet)
///
/// # Returns
/// `Ok(())` if valid, `Err` with descriptive message if invalid.
fn validate_onion_address(addr: &str) -> Result<()> {
    if !addr.ends_with(".onion") {
        anyhow::bail!("Onion address must end with '.onion'");
    }

    let without_suffix = addr.strip_suffix(".onion").unwrap();

    // V3 onion addresses are exactly 56 base32 characters
    if without_suffix.len() != 56 {
        anyhow::bail!(
            "Invalid v3 onion address: expected 56 characters before '.onion', got {}",
            without_suffix.len()
        );
    }

    // Base32 alphabet for Tor: a-z and 2-7
    if !without_suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
    {
        anyhow::bail!("Invalid v3 onion address: contains invalid characters (expected a-z, 2-7)");
    }

    Ok(())
}

/// Minimal address for serialization - only contains node ID and relay URL
/// IP addresses are auto-discovered by iroh, so we don't need them in the wormhole code
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MinimalAddr {
    /// Node ID (hex-encoded public key)
    pub id: String,
    /// Optional relay URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl MinimalAddr {
    #[cfg(feature = "iroh-addr")]
    /// Create from a full EndpointAddr, stripping IP addresses
    pub fn from_endpoint_addr(addr: &EndpointAddr) -> Self {
        let relay = addr.relay_urls().next().map(|r| r.to_string());
        Self {
            id: addr.id.to_string(),
            relay,
        }
    }

    #[cfg(feature = "iroh-addr")]

    /// Convert back to EndpointAddr
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr> {
        let id = self
            .id
            .parse()
            .context("Failed to parse endpoint ID from wormhole code")?;
        let mut addr = EndpointAddr::new(id);
        if let Some(ref relay_str) = self.relay {
            let relay_url: RelayUrl = relay_str
                .parse()
                .context("Failed to parse relay URL from wormhole code")?;
            addr = addr.with_relay_url(relay_url);
        }
        Ok(addr)
    }
}

/// Wormhole token containing all transfer metadata
/// This is a self-describing format that includes version, protocol, and encryption info
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WormholeToken {
    /// Token format version (for future compatibility checks)
    pub version: u8,
    /// Protocol identifier (e.g., "iroh", "tor", "webrtc")
    pub protocol: String,
    /// Unix timestamp when this token was created (for TTL validation)
    pub created_at: u64,
    /// AES-256-GCM key as base64 string (always present for iroh/tor/webrtc)
    pub key: String,
    /// Minimal endpoint address for connection (None for non-iroh transports)
    /// Contains only node ID and relay URL - IP addresses are auto-discovered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<MinimalAddr>,

    // Version 2 fields (Tor-specific):
    /// Onion address for Tor hidden service (e.g., "abc123...xyz.onion")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,

    // Version 2 fields (WebRTC-specific):
    /// Sender's ephemeral Nostr public key for signaling (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_sender_pubkey: Option<String>,
    /// Unique transfer session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_transfer_id: Option<String>,
    /// List of Nostr relay URLs for signaling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_relays: Option<Vec<String>>,
    /// Transfer type: "file" or "folder"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_transfer_type: Option<String>,
    /// Original filename for webrtc transfers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_filename: Option<String>,
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is set before Unix epoch")
        .as_secs()
}

/// Generate a wormhole code from endpoint address
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `addr` - The endpoint address to connect to
/// * `key` - The encryption key (required)
#[cfg(feature = "iroh-addr")]
pub fn generate_code(addr: &EndpointAddr, key: &[u8; 32]) -> Result<String> {
    // Use MinimalAddr to strip IP addresses - they're auto-discovered by iroh
    let minimal_addr = MinimalAddr::from_endpoint_addr(addr);

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        created_at: current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: Some(minimal_addr),
        onion_address: None,
        webrtc_sender_pubkey: None,
        webrtc_transfer_id: None,
        webrtc_relays: None,
        webrtc_transfer_type: None,
        webrtc_filename: None,
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Generate a wormhole code for Tor transfer
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `onion_address` - The .onion address of the hidden service (v3 format)
/// * `key` - The encryption key (required)
///
/// # Errors
///
/// Returns an error if the onion address is not a valid v3 format.
pub fn generate_tor_code(onion_address: String, key: &[u8; 32]) -> Result<String> {
    // Validate onion address format early to fail fast
    validate_onion_address(&onion_address).context("Invalid onion address in generate_tor_code")?;

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_TOR.to_string(),
        created_at: current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: None,
        onion_address: Some(onion_address),
        webrtc_sender_pubkey: None,
        webrtc_transfer_id: None,
        webrtc_relays: None,
        webrtc_transfer_type: None,
        webrtc_filename: None,
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Generate a wormhole code for webrtc transfer (WebRTC + Nostr signaling)
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `key` - The AES-256-GCM encryption key (always required for webrtc)
/// * `sender_pubkey` - Sender's ephemeral Nostr public key for signaling (hex)
/// * `transfer_id` - Unique transfer session ID
/// * `relays` - List of Nostr relay URLs for signaling
/// * `filename` - Original filename
/// * `transfer_type` - "file" or "folder"
///
/// # Errors
///
/// Returns an error if `transfer_type` is not "file" or "folder".
pub fn generate_webrtc_code(
    key: &[u8; 32],
    sender_pubkey: String,
    transfer_id: String,
    relays: Option<Vec<String>>,
    filename: String,
    transfer_type: &str,
) -> Result<String> {
    // Validate transfer_type early to fail fast
    if transfer_type != "file" && transfer_type != "folder" {
        anyhow::bail!(
            "Invalid transfer_type: '{}' (expected 'file' or 'folder')",
            transfer_type
        );
    }

    // Validate sender_pubkey format (hex string)
    if sender_pubkey.is_empty() || !sender_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid sender_pubkey: must be non-empty hex string");
    }

    // Validate transfer_id is non-empty
    if transfer_id.trim().is_empty() {
        anyhow::bail!("Invalid transfer_id: cannot be empty");
    }

    // Validate filename is non-empty and doesn't contain path separators
    if filename.trim().is_empty() {
        anyhow::bail!("Invalid filename: cannot be empty");
    }
    if filename.contains('/') || filename.contains('\\') {
        anyhow::bail!("Invalid filename: cannot contain path separators");
    }

    // Validate relay URLs if provided
    if let Some(ref relay_list) = relays {
        if relay_list.is_empty() {
            anyhow::bail!("Invalid relays: list cannot be empty if provided");
        }
        for relay in relay_list {
            if !relay.starts_with("ws://") && !relay.starts_with("wss://") {
                anyhow::bail!(
                    "Invalid relay URL '{}': must start with ws:// or wss://",
                    relay
                );
            }
        }
    }

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_WEBRTC.to_string(),
        created_at: current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: None,
        onion_address: None,
        webrtc_sender_pubkey: Some(sender_pubkey),
        webrtc_transfer_id: Some(transfer_id),
        webrtc_relays: relays,
        webrtc_transfer_type: Some(transfer_type.to_string()),
        webrtc_filename: Some(filename),
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Validate wormhole code format without fully parsing it
/// Returns Ok(()) if the format looks valid, Err with a helpful message otherwise
pub fn validate_code_format(code: &str) -> Result<()> {
    let code = code.trim();

    if code.is_empty() {
        anyhow::bail!("Wormhole code cannot be empty");
    }

    // Check for invalid characters (base64 URL-safe uses A-Z, a-z, 0-9, -, _)
    // Note: no padding (=) in URL_SAFE_NO_PAD
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Invalid wormhole code: contains invalid characters. Expected base64url-encoded string."
        );
    }

    // Minimum length check: minimal token data
    // Base64 encodes 3 bytes into 4 chars, so minimum ~20+ bytes payload = ~30+ chars
    if code.len() < 30 {
        anyhow::bail!("Invalid wormhole code: too short. Make sure you copied the entire code.");
    }

    // Try to decode base64
    let decoded = URL_SAFE_NO_PAD
        .decode(code)
        .context("Invalid wormhole code: not valid base64url encoding")?;

    // Check minimum decoded length (some bytes for token)
    if decoded.len() < 10 {
        anyhow::bail!("Invalid wormhole code: decoded data too short");
    }

    Ok(())
}

/// Parse a wormhole code to extract the token
/// Returns a WormholeToken containing all transfer metadata
pub fn parse_code(code: &str) -> Result<WormholeToken> {
    // Validate format first for better error messages
    validate_code_format(code)?;

    let serialized = URL_SAFE_NO_PAD
        .decode(code.trim())
        .context("Failed to decode wormhole code")?;

    let token: WormholeToken = serde_json::from_slice(&serialized)
        .context("Invalid wormhole code: failed to parse token. Make sure the code is correct.")?;

    // Validate version
    if token.version != CURRENT_VERSION {
        anyhow::bail!(
            "Unsupported token version {}. This receiver requires version {}.",
            token.version,
            CURRENT_VERSION
        );
    }

    // Validate protocol
    if token.protocol != PROTOCOL_IROH
        && token.protocol != PROTOCOL_TOR
        && token.protocol != PROTOCOL_WEBRTC
    {
        anyhow::bail!(
            "Invalid protocol '{}'. Supported protocols: '{}', '{}', '{}'",
            token.protocol,
            PROTOCOL_IROH,
            PROTOCOL_TOR,
            PROTOCOL_WEBRTC
        );
    }

    // Validate TTL
    let now = current_timestamp();
    if token.created_at > now + 60 {
        // Allow 60s clock skew into future
        anyhow::bail!("Invalid token: created_at is in the future. Check system clock.");
    }
    let age = now.saturating_sub(token.created_at);
    if age > CODE_TTL_SECS {
        let minutes = age / 60;
        anyhow::bail!(
            "Token expired: code is {} minutes old (max {} minutes). \
             Please request a new code from the sender.",
            minutes,
            CODE_TTL_SECS / 60
        );
    }

    // Validate key format (required for all current protocols)
    let key_bytes = URL_SAFE_NO_PAD
        .decode(&token.key)
        .context("Invalid key format: not valid base64")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    // For iroh protocol, ensure addr is present
    if token.protocol == PROTOCOL_IROH && token.addr.is_none() {
        anyhow::bail!("Invalid iroh token: missing endpoint address");
    }

    // For tor protocol, ensure onion_address is present and valid
    if token.protocol == PROTOCOL_TOR {
        match &token.onion_address {
            None => anyhow::bail!("Invalid tor token: missing onion address"),
            Some(addr) => {
                validate_onion_address(addr).context("Invalid tor token")?;
            }
        }
    }

    // For webrtc protocol, ensure webrtc fields are present and valid
    if token.protocol == PROTOCOL_WEBRTC {
        if token.webrtc_sender_pubkey.is_none() {
            anyhow::bail!("Invalid webrtc token: missing sender pubkey");
        }
        if token.webrtc_transfer_id.is_none() {
            anyhow::bail!("Invalid webrtc token: missing transfer ID");
        }
        if token.webrtc_filename.is_none() {
            anyhow::bail!("Invalid webrtc token: missing filename");
        }
        match token.webrtc_transfer_type.as_deref() {
            Some("file") | Some("folder") => {}
            Some(invalid) => {
                anyhow::bail!(
                    "Invalid webrtc token: unsupported transfer type '{}' (expected 'file' or 'folder')",
                    invalid
                );
            }
            None => {
                anyhow::bail!("Invalid webrtc token: missing transfer type");
            }
        }
    }

    Ok(token)
}

/// Helper function to decode a base64 key from WormholeToken into a 32-byte array
pub fn decode_key(key_str: &str) -> Result<[u8; 32]> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(key_str)
        .context("Failed to decode base64 key")?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}
