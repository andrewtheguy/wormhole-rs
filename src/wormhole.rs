use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::{EndpointAddr, RelayUrl};

/// Current token format version
pub const CURRENT_VERSION: u8 = 2;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Protocol identifier for nostr transport
pub const PROTOCOL_NOSTR: &str = "nostr";

/// Protocol identifier for tor transport
pub const PROTOCOL_TOR: &str = "tor";

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
    /// Create from a full EndpointAddr, stripping IP addresses
    pub fn from_endpoint_addr(addr: &EndpointAddr) -> Self {
        let relay = addr.relay_urls().next().map(|r| r.to_string());
        Self {
            id: addr.id.to_string(),
            relay,
        }
    }

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
    /// Protocol identifier (e.g., "iroh" or "nostr")
    pub protocol: String,
    /// Whether extra AES-256-GCM encryption layer is used
    pub extra_encrypt: bool,
    /// AES-256-GCM key as base64 string (only present if extra_encrypt is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Minimal endpoint address for connection (None for nostr-only transfers)
    /// Contains only node ID and relay URL - IP addresses are auto-discovered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<MinimalAddr>,

    // Version 2 fields (Nostr-specific):
    /// Sender's ephemeral Nostr public key (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_sender_pubkey: Option<String>,
    /// List of Nostr relay URLs (only for legacy mode; omitted in outbox mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_relays: Option<Vec<String>>,
    /// Unique transfer session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_transfer_id: Option<String>,
    /// Original filename (for Nostr transfers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_filename: Option<String>,
    /// Transfer type: "file" (default) or "folder" (tar archive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_transfer_type: Option<String>,
    /// Whether to use NIP-65 Outbox model for relay discovery
    /// When true, receiver discovers relays via NIP-65 from well-known bridge relays
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_use_outbox: Option<bool>,

    // Version 2 fields (Tor-specific):
    /// Onion address for Tor hidden service (e.g., "abc123...xyz.onion")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,
}

/// Generate a wormhole code from endpoint address
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `addr` - The endpoint address to connect to
/// * `extra_encrypt` - Whether to include an AES-256-GCM encryption key
/// * `key` - The encryption key (required if extra_encrypt is true)
pub fn generate_code(
    addr: &EndpointAddr,
    extra_encrypt: bool,
    key: Option<&[u8; 32]>,
) -> Result<String> {
    if extra_encrypt && key.is_none() {
        anyhow::bail!("Encryption key required when extra_encrypt is true");
    }

    // Use MinimalAddr to strip IP addresses - they're auto-discovered by iroh
    let minimal_addr = MinimalAddr::from_endpoint_addr(addr);

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        extra_encrypt,
        key: key.map(|k| URL_SAFE_NO_PAD.encode(k)),
        addr: Some(minimal_addr),
        nostr_sender_pubkey: None,
        nostr_relays: None,
        nostr_transfer_id: None,
        nostr_filename: None,
        nostr_transfer_type: None,
        nostr_use_outbox: None,
        onion_address: None,
    };

    let serialized =
        serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Generate a wormhole code for Nostr transfer
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `key` - The AES-256-GCM encryption key (always required for Nostr)
/// * `sender_pubkey` - Sender's ephemeral Nostr public key (hex)
/// * `transfer_id` - Unique transfer session ID
/// * `relays` - List of Nostr relay URLs (required for legacy mode, None for outbox mode)
/// * `filename` - Original filename
/// * `use_outbox` - Whether to use NIP-65 Outbox model for relay discovery
/// * `transfer_type` - "file" or "folder"
pub fn generate_nostr_code(
    key: &[u8; 32],
    sender_pubkey: String,
    transfer_id: String,
    relays: Option<Vec<String>>,
    filename: String,
    use_outbox: bool,
    transfer_type: &str,
) -> Result<String> {
    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_NOSTR.to_string(),
        extra_encrypt: true, // Always true for Nostr
        key: Some(URL_SAFE_NO_PAD.encode(key)),
        addr: None,
        nostr_sender_pubkey: Some(sender_pubkey),
        nostr_relays: relays,
        nostr_transfer_id: Some(transfer_id),
        nostr_filename: Some(filename),
        nostr_transfer_type: Some(transfer_type.to_string()),
        nostr_use_outbox: if use_outbox { Some(true) } else { None },
        onion_address: None,
    };

    let serialized =
        serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Generate a wormhole code for Tor transfer
/// Format: base64url(json(WormholeToken))
///
/// # Arguments
/// * `onion_address` - The .onion address of the hidden service
/// * `extra_encrypt` - Whether to include an AES-256-GCM encryption key
/// * `key` - The encryption key (required if extra_encrypt is true)
pub fn generate_tor_code(
    onion_address: String,
    extra_encrypt: bool,
    key: Option<&[u8; 32]>,
) -> Result<String> {
    if extra_encrypt && key.is_none() {
        anyhow::bail!("Encryption key required when extra_encrypt is true");
    }

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_TOR.to_string(),
        extra_encrypt,
        key: key.map(|k| URL_SAFE_NO_PAD.encode(k)),
        addr: None,
        nostr_sender_pubkey: None,
        nostr_relays: None,
        nostr_transfer_id: None,
        nostr_filename: None,
        nostr_transfer_type: None,
        nostr_use_outbox: None,
        onion_address: Some(onion_address),
    };

    let serialized =
        serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

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

    let token: WormholeToken = serde_json::from_slice(&serialized).context(
        "Invalid wormhole code: failed to parse token. Make sure the code is correct.",
    )?;

    // Validate version (support both v1 and v2)
    if token.version != 1 && token.version != 2 {
        anyhow::bail!(
            "Unsupported token version {}. This receiver supports versions 1 and 2.",
            token.version
        );
    }

    // Validate protocol for v2 tokens
    if token.version == 2 {
        if token.protocol != PROTOCOL_IROH
            && token.protocol != PROTOCOL_NOSTR
            && token.protocol != PROTOCOL_TOR
        {
            anyhow::bail!(
                "Invalid protocol '{}' in v2 token. Supported protocols: '{}', '{}', '{}'",
                token.protocol,
                PROTOCOL_IROH,
                PROTOCOL_NOSTR,
                PROTOCOL_TOR
            );
        }
    }

    // Validate key consistency
    if token.extra_encrypt && token.key.is_none() {
        anyhow::bail!("Invalid token: extra_encrypt is true but no key provided");
    }

    // Validate key format if present
    if let Some(ref key_str) = token.key {
        let key_bytes = URL_SAFE_NO_PAD
            .decode(key_str)
            .context("Invalid key format: not valid base64")?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "Invalid key length: expected 32 bytes, got {}",
                key_bytes.len()
            );
        }
    }

    // For version 1 tokens, ensure addr is present (backward compatibility)
    if token.version == 1 && token.addr.is_none() {
        anyhow::bail!("Invalid v1 token: missing endpoint address");
    }

    // For version 2 with iroh protocol, ensure addr is present
    if token.version == 2 && token.protocol == PROTOCOL_IROH && token.addr.is_none() {
        anyhow::bail!("Invalid v2 iroh token: missing endpoint address");
    }

    // For version 2 with nostr protocol, ensure nostr fields are present
    if token.version == 2 && token.protocol == PROTOCOL_NOSTR {
        if token.nostr_sender_pubkey.is_none() {
            anyhow::bail!("Invalid v2 nostr token: missing sender pubkey");
        }
        // nostr_relays is optional if nostr_use_outbox is true (relays discovered via NIP-65)
        if !token.nostr_use_outbox.unwrap_or(false) && token.nostr_relays.is_none() {
            anyhow::bail!("Invalid v2 nostr token: missing relay list");
        }
        if token.nostr_transfer_id.is_none() {
            anyhow::bail!("Invalid v2 nostr token: missing transfer ID");
        }
        if token.key.is_none() {
            anyhow::bail!("Invalid v2 nostr token: encryption key required for Nostr transfers");
        }
    }

    // For version 2 with tor protocol, ensure onion_address is present
    if token.version == 2 && token.protocol == PROTOCOL_TOR {
        if token.onion_address.is_none() {
            anyhow::bail!("Invalid v2 tor token: missing onion address");
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
