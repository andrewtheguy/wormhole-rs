use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::EndpointAddr;

/// Current token format version
pub const CURRENT_VERSION: u8 = 1;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Wormhole token containing all transfer metadata
/// This is a self-describing format that includes version, protocol, and encryption info
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WormholeToken {
    /// Token format version (for future compatibility checks)
    pub version: u8,
    /// Protocol identifier (e.g., "iroh")
    pub protocol: String,
    /// Whether extra AES-256-GCM encryption layer is used
    pub extra_encrypt: bool,
    /// AES-256-GCM key (only present if extra_encrypt is true)
    pub key: Option<[u8; 32]>,
    /// Endpoint address for connection
    pub addr: EndpointAddr,
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

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        extra_encrypt,
        key: key.copied(),
        addr: addr.clone(),
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

    // Validate version
    if token.version != CURRENT_VERSION {
        anyhow::bail!(
            "Unsupported token version {}. This receiver supports version {}.",
            token.version,
            CURRENT_VERSION
        );
    }

    // Validate key consistency
    if token.extra_encrypt && token.key.is_none() {
        anyhow::bail!("Invalid token: extra_encrypt is true but no key provided");
    }

    Ok(token)
}
