use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use iroh::EndpointAddr;

/// Payload structure for unencrypted mode (default)
/// Only contains the endpoint address - encryption relies on iroh's QUIC/TLS
#[derive(serde::Serialize, serde::Deserialize)]
struct WormholePayload {
    addr: EndpointAddr,
}

/// Payload structure for encrypted mode (--extra-encrypt)
/// Contains both the AES-256-GCM key and endpoint address
#[derive(serde::Serialize, serde::Deserialize)]
struct WormholePayloadEncrypted {
    key: [u8; 32],
    addr: EndpointAddr,
}

/// Generate a wormhole code from endpoint address (default, unencrypted mode)
/// Format: base64(postcard(addr))
pub fn generate_code(addr: &EndpointAddr) -> Result<String> {
    let payload = WormholePayload { addr: addr.clone() };

    let serialized =
        postcard::to_allocvec(&payload).context("Failed to serialize wormhole payload")?;

    Ok(STANDARD.encode(&serialized))
}

/// Generate a wormhole code with encryption key (--extra-encrypt mode)
/// Format: base64(postcard(key + addr))
pub fn generate_code_encrypted(key: &[u8; 32], addr: &EndpointAddr) -> Result<String> {
    let payload = WormholePayloadEncrypted {
        key: *key,
        addr: addr.clone(),
    };

    let serialized =
        postcard::to_allocvec(&payload).context("Failed to serialize wormhole payload")?;

    Ok(STANDARD.encode(&serialized))
}

/// Validate wormhole code format without fully parsing it
/// Returns Ok(()) if the format looks valid, Err with a helpful message otherwise
pub fn validate_code_format(code: &str) -> Result<()> {
    let code = code.trim();

    if code.is_empty() {
        anyhow::bail!("Wormhole code cannot be empty");
    }

    // Check for invalid characters (base64 standard uses A-Z, a-z, 0-9, +, /, =)
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        anyhow::bail!(
            "Invalid wormhole code: contains invalid characters. Expected base64-encoded string."
        );
    }

    // Minimum length check: minimal EndpointAddr data (no key in default mode)
    // Base64 encodes 3 bytes into 4 chars, so minimum ~20+ bytes payload = ~30+ chars
    if code.len() < 30 {
        anyhow::bail!("Invalid wormhole code: too short. Make sure you copied the entire code.");
    }

    // Try to decode base64
    let decoded = STANDARD
        .decode(code)
        .context("Invalid wormhole code: not valid base64 encoding")?;

    // Check minimum decoded length (some bytes for EndpointAddr)
    if decoded.len() < 10 {
        anyhow::bail!("Invalid wormhole code: decoded data too short");
    }

    Ok(())
}

/// Parse a wormhole code to extract endpoint address (default, unencrypted mode)
pub fn parse_code(code: &str) -> Result<EndpointAddr> {
    // Validate format first for better error messages
    validate_code_format(code)?;

    let serialized = STANDARD
        .decode(code.trim())
        .context("Failed to decode wormhole code")?;

    let payload: WormholePayload = postcard::from_bytes(&serialized).context(
        "Invalid wormhole code: failed to parse payload. Make sure the code is correct.",
    )?;

    Ok(payload.addr)
}

/// Parse a wormhole code to extract key and endpoint address (--extra-encrypt mode)
pub fn parse_code_encrypted(code: &str) -> Result<([u8; 32], EndpointAddr)> {
    // Validate format first for better error messages
    validate_code_format(code)?;

    let serialized = STANDARD
        .decode(code.trim())
        .context("Failed to decode wormhole code")?;

    let payload: WormholePayloadEncrypted = postcard::from_bytes(&serialized).context(
        "Invalid wormhole code: failed to parse payload. Make sure the code is correct.",
    )?;

    Ok((payload.key, payload.addr))
}
