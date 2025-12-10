use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use iroh::EndpointAddr;

/// Payload structure for serialization
#[derive(serde::Serialize, serde::Deserialize)]
struct WormholePayload {
    key: [u8; 32],
    addr: EndpointAddr,
}

/// Generate a wormhole code from key and endpoint address
/// Format: base64(postcard(key + addr))
pub fn generate_code(key: &[u8; 32], addr: &EndpointAddr) -> Result<String> {
    // Create payload
    let payload = WormholePayload {
        key: *key,
        addr: addr.clone(),
    };
    
    // Serialize using postcard (compact binary format)
    let serialized = postcard::to_allocvec(&payload)
        .context("Failed to serialize wormhole payload")?;
    
    // Base64 encode (standard encoding uses + and / instead of - and _)
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
    if !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        anyhow::bail!("Invalid wormhole code: contains invalid characters. Expected base64-encoded string.");
    }

    // Minimum length check: 32-byte key + minimal EndpointAddr data
    // Base64 encodes 3 bytes into 4 chars, so minimum ~50+ bytes payload = ~70+ chars
    if code.len() < 50 {
        anyhow::bail!("Invalid wormhole code: too short. Make sure you copied the entire code.");
    }

    // Try to decode base64
    let decoded = STANDARD
        .decode(code)
        .context("Invalid wormhole code: not valid base64 encoding")?;

    // Check minimum decoded length (32 bytes for key + some bytes for EndpointAddr)
    if decoded.len() < 40 {
        anyhow::bail!("Invalid wormhole code: decoded data too short");
    }

    Ok(())
}

/// Parse a wormhole code to extract key and endpoint address
pub fn parse_code(code: &str) -> Result<([u8; 32], EndpointAddr)> {
    // Validate format first for better error messages
    validate_code_format(code)?;

    let serialized = STANDARD
        .decode(code.trim())
        .context("Failed to decode wormhole code")?;

    let payload: WormholePayload = postcard::from_bytes(&serialized)
        .context("Invalid wormhole code: failed to parse payload. Make sure the code is correct.")?;

    Ok((payload.key, payload.addr))
}
