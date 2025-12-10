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

/// Parse a wormhole code to extract key and endpoint address
pub fn parse_code(code: &str) -> Result<([u8; 32], EndpointAddr)> {
    let serialized = STANDARD
        .decode(code.trim())
        .context("Failed to decode wormhole code")?;
    
    let payload: WormholePayload = postcard::from_bytes(&serialized)
        .context("Failed to deserialize wormhole payload")?;
    
    Ok((payload.key, payload.addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_roundtrip() {
        // This test requires a valid EndpointAddr which needs an actual endpoint
        // For unit testing, we'd mock this
    }
}
