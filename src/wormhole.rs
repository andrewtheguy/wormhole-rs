use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::EndpointAddr;
use rand::Rng;

/// Wordlist for human-readable codes (subset for brevity)
const WORDLIST: &[&str] = &[
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "guitar", "hammer",
    "island", "jungle", "kitten", "lemon", "mango", "nectar", "orange", "piano",
    "quartz", "rabbit", "salmon", "tiger", "umbrella", "violet", "walrus", "xenon",
    "yellow", "zebra", "anchor", "breeze", "castle", "delta", "ember", "frost",
    "garden", "harbor", "ivory", "jasper", "koala", "lotus", "marble", "noble",
    "ocean", "pearl", "quest", "river", "silver", "thunder", "unity", "velvet",
    "whisper", "xenial", "yonder", "zenith", "blaze", "coral", "dawn", "echo",
    "fern", "glow", "haze", "iris", "jade", "karma", "lunar", "mystic",
];

/// Payload structure for serialization
#[derive(serde::Serialize, serde::Deserialize)]
struct WormholePayload {
    key: [u8; 32],
    addr: EndpointAddr,
}

/// Generate a wormhole code from key and endpoint address
/// Format: N-word-word-base64payload
pub fn generate_code(key: &[u8; 32], addr: &EndpointAddr) -> Result<String> {
    let mut rng = rand::thread_rng();
    
    // Create payload
    let payload = WormholePayload {
        key: *key,
        addr: addr.clone(),
    };
    
    // Serialize using postcard (compact binary format)
    let serialized = postcard::to_allocvec(&payload)
        .context("Failed to serialize wormhole payload")?;
    
    // Base64 encode the payload
    let encoded = URL_SAFE_NO_PAD.encode(&serialized);
    
    // Generate human-readable prefix
    let num: u8 = rng.gen_range(1..100);
    let word1 = WORDLIST[rng.gen_range(0..WORDLIST.len())];
    let word2 = WORDLIST[rng.gen_range(0..WORDLIST.len())];
    
    Ok(format!("{}-{}-{}-{}", num, word1, word2, encoded))
}

/// Parse a wormhole code to extract key and endpoint address
pub fn parse_code(code: &str) -> Result<([u8; 32], EndpointAddr)> {
    let parts: Vec<&str> = code.splitn(4, '-').collect();
    if parts.len() != 4 {
        anyhow::bail!("Invalid wormhole code format");
    }
    
    let encoded = parts[3];
    let serialized = URL_SAFE_NO_PAD
        .decode(encoded)
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
