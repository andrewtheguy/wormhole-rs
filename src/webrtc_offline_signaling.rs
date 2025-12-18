//! Offline WebRTC signaling via copy/paste JSON
//!
//! This module provides signaling for WebRTC connections without any servers.
//! Users manually copy and paste JSON between sender and receiver to establish
//! the connection. This is useful for direct LAN transfers without internet.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;

use crate::nostr_signaling::IceCandidatePayload;

// ============================================================================
// JSON Signaling Structures
// ============================================================================

/// Transfer information included in the offer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferInfo {
    pub filename: String,
    pub file_size: u64,
    pub transfer_type: String, // "file" or "folder"
    /// Encryption key (hex-encoded 32 bytes)
    pub encryption_key: String,
}

/// Offline offer containing SDP, ICE candidates, and transfer info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineOffer {
    pub sdp: String,
    pub ice_candidates: Vec<IceCandidatePayload>,
    pub transfer_info: TransferInfo,
}

/// Offline answer containing SDP and ICE candidates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineAnswer {
    pub sdp: String,
    pub ice_candidates: Vec<IceCandidatePayload>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert webrtc-rs ICE candidates to our serializable format
pub fn ice_candidates_to_payloads(candidates: Vec<RTCIceCandidate>) -> Vec<IceCandidatePayload> {
    candidates
        .into_iter()
        .filter_map(|c| {
            let json = c.to_json().ok()?;
            Some(IceCandidatePayload {
                candidate: json.candidate,
                sdp_m_line_index: json.sdp_mline_index,
                sdp_mid: json.sdp_mid,
            })
        })
        .collect()
}

// ============================================================================
// Display Functions
// ============================================================================

/// Compress and encode data for display
fn compress_and_encode(data: &[u8]) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .context("Failed to compress data")?;
    let compressed = encoder.finish().context("Failed to finish compression")?;
    Ok(URL_SAFE_NO_PAD.encode(&compressed))
}

/// Decode and decompress data from user input
fn decode_and_decompress(encoded: &str) -> Result<Vec<u8>> {
    let compressed = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("Failed to decode code")?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .context("Failed to decompress data")?;
    Ok(decompressed)
}

/// Display the offer as compressed base64url-encoded JSON for the user to copy
pub fn display_offer_json(offer: &OfflineOffer) -> Result<()> {
    let json = serde_json::to_string(offer).context("Failed to serialize offer")?;
    let encoded = compress_and_encode(json.as_bytes())?;

    println!();
    println!("=== COPY THIS CODE AND SEND TO RECEIVER ===");
    println!("{}", encoded);
    println!("============================================");
    println!();

    Ok(())
}

/// Display the answer as compressed base64url-encoded JSON for the user to copy
pub fn display_answer_json(answer: &OfflineAnswer) -> Result<()> {
    let json = serde_json::to_string(answer).context("Failed to serialize answer")?;
    let encoded = compress_and_encode(json.as_bytes())?;

    println!();
    println!("=== COPY THIS CODE AND SEND TO SENDER ===");
    println!("{}", encoded);
    println!("==========================================");
    println!();

    Ok(())
}

// ============================================================================
// Input Functions
// ============================================================================

/// Read and parse compressed base64url-encoded offer from user input
pub fn read_offer_json() -> Result<OfflineOffer> {
    print!("Paste sender's code: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let decompressed = decode_and_decompress(&input)?;
    let json = String::from_utf8(decompressed).context("Invalid UTF-8 in decoded data")?;
    let offer: OfflineOffer = serde_json::from_str(&json).context("Failed to parse offer")?;

    Ok(offer)
}

/// Read and parse compressed base64url-encoded answer from user input
pub fn read_answer_json() -> Result<OfflineAnswer> {
    print!("Paste receiver's response code: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let decompressed = decode_and_decompress(&input)?;
    let json = String::from_utf8(decompressed).context("Invalid UTF-8 in decoded data")?;
    let answer: OfflineAnswer = serde_json::from_str(&json).context("Failed to parse answer")?;

    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offer_serialization() {
        let offer = OfflineOffer {
            sdp: "v=0\r\n...".to_string(),
            ice_candidates: vec![IceCandidatePayload {
                candidate: "candidate:123".to_string(),
                sdp_m_line_index: Some(0),
                sdp_mid: Some("0".to_string()),
            }],
            transfer_info: TransferInfo {
                filename: "test.txt".to_string(),
                file_size: 1234,
                transfer_type: "file".to_string(),
                encryption_key: "0".repeat(64),
            },
        };

        let json = serde_json::to_string(&offer).unwrap();
        let parsed: OfflineOffer = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.sdp, offer.sdp);
        assert_eq!(parsed.transfer_info.filename, "test.txt");
        assert_eq!(parsed.ice_candidates.len(), 1);
    }

    #[test]
    fn test_answer_serialization() {
        let answer = OfflineAnswer {
            sdp: "v=0\r\n...".to_string(),
            ice_candidates: vec![],
        };

        let json = serde_json::to_string(&answer).unwrap();
        let parsed: OfflineAnswer = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.sdp, answer.sdp);
    }
}
