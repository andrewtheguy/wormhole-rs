//! Offline WebRTC signaling via copy/paste JSON
//!
//! This module provides signaling for WebRTC connections without any servers.
//! Users manually copy and paste JSON between sender and receiver to establish
//! the connection. This is useful for direct LAN transfers without internet.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
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

/// Display the offer JSON for the user to copy
pub fn display_offer_json(offer: &OfflineOffer) -> Result<()> {
    let json = serde_json::to_string(offer).context("Failed to serialize offer")?;

    println!();
    println!("=== COPY THIS JSON AND SEND TO RECEIVER ===");
    println!("{}", json);
    println!("============================================");
    println!();

    Ok(())
}

/// Display the answer JSON for the user to copy
pub fn display_answer_json(answer: &OfflineAnswer) -> Result<()> {
    let json = serde_json::to_string(answer).context("Failed to serialize answer")?;

    println!();
    println!("=== COPY THIS JSON AND SEND TO SENDER ===");
    println!("{}", json);
    println!("==========================================");
    println!();

    Ok(())
}

// ============================================================================
// Input Functions
// ============================================================================

/// Read and parse offer JSON from user input
pub fn read_offer_json() -> Result<OfflineOffer> {
    print!("Paste sender's JSON: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let offer: OfflineOffer =
        serde_json::from_str(input.trim()).context("Failed to parse offer JSON")?;

    Ok(offer)
}

/// Read and parse answer JSON from user input
pub fn read_answer_json() -> Result<OfflineAnswer> {
    print!("Paste receiver's response JSON: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let answer: OfflineAnswer =
        serde_json::from_str(input.trim()).context("Failed to parse answer JSON")?;

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
