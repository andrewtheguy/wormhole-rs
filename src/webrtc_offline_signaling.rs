//! Offline WebRTC signaling via copy/paste JSON
//!
//! This module provides signaling for WebRTC connections without any servers.
//! Users manually copy and paste JSON between sender and receiver to establish
//! the connection. This is useful for direct LAN transfers without internet.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;

use crate::nostr_signaling::IceCandidatePayload;

/// Line width for wrapped output (safe for most terminals)
const LINE_WIDTH: usize = 76;

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

/// Wrap a string to multiple lines of specified width
fn wrap_lines(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Display the offer as base64url-encoded JSON with CRC32 checksum for the user to copy
pub fn display_offer_json(offer: &OfflineOffer) -> Result<()> {
    let json = serde_json::to_string(offer).context("Failed to serialize offer")?;
    let json_bytes = json.as_bytes();
    let checksum = crc32fast::hash(json_bytes);
    let mut payload = json_bytes.to_vec();
    payload.extend_from_slice(&checksum.to_be_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&payload);
    let wrapped = wrap_lines(&encoded, LINE_WIDTH);

    println!();
    println!("=== SENDER STEP 1: Ask the receiver to run ===");
    println!("  wormhole-rs receive --manual-signaling");
    println!();
    println!("=== SENDER STEP 2: Press Enter to show response code and then copy it to send to receiver ===");
    std::io::stdout().flush()?;
    let _ = std::io::stdin().read_line(&mut String::new());
    println!("--- START CODE ---");
    println!("{}", wrapped);
    println!("--- END CODE ---");
    println!();
    println!("Copy the code above and send to receiver, then wait for their response code for STEP 3...");
    println!();

    Ok(())
}

/// Display the answer as base64url-encoded JSON with CRC32 checksum for the user to copy
pub fn display_answer_json(answer: &OfflineAnswer) -> Result<()> {
    let json = serde_json::to_string(answer).context("Failed to serialize answer")?;
    let json_bytes = json.as_bytes();
    let checksum = crc32fast::hash(json_bytes);
    let mut payload = json_bytes.to_vec();
    payload.extend_from_slice(&checksum.to_be_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&payload);
    let wrapped = wrap_lines(&encoded, LINE_WIDTH);

    println!();
    println!("=== RECEIVER STEP 2: Press Enter to show response code and then copy it to send to sender ===");
    std::io::stdout().flush()?;
    let _ = std::io::stdin().read_line(&mut String::new());
    println!("--- START CODE ---");
    println!("{}", wrapped);
    println!("--- END CODE ---");
    println!();
    println!("Copy the code above and send to sender, after sending the code above, wait for connection...");
    println!();

    Ok(())
}

// ============================================================================
// Input Functions
// ============================================================================

/// Read multi-line input until an empty line or the end marker
fn read_multiline_input() -> Result<String> {
    let stdin = std::io::stdin();
    let mut lines = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.context("Failed to read line")?;
        let trimmed = line.trim();

        // Stop on empty line or end marker
        if trimmed.is_empty() || trimmed.starts_with("===") {
            break;
        }

        lines.push(trimmed.to_string());
    }

    // Join all lines (removing any whitespace/newlines)
    Ok(lines.join(""))
}

/// Decode base64 input with CRC32 checksum validation, with retry on error
fn decode_with_checksum(prompt: &str) -> Result<String> {
    loop {
        println!("{}", prompt);
        std::io::stdout().flush()?;

        let encoded = read_multiline_input()?;

        if encoded.is_empty() {
            eprintln!("No input received. Please try again.\n");
            continue;
        }

        let decoded = match URL_SAFE_NO_PAD.decode(&encoded) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Invalid code format. Please try again.\n");
                continue;
            }
        };

        if decoded.len() < 4 {
            eprintln!("Code too short. Please try again.\n");
            continue;
        }

        let (json_bytes, checksum_bytes) = decoded.split_at(decoded.len() - 4);
        let expected = u32::from_be_bytes(checksum_bytes.try_into().unwrap());
        let actual = crc32fast::hash(json_bytes);

        if expected != actual {
            eprintln!("Checksum mismatch - code may have been corrupted during copy/paste.");
            eprintln!("Please try again.\n");
            continue;
        }

        return String::from_utf8(json_bytes.to_vec()).context("Invalid UTF-8 in decoded data");
    }
}

/// Read and parse base64url-encoded offer from user input with CRC32 validation
pub fn read_offer_json() -> Result<OfflineOffer> {
    let json = decode_with_checksum("=== RECEIVER STEP 1: Paste sender's code, then press Enter twice ===")?;
    serde_json::from_str(&json).context("Failed to parse offer")
}

/// Read and parse base64url-encoded answer from user input with CRC32 validation
pub fn read_answer_json() -> Result<OfflineAnswer> {
    let json = decode_with_checksum("=== SENDER STEP 3: Paste receiver's response code, then press Enter twice ===")?;
    serde_json::from_str(&json).context("Failed to parse answer")
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
