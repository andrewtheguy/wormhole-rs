//! Offline WebRTC signaling via copy/paste JSON
//!
//! This module provides signaling for WebRTC connections without any servers.
//! Users manually copy and paste JSON between sender and receiver to establish
//! the connection. This is useful for direct LAN transfers without internet.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;

use crate::signaling::nostr::IceCandidatePayload;
use crate::core::wormhole::CODE_TTL_SECS;

/// Line width for wrapped output (safe for most terminals)
const LINE_WIDTH: usize = 76;

/// Marker strings for manual signaling payloads (SSH-key style)
const OFFER_BEGIN_MARKER: &str = "-----BEGIN WORMHOLE WEBRTC OFFER-----";
const OFFER_END_MARKER: &str = "-----END WORMHOLE WEBRTC OFFER-----";
const ANSWER_BEGIN_MARKER: &str = "-----BEGIN WORMHOLE WEBRTC ANSWER-----";
const ANSWER_END_MARKER: &str = "-----END WORMHOLE WEBRTC ANSWER-----";

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    /// Unix timestamp when this offer was created (for TTL validation)
    pub created_at: u64,
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
    println!("{}", OFFER_BEGIN_MARKER);
    println!("{}", wrapped);
    println!("{}", OFFER_END_MARKER);
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
    println!("{}", ANSWER_BEGIN_MARKER);
    println!("{}", wrapped);
    println!("{}", ANSWER_END_MARKER);
    println!();
    println!("Copy the code above and send to sender, after sending the code above, wait for connection...");
    println!();

    Ok(())
}

// ============================================================================
// Input Functions
// ============================================================================

/// Extract base64 payload between explicit BEGIN/END markers
fn extract_marked_payload<I>(lines: I, begin: &str, end: &str) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let mut in_payload = false;
    let mut collected = Vec::new();

    for line in lines {
        let trimmed = line.trim();

        if trimmed.is_empty() && !in_payload {
            continue;
        }

        if trimmed == begin {
            if in_payload {
                anyhow::bail!("Duplicate BEGIN marker found.");
            }
            in_payload = true;
            continue;
        }

        if trimmed == end {
            if !in_payload {
                anyhow::bail!("END marker found before BEGIN marker.");
            }
            let joined = collected.join("");
            if joined.is_empty() {
                anyhow::bail!("No payload found between markers.");
            }
            return Ok(joined);
        }

        if !in_payload {
            anyhow::bail!("Unexpected text before BEGIN marker.");
        }

        if !trimmed.is_empty() {
            collected.push(trimmed.to_string());
        }
    }

    if !in_payload {
        anyhow::bail!("Missing BEGIN marker.");
    }

    anyhow::bail!("Missing END marker.");
}

/// Read multi-line input and extract base64 payload between markers
fn read_marked_input(begin: &str, end: &str) -> Result<String> {
    let stdin = std::io::stdin();
    let lines = stdin
        .lock()
        .lines()
        .map(|line| line.context("Failed to read line"));
    let mut collected = Vec::new();
    for line in lines {
        collected.push(line?);
        if collected.last().map(|l| l.trim() == end).unwrap_or(false) {
            break;
        }
    }
    extract_marked_payload(collected, begin, end)
}

/// Decode base64 input with CRC32 checksum validation, with retry on error
fn decode_with_checksum(prompt: &str, begin: &str, end: &str) -> Result<String> {
    loop {
        println!("{}", prompt);
        std::io::stdout().flush()?;

        let encoded = match read_marked_input(begin, end) {
            Ok(payload) => payload,
            Err(err) => {
                eprintln!("{err}\nPlease try again.\n");
                continue;
            }
        };

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

        // Need at least CRC32 (4 bytes) + minimal JSON
        if decoded.len() < 4 + 2 {
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

/// Validate TTL of an offer
fn validate_offer_ttl(offer: &OfflineOffer) -> Result<()> {
    let now = current_timestamp();

    // Allow 60s clock skew into future
    if offer.created_at > now + 60 {
        anyhow::bail!("Invalid offer: created_at is in the future. Check system clock.");
    }

    let age = now.saturating_sub(offer.created_at);
    if age > CODE_TTL_SECS {
        let minutes = age / 60;
        anyhow::bail!(
            "Offer expired: code is {} minutes old (max {} minutes). \
             Please request a new code from the sender.",
            minutes,
            CODE_TTL_SECS / 60
        );
    }

    Ok(())
}

/// Read and parse base64url-encoded offer from user input with CRC32 validation
pub fn read_offer_json() -> Result<OfflineOffer> {
    let json = decode_with_checksum(
        "=== RECEIVER STEP 1: Paste sender's code (including BEGIN/END markers) ===",
        OFFER_BEGIN_MARKER,
        OFFER_END_MARKER,
    )?;
    let offer: OfflineOffer = serde_json::from_str(&json).context("Failed to parse offer")?;
    validate_offer_ttl(&offer)?;
    Ok(offer)
}

/// Read and parse base64url-encoded answer from user input with CRC32 validation
pub fn read_answer_json() -> Result<OfflineAnswer> {
    let json = decode_with_checksum(
        "=== SENDER STEP 3: Paste receiver's response code (including BEGIN/END markers) ===",
        ANSWER_BEGIN_MARKER,
        ANSWER_END_MARKER,
    )?;
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
            created_at: current_timestamp(),
        };

        let json = serde_json::to_string(&offer).unwrap();
        let parsed: OfflineOffer = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.sdp, offer.sdp);
        assert_eq!(parsed.transfer_info.filename, "test.txt");
        assert_eq!(parsed.ice_candidates.len(), 1);
        assert!(parsed.created_at > 0);
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

    #[test]
    fn test_extract_marked_payload_ok() {
        let lines = vec![
            "  ".to_string(),
            OFFER_BEGIN_MARKER.to_string(),
            "abc".to_string(),
            "def".to_string(),
            OFFER_END_MARKER.to_string(),
        ];
        let payload =
            extract_marked_payload(lines, OFFER_BEGIN_MARKER, OFFER_END_MARKER).unwrap();
        assert_eq!(payload, "abcdef");
    }

    #[test]
    fn test_extract_marked_payload_missing_begin() {
        let lines = vec!["abc".to_string(), OFFER_END_MARKER.to_string()];
        let err = extract_marked_payload(lines, OFFER_BEGIN_MARKER, OFFER_END_MARKER).unwrap_err();
        assert!(err.to_string().contains("BEGIN"));
    }

    #[test]
    fn test_extract_marked_payload_missing_end() {
        let lines = vec![OFFER_BEGIN_MARKER.to_string(), "abc".to_string()];
        let err = extract_marked_payload(lines, OFFER_BEGIN_MARKER, OFFER_END_MARKER).unwrap_err();
        assert!(err.to_string().contains("END"));
    }

    #[test]
    fn test_extract_marked_payload_text_before_begin() {
        let lines = vec![
            "junk".to_string(),
            OFFER_BEGIN_MARKER.to_string(),
            "abc".to_string(),
            OFFER_END_MARKER.to_string(),
        ];
        let err = extract_marked_payload(lines, OFFER_BEGIN_MARKER, OFFER_END_MARKER).unwrap_err();
        assert!(err.to_string().contains("Unexpected"));
    }
}
