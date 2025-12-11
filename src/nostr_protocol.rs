use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr_sdk::prelude::*;
use rand::Rng;
use serde::Deserialize;

/// Chunk size for Nostr transfers (16KB)
/// Balances event size with transfer efficiency for Nostr relays
pub const NOSTR_CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

/// Nostr event kind for file transfer (ephemeral range 20000-29999)
/// Ephemeral events are not stored permanently by relays
pub fn nostr_file_transfer_kind() -> Kind {
    Kind::from_u16(24242)
}

/// Default public Nostr relays for file transfer (fallback if API fails)
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.wine",
];

/// Timeout for fetching relay list from nostr.watch API
const RELAY_API_TIMEOUT_SECS: u64 = 5;

/// Number of top relays to fetch from nostr.watch
const TOP_RELAYS_COUNT: usize = 5;

#[derive(Debug, Deserialize)]
struct NostrWatchResponse {
    relays: Vec<NostrWatchRelay>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NostrWatchRelay {
    relay_url: String,
    #[serde(default)]
    rtt: Option<RttInfo>,
}

#[derive(Debug, Deserialize)]
struct RttInfo {
    open: Option<RttValue>,
}

#[derive(Debug, Deserialize)]
struct RttValue {
    value: f64,
}

/// Fetch best relays from nostr.watch API
/// Returns a list of relay URLs on success, or None if the API call fails
async fn fetch_best_relays_from_api() -> Option<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(RELAY_API_TIMEOUT_SECS))
        .build()
        .ok()?;

    let response = client
        .get("https://api.nostr.watch/v2/relays")
        .send()
        .await
        .ok()?;

    let api_response: NostrWatchResponse = response.json().await.ok()?;

    // Filter for wss:// relays only (secure websockets) and sort by RTT (lower is better)
    let mut relays: Vec<_> = api_response
        .relays
        .into_iter()
        .filter(|r| r.relay_url.starts_with("wss://"))
        .collect();

    // Sort by RTT (lower is better), putting relays without RTT at the end
    relays.sort_by(|a, b| {
        let a_rtt = a.rtt.as_ref().and_then(|r| r.open.as_ref()).map(|o| o.value);
        let b_rtt = b.rtt.as_ref().and_then(|r| r.open.as_ref()).map(|o| o.value);

        match (a_rtt, b_rtt) {
            (Some(a_val), Some(b_val)) => a_val.total_cmp(&b_val),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });

    // Take top relays
    let relay_urls: Vec<String> = relays
        .into_iter()
        .take(TOP_RELAYS_COUNT)
        .map(|r| r.relay_url)
        .collect();

    if relay_urls.is_empty() {
        None
    } else {
        Some(relay_urls)
    }
}

/// Get best relays for file transfer
/// Tries to fetch from nostr.watch API, falls back to hardcoded defaults
pub async fn get_best_relays() -> Vec<String> {
    match fetch_best_relays_from_api().await {
        Some(relays) if !relays.is_empty() => {
            println!("📡 Using top {} relays from nostr.watch", relays.len());
            relays
        }
        _ => {
            println!("📡 Using default relays (nostr.watch unavailable)");
            DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
        }
    }
}

/// Event type tag values
pub const EVENT_TYPE_CHUNK: &str = "chunk";
pub const EVENT_TYPE_ACK: &str = "ack";

/// Tag names for file transfer metadata
pub const TAG_TRANSFER_ID: &str = "t";
pub const TAG_SEQUENCE: &str = "seq";
pub const TAG_TOTAL: &str = "total";
pub const TAG_TYPE: &str = "type";

/// Generate a random transfer ID (16 bytes, hex encoded)
pub fn generate_transfer_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

/// Create a chunk event for file transfer
///
/// # Arguments
/// * `keys` - Sender's keys for signing
/// * `transfer_id` - Unique transfer session ID
/// * `seq` - Chunk sequence number (0-indexed)
/// * `total` - Total number of chunks
/// * `encrypted_chunk` - AES-256-GCM encrypted chunk data
pub fn create_chunk_event(
    keys: &Keys,
    transfer_id: &str,
    seq: u32,
    total: u32,
    encrypted_chunk: &[u8],
) -> Result<Event> {
    // Base64 encode the encrypted chunk
    let content = STANDARD.encode(encrypted_chunk);

    // Build event with tags
    // Note: No 'p' tag needed - receiver filters by sender's pubkey (event author) and transfer_id
    let event = EventBuilder::new(nostr_file_transfer_kind(), content)
        .tags(vec![
            Tag::custom(
                TagKind::Custom(TAG_TRANSFER_ID.into()),
                vec![transfer_id.to_string()],
            ),
            Tag::custom(TagKind::Custom(TAG_SEQUENCE.into()), vec![seq.to_string()]),
            Tag::custom(TagKind::Custom(TAG_TOTAL.into()), vec![total.to_string()]),
            Tag::custom(
                TagKind::Custom(TAG_TYPE.into()),
                vec![EVENT_TYPE_CHUNK.to_string()],
            ),
        ])
        .sign_with_keys(keys)
        .context("Failed to sign chunk event")?;

    Ok(event)
}

/// Create an ACK event for acknowledging chunk receipt
///
/// # Arguments
/// * `keys` - Receiver's keys for signing
/// * `sender_pubkey` - Sender's public key
/// * `transfer_id` - Unique transfer session ID
/// * `seq` - Chunk sequence number being acknowledged (-1 for final ACK)
pub fn create_ack_event(
    keys: &Keys,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
    seq: i32,
) -> Result<Event> {
    let event = EventBuilder::new(nostr_file_transfer_kind(), "")
        .tags(vec![
            Tag::public_key(*sender_pubkey),
            Tag::custom(
                TagKind::Custom(TAG_TRANSFER_ID.into()),
                vec![transfer_id.to_string()],
            ),
            Tag::custom(TagKind::Custom(TAG_SEQUENCE.into()), vec![seq.to_string()]),
            Tag::custom(
                TagKind::Custom(TAG_TYPE.into()),
                vec![EVENT_TYPE_ACK.to_string()],
            ),
        ])
        .sign_with_keys(keys)
        .context("Failed to sign ACK event")?;

    Ok(event)
}

/// Parse a chunk event and extract metadata
///
/// Returns: (seq, total, encrypted_chunk_data)
pub fn parse_chunk_event(event: &Event) -> Result<(u32, u32, Vec<u8>)> {
    // Validate event kind
    if event.kind != nostr_file_transfer_kind() {
        anyhow::bail!("Invalid event kind: expected {}", nostr_file_transfer_kind());
    }

    // Extract sequence number
    let seq = event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_SEQUENCE
        })
        .and_then(|t| t.content())
        .context("Missing sequence tag")?
        .parse::<u32>()
        .context("Invalid sequence number")?;

    // Extract total chunks
    let total = event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_TOTAL
        })
        .and_then(|t| t.content())
        .context("Missing total tag")?
        .parse::<u32>()
        .context("Invalid total chunks")?;

    // Base64 decode the content
    let encrypted_chunk = STANDARD
        .decode(&event.content)
        .context("Failed to decode base64 chunk data")?;

    Ok((seq, total, encrypted_chunk))
}

/// Parse an ACK event and extract sequence number
///
/// Returns: sequence number being acknowledged
pub fn parse_ack_event(event: &Event) -> Result<i32> {
    // Validate event kind
    if event.kind != nostr_file_transfer_kind() {
        anyhow::bail!("Invalid event kind: expected {}", nostr_file_transfer_kind());
    }

    // Extract sequence number
    let seq = event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_SEQUENCE
        })
        .and_then(|t| t.content())
        .context("Missing sequence tag")?
        .parse::<i32>()
        .context("Invalid sequence number")?;

    Ok(seq)
}

/// Extract transfer ID from an event
pub fn get_transfer_id(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_TRANSFER_ID
        })
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

/// Check if event is a chunk event (vs ACK)
pub fn is_chunk_event(event: &Event) -> bool {
    event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_TYPE
        })
        .and_then(|t| t.content())
        .map(|s| s == EVENT_TYPE_CHUNK)
        .unwrap_or(false)
}

/// Check if event is an ACK event
pub fn is_ack_event(event: &Event) -> bool {
    event
        .tags
        .iter()
        .find(|t| {
            let kind = t.kind();
            kind.to_string() == TAG_TYPE
        })
        .and_then(|t| t.content())
        .map(|s| s == EVENT_TYPE_ACK)
        .unwrap_or(false)
}
