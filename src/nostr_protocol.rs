use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures::future::join_all;
use nostr_sdk::prelude::*;
use rand::Rng;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Maximum file size for Nostr transfers (512KB)
/// Nostr relays have message size limits, so we restrict file size
pub const MAX_NOSTR_FILE_SIZE: u64 = 512 * 1024; // 512KB

/// Chunk size for Nostr transfers (16KB)
/// Balances event size with transfer efficiency for Nostr relays
pub const NOSTR_CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

/// Nostr event kind for file transfer (ephemeral range 20000-29999)
/// Ephemeral events are not stored permanently by relays
pub fn nostr_file_transfer_kind() -> Kind {
    Kind::from_u16(24242)
}

/// Default public Nostr relays for file transfer
/// These are probed via NIP-11 to find the best relays
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.wine",
    // "wss://relay.nostr.band",
    // "wss://relay.snort.social",
    // "wss://purplepag.es",
    // "wss://nostr.mom",
    // "wss://relay.primal.net",
    // "wss://nostr.land",
    // "wss://nostr-pub.wellorder.net",
];

/// Timeout for fetching NIP-11 relay information
const RELAY_INFO_TIMEOUT_SECS: u64 = 5;

/// Timeout for WebSocket connectivity test
const RELAY_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Timeout for relay discovery queries
const RELAY_DISCOVERY_TIMEOUT_SECS: u64 = 10;

/// Number of top relays to use for file transfer
const TOP_RELAYS_COUNT: usize = 5;

/// Maximum number of relays to probe after discovery
const MAX_RELAYS_TO_PROBE: usize = 30;

/// Minimum max_message_length required (24KB: 16KB chunk + base64 overhead + tags)
const MIN_MESSAGE_LENGTH: i32 = 24 * 1024;

/// Minimum max_content_length required (22KB: base64 encoded 16KB chunk)
const MIN_CONTENT_LENGTH: i32 = 22 * 1024;

/// NIP-66 Relay Discovery event kind
fn relay_discovery_kind() -> Kind {
    Kind::from_u16(30166)
}

/// NIP-65 Relay List Metadata event kind
fn relay_list_kind() -> Kind {
    Kind::from_u16(10002)
}

/// Fetch NIP-11 relay information document from a relay
/// Returns the info document on success, or None if fetch fails
async fn fetch_relay_info(relay_url: &str) -> Option<RelayInformationDocument> {
    // Convert wss:// to https:// for HTTP request
    let http_url = relay_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(RELAY_INFO_TIMEOUT_SECS))
        .build()
        .ok()?;

    let response = client
        .get(&http_url)
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .ok()?;

    let json = response.text().await.ok()?;
    RelayInformationDocument::from_json(&json).ok()
}

/// Test WebSocket connectivity to a relay and measure response time
/// Returns (relay_url, response_time) on success
async fn test_relay_connectivity(relay_url: &str) -> Option<(String, Duration)> {
    let start = Instant::now();

    // Create a temporary client to test connectivity
    let client = Client::default();

    // Add the relay
    if client.add_relay(relay_url).await.is_err() {
        return None;
    }

    // Try to connect (spawns background task)
    client.connect().await;

    // Wait for connection with timeout
    let timeout = Duration::from_secs(RELAY_CONNECT_TIMEOUT_SECS);
    let relay = client.relay(relay_url).await.ok()?;

    // Wait for relay to connect or timeout
    relay.wait_for_connection(timeout).await;

    // Check if actually connected
    if !relay.is_connected() {
        client.disconnect().await;
        return None;
    }

    let elapsed = start.elapsed();

    // Disconnect after test
    client.disconnect().await;

    Some((relay_url.to_string(), elapsed))
}

/// Probe a relay: check NIP-11 capabilities and test WebSocket connectivity
/// Returns (relay_url, response_time) if relay passes all checks
async fn probe_relay(relay_url: &str) -> Option<(String, Duration)> {
    // First, fetch NIP-11 to check capabilities
    if let Some(info) = fetch_relay_info(relay_url).await {
        if !is_relay_suitable(&info) {
            return None;
        }
    }
    // If NIP-11 fetch fails, we still try connectivity
    // (some relays don't serve NIP-11 but still work fine)

    // Test actual WebSocket connectivity
    test_relay_connectivity(relay_url).await
}

/// Check if a relay has suitable capabilities for our file transfer use case
fn is_relay_suitable(info: &RelayInformationDocument) -> bool {
    if let Some(ref limitation) = info.limitation {
        // Check message length limit
        if let Some(max_msg) = limitation.max_message_length {
            if max_msg < MIN_MESSAGE_LENGTH {
                return false;
            }
        }

        // Check content length limit
        if let Some(max_content) = limitation.max_content_length {
            if max_content < MIN_CONTENT_LENGTH {
                return false;
            }
        }

        // Skip relays requiring payment (we want free public relays)
        if limitation.payment_required == Some(true) {
            return false;
        }

        // Skip relays requiring auth (ephemeral events shouldn't need auth)
        if limitation.auth_required == Some(true) {
            return false;
        }
    }

    true
}

/// Extract relay URL from a NIP-66 relay discovery event (kind 30166)
/// The relay URL is stored in the 'd' tag
fn extract_relay_from_nip66(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .map(|s| s.to_string())
        .filter(|url| url.starts_with("wss://") || url.starts_with("ws://"))
}

/// Extract relay URLs from a NIP-65 relay list event (kind 10002)
/// Relay URLs are stored in 'r' tags
fn extract_relays_from_nip65(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::Relay)
        .filter_map(|t| t.content())
        .map(|s| s.to_string())
        .filter(|url| url.starts_with("wss://") || url.starts_with("ws://"))
        .collect()
}

/// Discover relays by querying seed relays for NIP-66 and NIP-65 events
async fn discover_relays_from_seeds() -> HashSet<String> {
    let mut discovered: HashSet<String> = HashSet::new();

    // Add seed relays to discovered set
    for relay in DEFAULT_NOSTR_RELAYS {
        discovered.insert(relay.to_string());
    }

    // Create a temporary client to query seed relays
    let client = Client::default();

    // Add seed relays
    for relay_url in DEFAULT_NOSTR_RELAYS {
        let _ = client.add_relay(relay_url.to_string()).await;
    }

    // Connect to relays
    client.connect().await;

    // Query for NIP-66 relay discovery events (kind 30166)
    // These are published by relay monitors
    let nip66_filter = Filter::new()
        .kind(relay_discovery_kind())
        .limit(100);

    // Query for NIP-65 relay list events (kind 10002)
    // These are published by users listing their preferred relays
    let nip65_filter = Filter::new()
        .kind(relay_list_kind())
        .limit(100);

    let timeout = Duration::from_secs(RELAY_DISCOVERY_TIMEOUT_SECS);

    // Fetch NIP-66 events
    if let Ok(nip66_events) = client
        .fetch_events(nip66_filter, timeout)
        .await
    {
        for event in nip66_events.iter() {
            if let Some(relay_url) = extract_relay_from_nip66(event) {
                discovered.insert(relay_url);
            }
        }
    }

    // Fetch NIP-65 events
    if let Ok(nip65_events) = client
        .fetch_events(nip65_filter, timeout)
        .await
    {
        for event in nip65_events.iter() {
            for relay_url in extract_relays_from_nip65(event) {
                discovered.insert(relay_url);
            }
        }
    }

    // Disconnect from seed relays
    client.disconnect().await;

    discovered
}

/// Discover best relays by querying seed relays and probing
/// 1. Query seed relays for NIP-66/NIP-65 events to discover more relays
/// 2. Probe discovered relays: check NIP-11 capabilities + test WebSocket connectivity
/// 3. Sort by WebSocket response time and return top relays
async fn discover_best_relays() -> Vec<String> {
    // Discover relays from seed relays via NIP-66 and NIP-65
    let discovered = discover_relays_from_seeds().await;

    let relay_count = discovered.len();
    if relay_count > DEFAULT_NOSTR_RELAYS.len() {
        println!(
            "📡 Discovered {} relays from {} seeds",
            relay_count,
            DEFAULT_NOSTR_RELAYS.len()
        );
    }

    // Limit number of relays to probe to avoid too many connections
    let relays_to_probe: Vec<_> = discovered
        .into_iter()
        .take(MAX_RELAYS_TO_PROBE)
        .collect();

    // Probe relays in parallel: NIP-11 capability check + WebSocket connectivity test
    let futures: Vec<_> = relays_to_probe
        .iter()
        .map(|url| probe_relay(url))
        .collect();

    let results = join_all(futures).await;

    // Filter successful probes
    let mut responsive_relays: Vec<_> = results.into_iter().flatten().collect();

    // Sort by WebSocket response time (faster = better)
    responsive_relays.sort_by(|a, b| a.1.cmp(&b.1));

    // Take top relays
    responsive_relays
        .into_iter()
        .take(TOP_RELAYS_COUNT)
        .map(|(url, _)| url)
        .collect()
}

/// Get best relays for file transfer
/// Discovers relays via NIP-65/NIP-66, probes them, falls back to defaults if none respond
pub async fn get_best_relays() -> Vec<String> {
    let relays = discover_best_relays().await;

    if !relays.is_empty() {
        println!("📡 Using {} fastest responding relays", relays.len());
        relays
    } else {
        println!("📡 Using default relays (discovery failed)");
        DEFAULT_NOSTR_RELAYS
            .iter()
            .take(TOP_RELAYS_COUNT)
            .map(|s| s.to_string())
            .collect()
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
