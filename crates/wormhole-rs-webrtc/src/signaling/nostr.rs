//! Nostr-based WebRTC signaling for webrtc transport
//!
//! This module provides WebRTC signaling via Nostr events, replacing the PeerJS
//! WebSocket signaling server. It enables decentralized peer discovery and
//! connection establishment using Nostr relays.
//!
//! Event structure (reuses kind 24242):
//! - type="webrtc-offer": SDP offer from sender
//! - type="webrtc-answer": SDP answer from receiver

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// Timeout for relay connections
const RELAY_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

use wormhole_common::signaling::nostr_protocol::{
    generate_transfer_id, get_best_relays, nostr_file_transfer_kind, DEFAULT_NOSTR_RELAYS,
};

// Signaling event types
const SIGNALING_TYPE_OFFER: &str = "webrtc-offer";
const SIGNALING_TYPE_ANSWER: &str = "webrtc-answer";

/// SDP payload for offer/answer exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpPayload {
    pub sdp: String,
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub candidates: Vec<IceCandidatePayload>,
}

/// ICE candidate payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidatePayload {
    pub candidate: String,
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_m_line_index: Option<u16>,
    #[serde(rename = "sdpMid")]
    pub sdp_mid: Option<String>,
}

/// Signaling message types received from Nostr
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SignalingMessage {
    Offer {
        sender_pubkey: PublicKey,
        sdp: SdpPayload,
    },
    Answer {
        sender_pubkey: PublicKey,
        sdp: SdpPayload,
    },
}

/// Helper to setup client with relays and connect
///
/// Creates a Nostr client, adds the specified relays, connects, and waits
/// for at least one relay to successfully connect. Returns an error if
/// no relays could be added or connected.
async fn setup_client_with_relays(keys: &Keys, relay_urls: &[String]) -> Result<Client> {
    let client = Client::new(keys.clone());

    // Add relays
    let mut added_relays = 0usize;
    for relay_url in relay_urls {
        match client.add_relay(relay_url).await {
            Ok(_) => {
                added_relays += 1;
            }
            Err(e) => {
                log::error!("Failed to add relay {}: {}", relay_url, e);
            }
        }
    }
    if added_relays == 0 {
        anyhow::bail!("Failed to add any Nostr relays; cannot continue without relays.");
    }

    // Connect and wait for at least one relay to connect
    client.connect().await;
    client.wait_for_connection(RELAY_CONNECTION_TIMEOUT).await;

    // Verify at least one relay connected
    let relay_statuses = client.relays().await;
    let connected_count = relay_statuses.values().filter(|r| r.is_connected()).count();

    if connected_count == 0 {
        anyhow::bail!(
            "Failed to connect to any Nostr relay within timeout. \
             Check network connectivity and relay availability."
        );
    }

    log::debug!(
        "Connected to {}/{} Nostr relays",
        connected_count,
        relay_statuses.len()
    );

    Ok(client)
}

/// Nostr signaling client for WebRTC
pub struct NostrSignaling {
    client: Client,
    keys: Keys,
    transfer_id: String,
    relay_urls: Vec<String>,
}

/// Validate that an event belongs to the specified transfer and parse it into a SignalingMessage.
///
/// This is a standalone function for use in spawned tasks where we can't use `&self`.
/// Returns Some(SignalingMessage) if the event has the correct transfer tag and
/// can be parsed as a valid signaling message, None otherwise.
fn validate_and_parse_event_with_id(event: &Event, transfer_id: &str) -> Option<SignalingMessage> {
    // Check if this is for our transfer
    let is_our_transfer = event.tags.iter().any(|t| {
        t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T))
            && t.content() == Some(transfer_id)
    });

    if is_our_transfer {
        NostrSignaling::parse_signaling_event(event)
    } else {
        None
    }
}

/// Process an event in the background receiver task.
///
/// Validates the event, parses it, and sends to the channel if valid.
/// Returns `true` if the task should continue, `false` if it should exit
/// (channel closed).
async fn process_event_for_receiver(
    event: &Event,
    transfer_id: &str,
    tx: &mpsc::Sender<SignalingMessage>,
) -> bool {
    if let Some(msg) = validate_and_parse_event_with_id(event, transfer_id) {
        if tx.send(msg).await.is_err() {
            log::debug!("Message receiver channel closed, stopping background task");
            return false;
        }
    }
    true
}

impl NostrSignaling {
    /// Create a new Nostr signaling client
    pub async fn new(custom_relays: Option<Vec<String>>, use_default_relays: bool) -> Result<Self> {
        let keys = Keys::generate();

        // Determine which relays to use
        let relay_urls = if let Some(relays) = custom_relays {
            relays
        } else if use_default_relays {
            DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            get_best_relays().await
        };

        let client = setup_client_with_relays(&keys, &relay_urls).await?;

        // Generate transfer ID
        let transfer_id = generate_transfer_id();

        Ok(Self {
            client,
            keys,
            transfer_id,
            relay_urls,
        })
    }

    /// Get our public key
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get the transfer ID
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Get the relay URLs
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Get a reference to the signing keys
    ///
    /// This is needed for operations that require signing events
    /// (e.g., PIN-based code publishing). The keys should not be
    /// exposed or stored elsewhere.
    pub fn signing_keys(&self) -> &Keys {
        &self.keys
    }

    /// Create a signaling event with common tags
    fn create_signaling_event(
        &self,
        peer_pubkey: &PublicKey,
        event_type: &str,
        content: &str,
    ) -> Result<Event> {
        let tags = vec![
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T)),
                vec![self.transfer_id.clone()],
            ),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                vec![peer_pubkey.to_hex()],
            ),
            Tag::custom(TagKind::Custom("type".into()), vec![event_type.to_string()]),
        ];

        let event = EventBuilder::new(nostr_file_transfer_kind(), content)
            .tags(tags)
            .sign_with_keys(&self.keys)?;

        Ok(event)
    }

    /// Publish an SDP offer
    pub async fn publish_offer(
        &self,
        receiver_pubkey: &PublicKey,
        sdp: &str,
        candidates: Vec<IceCandidatePayload>,
    ) -> Result<()> {
        let payload = SdpPayload {
            sdp: sdp.to_string(),
            sdp_type: "offer".to_string(),
            candidates,
        };
        let content = STANDARD.encode(serde_json::to_string(&payload)?);

        let event = self.create_signaling_event(receiver_pubkey, SIGNALING_TYPE_OFFER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish SDP offer")?;

        Ok(())
    }

    /// Publish an SDP answer
    pub async fn publish_answer(
        &self,
        sender_pubkey: &PublicKey,
        sdp: &str,
        candidates: Vec<IceCandidatePayload>,
    ) -> Result<()> {
        let payload = SdpPayload {
            sdp: sdp.to_string(),
            sdp_type: "answer".to_string(),
            candidates,
        };
        let content = STANDARD.encode(serde_json::to_string(&payload)?);

        let event = self.create_signaling_event(sender_pubkey, SIGNALING_TYPE_ANSWER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish SDP answer")?;

        Ok(())
    }

    /// Subscribe to signaling events for our public key
    pub async fn subscribe(&self) -> Result<()> {
        let filter = Filter::new()
            .kind(nostr_file_transfer_kind())
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::T),
                self.transfer_id.clone(),
            )
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::P),
                self.keys.public_key().to_hex(),
            );

        self.client
            .subscribe(filter, None)
            .await
            .context("Failed to subscribe to signaling events")?;

        Ok(())
    }

    /// Parse a signaling event into a SignalingMessage
    fn parse_signaling_event(event: &Event) -> Option<SignalingMessage> {
        // Get event type
        let event_type = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::Custom(std::borrow::Cow::Borrowed("type")))
            .and_then(|t| t.content())?;

        match event_type {
            SIGNALING_TYPE_OFFER => {
                let decoded = STANDARD.decode(&event.content).ok()?;
                let payload: SdpPayload = serde_json::from_slice(&decoded).ok()?;
                Some(SignalingMessage::Offer {
                    sender_pubkey: event.pubkey,
                    sdp: payload,
                })
            }
            SIGNALING_TYPE_ANSWER => {
                let decoded = STANDARD.decode(&event.content).ok()?;
                let payload: SdpPayload = serde_json::from_slice(&decoded).ok()?;
                Some(SignalingMessage::Answer {
                    sender_pubkey: event.pubkey,
                    sdp: payload,
                })
            }
            _ => None,
        }
    }

    /// Validate that an event belongs to our transfer and parse it into a SignalingMessage.
    ///
    /// Returns Some(SignalingMessage) if the event has the correct transfer tag and
    /// can be parsed as a valid signaling message, None otherwise.
    fn validate_and_parse_event(&self, event: &Event) -> Option<SignalingMessage> {
        validate_and_parse_event_with_id(event, &self.transfer_id)
    }

    /// Wait for a specific signaling message type with timeout
    #[allow(dead_code)]
    pub async fn wait_for_message(&self, timeout_secs: u64) -> Result<Option<SignalingMessage>> {
        let mut notifications = self.client.notifications();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            // Compute remaining time to deadline, exit if past deadline
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Use remaining time capped at 1 second for the poll timeout
            let poll_timeout = remaining.min(Duration::from_secs(1));

            match timeout(poll_timeout, notifications.recv()).await {
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                    if let Some(msg) = self.validate_and_parse_event(&event) {
                        return Ok(Some(msg));
                    }
                }
                Ok(Ok(RelayPoolNotification::Message { message, .. })) => {
                    // Handle Event messages that come through as Message notifications
                    if let nostr_sdk::RelayMessage::Event { event, .. } = message {
                        if let Some(msg) = self.validate_and_parse_event(&event) {
                            return Ok(Some(msg));
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => break,
                Err(_) => continue, // Timeout, loop will check deadline
            }
        }

        Ok(None)
    }

    /// Start a message receiver task that sends messages to a channel
    pub fn start_message_receiver(
        &self,
    ) -> (
        mpsc::Receiver<SignalingMessage>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(100);
        let client = self.client.clone();
        let transfer_id = self.transfer_id.clone();

        let handle = tokio::spawn(async move {
            let mut notifications = client.notifications();

            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if !process_event_for_receiver(&event, &transfer_id, &tx).await {
                            break;
                        }
                    }
                    Ok(RelayPoolNotification::Message { message, .. }) => {
                        // Handle Event messages that come through as Message notifications
                        if let nostr_sdk::RelayMessage::Event { event, .. } = message {
                            if !process_event_for_receiver(&event, &transfer_id, &tx).await {
                                break;
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        log::warn!(
                            "Nostr relay notification stream error, stopping receiver: {}",
                            e
                        );
                        break;
                    }
                }
            }
        });

        (rx, handle)
    }

    /// Disconnect from relays
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }
}

/// Create a NostrSignaling for sender side
pub async fn create_sender_signaling(
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<NostrSignaling> {
    let signaling = NostrSignaling::new(custom_relays, use_default_relays).await?;
    signaling.subscribe().await?;
    Ok(signaling)
}

/// Create a NostrSignaling for receiver side with existing transfer info
pub async fn create_receiver_signaling(
    transfer_id: &str,
    relay_urls: Vec<String>,
) -> Result<NostrSignaling> {
    let keys = Keys::generate();
    let client = setup_client_with_relays(&keys, &relay_urls).await?;

    let signaling = NostrSignaling {
        client,
        keys,
        transfer_id: transfer_id.to_string(),
        relay_urls,
    };

    signaling.subscribe().await?;

    Ok(signaling)
}
