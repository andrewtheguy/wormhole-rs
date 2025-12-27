//! ICE signaling - exchange credentials and candidates via Nostr or manual mode.
//!
//! Adapts the existing Nostr signaling to work with ICE credentials and candidates
//! instead of WebRTC SDP.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::time::{timeout, Duration};

use super::agent::{IceCandidateInfo, IceCredentials};
use wormhole_common::signaling::nostr_protocol::{
    generate_transfer_id, get_best_relays, nostr_file_transfer_kind, DEFAULT_NOSTR_RELAYS,
};

// Signaling event types for ICE
const SIGNALING_TYPE_ICE_OFFER: &str = "ice-offer";
const SIGNALING_TYPE_ICE_ANSWER: &str = "ice-answer";

/// ICE signaling payload exchanged via Nostr.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceSignalingPayload {
    /// ICE username fragment
    pub ufrag: String,
    /// ICE password
    pub pwd: String,
    /// List of ICE candidates
    pub candidates: Vec<IceCandidateInfo>,
}

impl IceSignalingPayload {
    pub fn new(creds: &IceCredentials, candidates: Vec<IceCandidateInfo>) -> Self {
        Self {
            ufrag: creds.ufrag.clone(),
            pwd: creds.pwd.clone(),
            candidates,
        }
    }
}

/// ICE signaling message received from Nostr.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum IceSignalingMessage {
    Offer {
        sender_pubkey: PublicKey,
        payload: IceSignalingPayload,
    },
    Answer {
        sender_pubkey: PublicKey,
        payload: IceSignalingPayload,
    },
}

/// Nostr signaling client for ICE transport.
pub struct IceNostrSignaling {
    pub client: Client,
    pub keys: Keys,
    transfer_id: String,
    relay_urls: Vec<String>,
}

impl IceNostrSignaling {
    /// Create a new ICE Nostr signaling client.
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

        let client = Client::new(keys.clone());

        // Add relays
        let mut added_relays = 0usize;
        for relay_url in &relay_urls {
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

        // Connect
        client.connect().await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Generate transfer ID
        let transfer_id = generate_transfer_id();

        Ok(Self {
            client,
            keys,
            transfer_id,
            relay_urls,
        })
    }

    /// Get our public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get the transfer ID.
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Get the relay URLs.
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Create a signaling event with common tags.
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

    /// Publish an ICE offer (sender's credentials + candidates).
    pub async fn publish_offer(
        &self,
        receiver_pubkey: &PublicKey,
        payload: &IceSignalingPayload,
    ) -> Result<()> {
        let content = STANDARD.encode(serde_json::to_string(payload)?);

        let event =
            self.create_signaling_event(receiver_pubkey, SIGNALING_TYPE_ICE_OFFER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish ICE offer")?;

        Ok(())
    }

    /// Publish an ICE answer (receiver's credentials + candidates).
    pub async fn publish_answer(
        &self,
        sender_pubkey: &PublicKey,
        payload: &IceSignalingPayload,
    ) -> Result<()> {
        let content = STANDARD.encode(serde_json::to_string(payload)?);

        let event =
            self.create_signaling_event(sender_pubkey, SIGNALING_TYPE_ICE_ANSWER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish ICE answer")?;

        Ok(())
    }

    /// Subscribe to signaling events for our public key.
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

    /// Parse a signaling event into an IceSignalingMessage.
    fn parse_signaling_event(event: &Event) -> Option<IceSignalingMessage> {
        // Get event type
        let event_type = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::Custom(std::borrow::Cow::Borrowed("type")))
            .and_then(|t| t.content())?;

        match event_type {
            SIGNALING_TYPE_ICE_OFFER => {
                let decoded = STANDARD.decode(&event.content).ok()?;
                let payload: IceSignalingPayload = serde_json::from_slice(&decoded).ok()?;
                Some(IceSignalingMessage::Offer {
                    sender_pubkey: event.pubkey,
                    payload,
                })
            }
            SIGNALING_TYPE_ICE_ANSWER => {
                let decoded = STANDARD.decode(&event.content).ok()?;
                let payload: IceSignalingPayload = serde_json::from_slice(&decoded).ok()?;
                Some(IceSignalingMessage::Answer {
                    sender_pubkey: event.pubkey,
                    payload,
                })
            }
            _ => None,
        }
    }

    /// Wait for a specific signaling message type with timeout.
    pub async fn wait_for_message(&self, timeout_secs: u64) -> Result<Option<IceSignalingMessage>> {
        let mut notifications = self.client.notifications();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        while tokio::time::Instant::now() < deadline {
            match timeout(Duration::from_secs(1), notifications.recv()).await {
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                    // Check if this is for our transfer
                    let is_our_transfer = event.tags.iter().any(|t| {
                        t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T))
                            && t.content() == Some(&self.transfer_id)
                    });

                    if is_our_transfer {
                        if let Some(msg) = Self::parse_signaling_event(&event) {
                            return Ok(Some(msg));
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }

        Ok(None)
    }

    /// Disconnect from relays.
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }
}

/// Create signaling for sender side.
pub async fn create_sender_signaling(
    custom_relays: Option<Vec<String>>,
    use_default_relays: bool,
) -> Result<IceNostrSignaling> {
    let signaling = IceNostrSignaling::new(custom_relays, use_default_relays).await?;
    signaling.subscribe().await?;
    Ok(signaling)
}

/// Create signaling for receiver side with existing transfer info.
pub async fn create_receiver_signaling(
    transfer_id: &str,
    relay_urls: Vec<String>,
) -> Result<IceNostrSignaling> {
    let keys = Keys::generate();
    let client = Client::new(keys.clone());

    // Add relays
    let mut added_relays = 0usize;
    for relay_url in &relay_urls {
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

    // Connect
    client.connect().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let signaling = IceNostrSignaling {
        client,
        keys,
        transfer_id: transfer_id.to_string(),
        relay_urls,
    };

    signaling.subscribe().await?;

    Ok(signaling)
}
