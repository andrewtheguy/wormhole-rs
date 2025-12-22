//! Nostr-based WebRTC signaling for webrtc transport
//!
//! This module provides WebRTC signaling via Nostr events, replacing the PeerJS
//! WebSocket signaling server. It enables decentralized peer discovery and
//! connection establishment using Nostr relays.
//!
//! Event structure (reuses kind 24242):
//! - type="webrtc-offer": SDP offer from sender
//! - type="webrtc-answer": SDP answer from receiver
//! - type="webrtc-ice": ICE candidate exchange

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::nostr_protocol::{
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
/// Signaling message types received from Nostr
#[derive(Debug, Clone)]
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

/// Nostr signaling client for WebRTC
pub struct NostrSignaling {
    pub client: Client,
    pub keys: Keys,
    transfer_id: String,
    relay_urls: Vec<String>,
}

impl NostrSignaling {
    /// Create a new Nostr signaling client
    pub async fn new(custom_relays: Option<Vec<String>>, use_default_relays: bool) -> Result<Self> {
        let keys = Keys::generate();

        // Determine which relays to use
        let relay_urls = if let Some(relays) = custom_relays {
            relays
        } else if use_default_relays {
            DEFAULT_NOSTR_RELAYS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            get_best_relays().await
        };

        let client = Client::new(keys.clone());

        // Add relays
        for relay_url in &relay_urls {
            if let Err(e) = client.add_relay(relay_url).await {
                eprintln!("Failed to add relay {}: {}", relay_url, e);
            }
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

    /// Create a signaling event with common tags
    fn create_signaling_event(
        &self,
        peer_pubkey: &PublicKey,
        event_type: &str,
        seq: Option<u32>,
        content: &str,
    ) -> Result<Event> {
        let mut tags = vec![
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

        if let Some(s) = seq {
            tags.push(Tag::custom(
                TagKind::Custom("seq".into()),
                vec![s.to_string()],
            ));
        }

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

        let event =
            self.create_signaling_event(receiver_pubkey, SIGNALING_TYPE_OFFER, Some(0), &content)?;

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

        let event =
            self.create_signaling_event(sender_pubkey, SIGNALING_TYPE_ANSWER, Some(0), &content)?;

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
            .find(|t| {
                t.kind()
                    == TagKind::Custom(std::borrow::Cow::Borrowed("type"))
            })
            .and_then(|t| t.content())?;

        // Get sequence number if present
        let _seq: Option<u32> = event
            .tags
            .iter()
            .find(|t| {
                t.kind()
                    == TagKind::Custom(std::borrow::Cow::Borrowed("seq"))
            })
            .and_then(|t| t.content())
            .and_then(|s| s.parse().ok());

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

    /// Wait for a specific signaling message type with timeout
    pub async fn wait_for_message(
        &self,
        timeout_secs: u64,
    ) -> Result<Option<SignalingMessage>> {
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

    /// Start a message receiver task that sends messages to a channel
    pub fn start_message_receiver(
        &self,
    ) -> (mpsc::Receiver<SignalingMessage>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(100);
        let client = self.client.clone();
        let transfer_id = self.transfer_id.clone();

        let handle = tokio::spawn(async move {
            let mut notifications = client.notifications();

            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        // Check if this is for our transfer
                        let is_our_transfer = event.tags.iter().any(|t| {
                            t.kind()
                                == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T))
                                && t.content() == Some(&transfer_id)
                        });

                        if is_our_transfer {
                            if let Some(msg) = Self::parse_signaling_event(&event) {
                                if tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(_) => break,
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
    let client = Client::new(keys.clone());

    // Add relays
    for relay_url in &relay_urls {
        if let Err(e) = client.add_relay(relay_url).await {
            eprintln!("Failed to add relay {}: {}", relay_url, e);
        }
    }

    // Connect
    client.connect().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let signaling = NostrSignaling {
        client,
        keys,
        transfer_id: transfer_id.to_string(),
        relay_urls,
    };

    signaling.subscribe().await?;

    Ok(signaling)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_payload_serialization() {
        let payload = SdpPayload {
            sdp: "v=0\r\n...".to_string(),
            sdp_type: "offer".to_string(),
            candidates: vec![],
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"offer\""));

        let decoded: SdpPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sdp_type, "offer");
    }

    #[test]
    fn test_ice_candidate_payload_serialization() {
        let payload = IceCandidatePayload {
            candidate: "candidate:1 1 UDP ...".to_string(),
            sdp_m_line_index: Some(0),
            sdp_mid: Some("0".to_string()),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"sdpMLineIndex\":0"));

        let decoded: IceCandidatePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sdp_m_line_index, Some(0));
    }
}
