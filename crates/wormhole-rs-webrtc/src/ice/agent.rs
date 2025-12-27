//! ICE Agent wrapper for TCP-based NAT traversal.
//!
//! Wraps webrtc-ice Agent configured for TCP candidates only,
//! providing a simpler API for our file transfer use case.
//!
//! Note: This implementation uses a simplified approach where both peers
//! exchange credentials and candidates before attempting to connect.
//! The ICE agent handles candidate pairing internally.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::agent::Agent;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::url::Url;

use super::IceConn;

/// Default STUN servers for NAT traversal.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
];

/// ICE credentials for signaling exchange.
#[derive(Debug, Clone)]
pub struct IceCredentials {
    /// Username fragment (ufrag)
    pub ufrag: String,
    /// Password
    pub pwd: String,
}

/// Serialized ICE candidate for signaling.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IceCandidateInfo {
    /// Candidate string in SDP format
    pub candidate: String,
}

/// ICE agent wrapper configured for TCP candidates.
///
/// This provides NAT traversal using ICE with TCP candidates,
/// returning a connection that implements AsyncRead/AsyncWrite.
pub struct IceTransport {
    agent: Agent,
    /// Channel to receive gathered candidates
    candidate_rx: mpsc::Receiver<Arc<dyn Candidate + Send + Sync>>,
}

impl IceTransport {
    /// Create a new ICE transport with default STUN servers.
    pub async fn new() -> Result<Self> {
        Self::with_stun_servers(DEFAULT_STUN_SERVERS).await
    }

    /// Create a new ICE transport with custom STUN servers.
    pub async fn with_stun_servers(stun_urls: &[&str]) -> Result<Self> {
        // Parse STUN URLs
        let urls: Vec<Url> = stun_urls
            .iter()
            .filter_map(|s| Url::parse_url(s).ok())
            .collect();

        if urls.is_empty() {
            anyhow::bail!("No valid STUN URLs provided");
        }

        // Channel for receiving candidates as they're gathered
        let (candidate_tx, candidate_rx) = mpsc::channel(32);

        // Configure agent for UDP candidates (standard ICE)
        let config = AgentConfig {
            urls,
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            ..Default::default()
        };

        let agent = Agent::new(config)
            .await
            .context("Failed to create ICE agent")?;

        // Set up candidate handler
        let tx = candidate_tx;
        agent.on_candidate(Box::new(move |c| {
            if let Some(candidate) = c {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send(candidate).await;
                })
            } else {
                // Gathering complete (null candidate)
                Box::pin(async {})
            }
        }));

        Ok(Self {
            agent,
            candidate_rx,
        })
    }

    /// Get local ICE credentials for signaling.
    pub async fn get_local_credentials(&self) -> IceCredentials {
        let (ufrag, pwd) = self.agent.get_local_user_credentials().await;
        IceCredentials { ufrag, pwd }
    }

    /// Start gathering ICE candidates.
    ///
    /// Returns immediately; candidates will be received via `next_candidate()`.
    pub async fn gather_candidates(&self) -> Result<()> {
        self.agent
            .gather_candidates()
            .context("Failed to start candidate gathering")?;
        Ok(())
    }

    /// Get the next gathered candidate.
    ///
    /// Returns `None` when gathering is complete.
    pub async fn next_candidate(&mut self) -> Option<IceCandidateInfo> {
        // Receive with timeout to detect gathering complete
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            self.candidate_rx.recv(),
        )
        .await
        {
            Ok(Some(candidate)) => Some(IceCandidateInfo {
                candidate: candidate.marshal(),
            }),
            Ok(None) | Err(_) => None,
        }
    }

    /// Collect all gathered candidates (blocking until complete).
    pub async fn collect_candidates(&mut self) -> Vec<IceCandidateInfo> {
        let mut candidates = Vec::new();
        while let Some(c) = self.next_candidate().await {
            candidates.push(c);
        }
        candidates
    }

    /// Set remote credentials received via signaling.
    pub async fn set_remote_credentials(&self, creds: &IceCredentials) -> Result<()> {
        self.agent
            .set_remote_credentials(creds.ufrag.clone(), creds.pwd.clone())
            .await
            .context("Failed to set remote credentials")?;
        Ok(())
    }

    /// Add remote candidates received via signaling.
    ///
    /// This must be called after set_remote_credentials and before dial/accept.
    pub fn add_remote_candidates(&self, candidates: &[IceCandidateInfo]) -> Result<()> {
        for c in candidates {
            match unmarshal_candidate(&c.candidate) {
                Ok(candidate) => {
                    eprintln!("Adding remote candidate: {}", candidate);
                    let candidate: Arc<dyn Candidate + Send + Sync> = Arc::new(candidate);
                    if let Err(e) = self.agent.add_remote_candidate(&candidate) {
                        eprintln!("Warning: Failed to add remote candidate: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to unmarshal candidate '{}': {}", c.candidate, e);
                }
            }
        }
        Ok(())
    }

    /// Connect as the controlling agent (sender/dialer).
    ///
    /// Call this after exchanging credentials.
    pub async fn dial(self, remote_ufrag: &str, remote_pwd: &str) -> Result<IceConn> {
        let (cancel_tx, cancel_rx) = mpsc::channel(1);

        // Keep cancel_tx alive - dropping it would cancel the dial
        let _cancel_tx = cancel_tx;

        let conn = self
            .agent
            .dial(cancel_rx, remote_ufrag.to_string(), remote_pwd.to_string())
            .await
            .context("ICE dial failed")?;

        // conn is already Arc<impl Conn>, pass directly
        Ok(IceConn::new(conn))
    }

    /// Connect as the controlled agent (receiver/acceptor).
    ///
    /// Call this after exchanging credentials.
    pub async fn accept(self, remote_ufrag: &str, remote_pwd: &str) -> Result<IceConn> {
        let (cancel_tx, cancel_rx) = mpsc::channel(1);

        // Keep cancel_tx alive - dropping it would cancel the accept
        let _cancel_tx = cancel_tx;

        let conn = self
            .agent
            .accept(cancel_rx, remote_ufrag.to_string(), remote_pwd.to_string())
            .await
            .context("ICE accept failed")?;

        // conn is already Arc<impl Conn>, pass directly
        Ok(IceConn::new(conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_ice_transport() {
        let transport = IceTransport::new().await;
        assert!(transport.is_ok(), "Should create ICE transport");
    }

    #[tokio::test]
    async fn test_get_credentials() {
        let transport = IceTransport::new().await.unwrap();
        let creds = transport.get_local_credentials().await;

        assert!(!creds.ufrag.is_empty(), "ufrag should not be empty");
        assert!(!creds.pwd.is_empty(), "pwd should not be empty");
    }
}
