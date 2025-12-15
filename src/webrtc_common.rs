//! WebRTC common utilities for peer-to-peer file transfer
//!
//! This module contains:
//! - Peer ID generation (human-friendly format)
//! - PeerJS signaling protocol messages
//! - PeerJS WebSocket client
//! - WebRTC peer connection management

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

// ============================================================================
// Constants
// ============================================================================

/// Default PeerJS server
pub const DEFAULT_PEERJS_SERVER: &str = "0.peerjs.com";

/// PeerJS WebSocket path
const PEERJS_PATH: &str = "/peerjs";

/// PeerJS API key (default public key)
const PEERJS_KEY: &str = "peerjs";

/// Heartbeat interval for keeping connection alive
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Google STUN server for NAT traversal
const STUN_SERVER: &str = "stun:stun.l.google.com:19302";

// ============================================================================
// Peer ID Generation
// ============================================================================

const ADJECTIVES: &[&str] = &[
    "happy", "sunny", "brave", "calm", "cool", "cute", "fast", "kind",
    "neat", "nice", "quiet", "smart", "soft", "warm", "wild", "wise",
    "bold", "bright", "clean", "clever", "cozy", "eager", "fair", "fancy",
    "gentle", "glad", "golden", "grand", "great", "jolly", "keen", "lively",
    "lucky", "merry", "mighty", "noble", "proud", "pure", "quick", "rapid",
    "rich", "royal", "sharp", "shiny", "silver", "simple", "smooth", "snowy",
    "spicy", "steady", "strong", "super", "sweet", "swift", "tender", "tiny",
    "vivid", "witty", "young", "zesty",
];

const NOUNS: &[&str] = &[
    "apple", "banana", "cherry", "dolphin", "eagle", "falcon", "grape",
    "harbor", "island", "jungle", "kitten", "lemon", "mango", "nectar",
    "orange", "panda", "quartz", "rabbit", "sunset", "tiger", "umbrella",
    "violet", "walrus", "xenon", "yellow", "zebra", "anchor", "breeze",
    "castle", "dragon", "ember", "forest", "glacier", "horizon", "indigo",
    "jasper", "kraken", "lantern", "meadow", "nebula", "ocean", "phoenix",
    "quasar", "river", "shadow", "thunder", "unicorn", "vortex", "willow",
    "crystal", "dusk", "echo", "flame", "glow", "haze", "iris", "jewel",
    "karma", "lotus", "moon", "nova",
];

/// Generate a human-friendly peer ID like "happy-apple-sunset"
pub fn generate_peer_id() -> String {
    let mut rng = thread_rng();
    let adj1 = ADJECTIVES.choose(&mut rng).unwrap();
    let noun1 = NOUNS.choose(&mut rng).unwrap();
    let noun2 = NOUNS.choose(&mut rng).unwrap();
    format!("{}-{}-{}", adj1, noun1, noun2)
}

/// Validate a peer ID format
pub fn is_valid_peer_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let chars: Vec<char> = id.chars().collect();
    // First and last must be alphanumeric
    if !chars.first().map(|c| c.is_alphanumeric()).unwrap_or(false) {
        return false;
    }
    if !chars.last().map(|c| c.is_alphanumeric()).unwrap_or(false) {
        return false;
    }
    // All characters must be alphanumeric, dash, or underscore
    chars.iter().all(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
}

// ============================================================================
// PeerJS Signaling Messages
// ============================================================================

/// Messages received from the PeerJS server
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "OPEN")]
    Open,

    #[serde(rename = "ID-TAKEN")]
    IdTaken,

    #[serde(rename = "INVALID-KEY")]
    InvalidKey,

    #[serde(rename = "ERROR")]
    Error { payload: Option<ErrorPayload> },

    #[serde(rename = "OFFER")]
    Offer {
        src: String,
        dst: String,
        payload: SdpPayload,
    },

    #[serde(rename = "ANSWER")]
    Answer {
        src: String,
        dst: String,
        payload: SdpPayload,
    },

    #[serde(rename = "CANDIDATE")]
    Candidate {
        src: String,
        dst: String,
        payload: CandidatePayload,
    },

    #[serde(rename = "LEAVE")]
    Leave { src: String },

    #[serde(rename = "EXPIRE")]
    Expire,

    #[serde(rename = "HEARTBEAT")]
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    #[serde(rename = "msg")]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpPayload {
    pub sdp: SessionDescription,
    #[serde(rename = "type")]
    pub connection_type: String,
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reliable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serialization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDescription {
    pub sdp: String,
    #[serde(rename = "type")]
    pub sdp_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePayload {
    pub candidate: IceCandidate,
    #[serde(rename = "type")]
    pub connection_type: String,
    #[serde(rename = "connectionId")]
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_m_line_index: Option<u16>,
    #[serde(rename = "sdpMid")]
    pub sdp_mid: Option<String>,
    #[serde(rename = "usernameFragment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_fragment: Option<String>,
}

/// Messages sent to the PeerJS server
#[derive(Debug, Clone, Serialize)]
pub struct ClientMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl ClientMessage {
    pub fn heartbeat() -> Self {
        Self {
            msg_type: "HEARTBEAT".to_string(),
            src: None,
            dst: None,
            payload: None,
        }
    }

    pub fn offer(src: &str, dst: &str, payload: SdpPayload) -> Self {
        Self {
            msg_type: "OFFER".to_string(),
            src: Some(src.to_string()),
            dst: Some(dst.to_string()),
            payload: Some(serde_json::to_value(payload).unwrap()),
        }
    }

    pub fn answer(src: &str, dst: &str, payload: SdpPayload) -> Self {
        Self {
            msg_type: "ANSWER".to_string(),
            src: Some(src.to_string()),
            dst: Some(dst.to_string()),
            payload: Some(serde_json::to_value(payload).unwrap()),
        }
    }

    pub fn candidate(src: &str, dst: &str, payload: CandidatePayload) -> Self {
        Self {
            msg_type: "CANDIDATE".to_string(),
            src: Some(src.to_string()),
            dst: Some(dst.to_string()),
            payload: Some(serde_json::to_value(payload).unwrap()),
        }
    }
}

// ============================================================================
// PeerJS Client
// ============================================================================

/// WebSocket client for PeerJS signaling server
pub struct PeerJsClient {
    peer_id: String,
    ws_write: futures::stream::SplitSink<
        WebSocketStream<MaybeTlsStream<TcpStream>>,
        Message,
    >,
    message_rx: mpsc::Receiver<ServerMessage>,
    _heartbeat_handle: tokio::task::JoinHandle<()>,
}

impl PeerJsClient {
    /// Connect to PeerJS server with a given peer ID
    pub async fn connect(peer_id: &str, server: Option<&str>) -> Result<Self> {
        let server = server.unwrap_or(DEFAULT_PEERJS_SERVER);
        let token = Uuid::new_v4().to_string();

        let url = format!(
            "wss://{}{}?key={}&id={}&token={}",
            server, PEERJS_PATH, PEERJS_KEY, peer_id, token
        );

        println!("Connecting to PeerJS server: {}", server);

        let (ws_stream, _) = connect_async(&url)
            .await
            .context("Failed to connect to PeerJS server")?;
        let (ws_write, mut ws_read) = ws_stream.split();

        let (message_tx, message_rx) = mpsc::channel(100);
        let (heartbeat_tx, mut heartbeat_rx) = mpsc::channel::<Message>(10);

        // Spawn message reader task
        let message_tx_clone = message_tx.clone();
        tokio::spawn(async move {
            while let Some(msg_result) = ws_read.next().await {
                match msg_result {
                    Ok(Message::Text(text)) => {
                        match serde_json::from_str::<ServerMessage>(&text) {
                            Ok(server_msg) => {
                                if message_tx_clone.send(server_msg).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to parse server message: {} - {}", e, text);
                            }
                        }
                    }
                    Ok(Message::Ping(data)) => {
                        let _ = heartbeat_tx.send(Message::Pong(data)).await;
                    }
                    Ok(Message::Close(_)) => {
                        break;
                    }
                    Err(e) => {
                        eprintln!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Create heartbeat sender task
        let heartbeat_handle = tokio::spawn(async move {
            let mut heartbeat_interval = interval(HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = heartbeat_interval.tick() => {
                        // Heartbeat tick - handled in main write loop
                    }
                    Some(_msg) = heartbeat_rx.recv() => {
                        // Pong response - would need ws_write access
                    }
                }
            }
        });

        Ok(Self {
            peer_id: peer_id.to_string(),
            ws_write,
            message_rx,
            _heartbeat_handle: heartbeat_handle,
        })
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Wait for the OPEN message from server
    pub async fn wait_for_open(&mut self) -> Result<()> {
        while let Some(msg) = self.message_rx.recv().await {
            match msg {
                ServerMessage::Open => {
                    println!("Connected to PeerJS server as: {}", self.peer_id);
                    return Ok(());
                }
                ServerMessage::IdTaken => {
                    anyhow::bail!("Peer ID '{}' is already taken", self.peer_id);
                }
                ServerMessage::InvalidKey => {
                    anyhow::bail!("Invalid PeerJS API key");
                }
                ServerMessage::Error { payload } => {
                    let msg = payload
                        .map(|p| p.message)
                        .unwrap_or_else(|| "Unknown error".to_string());
                    anyhow::bail!("PeerJS error: {}", msg);
                }
                _ => {
                    // Ignore other messages while waiting for OPEN
                }
            }
        }
        anyhow::bail!("Connection closed while waiting for OPEN")
    }

    /// Receive a message from the server
    pub async fn recv_message(&mut self) -> Result<ServerMessage> {
        self.message_rx
            .recv()
            .await
            .context("Channel closed")
    }

    /// Send a heartbeat message
    pub async fn send_heartbeat(&mut self) -> Result<()> {
        let msg = ClientMessage::heartbeat();
        self.send_raw(&msg).await
    }

    /// Send an SDP offer to a destination peer
    pub async fn send_offer(
        &mut self,
        dst: &str,
        sdp: &str,
        connection_id: &str,
    ) -> Result<()> {
        let payload = SdpPayload {
            sdp: SessionDescription {
                sdp: sdp.to_string(),
                sdp_type: "offer".to_string(),
            },
            connection_type: "data".to_string(),
            connection_id: connection_id.to_string(),
            browser: Some("wormhole-rs".to_string()),
            label: Some(connection_id.to_string()),
            reliable: Some(true),
            serialization: Some("binary".to_string()),
        };

        let msg = ClientMessage::offer(&self.peer_id, dst, payload);
        self.send_raw(&msg).await
    }

    /// Send an SDP answer to a destination peer
    pub async fn send_answer(
        &mut self,
        dst: &str,
        sdp: &str,
        connection_id: &str,
    ) -> Result<()> {
        let payload = SdpPayload {
            sdp: SessionDescription {
                sdp: sdp.to_string(),
                sdp_type: "answer".to_string(),
            },
            connection_type: "data".to_string(),
            connection_id: connection_id.to_string(),
            browser: Some("wormhole-rs".to_string()),
            label: None,
            reliable: None,
            serialization: None,
        };

        let msg = ClientMessage::answer(&self.peer_id, dst, payload);
        self.send_raw(&msg).await
    }

    /// Send an ICE candidate to a destination peer
    pub async fn send_candidate(
        &mut self,
        dst: &str,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_m_line_index: Option<u16>,
        connection_id: &str,
    ) -> Result<()> {
        let payload = CandidatePayload {
            candidate: IceCandidate {
                candidate: candidate.to_string(),
                sdp_m_line_index,
                sdp_mid: sdp_mid.map(|s| s.to_string()),
                username_fragment: None,
            },
            connection_type: "data".to_string(),
            connection_id: connection_id.to_string(),
        };

        let msg = ClientMessage::candidate(&self.peer_id, dst, payload);
        self.send_raw(&msg).await
    }

    /// Send a raw message to the server
    async fn send_raw(&mut self, msg: &ClientMessage) -> Result<()> {
        let json = serde_json::to_string(msg)?;
        self.ws_write
            .send(Message::Text(json))
            .await
            .context("Failed to send message")?;
        Ok(())
    }
}

// ============================================================================
// WebRTC Peer Connection
// ============================================================================

/// WebRTC peer connection wrapper
pub struct WebRtcPeer {
    peer_connection: Arc<RTCPeerConnection>,
    ice_candidate_rx: Option<mpsc::Receiver<RTCIceCandidate>>,
    data_channel_rx: Option<mpsc::Receiver<Arc<RTCDataChannel>>>,
}

impl WebRtcPeer {
    /// Create a new WebRTC peer connection
    pub async fn new() -> Result<Self> {
        let ice_servers = vec![
            // STUN server for NAT traversal discovery
            RTCIceServer {
                urls: vec![STUN_SERVER.to_owned()],
                ..Default::default()
            },
        ];

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .context("Failed to register default codecs")?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .context("Failed to register interceptors")?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let peer_connection = Arc::new(
            api.new_peer_connection(config)
                .await
                .context("Failed to create peer connection")?,
        );

        let (ice_candidate_tx, ice_candidate_rx) = mpsc::channel(50);
        let (data_channel_tx, data_channel_rx) = mpsc::channel(1);

        // Set up ICE candidate handler
        let ice_tx = ice_candidate_tx.clone();
        peer_connection.on_ice_candidate(Box::new(move |candidate| {
            let ice_tx = ice_tx.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    let _ = ice_tx.send(candidate).await;
                }
            })
        }));

        // Set up connection state handler
        peer_connection.on_peer_connection_state_change(Box::new(move |state| {
            Box::pin(async move {
                match state {
                    RTCPeerConnectionState::Connected => {
                        println!("WebRTC connection established!");
                    }
                    RTCPeerConnectionState::Disconnected => {
                        println!("WebRTC connection disconnected");
                    }
                    RTCPeerConnectionState::Failed => {
                        eprintln!("WebRTC connection failed");
                    }
                    RTCPeerConnectionState::Closed => {
                        println!("WebRTC connection closed");
                    }
                    _ => {}
                }
            })
        }));

        // Set up data channel handler (for incoming data channels)
        let dc_tx = data_channel_tx.clone();
        peer_connection.on_data_channel(Box::new(move |dc| {
            let dc_tx = dc_tx.clone();
            println!("New data channel: {}", dc.label());
            Box::pin(async move {
                let _ = dc_tx.send(dc).await;
            })
        }));

        Ok(Self {
            peer_connection,
            ice_candidate_rx: Some(ice_candidate_rx),
            data_channel_rx: Some(data_channel_rx),
        })
    }

    /// Take ownership of the ICE candidate receiver
    pub fn take_ice_candidate_rx(&mut self) -> Option<mpsc::Receiver<RTCIceCandidate>> {
        self.ice_candidate_rx.take()
    }

    /// Take ownership of the data channel receiver
    pub fn take_data_channel_rx(&mut self) -> Option<mpsc::Receiver<Arc<RTCDataChannel>>> {
        self.data_channel_rx.take()
    }

    /// Create a data channel with the given label
    pub async fn create_data_channel(&self, label: &str) -> Result<Arc<RTCDataChannel>> {
        let dc = self
            .peer_connection
            .create_data_channel(label, None)
            .await
            .context("Failed to create data channel")?;
        println!("Created data channel: {}", label);
        Ok(dc)
    }

    /// Create an SDP offer
    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        self.peer_connection
            .create_offer(None)
            .await
            .context("Failed to create offer")
    }

    /// Create an SDP answer
    pub async fn create_answer(&self) -> Result<RTCSessionDescription> {
        self.peer_connection
            .create_answer(None)
            .await
            .context("Failed to create answer")
    }

    /// Set the local description
    pub async fn set_local_description(&self, sdp: RTCSessionDescription) -> Result<()> {
        self.peer_connection
            .set_local_description(sdp)
            .await
            .context("Failed to set local description")
    }

    /// Set the remote description
    pub async fn set_remote_description(&self, sdp: RTCSessionDescription) -> Result<()> {
        self.peer_connection
            .set_remote_description(sdp)
            .await
            .context("Failed to set remote description")
    }

    /// Add an ICE candidate
    pub async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<()> {
        self.peer_connection
            .add_ice_candidate(candidate)
            .await
            .context("Failed to add ICE candidate")
    }

    /// Get the connection state
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer_connection.connection_state()
    }

    /// Close the peer connection
    pub async fn close(&self) -> Result<()> {
        self.peer_connection
            .close()
            .await
            .context("Failed to close peer connection")
    }
}

/// Set up handlers for a data channel to send/receive messages
pub fn setup_data_channel_handlers(
    dc: &Arc<RTCDataChannel>,
    message_tx: mpsc::Sender<Vec<u8>>,
    open_tx: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let dc_label = dc.label().to_string();

    // On open
    if let Some(open_tx) = open_tx {
        let label = dc_label.clone();
        dc.on_open(Box::new(move || {
            println!("Data channel '{}' opened", label);
            let _ = open_tx.send(());
            Box::pin(async {})
        }));
    }

    // On message
    let label = dc_label.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let message_tx = message_tx.clone();
        let _label = label.clone();
        Box::pin(async move {
            let _ = message_tx.send(msg.data.to_vec()).await;
        })
    }));

    // On error
    let label = dc_label.clone();
    dc.on_error(Box::new(move |err| {
        eprintln!("Data channel '{}' error: {}", label, err);
        Box::pin(async {})
    }));

    // On close
    dc.on_close(Box::new(move || {
        println!("Data channel '{}' closed", dc_label);
        Box::pin(async {})
    }));
}
