//! WebRTC common utilities for peer-to-peer file transfer
//!
//! This module contains:
//! - WebRTC peer connection management
//! - Data channel handlers

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::stats::StatsReportType;

// ============================================================================
// Constants
// ============================================================================

/// Google STUN server for NAT traversal
const STUN_SERVER: &str = "stun:stun.l.google.com:19302";

// ============================================================================
// WebRTC Peer Connection
// ============================================================================

/// WebRTC peer connection wrapper
pub struct WebRtcPeer {
    peer_connection: Arc<RTCPeerConnection>,
    ice_candidate_rx: Option<mpsc::Receiver<RTCIceCandidate>>,
    data_channel_rx: Option<mpsc::Receiver<Arc<RTCDataChannel>>>,
    ice_gathering_rx: Option<watch::Receiver<RTCIceGathererState>>,
}

impl WebRtcPeer {
    /// Create a new WebRTC peer connection with STUN server for NAT traversal
    pub async fn new() -> Result<Self> {
        let ice_servers = vec![
            // STUN server for NAT traversal discovery
            RTCIceServer {
                urls: vec![STUN_SERVER.to_owned()],
                ..Default::default()
            },
        ];
        Self::new_with_config(ice_servers).await
    }

    /// Create a new WebRTC peer connection for offline/direct LAN use (no STUN servers)
    #[allow(dead_code)]
    pub async fn new_offline() -> Result<Self> {
        // No ICE servers - only direct host candidates will be used
        Self::new_with_config(vec![]).await
    }

    /// Internal helper to create peer connection with given ICE servers
    async fn new_with_config(ice_servers: Vec<RTCIceServer>) -> Result<Self> {
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
        let (ice_gathering_tx, ice_gathering_rx) = watch::channel(RTCIceGathererState::New);

        // Set up ICE candidate handler
        let ice_tx = ice_candidate_tx.clone();
        peer_connection.on_ice_candidate(Box::new(move |candidate| {
            let ice_tx = ice_tx.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    if ice_tx.send(candidate).await.is_err() {
                        log::warn!("Failed to send ICE candidate - receiver dropped");
                    }
                }
            })
        }));

        // Set up ICE gathering state handler (for vanilla ICE / offline mode)
        peer_connection.on_ice_gathering_state_change(Box::new(move |state| {
            if ice_gathering_tx.send(state).is_err() {
                log::warn!("Failed to send ICE gathering state - receiver dropped");
            }
            Box::pin(async {})
        }));

        // Set up connection state handler
        peer_connection.on_peer_connection_state_change(Box::new(move |state| {
            Box::pin(async move {
                match state {
                    RTCPeerConnectionState::Connected => {
                        eprintln!("WebRTC connection established!");
                    }
                    RTCPeerConnectionState::Disconnected => {
                        eprintln!("WebRTC connection disconnected");
                    }
                    RTCPeerConnectionState::Failed => {
                        log::error!("WebRTC connection failed");
                    }
                    RTCPeerConnectionState::Closed => {
                        eprintln!("WebRTC connection closed");
                    }
                    _ => {}
                }
            })
        }));

        // Set up data channel handler (for incoming data channels)
        let dc_tx = data_channel_tx.clone();
        peer_connection.on_data_channel(Box::new(move |dc| {
            let dc_tx = dc_tx.clone();
            let label = dc.label().to_string();
            Box::pin(async move {
                if dc_tx.send(dc).await.is_err() {
                    log::warn!(
                        "Failed to forward data channel '{}' - receiver dropped",
                        label
                    );
                }
            })
        }));

        Ok(Self {
            peer_connection,
            ice_candidate_rx: Some(ice_candidate_rx),
            data_channel_rx: Some(data_channel_rx),
            ice_gathering_rx: Some(ice_gathering_rx),
        })
    }

    /// Take ownership of the ICE candidate receiver
    #[allow(dead_code)]
    pub fn take_ice_candidate_rx(&mut self) -> Option<mpsc::Receiver<RTCIceCandidate>> {
        self.ice_candidate_rx.take()
    }

    /// Take ownership of the data channel receiver
    pub fn take_data_channel_rx(&mut self) -> Option<mpsc::Receiver<Arc<RTCDataChannel>>> {
        self.data_channel_rx.take()
    }

    /// Take ownership of the ICE gathering state receiver
    #[allow(dead_code)]
    pub fn take_ice_gathering_rx(&mut self) -> Option<watch::Receiver<RTCIceGathererState>> {
        self.ice_gathering_rx.take()
    }

    /// Wait for ICE gathering to complete and collect all candidates.
    /// This is used for "vanilla ICE" (non-trickle) signaling where we need
    /// all candidates before generating the offer/answer JSON.
    pub async fn gather_ice_candidates(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<RTCIceCandidate>> {
        let mut ice_rx = self
            .ice_candidate_rx
            .take()
            .context("ICE candidate receiver already taken")?;
        let mut gathering_rx = self
            .ice_gathering_rx
            .take()
            .context("ICE gathering receiver already taken")?;

        let mut candidates = Vec::new();

        tokio::select! {
            _ = tokio::time::sleep(timeout) => {
                // Timeout reached, return what we have
                eprintln!("ICE gathering timeout, collected {} candidates", candidates.len());
            }
            _ = async {
                loop {
                    tokio::select! {
                        candidate = ice_rx.recv() => {
                            if let Some(candidate) = candidate {
                                candidates.push(candidate);
                            }
                        }
                        result = gathering_rx.changed() => {
                            if result.is_ok() {
                                let state = *gathering_rx.borrow();
                                if state == RTCIceGathererState::Complete {
                                    // Give a small delay to collect any remaining candidates
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    // Drain any remaining candidates
                                    while let Ok(candidate) = ice_rx.try_recv() {
                                        candidates.push(candidate);
                                    }
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            } => {}
        }

        Ok(candidates)
    }

    /// Create a data channel with the given label
    pub async fn create_data_channel(&self, label: &str) -> Result<Arc<RTCDataChannel>> {
        let dc = self
            .peer_connection
            .create_data_channel(label, None)
            .await
            .context("Failed to create data channel")?;
        eprintln!("Created data channel: {}", label);
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
    pub async fn add_ice_candidate(
        &self,
        candidate: webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
    ) -> Result<()> {
        self.peer_connection
            .add_ice_candidate(candidate)
            .await
            .context("Failed to add ICE candidate")
    }

    /// Get the connection state
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer_connection.connection_state()
    }

    /// Get the ICE connection state
    #[allow(dead_code)]
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.peer_connection.ice_connection_state()
    }

    /// Get connection info (candidate type, addresses, etc.)
    pub async fn get_connection_info(&self) -> WebRtcConnectionInfo {
        let stats = self.peer_connection.get_stats().await;

        let mut local_candidate_type = None;
        let mut remote_candidate_type = None;
        let mut local_address = None;
        let mut remote_address = None;
        let mut nominated_pair_local_id = None;
        let mut nominated_pair_remote_id = None;

        // First pass: find the nominated candidate pair
        for (_id, report) in &stats.reports {
            if let StatsReportType::CandidatePair(pair) = report {
                if pair.nominated {
                    nominated_pair_local_id = Some(pair.local_candidate_id.clone());
                    nominated_pair_remote_id = Some(pair.remote_candidate_id.clone());
                    break;
                }
            }
        }

        // Second pass: get candidate details
        for (id, report) in &stats.reports {
            match report {
                StatsReportType::LocalCandidate(candidate) => {
                    if nominated_pair_local_id.as_ref() == Some(id) {
                        local_candidate_type = Some(format!("{:?}", candidate.candidate_type));
                        local_address = Some(format!("{}:{}", candidate.ip, candidate.port));
                    }
                }
                StatsReportType::RemoteCandidate(candidate) => {
                    if nominated_pair_remote_id.as_ref() == Some(id) {
                        remote_candidate_type = Some(format!("{:?}", candidate.candidate_type));
                        remote_address = Some(format!("{}:{}", candidate.ip, candidate.port));
                    }
                }
                _ => {}
            }
        }

        // Determine connection type based on candidate types
        let connection_type = match (&local_candidate_type, &remote_candidate_type) {
            (Some(local), Some(remote)) => {
                let local_lower = local.to_lowercase();
                let remote_lower = remote.to_lowercase();
                if local_lower.contains("relay") || remote_lower.contains("relay") {
                    "Relay (TURN)".to_string()
                } else if local_lower.contains("host") && remote_lower.contains("host") {
                    "Direct (Host)".to_string()
                } else if local_lower.contains("srflx") || remote_lower.contains("srflx") {
                    "Direct (STUN)".to_string()
                } else if local_lower.contains("prflx") || remote_lower.contains("prflx") {
                    "Direct (Peer Reflexive)".to_string()
                } else {
                    format!("Unknown ({}/{})", local, remote)
                }
            }
            _ => "Unknown".to_string(),
        };

        WebRtcConnectionInfo {
            connection_type,
            local_address,
            remote_address,
        }
    }

    /// Close the peer connection
    pub async fn close(&self) -> Result<()> {
        self.peer_connection
            .close()
            .await
            .context("Failed to close peer connection")
    }
}

/// WebRTC connection information
#[derive(Debug, Clone)]
pub struct WebRtcConnectionInfo {
    pub connection_type: String,
    pub local_address: Option<String>,
    pub remote_address: Option<String>,
}

// ============================================================================
// DataChannelStream - AsyncRead + AsyncWrite adapter for data channels
// ============================================================================

use bytes::Bytes;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

/// A stream adapter that wraps a WebRTC data channel to implement AsyncRead + AsyncWrite.
///
/// This allows using the common transfer protocol with WebRTC data channels.
pub struct DataChannelStream {
    data_channel: Arc<RTCDataChannel>,
    message_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    read_buffer: VecDeque<u8>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl DataChannelStream {
    /// Create a new DataChannelStream from a data channel.
    ///
    /// Sets up the message handler and returns the stream.
    /// The `open_tx` is signaled when the data channel opens (if provided).
    pub fn new(
        data_channel: Arc<RTCDataChannel>,
        open_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let (message_tx, message_rx) = mpsc::channel::<Vec<u8>>(1000);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let dc_label = data_channel.label().to_string();

        // On open
        if let Some(open_tx) = open_tx {
            let label = dc_label.clone();
            data_channel.on_open(Box::new(move || {
                eprintln!("Data channel '{}' opened", label);
                let _ = open_tx.send(());
                Box::pin(async {})
            }));
        }

        // On message - forward to channel
        let tx = message_tx.clone();
        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx.clone();
            Box::pin(async move {
                if tx.send(msg.data.to_vec()).await.is_err() {
                    log::warn!("Failed to forward data channel message - receiver dropped");
                }
            })
        }));

        // On error
        let label = dc_label.clone();
        data_channel.on_error(Box::new(move |err| {
            log::error!("Data channel '{}' error: {}", label, err);
            Box::pin(async {})
        }));

        // On close - mark as closed
        let closed_flag = closed.clone();
        data_channel.on_close(Box::new(move || {
            closed_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            eprintln!("Data channel '{}' closed", dc_label);
            Box::pin(async {})
        }));

        Self {
            data_channel,
            message_rx: Arc::new(Mutex::new(message_rx)),
            read_buffer: VecDeque::new(),
            closed,
        }
    }

    /// Check if the data channel is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl AsyncRead for DataChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            for _ in 0..to_read {
                if let Some(byte) = self.read_buffer.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            return Poll::Ready(Ok(()));
        }

        // Check if channel is closed
        if self.is_closed() {
            return Poll::Ready(Ok(())); // EOF
        }

        // Try to receive more data
        let message_rx = self.message_rx.clone();

        // We need to poll the receiver
        // Since we can't hold the lock across await points in poll, we use try_lock
        let result = match message_rx.try_lock() {
            Ok(mut rx) => {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(data)) => Some(data),
                    Poll::Ready(None) => None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            Err(_) => {
                // Lock is held, wake up later
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match result {
            Some(data) => {
                // Buffer the data
                self.read_buffer.extend(data);

                // Now read from buffer
                let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
                for _ in 0..to_read {
                    if let Some(byte) = self.read_buffer.pop_front() {
                        buf.put_slice(&[byte]);
                    }
                }
                Poll::Ready(Ok(()))
            }
            None => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for DataChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Data channel closed",
            )));
        }

        // WebRTC data channel send is async, but we need to block here
        // We'll spawn a task to send and use a oneshot to get the result
        let data_channel = self.data_channel.clone();
        let data = Bytes::copy_from_slice(buf);
        let len = buf.len();

        // Use a waker-based approach
        let waker = cx.waker().clone();

        // Spawn the send operation
        tokio::spawn(async move {
            let _ = data_channel.send(&data).await;
            waker.wake();
        });

        // Return the length immediately since WebRTC data channels are reliable
        // and will buffer the data
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // WebRTC data channels handle their own buffering
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // We don't close the channel here - the caller manages the lifecycle
        Poll::Ready(Ok(()))
    }
}
