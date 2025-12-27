//! WebRTC common utilities for peer-to-peer file transfer
//!
//! This module contains:
//! - WebRTC peer connection management
//! - Data channel handlers

use anyhow::{Context, Result};
use webrtc::ice::candidate::CandidateType;
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
// Helper Functions
// ============================================================================

/// Convert a CandidateType to a human-readable string
fn candidate_type_to_str(ct: CandidateType) -> &'static str {
    match ct {
        CandidateType::Host => "Host",
        CandidateType::ServerReflexive => "ServerReflexive",
        CandidateType::PeerReflexive => "PeerReflexive",
        CandidateType::Relay => "Relay",
        CandidateType::Unspecified => "Unspecified",
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
                        // Expected during shutdown when receiver is dropped
                        log::trace!("ICE candidate channel closed");
                    }
                }
            })
        }));

        // Set up ICE gathering state handler (for vanilla ICE / offline mode)
        peer_connection.on_ice_gathering_state_change(Box::new(move |state| {
            if ice_gathering_tx.send(state).is_err() {
                // Expected during shutdown when receiver is dropped
                log::trace!("ICE gathering state channel closed");
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
                    // Expected during shutdown when receiver is dropped
                    log::trace!("Data channel '{}' receiver closed", label);
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
                            match candidate {
                                Some(candidate) => {
                                    candidates.push(candidate);
                                }
                                None => {
                                    // Channel closed (sender dropped), drain any remaining and exit
                                    while let Ok(candidate) = ice_rx.try_recv() {
                                        candidates.push(candidate);
                                    }
                                    break;
                                }
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

        let mut local_candidate_type: Option<CandidateType> = None;
        let mut remote_candidate_type: Option<CandidateType> = None;
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
                        local_candidate_type = Some(candidate.candidate_type);
                        local_address = Some(format!("{}:{}", candidate.ip, candidate.port));
                    }
                }
                StatsReportType::RemoteCandidate(candidate) => {
                    if nominated_pair_remote_id.as_ref() == Some(id) {
                        remote_candidate_type = Some(candidate.candidate_type);
                        remote_address = Some(format!("{}:{}", candidate.ip, candidate.port));
                    }
                }
                _ => {}
            }
        }

        // Determine connection type based on candidate types
        let connection_type = match (local_candidate_type, remote_candidate_type) {
            (Some(local), Some(remote)) => {
                // If either side uses a relay, the connection is relayed
                if matches!(local, CandidateType::Relay)
                    || matches!(remote, CandidateType::Relay)
                {
                    "Relay (TURN)".to_string()
                } else if matches!(local, CandidateType::Host)
                    && matches!(remote, CandidateType::Host)
                {
                    "Direct (Host)".to_string()
                } else if matches!(local, CandidateType::ServerReflexive)
                    || matches!(remote, CandidateType::ServerReflexive)
                {
                    "Direct (STUN)".to_string()
                } else if matches!(local, CandidateType::PeerReflexive)
                    || matches!(remote, CandidateType::PeerReflexive)
                {
                    "Direct (Peer Reflexive)".to_string()
                } else {
                    // Fallback for Unspecified or any future variants
                    format!(
                        "Unknown ({}/{})",
                        candidate_type_to_str(local),
                        candidate_type_to_str(remote)
                    )
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
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Efficiently drain bytes from a VecDeque into a ReadBuf using bulk copies.
///
/// Uses `as_slices()` to get contiguous slices and copies them in at most two
/// bulk operations instead of byte-by-byte, providing much better performance.
fn drain_vecdeque_to_readbuf(buffer: &mut VecDeque<u8>, buf: &mut ReadBuf<'_>) -> usize {
    let to_read = std::cmp::min(buf.remaining(), buffer.len());
    if to_read == 0 {
        return 0;
    }

    let (first, second) = buffer.as_slices();

    if to_read <= first.len() {
        // All bytes come from the first slice
        buf.put_slice(&first[..to_read]);
    } else {
        // Need bytes from both slices
        buf.put_slice(first);
        let remaining = to_read - first.len();
        buf.put_slice(&second[..remaining]);
    }

    // Remove the bytes we just copied
    buffer.drain(..to_read);

    to_read
}
/// A stream adapter that wraps a WebRTC data channel to implement AsyncRead + AsyncWrite.
///
/// This allows using the common transfer protocol with WebRTC data channels.
pub struct DataChannelStream {
    data_channel: Arc<RTCDataChannel>,
    message_rx: mpsc::Receiver<Vec<u8>>,
    read_buffer: VecDeque<u8>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// Tracks if any messages were dropped due to buffer overflow.
    /// If true, the stream will return an error on the next read to prevent
    /// silent data corruption in file transfers.
    messages_dropped: Arc<std::sync::atomic::AtomicBool>,
    /// Pending write operation result receiver
    write_pending: Option<tokio::sync::oneshot::Receiver<Result<usize, String>>>,
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
        let messages_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

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

        // On message - forward to channel synchronously to preserve ordering.
        // try_send is non-blocking and maintains message order. If the channel
        // is full (which shouldn't happen with our 1000-message buffer), we set
        // a flag to surface an error on the next read rather than silently
        // dropping data which would corrupt file transfers.
        let tx = message_tx.clone();
        let dropped_flag = messages_dropped.clone();
        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let data = msg.data.to_vec();
            match tx.try_send(data) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Mark that messages were dropped - the reader will detect this
                    // and return an error to prevent silent data corruption.
                    dropped_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    log::error!(
                        "Data channel message buffer full - message dropped. \
                         Transfer will fail to prevent data corruption."
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Expected during shutdown when receiver is dropped
                    log::trace!("Data channel message receiver closed");
                }
            }
            Box::pin(async {})
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
            message_rx,
            read_buffer: VecDeque::new(),
            closed,
            messages_dropped,
            write_pending: None,
        }
    }

    /// Check if the data channel is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Check if any messages were dropped due to buffer overflow.
    /// If true, the transfer data may be corrupted.
    fn has_dropped_messages(&self) -> bool {
        self.messages_dropped
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl AsyncRead for DataChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Check if any messages were dropped - fail fast to prevent silent corruption
        if self.has_dropped_messages() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Data channel buffer overflow - messages were dropped, transfer data corrupted",
            )));
        }

        // First, drain any buffered data using bulk copy
        if !self.read_buffer.is_empty() {
            let this = self.as_mut().get_mut();
            drain_vecdeque_to_readbuf(&mut this.read_buffer, buf);
            return Poll::Ready(Ok(()));
        }

        // Check if channel is closed
        if self.is_closed() {
            return Poll::Ready(Ok(())); // EOF
        }

        // Poll the receiver directly - we have &mut self so exclusive access
        let this = self.as_mut().get_mut();
        match this.message_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                // Buffer the data
                this.read_buffer.extend(data);

                // Read from buffer using bulk copy
                drain_vecdeque_to_readbuf(&mut this.read_buffer, buf);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DataChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Data channel closed",
            )));
        }

        let this = self.as_mut().get_mut();

        // Check if we have a pending write operation
        if let Some(ref mut pending_rx) = this.write_pending {
            // Poll the pending operation
            match Pin::new(pending_rx).poll(cx) {
                Poll::Ready(Ok(Ok(len))) => {
                    this.write_pending = None;
                    return Poll::Ready(Ok(len));
                }
                Poll::Ready(Ok(Err(e))) => {
                    this.write_pending = None;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Ready(Err(_)) => {
                    // Channel closed unexpectedly
                    this.write_pending = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Write operation cancelled",
                    )));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        // Start a new write operation
        let data_channel = this.data_channel.clone();
        let data = Bytes::copy_from_slice(buf);
        let len = buf.len();

        let (tx, mut rx) = tokio::sync::oneshot::channel();

        // Spawn the send operation
        tokio::spawn(async move {
            match data_channel.send(&data).await {
                Ok(_) => {
                    let _ = tx.send(Ok(len));
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                }
            }
        });

        // Poll immediately to register the waker, then store if still pending
        match Pin::new(&mut rx).poll(cx) {
            Poll::Ready(Ok(Ok(len))) => Poll::Ready(Ok(len)),
            Poll::Ready(Ok(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Write operation cancelled",
                )))
            }
            Poll::Pending => {
                // Store the receiver for future polls - waker is now registered
                this.write_pending = Some(rx);
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if there's a pending write operation that needs to complete
        if let Some(ref mut pending_rx) = this.write_pending {
            match Pin::new(pending_rx).poll(cx) {
                Poll::Ready(Ok(Ok(_))) => {
                    this.write_pending = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    this.write_pending = None;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
                Poll::Ready(Err(_)) => {
                    this.write_pending = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Write operation cancelled during flush",
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            // No pending write, flush is complete
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // We don't close the channel here - the caller manages the lifecycle
        Poll::Ready(Ok(()))
    }
}
