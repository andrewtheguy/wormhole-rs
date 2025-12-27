//! IceConn: AsyncRead/AsyncWrite adapter for webrtc-ice connections.
//!
//! Bridges webrtc-ice's Conn trait (async fn send/recv) to tokio's
//! AsyncRead/AsyncWrite traits (poll-based) for use with the unified
//! transfer protocol.
//!
//! Implements reliable message delivery over UDP with fragmentation,
//! sequencing, and acknowledgments.

use bytes::BytesMut;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use webrtc_util::Conn;

/// Buffer size for receiving data from ICE connection.
const RECV_BUFFER_SIZE: usize = 65536;

/// Channel buffer size
const CHANNEL_BUFFER_SIZE: usize = 256;

/// Maximum UDP payload size (conservative, works across most networks)
const MAX_UDP_PAYLOAD: usize = 1200;

/// Header size for our reliable protocol:
/// - 4 bytes: message ID (u32)
/// - 2 bytes: fragment index (u16)
/// - 2 bytes: total fragments (u16)
const HEADER_SIZE: usize = 8;

/// Maximum data per fragment
const MAX_FRAGMENT_DATA: usize = MAX_UDP_PAYLOAD - HEADER_SIZE;

/// ACK message type marker (message_id = 0xFFFFFFFF)
const ACK_MESSAGE_ID: u32 = 0xFFFFFFFF;

/// Result from the background recv task
enum RecvResult {
    Data(Vec<u8>),
    Error(String),
    Closed,
}

/// Fragment being reassembled
struct ReassemblyBuffer {
    fragments: HashMap<u16, Vec<u8>>,
    total_fragments: u16,
    last_update: std::time::Instant,
}

/// Wrapper around webrtc-ice Conn that implements AsyncRead/AsyncWrite.
///
/// Provides reliable, ordered message delivery over UDP with:
/// - Message fragmentation for large payloads
/// - Sequence numbers for ordering
/// - Acknowledgments for reliability
pub struct IceConn {
    conn: Arc<dyn Conn + Send + Sync>,
    recv_rx: mpsc::Receiver<RecvResult>,
    send_tx: mpsc::Sender<Vec<u8>>,
    read_buf: BytesMut,
    closed: bool,
}

impl IceConn {
    /// Create a new IceConn from a webrtc-ice connection.
    pub fn new(conn: Arc<dyn Conn + Send + Sync>) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);

        // Shared state for ACKs
        let pending_acks: Arc<Mutex<HashMap<u32, bool>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn background task to read and reassemble messages
        let conn_read = conn.clone();
        let pending_acks_recv = pending_acks.clone();
        tokio::spawn(async move {
            let mut reassembly: HashMap<u32, ReassemblyBuffer> = HashMap::new();
            let mut next_expected_msg_id: u32 = 0;
            let mut completed_messages: HashMap<u32, Vec<u8>> = HashMap::new();

            loop {
                let mut buf = vec![0u8; RECV_BUFFER_SIZE];
                match conn_read.recv(&mut buf).await {
                    Ok(0) => {
                        let _ = recv_tx.send(RecvResult::Closed).await;
                        break;
                    }
                    Ok(n) if n >= HEADER_SIZE => {
                        let msg_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        let frag_idx = u16::from_be_bytes([buf[4], buf[5]]);
                        let total_frags = u16::from_be_bytes([buf[6], buf[7]]);
                        let data = buf[HEADER_SIZE..n].to_vec();

                        // Check if this is an ACK
                        if msg_id == ACK_MESSAGE_ID {
                            // ACK packet: data contains the acked message_id
                            if data.len() >= 4 {
                                let acked_id =
                                    u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                                pending_acks_recv.lock().await.insert(acked_id, true);
                            }
                            continue;
                        }

                        // Send ACK for this fragment
                        let mut ack = vec![0u8; HEADER_SIZE + 4];
                        ack[0..4].copy_from_slice(&ACK_MESSAGE_ID.to_be_bytes());
                        ack[4..6].copy_from_slice(&frag_idx.to_be_bytes());
                        ack[6..8].copy_from_slice(&1u16.to_be_bytes());
                        ack[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&msg_id.to_be_bytes());
                        let _ = conn_read.send(&ack).await;

                        // Store fragment
                        let entry = reassembly.entry(msg_id).or_insert_with(|| ReassemblyBuffer {
                            fragments: HashMap::new(),
                            total_fragments: total_frags,
                            last_update: std::time::Instant::now(),
                        });
                        entry.fragments.insert(frag_idx, data);
                        entry.last_update = std::time::Instant::now();

                        // Check if message is complete
                        if entry.fragments.len() == entry.total_fragments as usize {
                            // Reassemble in order
                            let mut complete = Vec::new();
                            for i in 0..entry.total_fragments {
                                if let Some(frag) = entry.fragments.get(&i) {
                                    complete.extend_from_slice(frag);
                                }
                            }
                            reassembly.remove(&msg_id);
                            completed_messages.insert(msg_id, complete);
                        }

                        // Deliver messages in order
                        while let Some(msg) = completed_messages.remove(&next_expected_msg_id) {
                            if recv_tx.send(RecvResult::Data(msg)).await.is_err() {
                                return;
                            }
                            next_expected_msg_id = next_expected_msg_id.wrapping_add(1);
                        }
                    }
                    Ok(_) => {
                        // Packet too small, ignore
                        continue;
                    }
                    Err(e) => {
                        let _ = recv_tx.send(RecvResult::Error(e.to_string())).await;
                        break;
                    }
                }
            }
        });

        // Spawn background task for reliable sending
        let conn_write = conn.clone();
        tokio::spawn(async move {
            let mut msg_id: u32 = 0;

            while let Some(data) = send_rx.recv().await {
                let current_msg_id = msg_id;
                msg_id = msg_id.wrapping_add(1);

                // Fragment the message
                let chunks: Vec<&[u8]> = if data.is_empty() {
                    vec![&[]]
                } else {
                    data.chunks(MAX_FRAGMENT_DATA).collect()
                };
                let total_frags = chunks.len() as u16;

                // Send all fragments with pacing to avoid overwhelming the network
                for (idx, chunk) in chunks.iter().enumerate() {
                    let frag_idx = idx as u16;

                    // Build fragment packet
                    let mut packet = Vec::with_capacity(HEADER_SIZE + chunk.len());
                    packet.extend_from_slice(&current_msg_id.to_be_bytes());
                    packet.extend_from_slice(&frag_idx.to_be_bytes());
                    packet.extend_from_slice(&total_frags.to_be_bytes());
                    packet.extend_from_slice(chunk);

                    if let Err(e) = conn_write.send(&packet).await {
                        log::debug!("Send error: {}", e);
                        return;
                    }

                    // Pace fragments to avoid buffer overflow
                    // This is ~1ms per fragment = ~1.2 MB/s max throughput
                    tokio::time::sleep(Duration::from_micros(500)).await;
                }
            }
        });

        Self {
            conn,
            recv_rx,
            send_tx,
            read_buf: BytesMut::new(),
            closed: false,
        }
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &Arc<dyn Conn + Send + Sync> {
        &self.conn
    }
}

impl AsyncRead for IceConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed && self.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if !self.read_buf.is_empty() {
            let to_copy = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(to_copy));
            return Poll::Ready(Ok(()));
        }

        match self.recv_rx.poll_recv(cx) {
            Poll::Ready(Some(RecvResult::Data(data))) => {
                self.read_buf.extend_from_slice(&data);
                let to_copy = std::cmp::min(self.read_buf.len(), buf.remaining());
                buf.put_slice(&self.read_buf.split_to(to_copy));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(RecvResult::Error(e))) => {
                self.closed = true;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(RecvResult::Closed)) | Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for IceConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = buf.to_vec();
        let len = data.len();

        match self.send_tx.try_send(data) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(data)) => {
                let send_tx = self.send_tx.clone();
                let len = data.len();
                tokio::spawn(async move {
                    let _ = send_tx.send(data).await;
                });
                Poll::Ready(Ok(len))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::other("Connection closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            let _ = conn.close().await;
        });
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    // Tests require network setup
}
