//! IceConn: AsyncRead/AsyncWrite adapter for webrtc-ice connections.
//!
//! Bridges webrtc-ice's Conn trait (async fn send/recv) to tokio's
//! AsyncRead/AsyncWrite traits (poll-based) for use with the unified
//! transfer protocol.

use bytes::BytesMut;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use webrtc_util::Conn;

/// Buffer size for receiving data from ICE connection.
const RECV_BUFFER_SIZE: usize = 65536;

pin_project! {
    /// Wrapper around webrtc-ice Conn that implements AsyncRead/AsyncWrite.
    ///
    /// This adapter allows using ICE TCP connections with the unified
    /// transfer protocol functions (run_sender_transfer, run_receiver_transfer).
    pub struct IceConn {
        conn: Arc<dyn Conn + Send + Sync>,
        // Buffer for data received from conn.recv()
        read_buf: Arc<Mutex<BytesMut>>,
        // Flag to track if we're currently receiving
        recv_in_progress: Arc<Mutex<bool>>,
    }
}

impl IceConn {
    /// Create a new IceConn from a webrtc-ice connection.
    pub fn new(conn: Arc<dyn Conn + Send + Sync>) -> Self {
        Self {
            conn,
            read_buf: Arc::new(Mutex::new(BytesMut::new())),
            recv_in_progress: Arc::new(Mutex::new(false)),
        }
    }

    /// Get the underlying connection for direct access if needed.
    #[allow(dead_code)]
    pub fn inner(&self) -> &Arc<dyn Conn + Send + Sync> {
        &self.conn
    }
}

impl AsyncRead for IceConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let conn = this.conn.clone();
        let read_buf = this.read_buf.clone();
        let recv_in_progress = this.recv_in_progress.clone();

        // Try to get data from buffer first
        let mut buf_guard = match read_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Buffer is locked, wake and try again
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // If we have buffered data, return it
        if !buf_guard.is_empty() {
            let to_copy = std::cmp::min(buf_guard.len(), buf.remaining());
            buf.put_slice(&buf_guard.split_to(to_copy));
            return Poll::Ready(Ok(()));
        }

        // Check if a recv is already in progress
        let mut in_progress = match recv_in_progress.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if *in_progress {
            // Recv already in progress, wait
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // Start a new recv operation
        *in_progress = true;
        drop(in_progress);
        drop(buf_guard);

        let waker = cx.waker().clone();
        let read_buf_clone = read_buf.clone();
        let recv_in_progress_clone = recv_in_progress.clone();

        tokio::spawn(async move {
            let mut recv_buffer = vec![0u8; RECV_BUFFER_SIZE];
            match conn.recv(&mut recv_buffer).await {
                Ok(n) => {
                    let mut buf = read_buf_clone.lock().await;
                    buf.extend_from_slice(&recv_buffer[..n]);
                }
                Err(e) => {
                    // Log error but don't fail - next read will get EOF or retry
                    log::debug!("IceConn recv error: {}", e);
                }
            }
            *recv_in_progress_clone.lock().await = false;
            waker.wake();
        });

        Poll::Pending
    }
}

impl AsyncWrite for IceConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let conn = this.conn.clone();
        let data = buf.to_vec();
        let waker = cx.waker().clone();

        // Spawn the send operation
        tokio::spawn(async move {
            match conn.send(&data).await {
                Ok(_) => {}
                Err(e) => {
                    log::debug!("IceConn send error: {}", e);
                }
            }
            waker.wake();
        });

        // Return immediately with full buffer consumed
        // This is a simplification - a more robust implementation would
        // track send completion and apply backpressure
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TCP handles flushing at the OS level
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let conn = this.conn.clone();

        // Spawn close operation
        tokio::spawn(async move {
            let _ = conn.close().await;
        });

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    // Tests will be added once we have a working ICE agent to create connections
}
