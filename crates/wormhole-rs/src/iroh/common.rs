//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::{RecvStream, RelayMode, SendStream},
    Endpoint, RelayMap, RelayUrl,
};
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A duplex wrapper that combines separate send/recv streams into a single bidirectional stream.
///
/// This allows iroh's separate `SendStream` and `RecvStream` to be used with APIs that
/// expect a single stream implementing both `AsyncRead` and `AsyncWrite`.
pub struct IrohDuplex<'a> {
    pub send: &'a mut SendStream,
    pub recv: &'a mut RecvStream,
}

impl<'a> IrohDuplex<'a> {
    /// Create a new duplex wrapper from separate send and receive streams.
    pub fn new(send: &'a mut SendStream, recv: &'a mut RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for IrohDuplex<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for IrohDuplex<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

/// An owned duplex wrapper that takes ownership of send/recv streams.
///
/// This is needed for `run_receiver_transfer` which requires `'static` lifetime
/// due to spawn_blocking usage in folder transfers.
pub struct OwnedIrohDuplex {
    send: SendStream,
    recv: RecvStream,
}

impl OwnedIrohDuplex {
    /// Create a new owned duplex from separate send and receive streams.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    /// Consume the duplex and return the underlying send stream.
    /// Used to call finish() after transfer completes.
    pub fn into_send_stream(self) -> SendStream {
        self.send
    }
}

impl AsyncRead for OwnedIrohDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for OwnedIrohDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

/// Application-Layer Protocol Negotiation identifier for wormhole transfers.
pub const ALPN: &[u8] = b"wormhole-transfer/1";

/// Parse relay URL strings into a RelayMode.
///
/// If URLs are provided, returns `RelayMode::Custom` with a RelayMap containing all URLs.
/// If no URLs are provided, returns `RelayMode::Default` to use iroh's public relays.
/// Multiple relays provide automatic failover - iroh selects the best one based on latency.
pub fn parse_relay_mode(relay_urls: Vec<String>) -> Result<RelayMode> {
    if relay_urls.is_empty() {
        Ok(RelayMode::Default)
    } else {
        let parsed_urls: Vec<RelayUrl> = relay_urls
            .iter()
            .map(|url| url.parse().context(format!("Invalid relay URL: {}", url)))
            .collect::<Result<Vec<_>>>()?;
        let relay_map = RelayMap::from_iter(parsed_urls);
        Ok(RelayMode::Custom(relay_map))
    }
}

/// Print info about custom relay servers being used.
fn print_relay_info(relay_urls: &[String]) {
    if relay_urls.is_empty() {
        return;
    }
    if relay_urls.len() == 1 {
        eprintln!("Using custom relay server");
    } else {
        eprintln!(
            "Using {} custom relay servers (with failover)",
            relay_urls.len()
        );
    }
}

/// Create an iroh endpoint configured for sending (accepts incoming connections).
///
/// Sets up N0 DNS discovery, pkarr publishing, and local mDNS discovery.
/// The endpoint is configured with ALPN for wormhole transfers.
/// Multiple relay URLs provide automatic failover based on latency.
pub async fn create_sender_endpoint(relay_urls: Vec<String>) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls.clone())?;
    if !matches!(relay_mode, RelayMode::Default) {
        print_relay_info(&relay_urls);
    }

    let endpoint = Endpoint::empty_builder(relay_mode)
        .alpns(vec![ALPN.to_vec()])
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    // Wait for endpoint to be online (connected to relay)
    endpoint.online().await;

    Ok(endpoint)
}

/// Create an iroh endpoint configured for receiving (connects to sender).
///
/// Sets up N0 DNS discovery, pkarr publishing, and local mDNS discovery.
/// Does not set ALPN as the receiver specifies it when connecting.
/// Multiple relay URLs provide automatic failover based on latency.
pub async fn create_receiver_endpoint(relay_urls: Vec<String>) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls.clone())?;
    if !matches!(relay_mode, RelayMode::Default) {
        print_relay_info(&relay_urls);
    }

    let endpoint = Endpoint::empty_builder(relay_mode)
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    Ok(endpoint)
}
