//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use iroh::{
    Endpoint, RelayMap, RelayUrl,
    address_lookup::{DnsAddressLookup, MdnsAddressLookup, PkarrPublisher},
    endpoint::{QuicTransportConfig, RecvStream, RelayMode, SendStream},
};
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
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

/// QUIC transport parameters to avoid flow-control stalls on larger transfers.
/// iroh 0.96 defaults are too small; these match the proven tunnel-rs defaults.
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const QUIC_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const QUIC_SEND_WINDOW: u32 = 8 * 1024 * 1024;

fn build_transport_config() -> Result<QuicTransportConfig> {
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("Failed to convert QUIC idle timeout")?;

    Ok(QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL)
        .receive_window(QUIC_RECEIVE_WINDOW.into())
        .stream_receive_window(QUIC_RECEIVE_WINDOW.into())
        .send_window(QUIC_SEND_WINDOW.into())
        .build())
}

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
            .map(|url| {
                url.parse()
                    .with_context(|| format!("Invalid relay URL: {}", url))
            })
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
    print_relay_info(&relay_urls);
    let relay_mode = parse_relay_mode(relay_urls)?;
    let transport_config = build_transport_config()?;

    let endpoint = Endpoint::empty_builder(relay_mode)
        .transport_config(transport_config)
        .alpns(vec![ALPN.to_vec()])
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .address_lookup(MdnsAddressLookup::builder())
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
    print_relay_info(&relay_urls);
    let relay_mode = parse_relay_mode(relay_urls)?;
    let transport_config = build_transport_config()?;

    let endpoint = Endpoint::empty_builder(relay_mode)
        .transport_config(transport_config)
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .address_lookup(MdnsAddressLookup::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    Ok(endpoint)
}
