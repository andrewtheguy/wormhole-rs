//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint, RelayUrl,
};

/// Application-Layer Protocol Negotiation identifier for wormhole transfers.
pub const ALPN: &[u8] = b"wormhole-transfer/1";

/// Parse an optional relay URL string into a RelayMode.
///
/// If a URL is provided, returns `RelayMode::Custom` with the parsed URL.
/// If no URL is provided, returns `RelayMode::Default` to use iroh's public relays.
pub fn parse_relay_mode(relay_url: Option<String>) -> Result<RelayMode> {
    match relay_url {
        Some(url) => {
            let relay_url: RelayUrl = url.parse().context("Invalid relay URL")?;
            Ok(RelayMode::Custom(relay_url.into()))
        }
        None => Ok(RelayMode::Default),
    }
}

/// Create an iroh endpoint configured for sending (accepts incoming connections).
///
/// Sets up N0 DNS discovery, pkarr publishing, and local mDNS discovery.
/// The endpoint is configured with ALPN for wormhole transfers.
pub async fn create_sender_endpoint(relay_url: Option<String>) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_url)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    if using_custom_relay {
        println!("Using custom relay server");
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
pub async fn create_receiver_endpoint(relay_url: Option<String>) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_url)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    if using_custom_relay {
        println!("Using custom relay server");
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
