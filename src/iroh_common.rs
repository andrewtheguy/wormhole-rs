//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::RelayMode,
    Endpoint, RelayMap, RelayUrl,
};

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

/// Create an iroh endpoint configured for sending (accepts incoming connections).
///
/// Sets up N0 DNS discovery, pkarr publishing, and local mDNS discovery.
/// The endpoint is configured with ALPN for wormhole transfers.
/// Multiple relay URLs provide automatic failover based on latency.
pub async fn create_sender_endpoint(relay_urls: Vec<String>) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls.clone())?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    if using_custom_relay {
        if relay_urls.len() == 1 {
            println!("Using custom relay server");
        } else {
            println!("Using {} custom relay servers (with failover)", relay_urls.len());
        }
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
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    if using_custom_relay {
        if relay_urls.len() == 1 {
            println!("Using custom relay server");
        } else {
            println!("Using {} custom relay servers (with failover)", relay_urls.len());
        }
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
