//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    endpoint::{ConnectionType, RelayMode},
    Endpoint, EndpointId, RelayMap, RelayUrl, Watcher,
};
use std::time::Duration;

/// Application-Layer Protocol Negotiation identifier for wormhole transfers.
pub const ALPN: &[u8] = b"wormhole-transfer/1";

/// Timeout for waiting for direct connection (hole-punching)
pub const DIRECT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of waiting for direct connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectConnectionResult {
    /// Direct P2P connection was established
    Direct,
    /// Connection is still using relay (hole-punching failed or timed out)
    StillRelay,
}

/// Wait for connection type to stabilize.
/// Gives time for hole-punching to establish direct connection.
/// Uses async notifications from the Watcher to react immediately to changes.
pub async fn wait_for_direct_connection(
    endpoint: &Endpoint,
    remote_id: EndpointId,
) -> DirectConnectionResult {
    let Some(mut watcher) = endpoint.conn_type(remote_id) else {
        return DirectConnectionResult::StillRelay; // Unknown = treat as non-direct
    };

    // Check initial state - if already direct, accept immediately
    if matches!(watcher.get(), ConnectionType::Direct(_)) {
        return DirectConnectionResult::Direct;
    }

    // Wait for connection type updates with timeout
    let result = tokio::time::timeout(DIRECT_WAIT_TIMEOUT, async {
        loop {
            match watcher.updated().await {
                Ok(ConnectionType::Direct(_)) => {
                    return DirectConnectionResult::Direct;
                }
                Ok(_) => {
                    // Still Relay or Mixed, continue waiting for next update
                }
                Err(_) => {
                    return DirectConnectionResult::StillRelay;
                }
            }
        }
    })
    .await;

    match result {
        Ok(conn_result) => conn_result,
        Err(_timeout) => DirectConnectionResult::StillRelay,
    }
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
///
/// Returns (Endpoint, using_custom_relay) where using_custom_relay indicates
/// whether custom relay servers are being used (vs default public relays).
pub async fn create_sender_endpoint(relay_urls: Vec<String>) -> Result<(Endpoint, bool)> {
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

    Ok((endpoint, using_custom_relay))
}

/// Create an iroh endpoint configured for receiving (connects to sender).
///
/// Sets up N0 DNS discovery, pkarr publishing, and local mDNS discovery.
/// Does not set ALPN as the receiver specifies it when connecting.
/// Multiple relay URLs provide automatic failover based on latency.
///
/// Returns (Endpoint, using_custom_relay) where using_custom_relay indicates
/// whether custom relay servers are being used (vs default public relays).
pub async fn create_receiver_endpoint(relay_urls: Vec<String>) -> Result<(Endpoint, bool)> {
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

    Ok((endpoint, using_custom_relay))
}
