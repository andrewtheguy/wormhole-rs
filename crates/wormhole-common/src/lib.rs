//! wormhole-common: Shared library for wormhole-rs transports
//!
//! This crate provides the core functionality shared across all wormhole-rs
//! transport implementations (iroh, Tor, mDNS).

pub mod auth;
pub mod core;
pub mod signaling;
