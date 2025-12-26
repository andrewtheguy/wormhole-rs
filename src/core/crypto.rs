//! AES-256-GCM encryption module for application-layer payload protection.
//!
//! wormhole-rs always encrypts headers and chunks with AES-256-GCM before
//! sending over any transport. This provides consistent end-to-end protection
//! regardless of the underlying protocol.
//!
//! # Nonce Strategy
//!
//! Each encryption call generates a fresh random 96-bit nonce. This guarantees
//! nonce uniqueness even if:
//! - The same chunk_num is used multiple times (e.g., retries)
//! - Different data is encrypted with the same (key, chunk_num)
//! - Control signals are sent multiple times
//!
//! The nonce is transmitted with the ciphertext (first 12 bytes), and the
//! receiver uses it directly for decryption. GCM's authentication tag ensures
//! integrity - any tampering of nonce or ciphertext causes decryption failure.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;

pub const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks
const NONCE_SIZE: usize = 12; // 96 bits
const TAG_SIZE: usize = 16; // 128 bits

/// Generate a random 256-bit encryption key.
///
/// Must be called once per transfer session. The key should never be reused
/// across sessions.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt a chunk of data using AES-256-GCM with a random nonce.
///
/// Each call generates a fresh random 96-bit nonce, guaranteeing uniqueness
/// even if chunk_num is reused or if there are retries/retransmissions.
/// This eliminates the risk of nonce reuse which would be catastrophic for
/// AES-GCM security.
///
/// The `chunk_num` parameter is preserved for API compatibility and may be
/// used for application-level chunk identification, but is not used in
/// nonce derivation.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt_chunk(key: &[u8; 32], _chunk_num: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Generate random nonce for each encryption - guarantees uniqueness
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: nonce || ciphertext || tag (tag is included in ciphertext by aes-gcm)
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a chunk of data using AES-256-GCM.
///
/// The nonce is extracted from the ciphertext (first 12 bytes).
/// Authentication is provided by the GCM tag - if the ciphertext is
/// tampered or the wrong key is used, decryption will fail.
///
/// The `chunk_num` parameter is preserved for API compatibility and may be
/// used for application-level chunk identification, but is not used in
/// decryption (the transmitted nonce is used directly).
///
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt_chunk(key: &[u8; 32], _chunk_num: u64, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        anyhow::bail!("Encrypted data too short");
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Extract nonce from ciphertext - use transmitted nonce directly
    let nonce_bytes = &encrypted[..NONCE_SIZE];
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
        .context("Authentication failed - data may be corrupted or tampered")?;

    Ok(plaintext)
}
