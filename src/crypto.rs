//! AES-256-GCM encryption module for application-layer payload protection.
//!
//! wormhole-rs always encrypts headers and chunks with AES-256-GCM before
//! sending over any transport. This provides consistent end-to-end protection
//! regardless of the underlying protocol.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;

pub const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks
const NONCE_SIZE: usize = 12; // 96 bits
const TAG_SIZE: usize = 16; // 128 bits

/// Generate a random 256-bit encryption key
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Derive a unique nonce from the chunk number
/// Uses the chunk number as a counter to ensure nonce uniqueness
fn derive_nonce(chunk_num: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    // Use chunk number as counter in first 8 bytes
    nonce[..8].copy_from_slice(&chunk_num.to_le_bytes());
    nonce
}

/// Encrypt a chunk of data using AES-256-GCM
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt_chunk(key: &[u8; 32], chunk_num: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = derive_nonce(chunk_num);
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

/// Decrypt a chunk of data using AES-256-GCM
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt_chunk(key: &[u8; 32], chunk_num: u64, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        anyhow::bail!("Encrypted data too short");
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    
    // Extract nonce and verify it matches expected
    let nonce_bytes = &encrypted[..NONCE_SIZE];
    let expected_nonce = derive_nonce(chunk_num);
    if nonce_bytes != expected_nonce {
        anyhow::bail!("Nonce mismatch - possible replay attack or corruption");
    }
    
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
        .context("Authentication failed - data may be corrupted or tampered")?;

    Ok(plaintext)
}
