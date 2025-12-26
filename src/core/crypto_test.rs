#[cfg(test)]
mod tests {
    use crate::core::crypto::{decrypt_chunk, encrypt_chunk, generate_key};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = encrypt_chunk(&key, 0, plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, 0, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_chunks_different_nonces() {
        let key = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt_chunk(&key, 0, plaintext).unwrap();
        let enc2 = encrypt_chunk(&key, 1, plaintext).unwrap();

        // Same plaintext should produce different ciphertext with different chunk numbers
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_different_keys_different_nonces() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt_chunk(&key1, 0, plaintext).unwrap();
        let enc2 = encrypt_chunk(&key2, 0, plaintext).unwrap();

        // Same plaintext and chunk number but different keys should produce different nonces
        // (first 12 bytes are the nonce)
        assert_ne!(
            &enc1[..12],
            &enc2[..12],
            "Different keys must produce different nonces"
        );
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt_chunk(&key1, 0, plaintext).unwrap();

        // Decrypting with wrong key should fail (nonce mismatch or auth failure)
        let result = decrypt_chunk(&key2, 0, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }
}
