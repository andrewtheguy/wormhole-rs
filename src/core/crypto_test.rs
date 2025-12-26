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
    fn test_random_nonces_guarantee_uniqueness() {
        // With random nonces, even same (key, chunk_num, plaintext) produces unique ciphertext
        let key = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt_chunk(&key, 0, plaintext).unwrap();
        let enc2 = encrypt_chunk(&key, 0, plaintext).unwrap();

        // Nonces (first 12 bytes) must be different - random generation
        assert_ne!(
            &enc1[..12],
            &enc2[..12],
            "Random nonces must be unique for each encryption"
        );

        // Full ciphertext must be different
        assert_ne!(enc1, enc2, "Same plaintext must produce different ciphertext");

        // Both must decrypt correctly
        assert_eq!(
            decrypt_chunk(&key, 0, &enc1).unwrap(),
            plaintext.as_slice()
        );
        assert_eq!(
            decrypt_chunk(&key, 0, &enc2).unwrap(),
            plaintext.as_slice()
        );
    }

    #[test]
    fn test_different_chunks_have_unique_ciphertext() {
        let key = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt_chunk(&key, 0, plaintext).unwrap();
        let enc2 = encrypt_chunk(&key, 1, plaintext).unwrap();

        // Different encryptions produce different ciphertext (random nonces)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt_chunk(&key1, 0, plaintext).unwrap();

        // Decrypting with wrong key should fail (GCM authentication failure)
        let result = decrypt_chunk(&key2, 0, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_retry_safety() {
        // Simulates a retry scenario: same chunk_num used to encrypt different data
        // With random nonces, this is safe (no nonce reuse)
        let key = generate_key();
        let data_v1 = b"Original data";
        let data_v2 = b"Retry with different data";

        let enc1 = encrypt_chunk(&key, 5, data_v1).unwrap();
        let enc2 = encrypt_chunk(&key, 5, data_v2).unwrap();

        // Nonces must be different (random) - no nonce reuse
        assert_ne!(
            &enc1[..12],
            &enc2[..12],
            "Retry must use different nonce"
        );

        // Both decrypt correctly to their respective plaintexts
        assert_eq!(decrypt_chunk(&key, 5, &enc1).unwrap(), data_v1.as_slice());
        assert_eq!(decrypt_chunk(&key, 5, &enc2).unwrap(), data_v2.as_slice());
    }
}
