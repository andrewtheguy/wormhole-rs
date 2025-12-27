#[cfg(test)]
mod tests {
    use crate::core::crypto::{decrypt, encrypt, generate_key};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_random_nonces_guarantee_uniqueness() {
        // With random nonces, even same (key, plaintext) produces unique ciphertext
        let key = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();

        // Nonces (first 12 bytes) must be different - random generation
        assert_ne!(
            &enc1[..12],
            &enc2[..12],
            "Random nonces must be unique for each encryption"
        );

        // Full ciphertext must be different
        assert_ne!(enc1, enc2, "Same plaintext must produce different ciphertext");

        // Both must decrypt correctly
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext.as_slice());
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt(&key1, plaintext).unwrap();

        // Decrypting with wrong key should fail (GCM authentication failure)
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_retry_safety() {
        // Simulates a retry scenario: encrypting different data multiple times
        // With random nonces, this is safe (no nonce reuse)
        let key = generate_key();
        let data_v1 = b"Original data";
        let data_v2 = b"Retry with different data";

        let enc1 = encrypt(&key, data_v1).unwrap();
        let enc2 = encrypt(&key, data_v2).unwrap();

        // Nonces must be different (random) - no nonce reuse
        assert_ne!(
            &enc1[..12],
            &enc2[..12],
            "Each encryption must use different nonce"
        );

        // Both decrypt correctly to their respective plaintexts
        assert_eq!(decrypt(&key, &enc1).unwrap(), data_v1.as_slice());
        assert_eq!(decrypt(&key, &enc2).unwrap(), data_v2.as_slice());
    }
}
