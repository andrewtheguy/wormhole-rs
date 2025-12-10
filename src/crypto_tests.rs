#[cfg(test)]
mod tests {
    use crate::crypto::{decrypt_chunk, encrypt_chunk, generate_key};

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
}
