use tokio::io::duplex;
use wormhole_rs::core::crypto::{generate_key, CHUNK_SIZE};
use wormhole_rs::core::transfer::{
    recv_chunk, recv_encrypted_chunk, recv_encrypted_header, recv_header, send_chunk,
    send_encrypted_chunk, send_encrypted_header, send_header, FileHeader, TransferType,
};

// =============================================================================
// Unencrypted transfer tests (default mode, relies on QUIC/TLS)
// =============================================================================

#[tokio::test]
async fn test_unencrypted_header_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let header = FileHeader::new(TransferType::File, "test_file.txt".to_string(), 12345);

    let send_handle =
        tokio::spawn(async move { send_header(&mut client, &header).await });

    let received = recv_header(&mut server).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received.filename, "test_file.txt");
    assert_eq!(received.file_size, 12345);
}

#[tokio::test]
async fn test_unencrypted_single_chunk_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let data = b"Hello, World! This is test data for a single chunk.";

    let data_clone = data.to_vec();
    let send_handle = tokio::spawn(async move { send_chunk(&mut client, &data_clone).await });

    let received = recv_chunk(&mut server).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received, data);
}

#[tokio::test]
async fn test_unencrypted_multi_chunk_roundtrip() {
    let (mut client, mut server) = duplex(65536);

    let chunks: Vec<Vec<u8>> = vec![
        b"First chunk of data".to_vec(),
        b"Second chunk of data".to_vec(),
        b"Third chunk of data".to_vec(),
    ];

    let chunks_clone = chunks.clone();
    let send_handle = tokio::spawn(async move {
        for chunk in chunks_clone.iter() {
            send_chunk(&mut client, chunk).await.unwrap();
        }
    });

    for expected in chunks.iter() {
        let received = recv_chunk(&mut server).await.unwrap();
        assert_eq!(&received, expected);
    }

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_unencrypted_full_transfer_simulation() {
    let (mut client, mut server) = duplex(65536);

    let filename = "document.pdf".to_string();
    let file_data = b"This is the content of the file being transferred.";
    let file_size = file_data.len() as u64;

    let filename_clone = filename.clone();
    let file_data_clone = file_data.to_vec();
    let send_handle = tokio::spawn(async move {
        // Send header
        let header = FileHeader::new(TransferType::File, filename_clone, file_size);
        send_header(&mut client, &header).await.unwrap();

        // Send file data
        send_chunk(&mut client, &file_data_clone).await.unwrap();
    });

    // Receive header
    let received_header = recv_header(&mut server).await.unwrap();
    assert_eq!(received_header.filename, filename);
    assert_eq!(received_header.file_size, file_size);

    // Receive file data
    let received_data = recv_chunk(&mut server).await.unwrap();
    assert_eq!(received_data, file_data);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_unencrypted_large_file_multi_chunk() {
    // Test file larger than CHUNK_SIZE requiring multiple chunks
    let file_size = CHUNK_SIZE * 2 + 1000; // ~33KB, requires 3 chunks
    let (mut client, mut server) = duplex(file_size + 4096);

    let file_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        let header =
            FileHeader::new(TransferType::File, "large_file.bin".to_string(), file_size as u64);
        send_header(&mut client, &header).await.unwrap();

        // Send chunks
        for chunk in file_data_clone.chunks(CHUNK_SIZE) {
            send_chunk(&mut client, chunk).await.unwrap();
        }
    });

    // Receive header
    let received_header = recv_header(&mut server).await.unwrap();
    assert_eq!(received_header.file_size, file_size as u64);

    // Receive all chunks and reconstruct file
    let mut received_data = Vec::new();
    while received_data.len() < file_size {
        let chunk = recv_chunk(&mut server).await.unwrap();
        received_data.extend(chunk);
    }

    assert_eq!(received_data, file_data);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_unencrypted_folder_transfer_type() {
    let (mut client, mut server) = duplex(4096);
    let header = FileHeader::new(TransferType::Folder, "myfolder.tar".to_string(), 54321);

    let send_handle =
        tokio::spawn(async move { send_header(&mut client, &header).await });

    let received = recv_header(&mut server).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received.transfer_type, TransferType::Folder);
    assert_eq!(received.filename, "myfolder.tar");
    assert_eq!(received.file_size, 54321);
}

// =============================================================================
// Encrypted transfer tests (--extra-encrypt mode)
// =============================================================================

#[tokio::test]
async fn test_encrypted_header_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let header = FileHeader::new(TransferType::File, "test_file.txt".to_string(), 12345);

    let key_clone = key;
    let send_handle = tokio::spawn(async move {
        send_encrypted_header(&mut client, &key_clone, &header).await
    });

    let received = recv_encrypted_header(&mut server, &key).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received.filename, "test_file.txt");
    assert_eq!(received.file_size, 12345);
}

#[tokio::test]
async fn test_encrypted_single_chunk_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let data = b"Hello, World! This is test data for a single chunk.";

    let key_clone = key;
    let data_clone = data.to_vec();
    let send_handle = tokio::spawn(async move {
        send_encrypted_chunk(&mut client, &key_clone, 1, &data_clone).await
    });

    let received = recv_encrypted_chunk(&mut server, &key, 1).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received, data);
}

#[tokio::test]
async fn test_encrypted_multi_chunk_roundtrip() {
    let (mut client, mut server) = duplex(65536);
    let key = generate_key();

    let chunks: Vec<Vec<u8>> = vec![
        b"First chunk of data".to_vec(),
        b"Second chunk of data".to_vec(),
        b"Third chunk of data".to_vec(),
    ];

    let key_clone = key;
    let chunks_clone = chunks.clone();
    let send_handle = tokio::spawn(async move {
        for (i, chunk) in chunks_clone.iter().enumerate() {
            send_encrypted_chunk(&mut client, &key_clone, (i + 1) as u64, chunk)
                .await
                .unwrap();
        }
    });

    for (i, expected) in chunks.iter().enumerate() {
        let received = recv_encrypted_chunk(&mut server, &key, (i + 1) as u64)
            .await
            .unwrap();
        assert_eq!(&received, expected);
    }

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_full_transfer_simulation() {
    let (mut client, mut server) = duplex(65536);
    let key = generate_key();

    let filename = "document.pdf".to_string();
    let file_data = b"This is the content of the file being transferred.";
    let file_size = file_data.len() as u64;

    let key_clone = key;
    let filename_clone = filename.clone();
    let file_data_clone = file_data.to_vec();
    let send_handle = tokio::spawn(async move {
        // Send header (chunk 0)
        let header = FileHeader::new(TransferType::File, filename_clone, file_size);
        send_encrypted_header(&mut client, &key_clone, &header)
            .await
            .unwrap();

        // Send file data (chunk 1)
        send_encrypted_chunk(&mut client, &key_clone, 1, &file_data_clone)
            .await
            .unwrap();
    });

    // Receive header
    let received_header = recv_encrypted_header(&mut server, &key).await.unwrap();
    assert_eq!(received_header.filename, filename);
    assert_eq!(received_header.file_size, file_size);

    // Receive file data
    let received_data = recv_encrypted_chunk(&mut server, &key, 1).await.unwrap();
    assert_eq!(received_data, file_data);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_empty_file_transfer() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();

    let filename = "empty.txt".to_string();
    let file_size = 0u64;

    let key_clone = key;
    let filename_clone = filename.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new(TransferType::File, filename_clone, file_size);
        send_encrypted_header(&mut client, &key_clone, &header)
            .await
            .unwrap();
        // No chunks to send for empty file
    });

    let received_header = recv_encrypted_header(&mut server, &key).await.unwrap();
    assert_eq!(received_header.filename, filename);
    assert_eq!(received_header.file_size, 0);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_exact_chunk_size_file() {
    // Test file that is exactly CHUNK_SIZE (16KB)
    let (mut client, mut server) = duplex(CHUNK_SIZE + 1024);
    let key = generate_key();

    let file_data: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 256) as u8).collect();
    let file_size = file_data.len() as u64;

    let key_clone = key;
    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new(TransferType::File, "exact_chunk.bin".to_string(), file_size);
        send_encrypted_header(&mut client, &key_clone, &header)
            .await
            .unwrap();
        send_encrypted_chunk(&mut client, &key_clone, 1, &file_data_clone)
            .await
            .unwrap();
    });

    let received_header = recv_encrypted_header(&mut server, &key).await.unwrap();
    assert_eq!(received_header.file_size, CHUNK_SIZE as u64);

    let received_data = recv_encrypted_chunk(&mut server, &key, 1).await.unwrap();
    assert_eq!(received_data, file_data);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_large_file_multi_chunk() {
    // Test file larger than CHUNK_SIZE requiring multiple chunks
    let file_size = CHUNK_SIZE * 2 + 1000; // ~33KB, requires 3 chunks
    let (mut client, mut server) = duplex(file_size + 4096);
    let key = generate_key();

    let file_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

    let key_clone = key;
    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new(TransferType::File, "large_file.bin".to_string(), file_size as u64);
        send_encrypted_header(&mut client, &key_clone, &header)
            .await
            .unwrap();

        // Send chunks
        let mut chunk_num = 1u64;
        for chunk in file_data_clone.chunks(CHUNK_SIZE) {
            send_encrypted_chunk(&mut client, &key_clone, chunk_num, chunk)
                .await
                .unwrap();
            chunk_num += 1;
        }
    });

    // Receive header
    let received_header = recv_encrypted_header(&mut server, &key).await.unwrap();
    assert_eq!(received_header.file_size, file_size as u64);

    // Receive all chunks and reconstruct file
    let mut received_data = Vec::new();
    let mut chunk_num = 1u64;
    while received_data.len() < file_size {
        let chunk = recv_encrypted_chunk(&mut server, &key, chunk_num)
            .await
            .unwrap();
        received_data.extend(chunk);
        chunk_num += 1;
    }

    assert_eq!(received_data, file_data);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_special_characters_in_filename() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();

    let filename = "file with spaces & special (chars) [2024].txt".to_string();

    let key_clone = key;
    let header_clone = FileHeader::new(TransferType::File, filename.clone(), 100);
    let send_handle = tokio::spawn(async move {
        send_encrypted_header(&mut client, &key_clone, &header_clone)
            .await
            .unwrap();
    });

    let received = recv_encrypted_header(&mut server, &key).await.unwrap();
    assert_eq!(received.filename, filename);

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_wrong_chunk_number_fails() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let data = b"Test data";

    let key_clone = key;
    let send_handle = tokio::spawn(async move {
        // Send with chunk_num 5
        send_encrypted_chunk(&mut client, &key_clone, 5, data)
            .await
            .unwrap();
    });

    // Try to receive with wrong chunk_num (3 instead of 5)
    // This should fail because nonce won't match
    let result = recv_encrypted_chunk(&mut server, &key, 3).await;
    assert!(result.is_err());

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_wrong_key_fails_on_header() {
    let (mut client, mut server) = duplex(4096);
    let sender_key = generate_key();
    let receiver_key = generate_key(); // Different key!

    let header = FileHeader::new(TransferType::File, "secret.txt".to_string(), 1000);

    let send_handle = tokio::spawn(async move {
        send_encrypted_header(&mut client, &sender_key, &header)
            .await
            .unwrap();
    });

    // Receiver tries to decrypt with wrong key - should fail immediately
    let result = recv_encrypted_header(&mut server, &receiver_key).await;
    assert!(result.is_err());

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_wrong_key_fails_on_chunk() {
    let (mut client, mut server) = duplex(4096);
    let sender_key = generate_key();
    let receiver_key = generate_key(); // Different key!

    let data = b"Sensitive data that should not be readable";

    let send_handle = tokio::spawn(async move {
        send_encrypted_chunk(&mut client, &sender_key, 1, data)
            .await
            .unwrap();
    });

    // Receiver tries to decrypt with wrong key - should fail
    let result = recv_encrypted_chunk(&mut server, &receiver_key, 1).await;
    assert!(result.is_err());

    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_different_keys_produce_different_payloads() {
    use wormhole_rs::core::crypto::encrypt_chunk;

    // Same file content and metadata
    let data = b"Identical file content for both transfers";
    let chunk_num = 1u64;

    // Generate two different keys (simulating two separate transfers)
    let key1 = generate_key();
    let key2 = generate_key();

    // Encrypt the same data with different keys
    let encrypted1 = encrypt_chunk(&key1, chunk_num, data).unwrap();
    let encrypted2 = encrypt_chunk(&key2, chunk_num, data).unwrap();

    // Payloads should be different due to different keys
    assert_ne!(
        encrypted1, encrypted2,
        "Same data encrypted with different keys should produce different ciphertext"
    );

    // Also verify the nonces are the same (deterministic from chunk_num)
    // but ciphertext differs
    assert_eq!(
        &encrypted1[..12],
        &encrypted2[..12],
        "Nonces should be identical for same chunk_num"
    );
    assert_ne!(
        &encrypted1[12..],
        &encrypted2[12..],
        "Ciphertext should differ due to different keys"
    );
}

#[tokio::test]
async fn test_encrypted_different_keys_produce_different_headers() {
    use wormhole_rs::core::crypto::encrypt_chunk;

    // Same file metadata
    let header = FileHeader::new(TransferType::File, "same_file.txt".to_string(), 12345);
    let header_bytes = header.to_bytes();

    // Two different keys (two separate transfers of same file)
    let key1 = generate_key();
    let key2 = generate_key();

    // Encrypt header with chunk_num 0
    let encrypted1 = encrypt_chunk(&key1, 0, &header_bytes).unwrap();
    let encrypted2 = encrypt_chunk(&key2, 0, &header_bytes).unwrap();

    // Headers should produce different encrypted payloads
    assert_ne!(
        encrypted1, encrypted2,
        "Same header encrypted with different keys should produce different ciphertext"
    );
}

#[tokio::test]
async fn test_encrypted_each_transfer_generates_unique_key() {
    // Verify that generate_key() produces different keys each time
    // This ensures each file transfer has unique encryption
    let key1 = generate_key();
    let key2 = generate_key();
    let key3 = generate_key();

    assert_ne!(key1, key2, "Each generated key should be unique");
    assert_ne!(key2, key3, "Each generated key should be unique");
    assert_ne!(key1, key3, "Each generated key should be unique");
}
