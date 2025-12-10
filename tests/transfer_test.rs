use tokio::io::duplex;
use wormhole_rs::crypto::{generate_key, CHUNK_SIZE};
use wormhole_rs::transfer::{
    recv_encrypted_chunk, recv_encrypted_header, send_encrypted_chunk, send_encrypted_header,
    FileHeader,
};

#[tokio::test]
async fn test_header_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let header = FileHeader::new("test_file.txt".to_string(), 12345);

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
async fn test_single_chunk_roundtrip() {
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
async fn test_multi_chunk_roundtrip() {
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
async fn test_full_transfer_simulation() {
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
        let header = FileHeader::new(filename_clone, file_size);
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
async fn test_empty_file_transfer() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();

    let filename = "empty.txt".to_string();
    let file_size = 0u64;

    let key_clone = key;
    let filename_clone = filename.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new(filename_clone, file_size);
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
async fn test_exact_chunk_size_file() {
    // Test file that is exactly CHUNK_SIZE (16KB)
    let (mut client, mut server) = duplex(CHUNK_SIZE + 1024);
    let key = generate_key();

    let file_data: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 256) as u8).collect();
    let file_size = file_data.len() as u64;

    let key_clone = key;
    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new("exact_chunk.bin".to_string(), file_size);
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
async fn test_large_file_multi_chunk() {
    // Test file larger than CHUNK_SIZE requiring multiple chunks
    let file_size = CHUNK_SIZE * 2 + 1000; // ~33KB, requires 3 chunks
    let (mut client, mut server) = duplex(file_size + 4096);
    let key = generate_key();

    let file_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

    let key_clone = key;
    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        let header = FileHeader::new("large_file.bin".to_string(), file_size as u64);
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
async fn test_special_characters_in_filename() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();

    let filename = "file with spaces & special (chars) [2024].txt".to_string();

    let key_clone = key;
    let header_clone = FileHeader::new(filename.clone(), 100);
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
async fn test_wrong_chunk_number_fails() {
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
