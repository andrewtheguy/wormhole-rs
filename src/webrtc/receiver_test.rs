use anyhow::Result;
use crate::core::crypto::{encrypt_chunk, generate_key, CHUNK_SIZE};
use crate::webrtc::receiver::WebRtcStreamingReader;
use std::io::Read;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_webrtc_streaming_reader() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let key = generate_key();
    let file_data = b"Hello, World! This is a test for streaming reader.".to_vec();
    let file_size = file_data.len() as u64;

    // Spawn sender
    let key_clone = key;
    let file_data_clone = file_data.clone();
    tokio::spawn(async move {
        // Send chunk 1
        let encrypted = encrypt_chunk(&key_clone, 1, &file_data_clone).unwrap();
        
        // Construct message: [type(1)][chunk_num(8)][len(4)][encrypted]
        let mut msg = Vec::new();
        msg.push(1u8);
        msg.extend_from_slice(&1u64.to_be_bytes());
        msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        msg.extend_from_slice(&encrypted);

        tx.send(msg).await.unwrap();
        
        // Send EOF
        tx.send(vec![2u8]).await.unwrap();
    });

    // Create reader
    let runtime_handle = tokio::runtime::Handle::current();
    let mut reader = WebRtcStreamingReader::new(rx, key, file_size, runtime_handle);

    // Read data in blocking task
    let buffer = tokio::task::spawn_blocking(move || {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Ok::<Vec<u8>, std::io::Error>(buffer)
    }).await??;

    assert_eq!(buffer, file_data);
    Ok(())
}

#[tokio::test]
async fn test_webrtc_streaming_reader_multi_chunk() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let key = generate_key();
    
    // precise chunk size + 10 bytes
    let size = CHUNK_SIZE + 10;
    let file_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let file_size = file_data.len() as u64;

    // Spawn sender
    let key_clone = key;
    let file_data_clone = file_data.clone();
    tokio::spawn(async move {
        let mut chunk_num = 1;
        for chunk in file_data_clone.chunks(CHUNK_SIZE) {
            let encrypted = encrypt_chunk(&key_clone, chunk_num as u64, chunk).unwrap();
            
            let mut msg = Vec::new();
            msg.push(1u8);
            msg.extend_from_slice(&(chunk_num as u64).to_be_bytes());
            msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
            msg.extend_from_slice(&encrypted);

            tx.send(msg).await.unwrap();
            chunk_num += 1;
        }
        
        // Send EOF
        tx.send(vec![2u8]).await.unwrap();
    });

    // Create reader
    let runtime_handle = tokio::runtime::Handle::current();
    let mut reader = WebRtcStreamingReader::new(rx, key, file_size, runtime_handle);

    // Read data in blocking task
    let buffer = tokio::task::spawn_blocking(move || {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Ok::<Vec<u8>, std::io::Error>(buffer)
    }).await??;

    assert_eq!(buffer, file_data);
    Ok(())
}
