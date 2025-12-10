use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{decrypt_chunk, encrypt_chunk, CHUNK_SIZE};

/// Transfer protocol header
/// Format: filename_len (2 bytes) || filename || file_size (8 bytes)
pub struct FileHeader {
    pub filename: String,
    pub file_size: u64,
}

impl FileHeader {
    pub fn new(filename: String, file_size: u64) -> Self {
        Self { filename, file_size }
    }

    /// Serialize header for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let filename_bytes = self.filename.as_bytes();
        let mut bytes = Vec::with_capacity(2 + filename_bytes.len() + 8);
        
        bytes.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(filename_bytes);
        bytes.extend_from_slice(&self.file_size.to_be_bytes());
        
        bytes
    }

    /// Deserialize header from bytes
    pub async fn from_stream<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await.context("Failed to read filename length")?;
        let filename_len = u16::from_be_bytes(len_buf) as usize;

        let mut filename_buf = vec![0u8; filename_len];
        reader.read_exact(&mut filename_buf).await.context("Failed to read filename")?;
        let filename = String::from_utf8(filename_buf).context("Invalid filename encoding")?;

        let mut size_buf = [0u8; 8];
        reader.read_exact(&mut size_buf).await.context("Failed to read file size")?;
        let file_size = u64::from_be_bytes(size_buf);

        Ok(Self { filename, file_size })
    }
}

/// Send an encrypted chunk over the stream
/// Format: chunk_len (4 bytes) || encrypted_chunk
pub async fn send_encrypted_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    chunk_num: u64,
    data: &[u8],
) -> Result<()> {
    let encrypted = encrypt_chunk(key, chunk_num, data)?;
    
    // Write length prefix
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    
    // Write encrypted data
    writer.write_all(&encrypted).await?;
    
    Ok(())
}

/// Receive and decrypt a chunk from the stream
pub async fn recv_encrypted_chunk<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
    chunk_num: u64,
) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.context("Failed to read chunk length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    // Read encrypted data
    let mut encrypted = vec![0u8; len];
    reader.read_exact(&mut encrypted).await.context("Failed to read chunk data")?;
    
    // Decrypt
    decrypt_chunk(key, chunk_num, &encrypted)
}

/// Calculate number of chunks for a file
pub fn num_chunks(file_size: u64) -> u64 {
    (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
}

/// Format bytes for human-readable display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}
