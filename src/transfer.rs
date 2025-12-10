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
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            anyhow::bail!("Header data too short");
        }
        
        let filename_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + filename_len + 8 {
            anyhow::bail!("Header data truncated");
        }
        
        let filename = String::from_utf8(data[2..2 + filename_len].to_vec())
            .context("Invalid filename encoding")?;
        
        let size_start = 2 + filename_len;
        let file_size = u64::from_be_bytes(
            data[size_start..size_start + 8].try_into().unwrap()
        );
        
        Ok(Self { filename, file_size })
    }
}

/// Send an encrypted header over the stream (uses chunk_num 0)
/// Format: header_len (4 bytes) || encrypted_header
pub async fn send_encrypted_header<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    header: &FileHeader,
) -> Result<()> {
    let header_bytes = header.to_bytes();
    let encrypted = encrypt_chunk(key, 0, &header_bytes)?;
    
    // Write length prefix
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    
    // Write encrypted header
    writer.write_all(&encrypted).await?;
    
    Ok(())
}

/// Receive and decrypt a header from the stream (uses chunk_num 0)
pub async fn recv_encrypted_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<FileHeader> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    // Read encrypted header
    let mut encrypted = vec![0u8; len];
    reader.read_exact(&mut encrypted).await.context("Failed to read header data")?;
    
    // Decrypt
    let decrypted = decrypt_chunk(key, 0, &encrypted)?;
    
    FileHeader::from_bytes(&decrypted)
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
