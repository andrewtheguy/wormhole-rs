use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{decrypt_chunk, encrypt_chunk, CHUNK_SIZE};

/// Transfer type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferType {
    File = 0,
    Folder = 1, // Tar archive
}

impl TransferType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(TransferType::File),
            1 => Ok(TransferType::Folder),
            _ => anyhow::bail!("Unknown transfer type: {}", value),
        }
    }
}

/// Transfer protocol header
/// Format: transfer_type (1 byte) || filename_len (2 bytes) || filename || file_size (8 bytes)
pub struct FileHeader {
    pub transfer_type: TransferType,
    pub filename: String,
    pub file_size: u64,
}

impl FileHeader {
    pub fn new(transfer_type: TransferType, filename: String, file_size: u64) -> Self {
        Self {
            transfer_type,
            filename,
            file_size,
        }
    }

    /// Serialize header for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let filename_bytes = self.filename.as_bytes();
        let mut bytes = Vec::with_capacity(1 + 2 + filename_bytes.len() + 8);

        bytes.push(self.transfer_type as u8);
        bytes.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(filename_bytes);
        bytes.extend_from_slice(&self.file_size.to_be_bytes());

        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            anyhow::bail!("Header data too short");
        }

        let transfer_type = TransferType::from_u8(data[0])?;
        let filename_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + filename_len + 8 {
            anyhow::bail!("Header data truncated");
        }

        let filename = String::from_utf8(data[3..3 + filename_len].to_vec())
            .context("Invalid filename encoding")?;

        let size_start = 3 + filename_len;
        let file_size =
            u64::from_be_bytes(data[size_start..size_start + 8].try_into().unwrap());

        Ok(Self {
            transfer_type,
            filename,
            file_size,
        })
    }
}

/// Send a header over the stream (unencrypted, relies on QUIC/TLS)
/// Format: header_len (4 bytes) || header_data
pub async fn send_header<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    header: &FileHeader,
) -> Result<()> {
    let header_bytes = header.to_bytes();

    // Write length prefix
    let len = header_bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write header
    writer.write_all(&header_bytes).await?;

    Ok(())
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

/// Receive a header from the stream (unencrypted, relies on QUIC/TLS)
pub async fn recv_header<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<FileHeader> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read header
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("Failed to read header data")?;

    FileHeader::from_bytes(&data)
}

/// Receive and decrypt a header from the stream (uses chunk_num 0)
pub async fn recv_encrypted_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<FileHeader> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read encrypted header
    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .context("Failed to read header data")?;

    // Decrypt
    let decrypted = decrypt_chunk(key, 0, &encrypted)?;

    FileHeader::from_bytes(&decrypted)
}

/// Send a chunk over the stream (unencrypted, relies on QUIC/TLS)
/// Format: chunk_len (4 bytes) || chunk_data
pub async fn send_chunk<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    // Write length prefix
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write data
    writer.write_all(data).await?;

    Ok(())
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

/// Receive a chunk from the stream (unencrypted, relies on QUIC/TLS)
pub async fn recv_chunk<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read chunk length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read data
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("Failed to read chunk data")?;

    Ok(data)
}

/// Receive and decrypt a chunk from the stream
pub async fn recv_encrypted_chunk<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
    chunk_num: u64,
) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read chunk length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read encrypted data
    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .context("Failed to read chunk data")?;

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
