use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::core::crypto::{decrypt_chunk, encrypt_chunk, CHUNK_SIZE};
use crate::core::folder::{create_tar_archive, print_tar_creation_info};

/// Soft limit for large file transfers (100MB)
pub const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;

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

    // Flush to ensure header is sent immediately (required for Tor streams)
    writer.flush().await?;

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

/// Prompt user for confirmation if file exceeds soft limit.
/// Returns Ok(true) to proceed, Ok(false) to cancel.
pub fn confirm_large_transfer(file_size: u64, filename: &str) -> Result<bool> {
    if file_size <= LARGE_FILE_THRESHOLD {
        return Ok(true);
    }

    println!(
        "\n⚠️  Warning: {} is large ({}).",
        filename,
        format_bytes(file_size)
    );
    println!("Transfers are NOT resumable - if interrupted, you must start over.");
    println!("Large files are recommended for local connections only (wormhole-rs send-local).");
    print!("Continue anyway? [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Result of preparing a file for transfer
pub struct PreparedFile {
    pub file: File,
    pub filename: String,
    pub file_size: u64,
}

/// Prepare a file for sending: validate, confirm if large, and open.
/// Returns None if user cancels the transfer.
pub async fn prepare_file_for_send(file_path: &Path) -> Result<Option<PreparedFile>> {
    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?
        .to_string();

    println!(
        "📁 Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Confirm if file is large
    if !confirm_large_transfer(file_size, &filename)? {
        println!("Transfer cancelled.");
        return Ok(None);
    }

    // Open file
    let file = File::open(file_path)
        .await
        .context("Failed to open file")?;

    Ok(Some(PreparedFile {
        file,
        filename,
        file_size,
    }))
}

/// Result of preparing a folder archive for transfer
pub struct PreparedFolder {
    pub file: File,
    pub filename: String,
    pub file_size: u64,
    /// Keep temp file alive to prevent deletion until transfer completes
    pub temp_file: NamedTempFile,
}

/// Prepare a folder for sending: validate, create tar archive, confirm if large, and open.
/// Returns None if user cancels the transfer.
pub async fn prepare_folder_for_send(folder_path: &Path) -> Result<Option<PreparedFolder>> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    println!("📁 Creating tar archive of: {}", folder_name);
    print_tar_creation_info();

    // Create tar archive
    let tar_archive = create_tar_archive(folder_path)?;
    let filename = tar_archive.filename;
    let file_size = tar_archive.file_size;

    println!(
        "📦 Archive created: {} ({})",
        filename,
        format_bytes(file_size)
    );

    // Confirm if archive is large
    if !confirm_large_transfer(file_size, &filename)? {
        println!("Transfer cancelled.");
        return Ok(None);
    }

    // Open tar file
    let file = File::open(tar_archive.temp_file.path())
        .await
        .context("Failed to open tar file")?;

    Ok(Some(PreparedFolder {
        file,
        filename,
        file_size,
        temp_file: tar_archive.temp_file,
    }))
}

// ============================================================================
// Confirmation handshake protocol (file exists check before data transfer)
// ============================================================================

/// Signal sent by receiver to indicate transfer should proceed
pub const PROCEED_SIGNAL: &[u8] = b"PROCEED";

/// Signal sent by receiver to abort transfer (e.g., file exists and user declined)
pub const ABORT_SIGNAL: &[u8] = b"ABORT\0\0"; // Padded to 7 bytes like PROCEED

/// User's choice when file already exists
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExistsChoice {
    Overwrite,
    Rename,
    Cancel,
}

/// Find next available filename by appending _2, _3, etc.
/// Example: file.txt -> file_2.txt -> file_3.txt
pub fn find_available_filename(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new("."));

    for i in 2..=999 {
        let new_name = format!("{}_{}{}", stem, i, ext);
        let new_path = parent.join(&new_name);
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback with timestamp if somehow 999 files exist
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    parent.join(format!("{}_{}{}", stem, timestamp, ext))
}

/// Prompt user for choice when file already exists.
/// Returns the user's choice (overwrite, rename, or cancel).
pub fn prompt_file_exists(path: &Path) -> Result<FileExistsChoice> {
    let display_path = path.display().to_string();

    print!(
        "⚠️  File exists: {}\n[o]verwrite / [r]ename / [c]ancel: ",
        display_path
    );
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    let choice = input.trim().to_lowercase();
    match choice.as_str() {
        "o" | "overwrite" => Ok(FileExistsChoice::Overwrite),
        "r" | "rename" => Ok(FileExistsChoice::Rename),
        _ => Ok(FileExistsChoice::Cancel),
    }
}
