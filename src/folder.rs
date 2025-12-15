//! Transport-agnostic folder operations for tar archive creation and extraction.
//!
//! This module provides common folder handling logic used by both iroh and Tor transports.

use anyhow::{Context, Result};
use std::cmp;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::transfer::{recv_chunk, recv_encrypted_chunk};

/// Result of creating a tar archive from a folder.
pub struct TarArchive {
    /// The temporary file containing the tar archive.
    pub temp_file: NamedTempFile,
    /// The archive filename (folder_name.tar).
    pub filename: String,
    /// The archive size in bytes.
    pub file_size: u64,
}

/// Create a tar archive from a folder.
///
/// Returns the temp file containing the archive, the archive filename, and its size.
/// The caller is responsible for cleaning up the temp file on error/interrupt.
///
/// # Arguments
/// * `folder_path` - Path to the folder to archive
///
/// # Returns
/// * `TarArchive` containing the temp file, filename, and size
pub fn create_tar_archive(folder_path: &Path) -> Result<TarArchive> {
    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    // Create tar archive to temp file
    let temp_tar = NamedTempFile::new().context("Failed to create temporary file")?;

    // Build tar archive
    {
        let tar_file = temp_tar.reopen().context("Failed to open tar file")?;
        let mut builder = Builder::new(tar_file);

        // Walk the directory and add all entries
        for entry in WalkDir::new(folder_path) {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Calculate relative path from folder root
            let rel_path = path
                .strip_prefix(folder_path)
                .context("Failed to calculate relative path")?;

            // Skip the root folder itself
            if rel_path.as_os_str().is_empty() {
                continue;
            }

            // Create archive path with folder name as root
            let archive_path = Path::new(folder_name).join(rel_path);

            if path.is_dir() {
                builder
                    .append_dir(&archive_path, path)
                    .with_context(|| format!("Failed to add directory: {}", path.display()))?;
            } else if path.is_file() || path.is_symlink() {
                // append_path_with_name handles both regular files and symlinks
                builder
                    .append_path_with_name(path, &archive_path)
                    .with_context(|| format!("Failed to add file: {}", path.display()))?;
            }
            // Other special files (devices, sockets, etc.) are skipped
        }

        builder.finish().context("Failed to finalize tar archive")?;
    }

    // Get tar file size
    let file_size = std::fs::metadata(temp_tar.path())
        .context("Failed to read tar file metadata")?
        .len();

    let filename = format!("{}.tar", folder_name);

    Ok(TarArchive {
        temp_file: temp_tar,
        filename,
        file_size,
    })
}

/// Wrapper to bridge async chunk receiving with sync tar reading.
/// Implements std::io::Read by fetching chunks on demand.
/// Supports both encrypted and unencrypted modes.
pub struct StreamingReader<R> {
    recv_stream: R,
    key: Option<[u8; 32]>,
    chunk_num: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    bytes_remaining: u64,
    runtime_handle: tokio::runtime::Handle,
}

impl<R> StreamingReader<R> {
    /// Create a new StreamingReader.
    ///
    /// # Arguments
    /// * `recv_stream` - The async stream to read from
    /// * `key` - Optional AES-256-GCM encryption key
    /// * `file_size` - Total expected bytes to read
    /// * `runtime_handle` - Tokio runtime handle for blocking operations
    pub fn new(
        recv_stream: R,
        key: Option<[u8; 32]>,
        file_size: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            recv_stream,
            key,
            chunk_num: 1, // Chunks start at 1, header was 0
            buffer: Vec::new(),
            buffer_pos: 0,
            bytes_remaining: file_size,
            runtime_handle,
        }
    }

    /// Consume the StreamingReader and return the underlying stream.
    /// Use this to send ACK after extraction is complete.
    pub fn into_inner(self) -> R {
        self.recv_stream
    }
}

impl<R: tokio::io::AsyncReadExt + Unpin + Send> Read for StreamingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If buffer is exhausted and there's more data, fetch next chunk
        if self.buffer_pos >= self.buffer.len() && self.bytes_remaining > 0 {
            // Block on async chunk receive
            let chunk_result = self.runtime_handle.block_on(async {
                if let Some(ref key) = self.key {
                    recv_encrypted_chunk(&mut self.recv_stream, key, self.chunk_num).await
                } else {
                    recv_chunk(&mut self.recv_stream).await
                }
            });

            match chunk_result {
                Ok(chunk) => {
                    self.bytes_remaining = self.bytes_remaining.saturating_sub(chunk.len() as u64);
                    self.chunk_num += 1;
                    self.buffer = chunk;
                    self.buffer_pos = 0;
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to receive chunk: {}", e),
                    ));
                }
            }
        }

        // Return data from buffer
        if self.buffer_pos >= self.buffer.len() {
            return Ok(0); // EOF
        }

        let available = self.buffer.len() - self.buffer_pos;
        let to_copy = cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;

        Ok(to_copy)
    }
}

/// Extract a tar archive from a reader to a directory.
///
/// # Arguments
/// * `reader` - Any type implementing std::io::Read (can be StreamingReader or std::fs::File)
/// * `extract_dir` - Directory to extract files to
///
/// # Returns
/// * Vector of skipped entry descriptions (for logging)
pub fn extract_tar_archive<R: Read>(reader: R, extract_dir: &Path) -> Result<Vec<String>> {
    let (skipped, _reader) = extract_tar_archive_returning_reader(reader, extract_dir)?;
    Ok(skipped)
}

/// Extract a tar archive from a reader to a directory, returning the reader for further use.
///
/// This variant returns the underlying reader after extraction, allowing callers to
/// send ACK messages or perform other operations on the stream.
///
/// # Arguments
/// * `reader` - Any type implementing std::io::Read (can be StreamingReader or std::fs::File)
/// * `extract_dir` - Directory to extract files to
///
/// # Returns
/// * Tuple of (skipped entry descriptions, reader)
pub fn extract_tar_archive_returning_reader<R: Read>(
    reader: R,
    extract_dir: &Path,
) -> Result<(Vec<String>, R)> {
    let mut archive = Archive::new(reader);
    // Preserve file mode (0755, etc.) but not owner/group (UID/GID mismatch across machines)
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(false);

    let mut skipped = Vec::new();

    for entry in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry.context("Failed to read tar entry")?;
        let path = entry.path().context("Failed to get entry path")?.into_owned();

        // Check entry type
        let entry_type = entry.header().entry_type();

        // On Windows, symlinks require special privileges and may fail
        #[cfg(windows)]
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            skipped.push(format!("{} (symlink/hardlink)", path.display()));
            continue;
        }

        // Skip special files that can't be extracted
        if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            skipped.push(format!("{} (special file)", path.display()));
            continue;
        }

        // Extract the entry
        entry
            .unpack_in(extract_dir)
            .with_context(|| format!("Failed to extract: {}", path.display()))?;
    }

    // Return reader for ACK sending
    let reader = archive.into_inner();
    Ok((skipped, reader))
}

/// Print folder creation info messages.
pub fn print_tar_creation_info() {
    #[cfg(unix)]
    println!("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    println!("   Note: Windows does not support Unix file modes.");
    println!("   Symlinks are included; special files (devices, FIFOs) are skipped.");
}

/// Print folder extraction info messages.
pub fn print_tar_extraction_info() {
    #[cfg(unix)]
    println!("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    {
        println!("   Note: Unix file modes are not supported on Windows.");
        println!("   Symlinks require admin privileges and may be skipped.");
    }
    println!("   Special files (devices, FIFOs) will be skipped if present.");
}

/// Determine the extraction directory for a folder transfer.
///
/// If `output_dir` is provided, uses it directly.
/// Otherwise, generates a unique directory name with timestamp and random suffix.
///
/// # Arguments
/// * `output_dir` - Optional user-specified output directory
///
/// # Returns
/// * The directory path to extract files into
pub fn get_extraction_dir(output_dir: Option<PathBuf>) -> PathBuf {
    match output_dir {
        Some(dir) => dir,
        None => {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let random_id: u32 = rand::random();
            PathBuf::from(format!("wormhole_{}_{:08x}", timestamp, random_id))
        }
    }
}

/// Print skipped entries warning if any were skipped during extraction.
pub fn print_skipped_entries(skipped_entries: &[String]) {
    if !skipped_entries.is_empty() {
        println!(
            "\n⚠️  Skipped {} entries (not supported on this platform):",
            skipped_entries.len()
        );
        for entry in skipped_entries {
            println!("   - {}", entry);
        }
    }
}
