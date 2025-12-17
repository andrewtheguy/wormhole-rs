//! tmpfiles.org upload/download module for fallback file transfer
//!
//! tmpfiles.org is a simple file hosting service:
//! - Upload: POST https://tmpfiles.org/api/v1/upload with multipart form
//! - Response: {"status":"success","data":{"url":"http://tmpfiles.org/123/file.dat"}}
//! - Download: Replace "tmpfiles.org/" with "tmpfiles.org/dl/" in URL
//! - Files retained for 60 minutes
//! - Max file size: 100MB

use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest::multipart;
use serde::Deserialize;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

/// Maximum file size for tmpfiles.org (100MB)
pub const MAX_TMPFILES_SIZE: u64 = 100 * 1024 * 1024;

/// Upload response from tmpfiles.org API
#[derive(Deserialize)]
struct UploadResponse {
    status: String,
    data: UploadData,
}

#[derive(Deserialize)]
struct UploadData {
    url: String,
}

/// Convert tmpfiles.org URL to download URL format
///
/// Input:  http://tmpfiles.org/12345/filename.dat
/// Output: https://tmpfiles.org/dl/12345/filename.dat
pub fn convert_to_download_url(url: &str) -> String {
    url.replace("http://tmpfiles.org/", "https://tmpfiles.org/dl/")
}

/// Upload a file to tmpfiles.org by streaming from disk
///
/// This is more memory-efficient than upload_bytes for large files.
/// Returns the download URL (already converted to /dl/ format)
pub async fn upload_file(path: &Path, filename: &str) -> Result<String> {
    let file = File::open(path)
        .await
        .context("Failed to open file for upload")?;

    let file_size = file
        .metadata()
        .await
        .context("Failed to get file metadata")?
        .len();

    // Create a stream from the file
    let stream = ReaderStream::new(file);
    let body = reqwest::Body::wrap_stream(stream);

    // Create multipart form with streaming body
    let part = multipart::Part::stream_with_length(body, file_size)
        .file_name(filename.to_string())
        .mime_str("application/octet-stream")
        .context("Failed to set MIME type")?;

    let form = multipart::Form::new().part("file", part);

    let client = reqwest::Client::new();
    let response = client
        .post("https://tmpfiles.org/api/v1/upload")
        .multipart(form)
        .send()
        .await
        .context("Failed to upload to tmpfiles.org")?;

    // Check for HTTP errors
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "tmpfiles.org upload failed with status {}: {}",
            status,
            body
        );
    }

    // Parse response
    let upload_response: UploadResponse = response
        .json()
        .await
        .context("Failed to parse tmpfiles.org response")?;

    if upload_response.status != "success" {
        anyhow::bail!(
            "tmpfiles.org upload failed: status={}",
            upload_response.status
        );
    }

    // Convert URL to download format
    let download_url = convert_to_download_url(&upload_response.data.url);
    Ok(download_url)
}

/// Download a file from tmpfiles.org directly to disk
///
/// This is more memory-efficient than download_file for large files.
/// Returns the number of bytes downloaded.
pub async fn download_to_file(url: &str, path: &Path) -> Result<u64> {
    let client = reqwest::Client::new();

    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to download from tmpfiles.org")?;

    // Check for HTTP errors
    if !response.status().is_success() {
        let status = response.status();
        if status.as_u16() == 404 {
            anyhow::bail!(
                "tmpfiles.org download failed: file not found (may have expired after 60 minutes)"
            );
        }
        anyhow::bail!("tmpfiles.org download failed with status {}", status);
    }

    // Stream response body to file
    let mut file = File::create(path)
        .await
        .context("Failed to create output file")?;

    let mut stream = response.bytes_stream();
    let mut total_bytes = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read response chunk")?;
        file.write_all(&chunk)
            .await
            .context("Failed to write to file")?;
        total_bytes += chunk.len() as u64;
    }

    file.flush().await.context("Failed to flush file")?;

    Ok(total_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_to_download_url() {
        assert_eq!(
            convert_to_download_url("http://tmpfiles.org/15788663/womens-wool-piper-go.json"),
            "https://tmpfiles.org/dl/15788663/womens-wool-piper-go.json"
        );

        // Already https should work too
        assert_eq!(
            convert_to_download_url("https://tmpfiles.org/dl/12345/test.dat"),
            "https://tmpfiles.org/dl/12345/test.dat"
        );
    }
}
