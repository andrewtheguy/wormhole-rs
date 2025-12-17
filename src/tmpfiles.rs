//! tmpfiles.org upload/download module for fallback file transfer
//!
//! tmpfiles.org is a simple file hosting service:
//! - Upload: POST https://tmpfiles.org/api/v1/upload with multipart form
//! - Response: {"status":"success","data":{"url":"http://tmpfiles.org/123/file.dat"}}
//! - Download: Replace "tmpfiles.org/" with "tmpfiles.org/dl/" in URL
//! - Files retained for 60 minutes
//! - Max file size: 100MB

use anyhow::{Context, Result};
use reqwest::multipart;
use serde::Deserialize;

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

/// Upload bytes to tmpfiles.org with a filename
///
/// Returns the download URL (already converted to /dl/ format)
pub async fn upload_bytes(data: &[u8], filename: &str) -> Result<String> {
    let client = reqwest::Client::new();

    // Create multipart form with file data
    let part = multipart::Part::bytes(data.to_vec())
        .file_name(filename.to_string())
        .mime_str("application/octet-stream")
        .context("Failed to set MIME type")?;

    let form = multipart::Form::new().part("file", part);

    // Upload to tmpfiles.org
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

/// Download a file from tmpfiles.org
///
/// The URL should be in /dl/ format (use convert_to_download_url if needed)
pub async fn download_file(url: &str) -> Result<Vec<u8>> {
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

    let data = response
        .bytes()
        .await
        .context("Failed to read response body")?;

    Ok(data.to_vec())
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
