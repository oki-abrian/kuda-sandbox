use crate::error::{Result, SandboxError};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootfsImage {
    Alpine,
    Ubuntu,
    Debian,
    Custom(String),
}

pub struct ImageManager {
    cache_dir: PathBuf,
}

impl Default for ImageManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    Gzip,
    Xz,
    None,
}

impl Compression {
    fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
            Some(Compression::Gzip)
        } else if bytes.len() >= 6 && bytes[0..6] == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
            Some(Compression::Xz)
        } else if bytes.len() >= 262 && &bytes[257..262] == b"tar" {
            Some(Compression::None)
        } else {
            None
        }
    }

    fn extension(&self) -> &'static str {
        match self {
            Compression::Gzip => "tar.gz",
            Compression::Xz => "tar.xz",
            Compression::None => "tar",
        }
    }
}

impl ImageManager {
    pub fn new() -> Self {
        let home = std::env::var("HOME").ok().map(PathBuf::from);
        let base = match home {
            Some(h) if h.is_dir() => h.join(".kuda_sandbox").join("images"),
            _ => std::env::temp_dir().join("kuda_sandbox_images"),
        };
        Self { cache_dir: base }
    }

    pub fn with_cache_dir(dir: PathBuf) -> Self {
        Self { cache_dir: dir }
    }

    /// Returns path to the unpacked rootfs base directory
    pub fn get_image_path(&self, image: &RootfsImage) -> PathBuf {
        let name = match image {
            RootfsImage::Alpine => "alpine-latest".to_string(),
            RootfsImage::Ubuntu => "ubuntu-minimal".to_string(),
            RootfsImage::Debian => "debian-slim".to_string(),
            RootfsImage::Custom(s) => {
                // Never use raw URLs as directory names; hash them instead
                if s.starts_with("http://") || s.starts_with("https://") || s.contains('/') {
                    let mut hasher = Sha256::new();
                    hasher.update(s.as_bytes());
                    format!("custom-{:x}", hasher.finalize())[..24].to_string()
                } else {
                    s.clone()
                }
            }
        };
        self.cache_dir.join(name)
    }

    /// Checks if a rootfs image is already cached on disk
    pub fn is_cached(&self, image: &RootfsImage) -> bool {
        let p = self.get_image_path(image);
        p.exists() && p.join("bin").exists()
    }

    /// Unpacks a rootfs archive (tar.gz / tar.xz / tar) with Tar-Slip protection.
    /// Extraction goes to a sibling temp dir and is renamed atomically on success,
    /// so a failed run never leaves a half-valid cache entry behind.
    pub fn unpack_archive(&self, archive_path: &Path, image: &RootfsImage) -> Result<PathBuf> {
        let target_dir = self.get_image_path(image);
        if target_dir.exists() {
            return Ok(target_dir);
        }

        fs::create_dir_all(&self.cache_dir)?;
        let mut header = [0u8; 512];
        let mut f = fs::File::open(archive_path)?;
        let n = read_full(&mut f, &mut header)?;
        let compression = Compression::detect(&header[..n]).ok_or_else(|| {
            SandboxError::SetupFailed(format!(
                "File '{}' is not a recognizable tar/tar.gz/tar.xz archive",
                archive_path.display()
            ))
        })?;
        drop(f);

        let temp_target = self.cache_dir.join(format!(".extract_{}", uuid::Uuid::new_v4()));
        let res = (|| -> Result<PathBuf> {
            fs::create_dir_all(&temp_target)?;

            // Reopen fresh: the probe above consumed the first bytes of `f`
            let file = fs::File::open(archive_path)?;

            let reader: Box<dyn Read> = match compression {
                Compression::Gzip => Box::new(GzDecoder::new(file)),
                Compression::Xz => Box::new(xz2::read::XzDecoder::new_multi_decoder(file)),
                Compression::None => Box::new(file),
            };

            let mut archive = Archive::new(reader);
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;
                if path.is_absolute() || path.components().any(|c| c == std::path::Component::ParentDir) {
                    return Err(SandboxError::SecurityViolation(format!(
                        "Malicious tar entry detected with path traversal: {}",
                        path.display()
                    )));
                }
                entry.unpack_in(&temp_target)?;
            }

            if target_dir.exists() {
                let _ = fs::remove_dir_all(&target_dir);
            }
            fs::rename(&temp_target, &target_dir)?;
            Ok(target_dir.clone())
        })();

        if temp_target.exists() {
            let _ = fs::remove_dir_all(&temp_target);
        }
        res
    }

    /// Legacy alias kept for API compatibility
    pub fn unpack_tar_gz(&self, archive_path: &Path, image: &RootfsImage) -> Result<PathBuf> {
        self.unpack_archive(archive_path, image)
    }

    /// Pulls an official minimal rootfs image over HTTPS and caches it on disk.
    /// - Streams the body to disk (no full in-RAM buffering)
    /// - Verifies HTTP status and SHA256 (Alpine official sidecar checksum)
    /// - Extracts atomically (temp dir + rename)
    pub async fn pull_image(&self, image: &RootfsImage) -> Result<PathBuf> {
        let target_dir = self.get_image_path(image);
        if self.is_cached(image) {
            return Ok(target_dir);
        }

        let url = match image {
            RootfsImage::Alpine => {
                #[cfg(target_arch = "aarch64")]
                let arch = "aarch64";
                #[cfg(not(target_arch = "aarch64"))]
                let arch = "x86_64";
                format!("https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/{}/alpine-minirootfs-3.20.0-{}.tar.gz", arch, arch)
            }
            RootfsImage::Ubuntu => {
                "https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64-root.tar.xz".to_string()
            }
            RootfsImage::Debian => {
                "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.tar.xz".to_string()
            }
            RootfsImage::Custom(url) => url.clone(),
        };

        tracing::info!("Pulling rootfs image from {}", url);

        let resp = reqwest::get(&url).await.map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to download rootfs from {}: {}", url, e))
        })?;

        if !resp.status().is_success() {
            return Err(SandboxError::SetupFailed(format!(
                "HTTP error {} when downloading rootfs from {}",
                resp.status(),
                url
            )));
        }

        // Expected digest: official Alpine publishes a sidecar '<file>.sha256'
        let expected_sha256: Option<String> = if matches!(image, RootfsImage::Alpine) {
            fetch_alpine_sha256(&url).await?
        } else {
            None
        };

        fs::create_dir_all(&self.cache_dir)?;
        let temp_archive = self.cache_dir.join(format!("temp_{}.{}", uuid::Uuid::new_v4(), "download"));

        // Stream body to disk while hashing
        let hash_result = write_stream_and_hash(resp, &temp_archive).await;
        let actual_sha256 = match hash_result {
            Ok(h) => h,
            Err(e) => {
                let _ = fs::remove_file(&temp_archive);
                return Err(e);
            }
        };

        if let Some(expected) = &expected_sha256 {
            if !constant_time_eq(expected.trim(), &actual_sha256) {
                let _ = fs::remove_file(&temp_archive);
                return Err(SandboxError::SecurityViolation(format!(
                    "SHA256 mismatch for downloaded rootfs (expected {}, got {}). Supply-chain integrity check failed.",
                    expected.trim(),
                    actual_sha256
                )));
            }
        } else {
            tracing::warn!("No reference SHA256 available for this image; skipping integrity verification");
        }

        // Detect real compression from content, not from URL/file name
        let mut header = [0u8; 512];
        let mut f = fs::File::open(&temp_archive)?;
        let n = read_full(&mut f, &mut header)?;
        let compression = match Compression::detect(&header[..n]) {
            Some(c) => c,
            None => {
                let _ = fs::remove_file(&temp_archive);
                return Err(SandboxError::SetupFailed(
                    "Downloaded rootfs is not a recognizable tar/tar.gz/tar.xz archive".into(),
                ));
            }
        };
        drop(f);

        tracing::info!("Downloaded rootfs detected as {} archive", compression.extension());

        let temp_target = self.cache_dir.join(format!(".extract_{}", uuid::Uuid::new_v4()));
        let unpack_res = (|| -> Result<PathBuf> {
            fs::create_dir_all(&temp_target)?;

            let file = fs::File::open(&temp_archive)?;
            let reader: Box<dyn Read> = match compression {
                Compression::Gzip => Box::new(GzDecoder::new(file)),
                Compression::Xz => Box::new(xz2::read::XzDecoder::new_multi_decoder(file)),
                Compression::None => Box::new(file),
            };

            let mut archive = Archive::new(reader);
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;
                if path.is_absolute() || path.components().any(|c| c == std::path::Component::ParentDir) {
                    return Err(SandboxError::SecurityViolation(format!(
                        "Malicious tar entry detected with path traversal: {}",
                        path.display()
                    )));
                }
                entry.unpack_in(&temp_target)?;
            }

            if target_dir.exists() {
                let _ = fs::remove_dir_all(&target_dir);
            }
            fs::rename(&temp_target, &target_dir)?;
            Ok(target_dir.clone())
        })();

        let _ = fs::remove_file(&temp_archive);
        if temp_target.exists() {
            let _ = fs::remove_dir_all(&temp_target);
        }

        unpack_res
    }

    /// Creates a minimal rootfs directory layout if running without external rootfs
    pub fn prepare_synthetic_rootfs(&self, target_dir: &Path) -> Result<()> {
        let dirs = ["bin", "sbin", "usr/bin", "usr/lib", "lib", "etc", "tmp", "dev", "proc", "sys", "workspace"];
        for d in &dirs {
            fs::create_dir_all(target_dir.join(d))?;
        }
        Ok(())
    }
}

fn read_full(f: &mut fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = f.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

async fn fetch_alpine_sha256(url: &str) -> Result<Option<String>> {
    let checksum_url = format!("{}.sha256", url);
    let resp = reqwest::get(&checksum_url).await.map_err(|e| {
        SandboxError::SetupFailed(format!("Failed to fetch checksum sidecar {}: {}", checksum_url, e))
    })?;
    if !resp.status().is_success() {
        return Err(SandboxError::SetupFailed(format!(
            "Checksum sidecar {} returned HTTP {} — refusing unverified download",
            checksum_url,
            resp.status()
        )));
    }
    let body = resp.text().await.map_err(|e| {
        SandboxError::SetupFailed(format!("Failed to read checksum sidecar: {}", e))
    })?;
    let hash = body.split_whitespace().next().unwrap_or("").to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SandboxError::SetupFailed(format!(
            "Malformed checksum sidecar content: '{}'",
            body.trim()
        )));
    }
    Ok(Some(hash))
}

async fn write_stream_and_hash(resp: reqwest::Response, dest: &Path) -> Result<String> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::io::BufWriter::new(tokio::fs::File::create(dest).await?);
    let mut hasher = Sha256::new();
    let mut resp = resp;

    while let Some(chunk) = resp.chunk().await? {
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    Ok(format!("{:x}", hasher.finalize()))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
