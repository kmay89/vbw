use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use walkdir::WalkDir;

/// Conservative limits for untrusted bundles.
///
/// These are intentionally strict for "atm-grade" safety. If you need to verify
/// truly massive bundles, bump these in a controlled release and document it.
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB

fn sha256_file_streaming(p: &Path, max_size: u64) -> Result<(String, u64)> {
    let meta = fs::symlink_metadata(p).with_context(|| format!("stat {}", p.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("Refusing to hash symlink: {}", p.display()));
    }
    let len = meta.len();
    if len > max_size {
        return Err(anyhow!(
            "File too large: {} ({} bytes, max {} bytes)",
            p.display(),
            len,
            max_size
        ));
    }

    let mut f = fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("read {}", p.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok((hex::encode(h.finalize()), len))
}

pub fn hash_bundle(bundle_dir: &Path) -> Result<(String, Value)> {
    let mut files = Vec::new();
    let mut total_size: u64 = 0;

    for e in WalkDir::new(bundle_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if e.file_type().is_file() {
            // Never include VBW outputs in the bundle hash.
            if e.path().components().any(|c| c.as_os_str() == "vbw") {
                continue;
            }
            // Symlink defense (WalkDir normally reports symlinks separately, but be strict).
            let meta = fs::symlink_metadata(e.path())?;
            if meta.file_type().is_symlink() {
                return Err(anyhow!(
                    "Refusing to include symlink in bundle: {}",
                    e.path().display()
                ));
            }

            if files.len() >= MAX_BUNDLE_FILES {
                return Err(anyhow!(
                    "Too many files in bundle: {} (max {})",
                    files.len(),
                    MAX_BUNDLE_FILES
                ));
            }

            let size = meta.len();
            if size > MAX_FILE_SIZE {
                return Err(anyhow!(
                    "File too large: {} ({} bytes, max {} bytes)",
                    e.path().display(),
                    size,
                    MAX_FILE_SIZE
                ));
            }
            total_size = total_size.saturating_add(size);
            if total_size > MAX_TOTAL_SIZE {
                return Err(anyhow!(
                    "Bundle too large: {} bytes (max {} bytes)",
                    total_size,
                    MAX_TOTAL_SIZE
                ));
            }
            files.push(e.path().to_path_buf());
        }
    }
    files.sort();

    let mut h = Sha256::new();
    let mut listing = Vec::new();

    for p in &files {
        let (file_hash, len) = sha256_file_streaming(p, MAX_FILE_SIZE)?;
        h.update(file_hash.as_bytes());
        let relative_path = p.strip_prefix(bundle_dir).with_context(|| {
            format!(
                "Path '{}' should be prefixed with '{}'",
                p.display(),
                bundle_dir.display()
            )
        })?;
        listing.push(serde_json::json!({
            "path": relative_path.display().to_string(),
            "sha256": file_hash,
            "bytes": len
        }));
    }

    Ok((
        hex::encode(h.finalize()),
        serde_json::json!({
            "stats": {"files": listing.len(), "total_bytes": total_size, "max_file_bytes": MAX_FILE_SIZE},
            "files": listing
        }),
    ))
}
