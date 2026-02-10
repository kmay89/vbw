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
    #[allow(clippy::large_stack_arrays)]
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
        // Symlink defense: with follow_links(false), WalkDir reports symlinks
        // as their own entry type. Reject them before any other processing.
        if e.path_is_symlink() {
            return Err(anyhow!(
                "Refusing to include symlink in bundle: {}",
                e.path().display()
            ));
        }

        if e.file_type().is_file() {
            // Never include VBW outputs in the bundle hash.
            if e.path().components().any(|c| c.as_os_str() == "vbw") {
                continue;
            }

            if files.len() >= MAX_BUNDLE_FILES {
                return Err(anyhow!(
                    "Too many files in bundle: {} (max {})",
                    files.len(),
                    MAX_BUNDLE_FILES
                ));
            }

            let size = e.metadata()?.len();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_hash_deterministic() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::write(dir.path().join("b.txt"), b"world").unwrap();

        let (h1, e1) = hash_bundle(dir.path()).unwrap();
        let (h2, e2) = hash_bundle(dir.path()).unwrap();

        assert_eq!(h1, h2, "same bundle must produce identical hashes");
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_hash_changes_with_content() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.txt"), b"version1").unwrap();
        let (h1, _) = hash_bundle(dir.path()).unwrap();

        fs::write(dir.path().join("file.txt"), b"version2").unwrap();
        let (h2, _) = hash_bundle(dir.path()).unwrap();

        assert_ne!(h1, h2, "different content must produce different hashes");
    }

    #[test]
    fn test_excludes_vbw_output_dir() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("provenance.json"), b"{}").unwrap();
        let vbw_dir = dir.path().join("vbw");
        fs::create_dir_all(&vbw_dir).unwrap();
        fs::write(vbw_dir.join("report.json"), b"should-be-excluded").unwrap();

        let (_, evidence) = hash_bundle(dir.path()).unwrap();
        let file_count = evidence["stats"]["files"].as_u64().unwrap();
        assert_eq!(file_count, 1, "vbw/ directory should be excluded from hash");
    }

    #[test]
    fn test_empty_bundle() {
        let dir = TempDir::new().unwrap();
        let (hash, evidence) = hash_bundle(dir.path()).unwrap();

        assert!(!hash.is_empty());
        assert_eq!(evidence["stats"]["files"], 0);
        assert_eq!(evidence["stats"]["total_bytes"], 0);
    }

    #[test]
    fn test_evidence_contains_file_listing() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("artifact.bin"), b"binary-data").unwrap();

        let (_, evidence) = hash_bundle(dir.path()).unwrap();
        let files = evidence["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["path"], "artifact.bin");
        assert_eq!(files[0]["bytes"], 11); // len("binary-data")
        assert!(files[0]["sha256"].as_str().unwrap().len() == 64);
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_symlink_in_bundle() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real.txt");
        fs::write(&target, b"data").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link.txt")).unwrap();

        let result = hash_bundle(dir.path());
        assert!(result.is_err(), "symlinks must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("symlink"), "error should mention symlink");
    }
}
