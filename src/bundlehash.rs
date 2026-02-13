//! Deterministic SHA-256 hashing of evidence bundles.
//!
//! This module walks a bundle directory, computes a per-file SHA-256 hash for
//! every regular file, and then computes a bundle-level hash from the sorted
//! concatenation of per-file hashes. The result is a single hex-encoded
//! SHA-256 digest that uniquely identifies the bundle's contents.
//!
//! ## Determinism Guarantee
//!
//! The bundle hash is deterministic across platforms and runs because:
//! - Files are sorted by path (lexicographic order) before hashing.
//! - Hashes are computed from hex-encoded SHA-256 strings (not raw bytes),
//!   eliminating endianness concerns.
//! - The `vbw/` output directory is excluded from the hash to prevent
//!   circular dependency (VBW writes its report into `vbw/`).
//!
//! ## Security Controls
//!
//! - **Symlink rejection**: `WalkDir` runs with `follow_links(false)` and
//!   any symlink entry causes an immediate error. Individual file hashing
//!   also checks `symlink_metadata()` before opening.
//! - **Size limits**: Per-file (100 MB), total file count (10,000), and
//!   total bundle size (2 GB) are enforced to prevent denial-of-service.
//! - **Error propagation**: `WalkDir` errors are never silently swallowed.
//!   An unreadable entry produces an error, not an incomplete hash.
//! - **Streaming hashing**: Large files are hashed in 64 KB chunks to
//!   bound memory usage regardless of file size.
//!
//! ## Cryptographic Note
//!
//! SHA-256 is provided by the `sha2` crate (`RustCrypto` project), which is
//! a pure-Rust implementation with no FFI. It is **not** FIPS 140-2/140-3
//! certified. See `AUDIT-BOUNDARY.md` §Known-Limitations for FIPS guidance.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use walkdir::WalkDir;

/// Conservative limits for untrusted bundles.
///
/// These are intentionally strict for deployment in regulated environments
/// (ATM/POS firmware verification). If you need to verify truly massive
/// bundles, bump these in a controlled release and document the change.
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB per file
const MAX_BUNDLE_FILES: usize = 10_000; // 10,000 files max
const MAX_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GB total

/// Computes the SHA-256 hash of a single file using streaming I/O.
///
/// Reads the file in 64 KB chunks to bound memory usage. Rejects symlinks
/// and files exceeding `max_size` bytes before reading any content.
///
/// Returns `(hex_hash, file_size_bytes)`.
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
        // Safe: Read::read() guarantees n <= buf.len().
        #[allow(clippy::indexing_slicing)]
        h.update(&buf[..n]);
    }
    Ok((hex::encode(h.finalize()), len))
}

/// Computes a deterministic SHA-256 hash of an evidence bundle directory.
///
/// Walks `bundle_dir` recursively, hashing every regular file (excluding
/// the `vbw/` output subdirectory). Returns a tuple of:
/// - The hex-encoded bundle-level SHA-256 hash.
/// - A JSON evidence object containing file inventory with per-file hashes.
///
/// # Errors
///
/// Returns an error if:
/// - Any entry in the directory tree is a symlink.
/// - Any file exceeds 100 MB, the bundle exceeds 10,000 files, or the
///   total size exceeds 2 GB.
/// - Any file or directory is unreadable (errors are never silently skipped).
pub fn hash_bundle(bundle_dir: &Path) -> Result<(String, Value)> {
    let mut files = Vec::new();
    let mut total_size: u64 = 0;

    for entry in WalkDir::new(bundle_dir).follow_links(false) {
        // Never silently swallow WalkDir errors. For a security tool,
        // skipping unreadable entries would produce an incomplete hash
        // and could be exploited to exclude files from verification.
        let e = entry?;
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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

    #[test]
    fn test_sha256_file_streaming_rejects_oversized() {
        let dir = TempDir::new().unwrap();
        let big = dir.path().join("big.bin");
        // Write 1025 bytes but set max to 1024
        fs::write(&big, vec![0u8; 1025]).unwrap();

        let result = sha256_file_streaming(&big, 1024);
        assert!(result.is_err(), "files over max_size must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );
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

    #[cfg(unix)]
    #[test]
    fn test_propagates_walkdir_errors() {
        use std::os::unix::fs::PermissionsExt;

        /// RAII guard that restores directory permissions on drop, ensuring
        /// cleanup even if the test panics.
        struct PermissionsGuard<'a> {
            path: &'a std::path::Path,
            original_permissions: std::fs::Permissions,
        }

        impl Drop for PermissionsGuard<'_> {
            fn drop(&mut self) {
                let _ = fs::set_permissions(self.path, self.original_permissions.clone());
            }
        }

        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("locked");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("secret.txt"), b"data").unwrap();

        // Guard ensures permissions are restored even on panic.
        let original_permissions = fs::metadata(&subdir).unwrap().permissions();
        let _guard = PermissionsGuard {
            path: &subdir,
            original_permissions,
        };
        fs::set_permissions(&subdir, fs::Permissions::from_mode(0o000)).unwrap();

        // If we can still read the directory (e.g. running as root), skip.
        if fs::read_dir(&subdir).is_ok() {
            eprintln!("skipping test_propagates_walkdir_errors: permissions not enforced (root?)");
            return;
        }

        let result = hash_bundle(dir.path());
        assert!(
            result.is_err(),
            "WalkDir errors must propagate, not be silently ignored"
        );
    }
}
