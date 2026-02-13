//! Defensive file I/O guard -- single source of truth for untrusted file reads.
//!
//! Every location in VBW that reads an untrusted file (provenance JSON, policy
//! JSON, layout JSON) routes through [`read_validated`]. This module enforces
//! two invariants:
//!
//! 1. **Symlink rejection**: Files that are symlinks are refused before any
//!    content is read. This prevents an attacker from using a symlink to point
//!    VBW at an arbitrary file outside the bundle directory.
//!
//! 2. **Size bounding**: Files larger than the caller-specified `max_bytes`
//!    limit are refused. This prevents denial-of-service via oversized inputs
//!    (e.g., a 10 GB provenance file that would exhaust memory).
//!
//! ## Known Limitation: TOCTOU Window
//!
//! There is a time-of-check-to-time-of-use gap between `symlink_metadata()`
//! and `fs::read()`. An attacker with local filesystem write access could
//! swap a regular file for a symlink between the check and the read. This is
//! an accepted risk because VBW's threat model treats the local filesystem as
//! trusted infrastructure -- an attacker who can race the filesystem already
//! has local code execution, which is outside VBW's threat boundary.
//!
//! If closing this gap is required, open files with `O_NOFOLLOW` via
//! `std::os::unix::fs::OpenOptionsExt` and `fstat` the fd (~15 lines).
//! See `AUDIT-BOUNDARY.md` §Known-Limitations for the full risk acceptance.

use anyhow::{anyhow, Context, Result};
use std::{fs, path::Path};

/// Reads a file after verifying it is not a symlink and is within `max_bytes`.
///
/// This is the **only** function in VBW that reads untrusted files. All callers
/// (provenance loading, policy loading, layout loading) delegate here.
///
/// # Errors
///
/// Returns an error if:
/// - The path does not exist or is not readable.
/// - The path is a symlink (security: prevents path traversal).
/// - The file exceeds `max_bytes` (security: prevents memory exhaustion).
pub fn read_validated(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("Refusing to read symlink: {}", path.display()));
    }
    if meta.len() > max_bytes {
        return Err(anyhow!(
            "File too large: {} ({} bytes, max {max_bytes} bytes)",
            path.display(),
            meta.len(),
        ));
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}
