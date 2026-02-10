use anyhow::{anyhow, Context, Result};
use std::{fs, path::Path};

/// Reads a file after verifying it is not a symlink and is within `max_bytes`.
///
/// NOTE: narrow TOCTOU window between `symlink_metadata()` and `fs::read()`.
/// Closing it fully requires `O_NOFOLLOW` or `fstat` on the fd. The check
/// still catches accidental symlinks and raises the bar for exploitation.
/// See AUDIT-BOUNDARY.md §Known-Limitations for risk acceptance rationale.
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
