//! Policy configuration for VBW independence enforcement.
//!
//! The [`VbwPolicy`] struct defines the five configurable knobs that control
//! how strictly VBW enforces independence. Users provide a `vbw-policy.json`
//! file in their bundle directory; if absent, secure defaults are applied.
//!
//! ## Design Rationale
//!
//! - **Secure by default**: All security checks are enabled in the default
//!   policy. Users must explicitly opt out of protections.
//! - **Forward compatibility**: Unknown JSON fields are silently ignored by
//!   serde. This allows newer policy schemas to be consumed by older VBW
//!   versions without breaking. Auditors should note this is intentional.
//! - **Size-bounded loading**: Policy files are read via
//!   [`crate::fs_guard::read_validated`] with a 1 MB limit to prevent memory
//!   exhaustion from maliciously large policy files.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum policy file size (1 MB). This limit prevents denial-of-service
/// from oversized policy files while being generous enough for any realistic
/// policy configuration.
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// VBW policy configuration controlling independence enforcement behavior.
///
/// Each field maps directly to a check in [`crate::independence::check_independence`].
/// The default values ([`VbwPolicy::default()`]) enable all security checks,
/// following the principle of secure-by-default.
///
/// ## JSON Schema
///
/// ```json
/// {
///   "allowed_builder_prefixes": ["https://github.com/", "https://gitlab.com/"],
///   "builder_allowlist_is_warning": true,
///   "forbid_private_network_refs": true,
///   "forbid_secrets": true,
///   "require_digests": true
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbwPolicy {
    /// URI prefixes for allowed builders (e.g., `"https://github.com/"`).
    /// A builder whose ID starts with any of these prefixes passes the check.
    pub allowed_builder_prefixes: Vec<String>,
    /// If `true`, an unknown builder produces a warning instead of a failure.
    pub builder_allowlist_is_warning: bool,
    /// If `true`, provenance containing private/internal network addresses
    /// (RFC 1918, localhost, `.local`) is a blocking failure.
    pub forbid_private_network_refs: bool,
    /// If `true`, provenance containing embedded secrets (AWS keys, GitHub
    /// PATs, private keys, passwords, bearer tokens) is a blocking failure.
    pub forbid_secrets: bool,
    /// If `true`, provenance must contain at least one JSON object key named
    /// `"sha256"` or `"digest"`. Provenance without digests suggests
    /// non-reproducible evidence.
    pub require_digests: bool,
}

impl Default for VbwPolicy {
    fn default() -> Self {
        Self {
            allowed_builder_prefixes: vec![
                "https://github.com/".to_string(),
                "https://gitlab.com/".to_string(),
                "https://tekton.dev/".to_string(),
            ],
            builder_allowlist_is_warning: true,
            forbid_private_network_refs: true,
            forbid_secrets: true,
            require_digests: true,
        }
    }
}

impl VbwPolicy {
    /// Loads a VBW policy from a JSON file, or returns secure defaults.
    ///
    /// When `path` is `Some`, the file is read via [`crate::fs_guard::read_validated`]
    /// (symlink-checked, size-bounded to 1 MB) and parsed as JSON.
    /// When `path` is `None`, [`VbwPolicy::default()`] is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, is a symlink, exceeds
    /// 1 MB, or contains invalid JSON.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                serde_json::from_slice(&crate::fs_guard::read_validated(p, MAX_POLICY_BYTES)?)
                    .map_err(Into::into)
            }
            None => Ok(Self::default()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_policy_values() {
        let policy = VbwPolicy::default();
        assert!(policy.forbid_secrets);
        assert!(policy.forbid_private_network_refs);
        assert!(policy.require_digests);
        assert!(policy.builder_allowlist_is_warning);
        assert!(policy
            .allowed_builder_prefixes
            .contains(&"https://github.com/".to_string()));
        assert!(policy
            .allowed_builder_prefixes
            .contains(&"https://gitlab.com/".to_string()));
        assert!(policy
            .allowed_builder_prefixes
            .contains(&"https://tekton.dev/".to_string()));
    }

    #[test]
    fn test_load_none_returns_default() {
        let policy = VbwPolicy::load(None).unwrap();
        let default = VbwPolicy::default();
        assert_eq!(policy.forbid_secrets, default.forbid_secrets);
        assert_eq!(policy.require_digests, default.require_digests);
        assert_eq!(
            policy.allowed_builder_prefixes,
            default.allowed_builder_prefixes
        );
    }

    #[test]
    fn test_load_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{
                "allowed_builder_prefixes": ["https://custom.ci/"],
                "builder_allowlist_is_warning": false,
                "forbid_private_network_refs": false,
                "forbid_secrets": true,
                "require_digests": false
            }}"#
        )
        .unwrap();

        let policy = VbwPolicy::load(Some(f.path())).unwrap();
        assert_eq!(policy.allowed_builder_prefixes, vec!["https://custom.ci/"]);
        assert!(!policy.builder_allowlist_is_warning);
        assert!(!policy.forbid_private_network_refs);
        assert!(policy.forbid_secrets);
        assert!(!policy.require_digests);
    }

    #[test]
    fn test_load_invalid_json_fails() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "not valid json").unwrap();

        let result = VbwPolicy::load(Some(f.path()));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_file_fails() {
        let result = VbwPolicy::load(Some(Path::new("/nonexistent/policy.json")));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let big_file = dir.path().join("huge-policy.json");
        // Write just over MAX_POLICY_BYTES (1 MB + 1 byte).
        #[allow(clippy::cast_possible_truncation)]
        let data = vec![b' '; (MAX_POLICY_BYTES as usize) + 1];
        std::fs::write(&big_file, &data).unwrap();

        let result = VbwPolicy::load(Some(&big_file));
        assert!(result.is_err(), "oversized policy files must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_load_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real-policy.json");
        std::fs::write(
            &real_file,
            r#"{"allowed_builder_prefixes":[],"builder_allowlist_is_warning":true,"forbid_private_network_refs":true,"forbid_secrets":true,"require_digests":true}"#,
        )
        .unwrap();

        let link = dir.path().join("symlink-policy.json");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        let result = VbwPolicy::load(Some(&link));
        assert!(result.is_err(), "symlink policy files must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("symlink"), "error should mention symlink");
    }
}
