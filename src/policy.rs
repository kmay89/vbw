use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum policy file size (1 MB).
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbwPolicy {
    pub allowed_builder_prefixes: Vec<String>,
    pub builder_allowlist_is_warning: bool,
    pub forbid_private_network_refs: bool,
    pub forbid_secrets: bool,
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
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => Ok(serde_json::from_slice(&crate::fs_guard::read_validated(
                p,
                MAX_POLICY_BYTES,
            )?)?),
            None => Ok(Self::default()),
        }
    }
}

#[cfg(test)]
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
