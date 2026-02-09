use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

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
        if let Some(p) = path {
            let bytes = fs::read(p)?;
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            Ok(Self::default())
        }
    }
}
