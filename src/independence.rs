use anyhow::Result;
use regex::Regex;
use serde_json::{json, Value};
use crate::policy::VbwPolicy;

pub fn check_independence(prov: &Value, policy: &VbwPolicy) -> Result<Value> {
    let s = prov.to_string();

    let secret_patterns = vec![
        Regex::new(r"AKIA[0-9A-Z]{16}")?,
        Regex::new(r"(?i)aws_secret_access_key")?,
        Regex::new(r"(?i)BEGIN (RSA|EC|OPENSSH) PRIVATE KEY")?,
        // GitHub classic PATs are typically ~36-40 chars; bounding reduces worst-case scanning costs.
        Regex::new(r"(?i)ghp_[A-Za-z0-9]{30,60}")?,
        Regex::new(r"(?i)password\s*[:=]")?,
        Regex::new(r"(?i)\btoken\s*[:=]")?,
        // Rust's regex crate is linear-time (no catastrophic backtracking), but bounding
        // still limits scanning work on adversarially large inputs.
        Regex::new(r"(?i)bearer\s+[a-z0-9\-_\.=]{1,500}")?,
    ];

    let private_net_patterns = vec![
        Regex::new(r"\b10\.(?:\d{1,3}\.){2}\d{1,3}\b")?,
        Regex::new(r"\b192\.168\.(?:\d{1,3}\.)\d{1,3}\b")?,
        Regex::new(r"\b172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}\b")?,
        Regex::new(r"\blocalhost\b")?,
        Regex::new(r"\b127\.0\.0\.1\b")?,
        Regex::new(r"\.local\b")?,
    ];

    let mut blocking_failures = Vec::new();
    let mut warnings = Vec::new();
    let mut secret_hits = Vec::new();
    let mut net_hits = Vec::new();

    if policy.forbid_secrets {
        for re in &secret_patterns {
            if re.is_match(&s) {
                secret_hits.push(re.as_str().to_string());
            }
        }
        if !secret_hits.is_empty() {
            blocking_failures.push("secrets_detected".to_string());
        }
    }

    if policy.forbid_private_network_refs {
        for re in &private_net_patterns {
            if re.is_match(&s) {
                net_hits.push(re.as_str().to_string());
            }
        }
        if !net_hits.is_empty() {
            blocking_failures.push("private_network_references".to_string());
        }
    }

    let builder_id = prov.pointer("/predicate/builder/id")
        .and_then(|v| v.as_str())
        .or_else(|| prov.pointer("/builder/id").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let builder_on_allowlist = policy.allowed_builder_prefixes
        .iter()
        .any(|p| builder_id.starts_with(p));

    if !builder_on_allowlist {
        if policy.builder_allowlist_is_warning {
            warnings.push("builder_not_on_allowlist".to_string());
        } else {
            blocking_failures.push("builder_not_on_allowlist".to_string());
        }
    }

    if policy.require_digests {
        let has_digests = s.contains("\"sha256\"") || s.contains("\"digest\"");
        if !has_digests {
            blocking_failures.push("missing_digests".to_string());
        }
    }

    let overall = if blocking_failures.is_empty() { "pass" } else { "fail" };

    Ok(json!({
        "overall": overall,
        "builder_id": builder_id,
        "builder_on_allowlist": builder_on_allowlist,
        "secret_pattern_hits": secret_hits,
        "private_network_hits": net_hits,
        "blocking_failures": blocking_failures,
        "warnings": warnings
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_detects_aws_key() {
        let prov = json!({"env": "AKIAIOSFODNN7EXAMPLE"});
        let policy = VbwPolicy::default();
        let result = check_independence(&prov, &policy).unwrap();
        assert_eq!(result["overall"], "fail");
        assert!(result["blocking_failures"].as_array().unwrap().contains(&json!("secrets_detected")));
    }

    #[test]
    fn test_detects_private_ip() {
        let prov = json!({"server": "http://192.168.1.5"});
        let policy = VbwPolicy::default();
        let result = check_independence(&prov, &policy).unwrap();
        assert_eq!(result["overall"], "fail");
        assert!(result["blocking_failures"].as_array().unwrap().contains(&json!("private_network_references")));
    }

    #[test]
    fn test_builder_allowlist_warning() {
        // NOTE: builder.id is under predicate/builder/id for SLSA v1 provenance.
        let prov = json!({"predicate": {"builder": {"id": "https://custom.ci.example.com"}}});
        let mut policy = VbwPolicy::default();
        policy.builder_allowlist_is_warning = true;
        let result = check_independence(&prov, &policy).unwrap();
        assert_eq!(result["overall"], "pass");
        assert!(result["warnings"].as_array().unwrap().contains(&json!("builder_not_on_allowlist")));
    }

    #[test]
    fn test_builder_allowlist_blocking() {
        let prov = json!({"predicate": {"builder": {"id": "https://custom.ci.example.com"}}});
        let mut policy = VbwPolicy::default();
        policy.builder_allowlist_is_warning = false;
        let result = check_independence(&prov, &policy).unwrap();
        assert_eq!(result["overall"], "fail");
        assert!(result["blocking_failures"].as_array().unwrap().contains(&json!("builder_not_on_allowlist")));
    }

    #[test]
    fn test_missing_digests() {
        let prov = json!({"materials": []});
        let policy = VbwPolicy::default();
        let result = check_independence(&prov, &policy).unwrap();
        assert_eq!(result["overall"], "fail");
        assert!(result["blocking_failures"].as_array().unwrap().contains(&json!("missing_digests")));
    }
}
