//! Attestation generation -- produces an in-toto Statement v1 with a VBW predicate.
//!
//! The attestation binds the verification results to the evidence bundle hash,
//! creating an immutable record of what VBW checked and what it found. The
//! statement follows the [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
//! specification:
//!
//! - `_type`: `https://in-toto.io/Statement/v1`
//! - `subject[0]`: The evidence bundle, identified by its SHA-256 digest.
//! - `predicateType`: `https://scqcs.dev/vbw/predicate/v1`
//! - `predicate`: VBW-specific payload containing verification results,
//!   evidence inventory, timestamp, and VBW version.
//!
//! ## Signing
//!
//! VBW does **not** sign the attestation itself. Signing is delegated to
//! `cosign` (Sigstore) as an external subprocess, which provides keyless
//! signing with transparency log anchoring. This separation of concerns
//! means VBW's audit surface does not include key management or signing
//! algorithm implementation.

use anyhow::Result;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Creates an in-toto Statement v1 containing the VBW verification results.
///
/// The statement's `subject` field binds the attestation to the evidence
/// bundle via its SHA-256 hash. The `predicate` field contains the full
/// verification results (SLSA, in-toto, independence), the evidence
/// inventory, and metadata (VBW version, RFC 3339 timestamp).
///
/// # Errors
///
/// Returns an error only if RFC 3339 timestamp formatting fails (should
/// not happen in practice, but is propagated for defense in depth).
pub fn make_vbw_statement(
    bundle_sha256: &str,
    evidence: &Value,
    slsa_ok: bool,
    intoto_ok: bool,
    indep: &Value,
) -> Result<Value> {
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    Ok(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            { "name": "vbw-input-bundle", "digest": { "sha256": bundle_sha256 } }
        ],
        "predicateType": "https://scqcs.dev/vbw/predicate/v1",
        "predicate": {
            "vbw_version": env!("CARGO_PKG_VERSION"),
            "verifiedAt": ts,
            "results": {
                "slsa": { "ok": slsa_ok },
                "intoto": { "ok": intoto_ok },
                "independence": indep
            },
            "evidence": evidence
        }
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_statement_structure() {
        let evidence = json!({"files": []});
        let indep = json!({"overall": "pass"});
        let stmt = make_vbw_statement("abc123", &evidence, true, true, &indep).unwrap();

        assert_eq!(stmt["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(stmt["predicateType"], "https://scqcs.dev/vbw/predicate/v1");
    }

    #[test]
    fn test_subject_contains_digest() {
        let stmt = make_vbw_statement(
            "deadbeef",
            &json!({}),
            true,
            true,
            &json!({"overall": "pass"}),
        )
        .unwrap();

        let subject = &stmt["subject"][0];
        assert_eq!(subject["name"], "vbw-input-bundle");
        assert_eq!(subject["digest"]["sha256"], "deadbeef");
    }

    #[test]
    fn test_results_reflect_inputs() {
        let indep = json!({"overall": "fail", "blocking_failures": ["secrets_detected"]});

        let stmt = make_vbw_statement("abc", &json!({}), false, true, &indep).unwrap();

        let results = &stmt["predicate"]["results"];
        assert_eq!(results["slsa"]["ok"], false);
        assert_eq!(results["intoto"]["ok"], true);
        assert_eq!(results["independence"]["overall"], "fail");
    }

    #[test]
    fn test_timestamp_is_rfc3339() {
        let stmt =
            make_vbw_statement("abc", &json!({}), true, true, &json!({"overall": "pass"})).unwrap();

        let ts = stmt["predicate"]["verifiedAt"].as_str().unwrap();
        // RFC 3339 timestamps end with Z or +00:00 and contain T
        assert!(ts.contains('T'), "timestamp should be RFC 3339 format");
        assert!(
            ts.ends_with('Z') || ts.contains('+') || ts.contains('-'),
            "timestamp should have timezone"
        );
    }

    #[test]
    fn test_evidence_is_preserved() {
        let evidence = json!({"stats": {"files": 3}, "files": [{"path": "a.txt"}]});
        let stmt =
            make_vbw_statement("abc", &evidence, true, true, &json!({"overall": "pass"})).unwrap();

        assert_eq!(stmt["predicate"]["evidence"], evidence);
    }

    #[test]
    fn test_predicate_contains_vbw_version() {
        let stmt =
            make_vbw_statement("abc", &json!({}), true, true, &json!({"overall": "pass"})).unwrap();

        let version = stmt["predicate"]["vbw_version"].as_str().unwrap();
        assert!(
            !version.is_empty(),
            "attestation predicate must include the VBW version that produced it"
        );
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }
}
