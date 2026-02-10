use anyhow::Result;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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
}
