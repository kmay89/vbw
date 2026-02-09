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
