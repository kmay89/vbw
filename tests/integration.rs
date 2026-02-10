//! Integration tests for the VBW binary.
//!
//! These tests compile and invoke the `vbw` binary end-to-end, verifying that
//! the CLI produces correct output, exit codes, and report files. This is the
//! layer of testing that an auditor needs to see: proof that the tool works as
//! a whole, not just in isolated units.

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Returns the path to the compiled `vbw` binary.
fn vbw_bin() -> std::path::PathBuf {
    // cargo test builds the binary into the deps directory. Use the
    // CARGO_BIN_EXE_vbw env var if available (set by cargo for integration
    // tests of [[bin]] targets), otherwise fall back to cargo_bin lookup.
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_vbw") {
        std::path::PathBuf::from(p)
    } else {
        let mut path = std::env::current_exe()
            .expect("cannot determine test binary path")
            .parent()
            .expect("no parent directory")
            .parent()
            .expect("no grandparent directory")
            .to_path_buf();
        path.push("vbw");
        path
    }
}

/// Creates a minimal valid bundle in a temp directory.
fn create_minimal_bundle(dir: &Path) {
    fs::create_dir_all(dir.join("links")).unwrap();

    fs::write(
        dir.join("provenance.json"),
        r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "artifact-placeholder",
      "digest": {
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "buildType": "https://github.com/actions/runner@v1",
    "materials": [
      {
        "uri": "git+https://github.com/example/repo@refs/heads/main",
        "digest": { "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      }
    ]
  }
}"#,
    )
    .unwrap();

    fs::write(
        dir.join("layout.json"),
        r#"{"_type": "layout", "steps": [], "inspect": []}"#,
    )
    .unwrap();

    fs::write(
        dir.join("links").join("placeholder.link"),
        r#"{"_type": "link", "name": "placeholder"}"#,
    )
    .unwrap();
}

// -------------------------------------------------------------------------
// Happy-path tests
// -------------------------------------------------------------------------

#[test]
fn test_verify_minimal_bundle_dry_run_passes() {
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        output.status.success(),
        "vbw verify should pass on a clean minimal bundle.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify report.json was created
    let report_path = dir.path().join("vbw").join("report.json");
    assert!(report_path.exists(), "report.json should be created");

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["result"], "PASS");
    assert_eq!(
        report["report_schema"], "https://scqcs.dev/vbw/report/v1",
        "report must include schema version"
    );
    assert!(
        report["vbw_version"].as_str().is_some(),
        "report must include vbw_version"
    );
}

#[test]
fn test_verify_example_bundle_matches_minimal_bundle() {
    // Verify the shipped example bundle also passes.
    let output = Command::new(vbw_bin())
        .args([
            "verify",
            "examples/minimal-bundle",
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        output.status.success(),
        "The shipped minimal-bundle example must always pass.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

// -------------------------------------------------------------------------
// Failure-path tests
// -------------------------------------------------------------------------

#[test]
fn test_verify_fails_on_missing_provenance() {
    let dir = TempDir::new().unwrap();
    // Create layout but no provenance
    fs::create_dir_all(dir.path().join("links")).unwrap();
    fs::write(
        dir.path().join("layout.json"),
        r#"{"_type": "layout", "steps": [], "inspect": []}"#,
    )
    .unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "vbw verify should fail when provenance.json is missing"
    );
}

#[test]
fn test_verify_fails_on_embedded_secret() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("links")).unwrap();

    // Provenance with an embedded AWS key
    fs::write(
        dir.path().join("provenance.json"),
        r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "art", "digest": { "sha256": "0000000000000000000000000000000000000000000000000000000000000000" } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "materials": [],
    "env": { "AWS_KEY": "AKIAIOSFODNN7EXAMPLE" }
  }
}"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("layout.json"),
        r#"{"_type": "layout", "steps": [], "inspect": []}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("links").join("p.link"),
        r#"{"_type": "link"}"#,
    )
    .unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "vbw verify should fail when provenance contains an embedded AWS key"
    );

    // Verify the report captures the failure reason
    let report_path = dir.path().join("vbw").join("report.json");
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["result"], "FAIL");
    assert!(report["independence"]["blocking_failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "secrets_detected"));
}

#[test]
fn test_verify_fails_on_private_network_ref() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("links")).unwrap();

    fs::write(
        dir.path().join("provenance.json"),
        r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "art", "digest": { "sha256": "0000000000000000000000000000000000000000000000000000000000000000" } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "materials": [
      { "uri": "http://192.168.1.100/artifact.tar.gz", "digest": { "sha256": "aaa" } }
    ]
  }
}"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("layout.json"),
        r#"{"_type": "layout", "steps": [], "inspect": []}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("links").join("p.link"),
        r#"{"_type": "link"}"#,
    )
    .unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "vbw verify should fail when provenance references a private network"
    );

    let report_path = dir.path().join("vbw").join("report.json");
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["result"], "FAIL");
    assert!(report["independence"]["blocking_failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "private_network_references"));
}

#[test]
fn test_verify_fails_on_missing_digests() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("links")).unwrap();

    // Provenance with NO digest keys anywhere in the JSON structure
    fs::write(
        dir.path().join("provenance.json"),
        r#"{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "art" }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "materials": []
  }
}"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("layout.json"),
        r#"{"_type": "layout", "steps": [], "inspect": []}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("links").join("p.link"),
        r#"{"_type": "link"}"#,
    )
    .unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "vbw verify should fail when provenance has no digest keys"
    );
}

// -------------------------------------------------------------------------
// Report structure tests
// -------------------------------------------------------------------------

#[test]
fn test_report_contains_bundle_hash() {
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    let report_path = dir.path().join("vbw").join("report.json");
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();

    let hash = report["bundle_sha256"].as_str().unwrap();
    assert_eq!(
        hash.len(),
        64,
        "bundle_sha256 should be a 64-char hex string"
    );
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "bundle_sha256 must be valid hex"
    );
}

#[test]
fn test_report_hash_is_deterministic() {
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    // First run
    Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    let report1: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("vbw").join("report.json")).unwrap())
            .unwrap();
    let hash1 = report1["bundle_sha256"].as_str().unwrap().to_string();

    // Remove vbw output and re-run
    fs::remove_dir_all(dir.path().join("vbw")).unwrap();

    Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    let report2: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("vbw").join("report.json")).unwrap())
            .unwrap();
    let hash2 = report2["bundle_sha256"].as_str().unwrap();

    assert_eq!(
        hash1, hash2,
        "Same bundle must produce the same hash across runs"
    );
}

// -------------------------------------------------------------------------
// CLI argument validation
// -------------------------------------------------------------------------

#[test]
fn test_full_slsa_requires_artifact_flag() {
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--slsa-mode",
            "full",
            // Intentionally omitting --artifact and --no-external
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "SLSA full mode without --artifact must fail"
    );
}

#[test]
fn test_version_flag() {
    let output = Command::new(vbw_bin())
        .arg("--version")
        .output()
        .expect("failed to execute vbw");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("vbw"),
        "version output should contain 'vbw': {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_rejects_symlink_in_bundle_dir() {
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    // Replace layout.json with a symlink
    let layout_path = dir.path().join("layout.json");
    let real_layout = dir.path().join("layout-real.json");
    fs::rename(&layout_path, &real_layout).unwrap();
    std::os::unix::fs::symlink(&real_layout, &layout_path).unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        !output.status.success(),
        "vbw verify should reject bundles containing symlinks"
    );
}
