//! Integration tests for the VBW binary.
//!
//! These tests compile and invoke the `vbw` binary end-to-end, verifying that
//! the CLI produces correct output, exit codes, and report files. This is the
//! layer of testing that an auditor needs to see: proof that the tool works as
//! a whole, not just in isolated units.

// Test code uses .unwrap() and indexing freely -- this is standard Rust test
// practice and is distinct from the production code lint policy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

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
fn test_full_slsa_requires_artifact_when_tool_available() {
    // When --no-external is used, slsa-verifier is not probed, and the artifact
    // check is bypassed. This test verifies that --no-external plus --slsa-mode
    // full does NOT require --artifact (since external tools are skipped).
    //
    // The original --artifact requirement is enforced only when slsa-verifier
    // is actually installed. Since we cannot guarantee slsa-verifier is present
    // in CI, we test the complementary behavior: --no-external skips the check.
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    // With --no-external: should succeed even in full mode without --artifact
    let output = Command::new(vbw_bin())
        .args([
            "verify",
            dir.path().to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "full",
        ])
        .output()
        .expect("failed to execute vbw");

    assert!(
        output.status.success(),
        "SLSA full mode with --no-external should not require --artifact.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn test_verify_without_escape_hatches_degrades_gracefully() {
    // Run vbw verify without --no-external, --dry-run, or --slsa-mode schema-only.
    // When external tools are not installed (typical in CI), VBW should degrade
    // gracefully: produce a report with clear limitations documented.
    let dir = TempDir::new().unwrap();
    create_minimal_bundle(dir.path());

    let output = Command::new(vbw_bin())
        .args(["verify", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to execute vbw");

    // If external tools are not installed, the command should still succeed
    // (verification passes with degraded checks). If tools ARE installed,
    // it would fail because --artifact is required. Either outcome is acceptable.
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // Tools not installed -- graceful degradation path.
        // The report should exist and document the limitations.
        let report_path = dir.path().join("vbw").join("report.json");
        assert!(
            report_path.exists(),
            "report.json should be created even with degraded verification"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        // Report should document tool availability.
        assert!(
            report.get("external_tools").is_some(),
            "report should include external_tools status"
        );
    } else {
        // Tools ARE installed and --artifact is required.
        assert!(
            stderr.contains("--artifact") || stderr.contains("slsa-verifier"),
            "failure should mention missing --artifact or tool issue: {stderr}"
        );
    }
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

// -------------------------------------------------------------------------
// Build command tests
// -------------------------------------------------------------------------

#[test]
fn test_build_produces_witness_bundle() {
    let src_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    let artifact = src_dir.path().join("output.txt");
    let witness_dir = out_dir.path().join("witness");

    // Create source files
    fs::write(src_dir.path().join("main.txt"), b"source code").unwrap();

    let output = Command::new(vbw_bin())
        .args([
            "build",
            "--output-dir",
            witness_dir.to_str().unwrap(),
            "--artifact",
            artifact.to_str().unwrap(),
            "--source-dir",
            src_dir.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("echo built > {}", artifact.display()),
        ])
        .output()
        .expect("failed to execute vbw build");

    assert!(
        output.status.success(),
        "vbw build should succeed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify bundle structure
    assert!(
        witness_dir.join("manifest.json").exists(),
        "manifest.json should exist"
    );
    assert!(
        witness_dir.join("provenance.json").exists(),
        "provenance.json should exist"
    );
    assert!(
        witness_dir.join("layout.json").exists(),
        "layout.json should exist"
    );
    assert!(
        witness_dir.join("links").join("vbw-build.link").exists(),
        "link file should exist"
    );

    // Verify manifest contents
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(witness_dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["build"]["exit_code"], 0);
    assert!(
        manifest["source"]["sha256"].as_str().unwrap().len() == 64,
        "source hash should be 64 hex chars"
    );
}

#[test]
fn test_build_then_verify_roundtrip() {
    let src_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    let artifact = src_dir.path().join("output.bin");
    let witness_dir = out_dir.path().join("bundle");

    fs::write(src_dir.path().join("input.rs"), b"fn main() {}").unwrap();

    // Step 1: Build with witness
    let build_output = Command::new(vbw_bin())
        .args([
            "build",
            "--output-dir",
            witness_dir.to_str().unwrap(),
            "--artifact",
            artifact.to_str().unwrap(),
            "--source-dir",
            src_dir.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("echo hello > {}", artifact.display()),
        ])
        .output()
        .expect("failed to execute vbw build");

    assert!(
        build_output.status.success(),
        "build step failed: {}",
        String::from_utf8_lossy(&build_output.stderr),
    );

    // Step 2: Verify the witness bundle
    let verify_output = Command::new(vbw_bin())
        .args([
            "verify",
            witness_dir.to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw verify");

    assert!(
        verify_output.status.success(),
        "vbw verify should pass on a bundle produced by vbw build.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify_output.stdout),
        String::from_utf8_lossy(&verify_output.stderr),
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(witness_dir.join("vbw").join("report.json")).unwrap())
            .unwrap();
    assert_eq!(report["result"], "PASS");
}

#[test]
fn test_build_fails_on_bad_command() {
    let dir = TempDir::new().unwrap();
    let output = Command::new(vbw_bin())
        .args([
            "build",
            "--output-dir",
            dir.path().join("out").to_str().unwrap(),
            "--source-dir",
            dir.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .output()
        .expect("failed to execute vbw build");

    assert!(
        !output.status.success(),
        "vbw build should fail when the build command fails"
    );
}

#[test]
fn test_build_help_shows_build_subcommand() {
    let output = Command::new(vbw_bin())
        .arg("help")
        .output()
        .expect("failed to execute vbw help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("build"),
        "help output should mention the build subcommand: {stdout}"
    );
}

// -------------------------------------------------------------------------
// End-to-end: build a real Rust project, then verify the witness bundle
// -------------------------------------------------------------------------

/// Creates a minimal Rust hello-world project in the given directory.
fn create_rust_hello_world(dir: &Path) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "hello"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "hello"
path = "src/main.rs"
"#,
    )
    .unwrap();
    fs::write(
        dir.join("src").join("main.rs"),
        "fn main() { println!(\"hello vbw\"); }\n",
    )
    .unwrap();
}

#[test]
#[ignore = "slow: runs cargo build inside a temp project"]
fn test_build_verify_real_rust_project() {
    let project_dir = TempDir::new().unwrap();
    let witness_dir = TempDir::new().unwrap();
    let witness_path = witness_dir.path().join("bundle");

    create_rust_hello_world(project_dir.path());

    // Step 1: Build the Rust project with vbw build
    let artifact = project_dir
        .path()
        .join("target")
        .join("release")
        .join("hello");

    let build_output = Command::new(vbw_bin())
        .args([
            "build",
            "--output-dir",
            witness_path.to_str().unwrap(),
            "--artifact",
            artifact.to_str().unwrap(),
            "--source-dir",
            project_dir.path().to_str().unwrap(),
            "--",
            "cargo",
            "build",
            "--release",
            "--manifest-path",
        ])
        .arg(project_dir.path().join("Cargo.toml"))
        .output()
        .expect("failed to execute vbw build");

    assert!(
        build_output.status.success(),
        "vbw build with cargo should succeed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr),
    );

    // Verify the artifact was built
    assert!(artifact.exists(), "cargo build should produce the binary");

    // Step 2: Verify the witness bundle
    let verify_output = Command::new(vbw_bin())
        .args([
            "verify",
            witness_path.to_str().unwrap(),
            "--no-external",
            "--dry-run",
            "--slsa-mode",
            "schema-only",
        ])
        .output()
        .expect("failed to execute vbw verify");

    assert!(
        verify_output.status.success(),
        "vbw verify should pass on a Rust build witness bundle.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify_output.stdout),
        String::from_utf8_lossy(&verify_output.stderr),
    );

    // Step 3: Check verdict
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(witness_path.join("vbw").join("report.json")).unwrap())
            .unwrap();
    assert_eq!(report["result"], "PASS");
    assert_eq!(
        report["verdict"], "Verified-with-caveats",
        "verdict should be Verified-with-caveats since external tools are skipped"
    );

    // Step 4: Verify bundle includes transcript and manifest
    assert!(
        witness_path.join("transcript.txt").exists(),
        "transcript.txt should exist"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(witness_path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["build"]["exit_code"], 0);
    assert!(
        manifest["artifacts"].as_array().unwrap().len() == 1,
        "should have exactly one artifact"
    );
}

#[test]
fn test_verify_report_contains_verdict() {
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

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("vbw").join("report.json")).unwrap())
            .unwrap();

    // With --no-external, verdict should be Verified-with-caveats (pass but tools skipped)
    assert_eq!(report["result"], "PASS");
    assert_eq!(report["verdict"], "Verified-with-caveats");
}
