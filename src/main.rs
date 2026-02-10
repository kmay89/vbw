use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use time::format_description::well_known::Rfc3339;

mod attest;
mod bundlehash;
mod fs_guard;
mod independence;
mod policy;

use policy::VbwPolicy;

// "Atm-grade" defensive limits for untrusted inputs.
const MAX_JSON_BYTES: u64 = 20 * 1024 * 1024; // 20MB
const MAX_TOOL_ERR_BYTES: usize = 8 * 1024; // 8KB

/// Runs an external tool, returning an error with sanitized stderr on failure.
fn run_checked(cmd: &mut Command, name: &str) -> Result<()> {
    let out = cmd.output().with_context(|| format!("running {name}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{name} failed: {}",
            sanitize_tool_stderr(&out.stderr)
        ));
    }
    Ok(())
}

fn sanitize_tool_stderr(stderr: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(stderr).to_string();
    if s.len() > MAX_TOOL_ERR_BYTES {
        s.truncate(MAX_TOOL_ERR_BYTES);
        s.push_str("\n[TRUNCATED]");
    }

    // Best-effort secret redaction (the verifier should not leak env-paths/tokens into reports).
    let patterns = [
        (r"AKIA[0-9A-Z]{16}", "AKIA****************"),
        (r"(?i)ghp_[A-Za-z0-9]{30,60}", "ghp_****************"),
        (
            r"(?i)BEGIN (RSA|EC|OPENSSH) PRIVATE KEY",
            "BEGIN [REDACTED] PRIVATE KEY",
        ),
        (
            r"(?i)aws_secret_access_key\s*[:=]\s*[^\s]+",
            "aws_secret_access_key=[REDACTED]",
        ),
        (
            r"(?i)(password|token)\s*[:=]\s*[^\s]+",
            "[REDACTED]=[REDACTED]",
        ),
        (r"(?i)bearer\s+[a-z0-9\-_\.=]{1,500}", "bearer [REDACTED]"),
    ];
    for (pat, repl) in patterns {
        if let Ok(re) = Regex::new(pat) {
            s = re.replace_all(&s, repl).to_string();
        }
    }

    // Redact obvious absolute paths.
    s = s
        .lines()
        .map(|line| {
            if line.trim_start().starts_with('/') {
                "[REDACTED_PATH]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    s
}

#[derive(Parser)]
#[command(name = "vbw", about = "Verified Build Witness", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(ValueEnum, Clone, Debug)]
enum SlsaMode {
    Full,
    SchemaOnly,
}

#[derive(Subcommand)]
enum Cmd {
    Verify {
        /// Bundle directory
        bundle_dir: PathBuf,

        /// Expected source URI (passed to slsa-verifier when used)
        #[arg(long)]
        source_uri: Option<String>,

        /// Artifact(s) to verify (required for --slsa-mode full unless --no-external)
        #[arg(long)]
        artifact: Vec<PathBuf>,

        /// SLSA provenance path (defaults to `bundle_dir/provenance.json`)
        #[arg(long)]
        provenance: Option<PathBuf>,

        /// in-toto layout path (defaults to `bundle_dir/layout.json`)
        #[arg(long)]
        layout: Option<PathBuf>,

        /// in-toto links directory (defaults to `bundle_dir/links`)
        #[arg(long)]
        links_dir: Option<PathBuf>,

        /// Public key(s) used to verify the *root layout* signature (file or directory).
        /// If omitted, VBW performs structural checks only (no cryptographic in-toto verification).
        #[arg(long)]
        intoto_layout_keys: Option<PathBuf>,

        /// Skip calling external tools (slsa-verifier / in-toto-verify / cosign)
        #[arg(long)]
        no_external: bool,

        /// Only write report.json; do not generate/sign attestation
        #[arg(long)]
        dry_run: bool,

        /// SLSA verification mode
        #[arg(long, value_enum, default_value_t = SlsaMode::Full)]
        slsa_mode: SlsaMode,

        /// VBW policy JSON (defaults to bundle_dir/vbw-policy.json if present)
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Inspect a VBW attestation + sigstore bundle
    Show {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        sigstore_bundle: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify {
            bundle_dir,
            source_uri,
            artifact,
            provenance,
            layout,
            links_dir,
            intoto_layout_keys,
            no_external,
            dry_run,
            slsa_mode,
            policy,
        } => verify_bundle(
            &bundle_dir,
            source_uri,
            artifact,
            provenance,
            layout,
            links_dir,
            intoto_layout_keys,
            no_external,
            dry_run,
            slsa_mode,
            policy,
        ),
        Cmd::Show {
            attestation,
            sigstore_bundle,
        } => show_attestation(&attestation, &sigstore_bundle),
    }
}

fn verify_bundle(
    bundle_dir: &Path,
    source_uri: Option<String>,
    artifacts: Vec<PathBuf>,
    provenance: Option<PathBuf>,
    layout: Option<PathBuf>,
    links_dir: Option<PathBuf>,
    intoto_layout_keys: Option<PathBuf>,
    no_external: bool,
    dry_run: bool,
    slsa_mode: SlsaMode,
    policy_path: Option<PathBuf>,
) -> Result<()> {
    // Enforce SLSA honesty
    match slsa_mode {
        SlsaMode::Full => {
            if artifacts.is_empty() && !no_external {
                return Err(anyhow!(
                    "SLSA full verification requires --artifact. Use --slsa-mode schema-only if you only want JSON validation."
                ));
            }
        }
        SlsaMode::SchemaOnly => {}
    }

    let prov_path = provenance.unwrap_or(bundle_dir.join("provenance.json"));
    let layout_path = layout.unwrap_or(bundle_dir.join("layout.json"));
    let links = links_dir.unwrap_or(bundle_dir.join("links"));

    if !prov_path.exists() {
        return Err(anyhow!("Missing provenance: {}", prov_path.display()));
    }
    if !layout_path.exists() {
        return Err(anyhow!("Missing layout: {}", layout_path.display()));
    }

    // Load policy
    let policy_file = policy_path.or_else(|| {
        let p = bundle_dir.join("vbw-policy.json");
        p.exists().then_some(p)
    });
    let policy = VbwPolicy::load(policy_file.as_deref())?;

    // --- SLSA verification
    let mut slsa_ok = true;
    let mut slsa_detail = serde_json::json!({"skipped": no_external});

    if !no_external {
        match slsa_mode {
            SlsaMode::Full => {
                for a in &artifacts {
                    let ap = if a.is_absolute() {
                        a.clone()
                    } else {
                        bundle_dir.join(a)
                    };
                    let mut cmd = Command::new("slsa-verifier");
                    cmd.arg("verify-artifact")
                        .arg(&ap)
                        .arg("--provenance-path")
                        .arg(&prov_path);
                    if let Some(uri) = &source_uri {
                        cmd.arg("--source-uri").arg(uri);
                    }
                    let out = cmd.output().context("running slsa-verifier")?;
                    if !out.status.success() {
                        slsa_ok = false;
                        slsa_detail = serde_json::json!({
                            "error": sanitize_tool_stderr(&out.stderr)
                        });
                        break;
                    }
                }
            }
            SlsaMode::SchemaOnly => {
                let _v: Value =
                    serde_json::from_slice(&fs_guard::read_validated(&prov_path, MAX_JSON_BYTES)?)?;
                slsa_detail = serde_json::json!({
                    "mode": "schema-only",
                    "note": "Only JSON parse performed (no artifact verification)"
                });
            }
        }
    }

    // --- in-toto verification
    let mut intoto_ok = true;
    let intoto_detail;

    // Helper: gather key files from a path (file or directory)
    fn collect_key_paths(p: &Path) -> Result<Vec<PathBuf>> {
        // Canonicalize the root first (resolves symlinks, "..", etc.).
        let base = p
            .canonicalize()
            .with_context(|| format!("Failed to resolve key path: {}", p.display()))?;

        let mut out = Vec::new();
        if base.is_dir() {
            for ent in fs::read_dir(&base)
                .with_context(|| format!("reading key dir {}", base.display()))?
            {
                let ent = ent?;
                let path = ent.path();

                // Skip broken symlinks / unreadable entries.
                let Ok(md) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if md.file_type().is_symlink() {
                    // Never follow links from an untrusted bundle.
                    continue;
                }
                if !md.is_file() {
                    continue;
                }

                let canonical = path
                    .canonicalize()
                    .with_context(|| format!("resolve {}", path.display()))?;
                if !canonical.starts_with(&base) {
                    return Err(anyhow!(
                        "Security: Path traversal attempt detected. {} escapes {}",
                        path.display(),
                        base.display()
                    ));
                }
                out.push(canonical);
            }

            out.sort();
            if out.len() > 256 {
                return Err(anyhow!(
                    "Too many key files in directory ({} > 256)",
                    out.len()
                ));
            }
            Ok(out)
        } else if base.is_file() {
            // canonicalize() already resolved symlinks; no further check needed.
            Ok(vec![base])
        } else {
            Err(anyhow!(
                "Key path is not a file or directory: {}",
                base.display()
            ))
        }
    }

    let crypto_intoto = !no_external && intoto_layout_keys.is_some();

    if crypto_intoto {
        let keys_path = intoto_layout_keys.as_ref().unwrap();
        let key_paths = collect_key_paths(keys_path)?;
        if key_paths.is_empty() {
            intoto_ok = false;
            intoto_detail = serde_json::json!({
                "mode": "cryptographic",
                "error": format!("No key files found at {}", keys_path.display())
            });
        } else {
            let mut cmd = Command::new("in-toto-verify");
            cmd.arg("--layout")
                .arg(&layout_path)
                .arg("--link-dir")
                .arg(&links)
                .arg("--verification-keys");
            for kp in &key_paths {
                cmd.arg(kp);
            }
            let out = cmd
                .current_dir(bundle_dir)
                .output()
                .context("running in-toto-verify")?;
            if !out.status.success() {
                intoto_ok = false;
                intoto_detail = serde_json::json!({
                    "mode": "cryptographic",
                    "error": sanitize_tool_stderr(&out.stderr)
                });
            } else {
                intoto_detail = serde_json::json!({
                    "mode": "cryptographic",
                    "keys": key_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>()
                });
            }
        }
    } else if !links.exists() {
        // Structural-only: links dir missing is a blocking failure.
        intoto_ok = false;
        intoto_detail = if no_external {
            serde_json::json!({"mode": "structural-only", "error": "links/ missing"})
        } else {
            serde_json::json!({"mode": "structural-only", "error": "links/ missing",
                "warning": "No in-toto layout keys provided; signatures not verified"})
        };
    } else {
        // Structural-only: ensure layout JSON parses.
        let _v: Value =
            serde_json::from_slice(&fs_guard::read_validated(&layout_path, MAX_JSON_BYTES)?)?;
        intoto_detail = if no_external {
            serde_json::json!({"mode": "structural-only", "skipped": true})
        } else {
            serde_json::json!({"mode": "structural-only",
                "warning": "No in-toto layout keys provided; signatures not verified"})
        };
    }

    // --- VBW independence checks
    let prov_json: Value =
        serde_json::from_slice(&fs_guard::read_validated(&prov_path, MAX_JSON_BYTES)?)?;
    let indep = independence::check_independence(&prov_json, &policy)?;

    // --- Bundle hash
    let (bundle_sha256, evidence) = bundlehash::hash_bundle(bundle_dir)?;
    let vbw_out_dir = bundle_dir.join("vbw");
    fs::create_dir_all(&vbw_out_dir)?;

    let att_path = vbw_out_dir.join("vbw-attestation.json");
    let report_path = vbw_out_dir.join("report.json");

    // --- Generate report
    let now = time::OffsetDateTime::now_utc().format(&Rfc3339)?;
    let overall_pass = slsa_ok && intoto_ok && indep["overall"] == "pass";
    let result = if overall_pass { "PASS" } else { "FAIL" };

    let failures: Vec<String> = indep["blocking_failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect();

    let warnings: Vec<String> = indep["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect();

    let report = serde_json::json!({
        "report_schema": "https://scqcs.dev/vbw/report/v1",
        "vbw_version": env!("CARGO_PKG_VERSION"),
        "bundle_dir": bundle_dir.display().to_string(),
        "bundle_sha256": bundle_sha256,
        "verification_timestamp": now,
        "result": result,
        "failures": failures,
        "warnings": warnings,
        "slsa": { "ok": slsa_ok, "detail": slsa_detail },
        "intoto": { "ok": intoto_ok, "detail": intoto_detail },
        "independence": indep,
        "vbw_attestation_path": if dry_run { Value::Null } else { Value::String(att_path.display().to_string()) }
    });

    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    // --- Dry run exit
    if dry_run {
        println!(
            "(dry-run) Verification complete. See: {}",
            report_path.display()
        );
        if !overall_pass {
            return Err(anyhow!("Verification failed (dry-run)"));
        }
        return Ok(());
    }

    // --- Generate attestation
    let att = attest::make_vbw_statement(&bundle_sha256, &evidence, slsa_ok, intoto_ok, &indep)?;
    fs::write(&att_path, serde_json::to_vec_pretty(&att)?)?;

    // --- Sign with Sigstore
    let bundle_path = vbw_out_dir.join("vbw-attestation.sigstore.bundle");
    if !no_external {
        run_checked(
            Command::new("cosign")
                .args(["sign-blob", "--yes", "--bundle"])
                .arg(&bundle_path)
                .arg(&att_path),
            "cosign sign-blob",
        )?;
        run_checked(
            Command::new("cosign")
                .args(["verify-blob", "--bundle"])
                .arg(&bundle_path)
                .arg(&att_path),
            "cosign verify-blob",
        )?;
    }

    // --- Summary output
    if !slsa_ok {
        eprintln!("✗ SLSA check failed");
    } else {
        println!("✓ SLSA ok");
    }

    if !intoto_ok {
        eprintln!("✗ in-toto failed");
    } else {
        println!("✓ in-toto ok");
    }

    if !warnings.is_empty() {
        eprintln!("⚠ Warnings: {}", warnings.join(", "));
    }

    if !overall_pass {
        eprintln!("✗ Independence checks failed");
        return Err(anyhow!(
            "Verification failed. See: {}",
            report_path.display()
        ));
    }

    println!("✓ Independence policy: pass");
    println!("→ VBW attestation: {}", att_path.display());
    if !no_external {
        println!("→ Sigstore bundle: {}", bundle_path.display());
    }
    println!("→ Report: {}", report_path.display());

    Ok(())
}

fn show_attestation(attestation: &Path, sigstore_bundle: &Path) -> Result<()> {
    let att: Value =
        serde_json::from_slice(&fs_guard::read_validated(attestation, MAX_JSON_BYTES)?)?;

    let outv = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(sigstore_bundle)
        .arg(attestation)
        .output()
        .context("running cosign verify-blob")?;

    let sig_ok = outv.status.success();

    let bundle_digest = att
        .pointer("/subject/0/digest/sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let verified_at = att
        .pointer("/predicate/verifiedAt")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let slsa_ok = att
        .pointer("/predicate/results/slsa/ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let intoto_ok = att
        .pointer("/predicate/results/intoto/ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let indep = att
        .pointer("/predicate/results/independence/overall")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    println!("VBW Attestation v{}", env!("CARGO_PKG_VERSION"));
    println!("Bundle: sha256:{}", bundle_digest);
    println!("Verified: {}", verified_at);
    println!("SLSA: {}", if slsa_ok { "✓ pass" } else { "✗ fail" });
    println!("in-toto: {}", if intoto_ok { "✓ pass" } else { "✗ fail" });
    println!(
        "Independence: {}",
        if indep == "pass" {
            "✓ pass"
        } else {
            "✗ fail"
        }
    );
    println!(
        "Sigstore: {}",
        if sig_ok {
            "✓ verified"
        } else {
            "✗ NOT verified"
        }
    );

    if !sig_ok {
        eprintln!("\n{}", sanitize_tool_stderr(&outv.stderr));
        return Err(anyhow!("Sigstore verification failed"));
    }

    Ok(())
}
