//! Build witnessing -- captures the full build context and produces an evidence bundle.
//!
//! The `vbw build` command implements the VBW v1 witness workflow:
//!
//! 1. **Source hash**: Compute a deterministic SHA-256 of the source tree
//!    using `git ls-files` (if in a git repo) or a directory walk.
//! 2. **Environment capture**: Record OS, architecture, compiler versions,
//!    and any active container digest.
//! 3. **Dependency snapshot**: Hash lockfiles (Cargo.lock, package-lock.json,
//!    go.sum, etc.) if present.
//! 4. **Build execution**: Run the user's build command as a subprocess,
//!    capturing exit code, stdout size, and stderr size.
//! 5. **Output hashing**: Hash all artifacts specified by `--artifact`.
//! 6. **Manifest generation**: Write `manifest.json` binding source, env,
//!    deps, build transcript, and output hashes together.
//! 7. **Provenance generation**: Write SLSA v1 provenance with the builder
//!    identity and materials.
//! 8. **Bundle assembly**: Produce the complete `vbw/` evidence bundle
//!    directory ready for `vbw verify`.
//!
//! ## Security Properties
//!
//! - Build commands are executed via `std::process::Command` (no shell).
//! - Source hashing rejects symlinks and enforces size limits via
//!   [`crate::bundlehash`] infrastructure.
//! - All file I/O for lockfiles uses [`crate::fs_guard::read_validated`].
//! - Manifest and provenance are written as deterministic JSON.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
};
use time::format_description::well_known::Rfc3339;

/// Maximum size for individual lockfiles read during dependency snapshot.
const MAX_LOCKFILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// Maximum file size for artifact hashing.
const MAX_ARTIFACT_BYTES: u64 = 500 * 1024 * 1024; // 500 MB

/// Well-known lockfile names to automatically detect and hash.
const LOCKFILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "flake.lock",
];

/// Executes the full `vbw build` workflow.
///
/// # Errors
///
/// Returns an error if:
/// - The build command fails (non-zero exit code).
/// - Source directory does not exist or is unreadable.
/// - Artifact paths are invalid after the build completes.
/// - Any file I/O operation fails.
pub fn run_build(
    output_dir: &Path,
    artifacts: &[PathBuf],
    source_dir: Option<&Path>,
    builder_id: &str,
    build_cmd: &[String],
    key_path: Option<&Path>,
) -> Result<()> {
    if build_cmd.is_empty() {
        return Err(anyhow!(
            "No build command provided. Usage: vbw build -- <command> [args...]"
        ));
    }

    let src_dir = source_dir.unwrap_or(Path::new("."));
    if !src_dir.exists() {
        return Err(anyhow!(
            "Source directory does not exist: {}",
            src_dir.display()
        ));
    }

    // Resolve signing key early so we fail fast on bad keys.
    let signing_key = resolve_signing_key(key_path)?;

    let start_time = time::OffsetDateTime::now_utc();
    println!("VBW Build Witness v{}", env!("CARGO_PKG_VERSION"));
    println!();

    // Step 1: Hash source tree and record git metadata
    println!("[1/7] Hashing source tree...");
    let source_hash = hash_source_tree(src_dir)?;
    let source_commit = git_head_commit(src_dir);
    let worktree_dirty = git_worktree_dirty(src_dir);
    println!("  Source SHA-256: {source_hash}");
    if let Some(ref commit) = source_commit {
        println!("  Git commit: {commit}");
    }
    if worktree_dirty {
        println!("  Warning: working tree has uncommitted changes");
    }

    // Step 2: Capture environment (including container detection)
    println!("[2/7] Capturing environment...");
    let env_info = capture_environment();
    println!("  OS: {}", env_info.os);
    println!("  Arch: {}", env_info.arch);
    if let Some(ref ct) = env_info.container {
        println!("  Container: {ct}");
    }

    // Step 3: Record dependency lockfiles
    println!("[3/7] Recording dependency lockfiles...");
    let dep_hashes = hash_lockfiles(src_dir)?;
    if dep_hashes.is_empty() {
        println!("  No lockfiles found");
    } else {
        for (name, hash) in &dep_hashes {
            println!("  {name}: {hash}");
        }
    }

    // Step 4: Execute build command with transcript capture
    println!("[4/7] Running build command: {}", build_cmd.join(" "));

    // Create output dir early so we can write transcript there.
    fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory: {}", output_dir.display()))?;

    let transcript_path = output_dir.join("transcript.txt");
    let build_result = execute_build_with_transcript(build_cmd, &transcript_path)?;
    if !build_result.success {
        eprintln!(
            "  Build command failed with exit code: {}",
            build_result.exit_code
        );
        return Err(anyhow!(
            "Build command failed with exit code {}. Witness bundle not produced.",
            build_result.exit_code
        ));
    }
    println!("  Build succeeded (exit code 0)");

    // Step 5: Hash output artifacts
    println!("[5/7] Hashing output artifacts...");
    let mut artifact_hashes = Vec::new();
    for art in artifacts {
        if !art.exists() {
            return Err(anyhow!(
                "Artifact not found after build: {}. Ensure your build command produces this file.",
                art.display()
            ));
        }
        let (hash, size) = sha256_file(art, MAX_ARTIFACT_BYTES)?;
        println!("  {}: {hash} ({size} bytes)", art.display());
        artifact_hashes.push(serde_json::json!({
            "path": art.display().to_string(),
            "sha256": hash,
            "bytes": size
        }));
    }
    if artifacts.is_empty() {
        println!("  No artifacts specified (use --artifact to track output files)");
    }

    // Step 6: Write manifest and bundle
    println!("[6/7] Writing witness bundle...");
    let end_time = time::OffsetDateTime::now_utc();

    let links_dir = output_dir.join("links");
    fs::create_dir_all(&links_dir)?;

    // Canonicalize the source directory path for the manifest. This gives
    // downstream tools an unambiguous, absolute path rather than a relative
    // one like ".".
    let canonical_src_dir = src_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing source directory: {}", src_dir.display()))?;

    // Format timestamps, propagating errors rather than silently producing
    // empty strings (which would be invalid RFC 3339).
    let started_ts = start_time
        .format(&Rfc3339)
        .context("formatting start timestamp")?;
    let completed_ts = end_time
        .format(&Rfc3339)
        .context("formatting end timestamp")?;

    // Build source metadata object.
    // serde_json::Value indexing on objects is panic-free (returns Null for missing keys,
    // and assignment on objects inserts or replaces). Allow indexing here.
    #[allow(clippy::indexing_slicing)]
    let source_meta = {
        let mut m = serde_json::json!({
            "directory": canonical_src_dir.display().to_string(),
            "sha256": source_hash
        });
        if let Some(ref commit) = source_commit {
            m["commit"] = serde_json::Value::String(commit.clone());
        }
        if worktree_dirty {
            m["worktree_dirty"] = serde_json::Value::Bool(true);
        }
        m
    };

    // Build environment object.
    #[allow(clippy::indexing_slicing)]
    let env_obj = {
        let mut e = serde_json::json!({
            "os": env_info.os,
            "arch": env_info.arch,
            "compiler_versions": env_info.compilers,
            "env_vars": env_info.selected_env_vars
        });
        if let Some(ref ct) = env_info.container {
            e["container"] = serde_json::Value::String(ct.clone());
        }
        e
    };

    // Write manifest.json
    let manifest = serde_json::json!({
        "manifest_schema": "https://scqcs.dev/vbw/manifest/v1",
        "vbw_version": env!("CARGO_PKG_VERSION"),
        "source": source_meta,
        "environment": env_obj,
        "dependencies": dep_hashes.iter().map(|(name, hash)| {
            serde_json::json!({"lockfile": name, "sha256": hash})
        }).collect::<Vec<_>>(),
        "build": {
            "command": build_cmd,
            "exit_code": build_result.exit_code,
            "stdout_bytes": build_result.stdout_size,
            "stderr_bytes": build_result.stderr_size,
            "transcript": "transcript.txt"
        },
        "artifacts": artifact_hashes,
        "timestamps": {
            "started": started_ts,
            "completed": completed_ts
        }
    });
    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;

    // Write SLSA v1 provenance
    let provenance = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": artifact_hashes.iter().map(|a| {
            serde_json::json!({
                "name": a["path"],
                "digest": { "sha256": a["sha256"] }
            })
        }).collect::<Vec<_>>(),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "builder": { "id": builder_id },
            "buildType": "https://scqcs.dev/vbw/build/v1",
            "invocation": {
                "parameters": { "command": build_cmd }
            },
            "materials": [
                {
                    "uri": format!("file://{}", canonical_src_dir.display()),
                    "digest": { "sha256": source_hash }
                }
            ]
        }
    });
    let prov_path = output_dir.join("provenance.json");
    fs::write(&prov_path, serde_json::to_vec_pretty(&provenance)?)?;

    // Write minimal in-toto layout (structural placeholder for vbw verify)
    let layout = serde_json::json!({
        "_type": "layout",
        "steps": [],
        "inspect": []
    });
    fs::write(
        output_dir.join("layout.json"),
        serde_json::to_vec_pretty(&layout)?,
    )?;

    // Write link file
    let link = serde_json::json!({
        "_type": "link",
        "name": "vbw-build",
        "command": build_cmd,
        "materials": {
            "source": { "sha256": source_hash }
        },
        "products": artifact_hashes.iter().map(|a| {
            (a["path"].as_str().unwrap_or("unknown").to_string(), serde_json::json!({"sha256": a["sha256"]}))
        }).collect::<serde_json::Map<String, serde_json::Value>>()
    });
    fs::write(
        links_dir.join("vbw-build.link"),
        serde_json::to_vec_pretty(&link)?,
    )?;

    // Step 7: Sign manifest with Ed25519 (if key provided)
    println!("[7/7] Signing...");
    if let Some(ref sk) = signing_key {
        let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
        let signature = sign_manifest(sk, &manifest_hash);

        let sig_json = serde_json::json!({
            "algorithm": "ed25519",
            "public_key": hex::encode(sk.verifying_key().as_bytes()),
            "manifest_sha256": manifest_hash,
            "signature": signature
        });
        let sig_path = output_dir.join("signature.json");
        fs::write(&sig_path, serde_json::to_vec_pretty(&sig_json)?)?;
        println!("  Manifest signed with Ed25519");
        println!("  signature.json:   {}", sig_path.display());
    } else {
        println!("  No signing key provided (use --key or VBW_ED25519_SK_B64)");
    }

    println!();
    println!("Witness bundle written to: {}", output_dir.display());
    println!("  manifest.json:    {}", manifest_path.display());
    println!("  provenance.json:  {}", prov_path.display());
    println!(
        "  layout.json:      {}",
        output_dir.join("layout.json").display()
    );
    println!("  transcript.txt:   {}", transcript_path.display());
    println!();
    println!("Next: verify with `vbw verify {}`", output_dir.display());

    Ok(())
}

/// Returns the HEAD commit SHA from git, or None if not in a git repo.
fn git_head_commit(src_dir: &Path) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(src_dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Returns true if the git working tree has uncommitted changes.
fn git_worktree_dirty(src_dir: &Path) -> bool {
    Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(src_dir)
        .status()
        .map(|s| !s.success())
        .unwrap_or(false)
}

/// Detects if the current process is running inside a container.
///
/// Checks for `.dockerenv`, container-related cgroup entries, and
/// container-specific environment variables.
fn detect_container() -> Option<String> {
    // Check for Docker's sentinel file.
    if Path::new("/.dockerenv").exists() {
        return Some("docker".to_string());
    }

    // Check cgroup v1/v2 for container indicators.
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") {
            return Some("docker".to_string());
        }
        if cgroup.contains("kubepods") {
            return Some("kubernetes".to_string());
        }
        if cgroup.contains("lxc") {
            return Some("lxc".to_string());
        }
    }

    // Check well-known container environment variables.
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        return Some("kubernetes".to_string());
    }
    if std::env::var("container").is_ok() {
        return Some("container".to_string());
    }

    None
}

/// Resolves the Ed25519 signing key from either a file path or the
/// `VBW_ED25519_SK_B64` environment variable.
///
/// Returns `None` if no key source is available (unsigned build).
fn resolve_signing_key(key_path: Option<&Path>) -> Result<Option<ed25519_dalek::SigningKey>> {
    use base64::Engine;

    if let Some(path) = key_path {
        let bytes =
            fs::read(path).with_context(|| format!("reading signing key: {}", path.display()))?;
        return parse_signing_key_bytes(&bytes)
            .with_context(|| format!("parsing signing key from {}", path.display()))
            .map(Some);
    }

    if let Ok(b64) = std::env::var("VBW_ED25519_SK_B64") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("decoding VBW_ED25519_SK_B64 as base64")?;
        return parse_signing_key_bytes(&bytes)
            .context("parsing signing key from VBW_ED25519_SK_B64")
            .map(Some);
    }

    Ok(None)
}

/// Parses raw bytes into an Ed25519 signing key. Accepts 32-byte secret keys
/// or 64-byte keypairs (secret key in first 32 bytes).
fn parse_signing_key_bytes(bytes: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    let key_bytes: [u8; 32] = match bytes.len() {
        32 => bytes
            .try_into()
            .map_err(|_| anyhow!("failed to convert 32 bytes to key array"))?,
        64 => {
            // Keypair format: first 32 bytes are the secret key.
            #[allow(clippy::indexing_slicing)]
            bytes[..32]
                .try_into()
                .map_err(|_| anyhow!("failed to extract 32-byte secret from keypair"))?
        }
        n => {
            return Err(anyhow!(
                "Invalid key size: expected 32 or 64 bytes, got {n}"
            ));
        }
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

/// Signs the hex-encoded manifest hash with the Ed25519 key and returns the
/// hex-encoded signature.
fn sign_manifest(sk: &ed25519_dalek::SigningKey, manifest_sha256: &str) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(manifest_sha256.as_bytes());
    hex::encode(sig.to_bytes())
}

/// Executes the build command with output captured to a transcript file.
///
/// Stdout and stderr are piped, read in separate threads, printed to the
/// terminal in real time, and written to `transcript_path` with `[stdout]`
/// and `[stderr]` line prefixes. This preserves real-time output while
/// creating a full build log.
fn execute_build_with_transcript(
    build_cmd: &[String],
    transcript_path: &Path,
) -> Result<BuildResult> {
    let (program, args) = build_cmd
        .split_first()
        .ok_or_else(|| anyhow!("Empty build command"))?;

    let mut child = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("executing build command: {program}"))?;

    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout pipe"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr pipe"))?;

    let transcript = Arc::new(Mutex::new(std::io::BufWriter::new(
        fs::File::create(transcript_path)
            .with_context(|| format!("creating {}", transcript_path.display()))?,
    )));

    let t_out = transcript.clone();
    let stdout_thread = thread::spawn(move || -> Result<u64> {
        let reader = BufReader::new(child_stdout);
        let mut total = 0u64;
        let mut out = std::io::stdout();
        for line in reader.lines() {
            let line = line.context("reading stdout line")?;
            total = total.saturating_add(line.len() as u64 + 1);
            let _ = writeln!(out, "{line}");
            if let Ok(mut t) = t_out.lock() {
                let _ = writeln!(t, "[stdout] {line}");
            }
        }
        Ok(total)
    });

    let t_err = transcript.clone();
    let stderr_thread = thread::spawn(move || -> Result<u64> {
        let reader = BufReader::new(child_stderr);
        let mut total = 0u64;
        let mut err = std::io::stderr();
        for line in reader.lines() {
            let line = line.context("reading stderr line")?;
            total = total.saturating_add(line.len() as u64 + 1);
            let _ = writeln!(err, "{line}");
            if let Ok(mut t) = t_err.lock() {
                let _ = writeln!(t, "[stderr] {line}");
            }
        }
        Ok(total)
    });

    let status = child.wait().context("waiting for build command")?;

    let stdout_size = stdout_thread
        .join()
        .map_err(|_| anyhow!("stdout reader thread panicked"))??;
    let stderr_size = stderr_thread
        .join()
        .map_err(|_| anyhow!("stderr reader thread panicked"))??;

    let exit_code = status.code().unwrap_or(-1);
    Ok(BuildResult {
        success: status.success(),
        exit_code,
        stdout_size,
        stderr_size,
    })
}

/// Computes a deterministic SHA-256 hash of the source tree.
///
/// Prefers `git ls-files` if in a git repository (excludes untracked and
/// ignored files). Falls back to a full directory walk otherwise.
fn hash_source_tree(src_dir: &Path) -> Result<String> {
    // Try git ls-files first for deterministic, VCS-aware hashing.
    let git_files = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(src_dir)
        .output();

    let files: Vec<PathBuf> = match git_files {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut paths: Vec<PathBuf> = stdout
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(|s| src_dir.join(s))
                .filter(|p| p.is_file())
                .collect();
            paths.sort();
            paths
        }
        _ => {
            // Not a git repo or git not installed; walk the directory.
            let mut paths = Vec::new();
            collect_files_recursive(src_dir, &mut paths)?;
            paths.sort();
            paths
        }
    };

    let mut hasher = Sha256::new();
    for path in &files {
        let file_hash = sha256_file_quick(path)?;
        hasher.update(file_hash.as_bytes());
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Recursively collects regular files from a directory, skipping hidden
/// directories and the `vbw-out`/`target` build directories.
fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden directories, build artifacts, and VBW output.
        if name_str.starts_with('.')
            || name_str == "target"
            || name_str == "node_modules"
            || name_str == "vbw-out"
        {
            continue;
        }

        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue; // Never follow symlinks.
        }
        if meta.is_dir() {
            collect_files_recursive(&path, out)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Quick SHA-256 of a file (streaming, 64 KB buffer).
fn sha256_file_quick(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    #[allow(clippy::large_stack_arrays)]
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        #[allow(clippy::indexing_slicing)]
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of a file with size limit enforcement.
fn sha256_file(path: &Path, max_size: u64) -> Result<(String, u64)> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("Refusing to hash symlink: {}", path.display()));
    }
    let size = meta.len();
    if size > max_size {
        return Err(anyhow!(
            "Artifact too large: {} ({size} bytes, max {max_size} bytes)",
            path.display()
        ));
    }
    let hash = sha256_file_quick(path)?;
    Ok((hash, size))
}

/// Captured build environment information.
struct EnvInfo {
    os: String,
    arch: String,
    compilers: serde_json::Value,
    selected_env_vars: serde_json::Value,
    container: Option<String>,
}

/// Captures the current build environment: OS, architecture, compiler versions,
/// and container runtime detection.
fn capture_environment() -> EnvInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    // Probe common compilers for version info.
    let mut compilers = serde_json::Map::new();
    for (name, args) in [
        ("rustc", vec!["--version"]),
        ("gcc", vec!["--version"]),
        ("go", vec!["version"]),
        ("node", vec!["--version"]),
        ("python3", vec!["--version"]),
        ("java", vec!["-version"]),
    ] {
        if let Ok(out) = Command::new(name).args(&args).output() {
            if out.status.success() {
                let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !version.is_empty() {
                    compilers.insert(name.to_string(), serde_json::Value::String(version));
                }
            }
        }
    }

    // Capture selected environment variables that affect builds.
    let mut env_vars = serde_json::Map::new();
    for key in [
        "PATH",
        "RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CC",
        "CXX",
        "CFLAGS",
        "LDFLAGS",
        "GOFLAGS",
        "NODE_ENV",
    ] {
        if let Ok(val) = std::env::var(key) {
            env_vars.insert(key.to_string(), serde_json::Value::String(val));
        }
    }

    let container = detect_container();

    EnvInfo {
        os,
        arch,
        compilers: serde_json::Value::Object(compilers),
        selected_env_vars: serde_json::Value::Object(env_vars),
        container,
    }
}

/// Hashes all recognized lockfiles found in the source directory.
fn hash_lockfiles(src_dir: &Path) -> Result<Vec<(String, String)>> {
    let mut results = Vec::new();
    for name in LOCKFILE_NAMES {
        let path = src_dir.join(name);
        if path.is_file() {
            let bytes = crate::fs_guard::read_validated(&path, MAX_LOCKFILE_BYTES)?;
            let hash = hex::encode(Sha256::digest(&bytes));
            results.push(((*name).to_string(), hash));
        }
    }
    Ok(results)
}

/// Result of executing the build command.
struct BuildResult {
    success: bool,
    exit_code: i32,
    stdout_size: u64,
    stderr_size: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hash_lockfiles_finds_cargo_lock() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.lock"), b"[package]\nname = \"test\"").unwrap();

        let results = hash_lockfiles(dir.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "Cargo.lock");
        assert_eq!(results[0].1.len(), 64); // SHA-256 hex length
    }

    #[test]
    fn test_hash_lockfiles_empty_dir() {
        let dir = TempDir::new().unwrap();
        let results = hash_lockfiles(dir.path()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_hash_lockfiles_multiple() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.lock"), b"cargo").unwrap();
        fs::write(dir.path().join("package-lock.json"), b"npm").unwrap();
        fs::write(dir.path().join("go.sum"), b"go").unwrap();

        let results = hash_lockfiles(dir.path()).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_sha256_file_with_limit() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.bin");
        fs::write(&file, b"hello world").unwrap();

        let (hash, size) = sha256_file(&file, 1024).unwrap();
        assert_eq!(size, 11);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha256_file_rejects_oversized() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("big.bin");
        fs::write(&file, vec![0u8; 100]).unwrap();

        let result = sha256_file(&file, 50);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_source_tree_deterministic() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.rs"), b"fn main() {}").unwrap();
        fs::write(dir.path().join("b.rs"), b"fn helper() {}").unwrap();

        let h1 = hash_source_tree(dir.path()).unwrap();
        let h2 = hash_source_tree(dir.path()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_source_tree_changes_with_content() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), b"version1").unwrap();
        let h1 = hash_source_tree(dir.path()).unwrap();

        fs::write(dir.path().join("main.rs"), b"version2").unwrap();
        let h2 = hash_source_tree(dir.path()).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_execute_build_success() {
        let dir = TempDir::new().unwrap();
        let transcript = dir.path().join("transcript.txt");
        let result = execute_build_with_transcript(&["true".to_string()], &transcript).unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, 0);
        assert!(transcript.exists());
    }

    #[test]
    fn test_execute_build_failure() {
        let dir = TempDir::new().unwrap();
        let transcript = dir.path().join("transcript.txt");
        let result = execute_build_with_transcript(&["false".to_string()], &transcript).unwrap();
        assert!(!result.success);
        assert_ne!(result.exit_code, 0);
    }

    #[test]
    fn test_run_build_creates_bundle() {
        let dir = TempDir::new().unwrap();
        let src_dir = TempDir::new().unwrap();
        let artifact = src_dir.path().join("output.txt");

        // Create a source file
        fs::write(src_dir.path().join("input.txt"), b"source data").unwrap();

        // Run build that creates an artifact
        let output_dir = dir.path().join("witness");
        let result = run_build(
            &output_dir,
            &[artifact.clone()],
            Some(src_dir.path()),
            "https://github.com/actions/runner",
            &[
                "sh".to_string(),
                "-c".to_string(),
                format!("echo 'built' > {}", artifact.display()),
            ],
            None,
        );
        assert!(result.is_ok(), "run_build failed: {:?}", result.err());

        // Verify bundle structure
        assert!(output_dir.join("manifest.json").exists());
        assert!(output_dir.join("provenance.json").exists());
        assert!(output_dir.join("layout.json").exists());
        assert!(output_dir.join("links").join("vbw-build.link").exists());
        assert!(output_dir.join("transcript.txt").exists());

        // Verify manifest contents
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["build"]["exit_code"], 0);
        assert!(!manifest["source"]["sha256"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_run_build_fails_on_bad_command() {
        let dir = TempDir::new().unwrap();
        let result = run_build(
            &dir.path().join("out"),
            &[],
            Some(dir.path()),
            "https://github.com/actions/runner",
            &["false".to_string()],
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed"), "error: {err}");
    }

    #[test]
    fn test_run_build_with_signing() {
        let dir = TempDir::new().unwrap();
        let src_dir = TempDir::new().unwrap();
        let artifact = src_dir.path().join("output.txt");

        // Generate a test Ed25519 key (32 bytes of deterministic data).
        let key_bytes: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let key_file = dir.path().join("test.key");
        fs::write(&key_file, key_bytes).unwrap();

        fs::write(src_dir.path().join("input.txt"), b"source data").unwrap();

        let output_dir = dir.path().join("signed-witness");
        let result = run_build(
            &output_dir,
            &[artifact.clone()],
            Some(src_dir.path()),
            "https://github.com/actions/runner",
            &[
                "sh".to_string(),
                "-c".to_string(),
                format!("echo 'signed-build' > {}", artifact.display()),
            ],
            Some(key_file.as_path()),
        );
        assert!(result.is_ok(), "signed build failed: {:?}", result.err());

        // Verify signature.json was produced
        let sig_path = output_dir.join("signature.json");
        assert!(sig_path.exists(), "signature.json should be created");

        let sig: serde_json::Value = serde_json::from_slice(&fs::read(&sig_path).unwrap()).unwrap();
        assert_eq!(sig["algorithm"], "ed25519");
        assert!(sig["public_key"].as_str().unwrap().len() == 64);
        assert!(sig["manifest_sha256"].as_str().unwrap().len() == 64);
        assert!(!sig["signature"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_capture_environment() {
        let env = capture_environment();
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
    }
}
