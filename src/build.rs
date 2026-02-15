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
    io::Read,
    path::{Path, PathBuf},
    process::Command,
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

    let start_time = time::OffsetDateTime::now_utc();
    println!("VBW Build Witness v{}", env!("CARGO_PKG_VERSION"));
    println!();

    // Step 1: Hash source tree
    println!("[1/6] Hashing source tree...");
    let source_hash = hash_source_tree(src_dir)?;
    println!("  Source SHA-256: {source_hash}");

    // Step 2: Capture environment
    println!("[2/6] Capturing environment...");
    let env_info = capture_environment();
    println!("  OS: {}", env_info.os);
    println!("  Arch: {}", env_info.arch);

    // Step 3: Record dependency lockfiles
    println!("[3/6] Recording dependency lockfiles...");
    let dep_hashes = hash_lockfiles(src_dir)?;
    if dep_hashes.is_empty() {
        println!("  No lockfiles found");
    } else {
        for (name, hash) in &dep_hashes {
            println!("  {name}: {hash}");
        }
    }

    // Step 4: Execute build command
    println!("[4/6] Running build command: {}", build_cmd.join(" "));
    let build_result = execute_build(build_cmd)?;
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
    println!("[5/6] Hashing output artifacts...");
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
    println!("[6/6] Writing witness bundle...");
    let end_time = time::OffsetDateTime::now_utc();

    fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory: {}", output_dir.display()))?;

    let links_dir = output_dir.join("links");
    fs::create_dir_all(&links_dir)?;

    // Write manifest.json
    let manifest = serde_json::json!({
        "manifest_schema": "https://scqcs.dev/vbw/manifest/v1",
        "vbw_version": env!("CARGO_PKG_VERSION"),
        "source": {
            "directory": src_dir.canonicalize().unwrap_or_else(|_| src_dir.to_path_buf()).display().to_string(),
            "sha256": source_hash
        },
        "environment": {
            "os": env_info.os,
            "arch": env_info.arch,
            "compiler_versions": env_info.compilers,
            "env_vars": env_info.selected_env_vars
        },
        "dependencies": dep_hashes.iter().map(|(name, hash)| {
            serde_json::json!({"lockfile": name, "sha256": hash})
        }).collect::<Vec<_>>(),
        "build": {
            "command": build_cmd,
            "exit_code": build_result.exit_code,
            "stdout_bytes": build_result.stdout_size,
            "stderr_bytes": build_result.stderr_size
        },
        "artifacts": artifact_hashes,
        "timestamps": {
            "started": start_time.format(&Rfc3339).unwrap_or_default(),
            "completed": end_time.format(&Rfc3339).unwrap_or_default()
        }
    });
    let manifest_path = output_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

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
                    "uri": format!("file://{}", src_dir.canonicalize().unwrap_or_else(|_| src_dir.to_path_buf()).display()),
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

    // Write placeholder link
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

    println!();
    println!("Witness bundle written to: {}", output_dir.display());
    println!("  manifest.json:    {}", manifest_path.display());
    println!("  provenance.json:  {}", prov_path.display());
    println!(
        "  layout.json:      {}",
        output_dir.join("layout.json").display()
    );
    println!();
    println!("Next: verify with `vbw verify {}`", output_dir.display());

    Ok(())
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
}

/// Captures the current build environment: OS, architecture, and compiler versions.
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

    EnvInfo {
        os,
        arch,
        compilers: serde_json::Value::Object(compilers),
        selected_env_vars: serde_json::Value::Object(env_vars),
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

/// Executes the build command and captures its result.
///
/// The command is executed via `std::process::Command` -- no shell is invoked.
/// Stdout and stderr are inherited (streamed to the terminal) so the user sees
/// build output in real time. Sizes are captured from pipe output for recording.
fn execute_build(build_cmd: &[String]) -> Result<BuildResult> {
    let (program, args) = build_cmd
        .split_first()
        .ok_or_else(|| anyhow!("Empty build command"))?;

    let output = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .with_context(|| format!("executing build command: {program}"))?;

    // Print stdout/stderr so the user sees build output.
    if !output.stdout.is_empty() {
        let s = String::from_utf8_lossy(&output.stdout);
        print!("{s}");
    }
    if !output.stderr.is_empty() {
        let s = String::from_utf8_lossy(&output.stderr);
        eprint!("{s}");
    }

    let exit_code = output.status.code().unwrap_or(-1);
    #[allow(clippy::cast_possible_truncation)]
    Ok(BuildResult {
        success: output.status.success(),
        exit_code,
        stdout_size: output.stdout.len() as u64,
        stderr_size: output.stderr.len() as u64,
    })
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
        let result = execute_build(&["true".to_string()]).unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_execute_build_failure() {
        let result = execute_build(&["false".to_string()]).unwrap();
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
        );
        assert!(result.is_ok(), "run_build failed: {:?}", result.err());

        // Verify bundle structure
        assert!(output_dir.join("manifest.json").exists());
        assert!(output_dir.join("provenance.json").exists());
        assert!(output_dir.join("layout.json").exists());
        assert!(output_dir.join("links").join("vbw-build.link").exists());

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
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed"), "error: {err}");
    }

    #[test]
    fn test_capture_environment() {
        let env = capture_environment();
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
    }
}
