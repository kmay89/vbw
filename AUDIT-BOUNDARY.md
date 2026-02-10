# Audit Boundary and Intellectual Property Map

This document exists to accelerate third-party security audits. It precisely
delineates which code is **novel VBW intellectual property** (requiring
line-by-line audit) versus which functionality is **delegated to
independently-audited, widely-deployed open-source tools** (out of scope for
VBW-specific audit).

## Audience

Third-party auditors engaged to assess VBW for production deployment in
hardware supply chains (e.g., factory-level build verification for ATM/POS
terminal firmware).

---

## Audit Scope Summary

| Category | Lines of Code | Audit Depth Required |
|----------|--------------|---------------------|
| **VBW novel IP** (Rust, `src/`) | ~1,333 | Full line-by-line review |
| **Policy/config** (TOML, JSON) | ~120 | Review for correctness |
| **CI/CD workflows** (YAML) | ~250 | Review for supply chain integrity |
| **External tools** (slsa-verifier, in-toto-verify, cosign) | 0 (delegated) | Out of scope -- see below |
| **Rust dependencies** (crates.io) | 0 (vendored via Cargo.lock) | Covered by cargo-audit + cargo-deny |

**Total novel code requiring audit: ~1,333 lines of Rust.**

---

## Module-by-Module IP Map

### VBW Novel IP (IN SCOPE)

These modules contain all VBW-authored logic. Every line is original work by
the SCQCS Initiative.

#### `src/main.rs` (614 lines) -- CLI Orchestration

**What it does:**
- Parses CLI arguments via `clap` (derive API)
- Orchestrates the verify pipeline: load policy -> SLSA check -> in-toto
  check -> independence check -> bundle hash -> report -> attestation -> sign
- Calls external tools (`slsa-verifier`, `in-toto-verify`, `cosign`) as
  subprocesses via `std::process::Command`
- Implements defensive input reading (`read_file_limited`) with symlink/size
  checks
- Implements secret redaction (`sanitize_tool_stderr`) for error output

**What an auditor should focus on:**
- Subprocess invocation: Are arguments properly constructed? Can an attacker
  inject shell commands via bundle contents? (Answer: No -- `Command` does not
  invoke a shell; arguments are passed as separate OS strings.)
- File reading: Are TOCTOU windows exploitable in VBW's threat model? (Answer:
  VBW's threat model assumes the local filesystem is trusted; the bundle
  directory is the adversarial input. The symlink check raises the bar but does
  not fully close the TOCTOU window. See **Known Limitations** below.)
- Report assembly: Does the report faithfully reflect verification outcomes?
- Exit codes: Does VBW exit non-zero on any failure path?

#### `src/independence.rs` (174 lines) -- Independence Enforcement Engine

**What it does:**
- Scans SLSA provenance JSON for embedded secrets (7 regex patterns)
- Scans for private/internal network references (6 regex patterns)
- Checks builder identity against policy allowlist
- Verifies digest fields are present in the provenance structure

**What an auditor should focus on:**
- Regex patterns: Are they correct? Do they have false negatives that would
  miss a real secret? False positives that would block legitimate builds?
- Regex engine: Rust's `regex` crate guarantees linear-time matching (no
  catastrophic backtracking). This is a deliberate choice.
- Builder ID extraction: Does it correctly handle both SLSA v0.2 and v1
  provenance formats?

#### `src/bundlehash.rs` (269 lines) -- Evidence Bundle Hashing

**What it does:**
- Walks the bundle directory, computing SHA256 of every file
- Produces a deterministic bundle-level hash (SHA256 of sorted file hashes)
- Enforces size limits (100MB per file, 10K files, 2GB total)
- Rejects symlinks
- Produces an evidence inventory (file paths, sizes, individual hashes)

**What an auditor should focus on:**
- Determinism: Is the hash stable across platforms? (Answer: Yes -- files are
  sorted by path before hashing, and the hash is computed from hex-encoded
  SHA256 strings, not raw bytes.)
- Exclusion: Does the `vbw/` output directory exclusion work correctly?
- Streaming: Large files are hashed in 64KB chunks -- verify no truncation.

#### `src/attest.rs` (96 lines) -- Attestation Generation

**What it does:**
- Generates an in-toto Statement v1 with a VBW-specific predicate type
- Binds the attestation to the bundle hash via the `subject` field
- Includes verification results and evidence inventory in the predicate

**What an auditor should focus on:**
- Statement structure: Does it conform to in-toto Statement v1 spec?
- Binding: Is the bundle hash correctly placed in `subject[0].digest.sha256`?
- Timestamp: Is RFC 3339 formatting correct?

#### `src/policy.rs` (176 lines) -- Policy Configuration

**What it does:**
- Defines the `VbwPolicy` struct (5 boolean/list fields)
- Loads policy from JSON file with symlink/size checks
- Falls back to secure defaults when no policy file is provided

**What an auditor should focus on:**
- Default policy: Are the defaults appropriately strict?
- Deserialization: Does serde reject unknown fields? (Answer: Currently no --
  unknown fields are silently ignored. This is intentional for forward
  compatibility but should be noted.)

#### `src/lib.rs` (4 lines) -- Module Exports

Trivial. Exports the four modules above.

---

### Delegated to External Tools (OUT OF SCOPE for VBW audit)

VBW invokes these tools as **opaque subprocesses**. VBW does not link against
their code, does not parse their internal data structures, and does not modify
their behavior. VBW only inspects their exit code and stderr.

| Tool | Purpose | Maintained By | Audit Status |
|------|---------|--------------|-------------|
| [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) | SLSA provenance verification | Google / SLSA Framework | Widely audited; SLSA reference implementation |
| [`in-toto-verify`](https://github.com/in-toto/in-toto) | in-toto layout + link verification | NYU Secure Systems Lab / CNCF | Academic provenance; CNCF graduated project |
| [`cosign`](https://github.com/sigstore/cosign) | Sigstore keyless signing + verification | Sigstore / Linux Foundation | Formal audit by Trail of Bits (2022) and Chainguard |

**VBW's contract with these tools:**
1. VBW constructs command-line arguments from validated, bounded inputs
2. VBW checks only the process exit code (0 = success, non-zero = failure)
3. VBW sanitizes stderr before including it in reports (secret redaction)
4. VBW never parses stdout/stderr to make security decisions
5. If a tool is not installed, VBW exits with an error (does not silently skip)

---

### Rust Dependencies (COVERED BY AUTOMATED POLICY)

All dependencies come from crates.io and are enforced by `cargo-deny`:

| Crate | Purpose | License | Notes |
|-------|---------|---------|-------|
| `clap` | CLI argument parsing | MIT/Apache-2.0 | Most popular Rust CLI framework |
| `serde` + `serde_json` | JSON serialization | MIT/Apache-2.0 | De facto standard |
| `sha2` | SHA-256 hashing | MIT/Apache-2.0 | RustCrypto project; pure Rust, no FFI |
| `hex` | Hex encoding | MIT/Apache-2.0 | Trivial utility |
| `walkdir` | Recursive directory traversal | MIT/Unlicense | Well-audited |
| `regex` | Pattern matching | MIT/Apache-2.0 | Linear-time guarantee (no backtracking) |
| `time` | RFC 3339 timestamps | MIT/Apache-2.0 | |
| `anyhow` | Error handling | MIT/Apache-2.0 | |

**Dependency policy enforcement:**
- `cargo-audit`: Checks for known CVEs in dependencies (runs in CI + daily)
- `cargo-deny`: Enforces license allowlist, bans `openssl`, blocks git
  dependencies, blocks unknown registries
- `Cargo.lock`: Committed to repo for reproducible builds
- Dependabot: Automated weekly PRs for dependency updates

**Note on FIPS compliance:** The `sha2` crate is a pure-Rust implementation.
It is not FIPS 140-2/140-3 certified. If FIPS certification is required for
the deployment environment, the SHA-256 implementation would need to be
replaced with a FIPS-validated module (e.g., AWS-LC via `aws-lc-rs`). This
would be a targeted change to `bundlehash.rs` and `main.rs` only (~30 lines).

---

## Known Limitations (Documented Risk Acceptances)

### 1. TOCTOU Window in Symlink Checks

**Location:** `src/main.rs:23-41`, `src/policy.rs:42-56`

**Description:** There is a time-of-check-to-time-of-use gap between
`symlink_metadata()` and `fs::read()`. An attacker with local filesystem write
access could swap a regular file for a symlink between the check and the read.

**Risk assessment:** VBW's threat model treats the local filesystem as trusted
infrastructure. The adversarial input is the *bundle contents*, not the
filesystem itself. An attacker who can race the filesystem already has local
code execution, which is outside VBW's threat boundary. The check still
catches accidental symlinks and non-racing attacks.

**Mitigation if required:** On Unix, open files with `O_NOFOLLOW` via
`std::os::unix::fs::OpenOptionsExt` and fstat the fd. This is a ~15 line
change localized to `read_file_limited()`.

### 2. Schema-Only SLSA Mode

**Location:** `src/main.rs:272-279`

**Description:** In `--slsa-mode schema-only`, VBW only verifies that the
provenance file is valid JSON. It does not validate that required SLSA fields
are present.

**Risk assessment:** This mode is explicitly documented as "no artifact
verification." It exists for environments where `slsa-verifier` is not
installed. The report output clearly states `"mode": "schema-only"`.

### 3. External Tool Version Pinning

**Description:** VBW calls `slsa-verifier`, `in-toto-verify`, and `cosign` by
name without version pinning. Different versions may have different behavior.

**Mitigation:** For factory deployment, pin external tool versions in the
deployment image/container. VBW's report includes tool exit codes but not tool
versions. A future enhancement could capture `--version` output from each tool.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Verification passed. All checks (SLSA, in-toto, independence) succeeded. |
| `1` | Verification failed. At least one check failed. See `report.json` for details. |
| `1` | Input error. Missing required files, invalid JSON, oversized inputs, etc. |
| `1` | Tool error. An external tool failed to execute or returned an error. |

**Note:** Currently all failure modes produce exit code 1 (Rust's `anyhow`
default for `main() -> Result<()>`). For factory integration, a more granular
exit code scheme (e.g., 1=verification failure, 2=input error, 3=tool error)
would improve automation. This is identified as a future enhancement.

---

## Report JSON Schema

### `report.json` (version 1)

```json
{
  "report_schema": "https://scqcs.dev/vbw/report/v1",
  "vbw_version": "0.1.0",
  "bundle_dir": "<path>",
  "bundle_sha256": "<hex>",
  "verification_timestamp": "<RFC 3339>",
  "result": "PASS | FAIL",
  "failures": ["<string>", ...],
  "warnings": ["<string>", ...],
  "slsa": { "ok": true|false, "detail": {} },
  "intoto": { "ok": true|false, "detail": {} },
  "independence": {
    "overall": "pass | fail",
    "builder_id": "<string>",
    "builder_on_allowlist": true|false,
    "secret_pattern_hits": [],
    "private_network_hits": [],
    "blocking_failures": [],
    "warnings": []
  }
}
```

### `vbw-attestation.json` (in-toto Statement v1)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "vbw-input-bundle", "digest": { "sha256": "<hex>" } }
  ],
  "predicateType": "https://scqcs.dev/vbw/predicate/v1",
  "predicate": {
    "vbw_version": "0.1.0",
    "verifiedAt": "<RFC 3339>",
    "results": {
      "slsa": { "ok": true|false },
      "intoto": { "ok": true|false },
      "independence": { ... }
    },
    "evidence": {
      "stats": { "files": N, "total_bytes": N },
      "files": [{ "path": "<relative>", "sha256": "<hex>", "bytes": N }]
    }
  }
}
```

---

## Recommended Audit Procedure

For the fastest path to a complete audit:

1. **Start with this document.** It scopes the audit to ~1,333 lines of Rust.
2. **Read `ARCHITECTURE.md`** for the threat model.
3. **Read `SECURITY.md`** for the vulnerability disclosure process.
4. **Audit `src/` modules in this order:**
   - `policy.rs` (176 lines) -- simplest, establishes policy model
   - `independence.rs` (174 lines) -- core VBW value-add, regex review
   - `bundlehash.rs` (269 lines) -- hashing and file traversal
   - `attest.rs` (96 lines) -- attestation structure
   - `main.rs` (614 lines) -- orchestration, subprocess calls, I/O
5. **Run `make check`** to verify all quality gates pass.
6. **Run `make verify-example`** for an end-to-end smoke test.
7. **Review CI/CD workflows** in `.github/workflows/` for supply chain
   integrity.
8. **Review `deny.toml`** for dependency policy.
9. **Run `cargo tree`** to inspect the full dependency graph.

**Estimated audit duration for a senior security engineer:** 2-3 days for
full code review + 1 day for CI/CD and dependency review.
