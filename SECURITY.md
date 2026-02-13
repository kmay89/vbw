# Security Policy

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

### Coordinated Disclosure Process

1. **Email**: security@scqcs.dev
2. **Encrypt** your report if possible (PGP key available at https://scqcs.dev/.well-known/pgp-key.txt)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce (minimal proof of concept preferred)
   - Potential impact assessment
   - Suggested fix (if any)
   - Your name/handle for attribution (optional)
4. **Response SLA**: Initial acknowledgment within **48 hours**, triage within **5 business days**
5. **Disclosure timeline**: We follow a 90-day coordinated disclosure window

### What Qualifies

- Bypass of independence enforcement checks
- Path traversal or symlink-following vulnerabilities
- Secret leakage through error messages or reports
- Denial of service via crafted bundles (e.g., zip bombs, regex catastrophic backtracking)
- Any violation of the security model described below
- Dependency vulnerabilities not yet tracked by RustSec/cargo-audit

### What Does NOT Qualify

- Bugs in external tools (slsa-verifier, in-toto, cosign) -- report to those projects
- Feature requests or usability issues -- use GitHub Issues
- Findings in example/demo files that are clearly marked as non-production

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Current release    |
| < 0.1   | Not supported      |

## Security Model

VBW's guarantee is structural:

1. **No access required** -- VBW cannot leak what it never sees
2. **Cryptographic verification only** -- checks operate on signed evidence
3. **Transparent operation** -- verification is reproducible from the bundle
4. **Open source** -- code is auditable by anyone
5. **Defensive input handling** -- strict file size limits, no symlink following, secret redaction in error output

### Trust Boundaries

- VBW **does not** trust bundle contents (all inputs treated as adversarial)
- VBW **does not** access networks, secrets, or credentials
- VBW **does not** execute code from bundles
- VBW **delegates** cryptographic verification to established tools (slsa-verifier, in-toto, cosign)

If VBW ever requests credentials, private keys, or internal network access: **that is a bug**.

## Security Controls

### Compile-Time Controls

| Control | Mechanism | Location |
|---------|-----------|----------|
| No `unsafe` code | `#![forbid(unsafe_code)]` | `Cargo.toml [lints.rust]` |
| No `.unwrap()` in production | `clippy::unwrap_used = "deny"` | `Cargo.toml [lints.clippy]` |
| Pedantic linting | `clippy::pedantic = "warn"` | `Cargo.toml [lints.clippy]` |
| All warnings are errors | `RUSTFLAGS="-D warnings"` | CI pipeline |
| Pinned compiler version | `rust-toolchain.toml` | 1.88.0 exact |

### Dependency Controls

| Control | Tool | Frequency |
|---------|------|-----------|
| Known vulnerability scan | `cargo-audit` | Every PR + daily |
| Advisory database check | `cargo-deny advisories` | Daily + local (`make deny`) |
| License allowlist | `cargo-deny licenses` | Every PR + daily |
| Crate ban list | `cargo-deny bans` | Every PR + daily |
| Source registry restriction | `cargo-deny sources` | Every PR + daily |
| Automated updates | Dependabot | Weekly |

### Runtime Controls

| Control | Mechanism | Location |
|---------|-----------|----------|
| Symlink rejection | `symlink_metadata()` check | `fs_guard.rs` |
| File size limits | Per-file and total bounds | `fs_guard.rs`, `bundlehash.rs` |
| Secret redaction | Regex-based scrubbing | `main.rs` (`sanitize_tool_stderr`) |
| Linear-time regex | `regex` crate (no backtracking) | `independence.rs` |
| No shell invocation | `std::process::Command` | `main.rs` |
| Output truncation | 8 KB stderr limit | `main.rs` |

## RustSec Compliance

VBW is designed to produce a clean `cargo-audit` report:

- **Zero known advisories**: All dependencies are monitored against the
  [RustSec Advisory Database](https://rustsec.org/) on every PR and via
  daily scheduled workflow.
- **Unmaintained crate policy**: `cargo-deny` is configured to **deny**
  unmaintained dependencies (`unmaintained = "all"` in `deny.toml`).
- **UB-risk-0** (per Google's `cargo vet` scale): VBW contains zero
  `unsafe` blocks. The `#![forbid(unsafe_code)]` attribute prevents any
  `unsafe` code from being added, even with `#[allow]` overrides.
- **No C/C++ FFI**: OpenSSL and `openssl-sys` are explicitly banned in
  `deny.toml`. All dependencies are pure Rust.
- **Yanked version detection**: `cargo-audit` detects yanked crate
  versions by default; `cargo-deny` enforces via `yanked` policy.

## Supply Chain Security

- All CI/CD GitHub Actions are **pinned to SHA** (not mutable tags)
- Dependencies are audited via `cargo-audit` and `cargo-deny` on every PR and daily
- Only crates from crates.io are permitted (no git dependencies)
- Only OSI-approved permissive licenses are allowed (see `deny.toml`)
- Release binaries include SHA256 checksums and SBOM (CycloneDX)
- `Cargo.lock` is committed for reproducible builds
- Dependabot provides automated weekly dependency update PRs

## Audit Preparation

For auditors engaged to assess VBW, the recommended starting points are:

1. **[`AUDIT-BOUNDARY.md`](AUDIT-BOUNDARY.md)** -- Scopes the audit to ~1,300 lines of Rust
2. **[`ARCHITECTURE.md`](ARCHITECTURE.md)** -- Data flow, threat model, cryptographic inventory
3. **`src/` modules** -- Reviewed in dependency order (see `AUDIT-BOUNDARY.md`)
4. **`deny.toml`** -- Supply chain policy configuration
5. **`.github/workflows/`** -- CI/CD integrity review
