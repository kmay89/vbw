# VBW -- Verified Build Witness

**Zero-knowledge build integrity verification using SLSA + in-toto + Sigstore.**

VBW is a thin, auditable policy layer that enforces **independence**: if a build
*requires* internal access, private networks, or secrets, VBW treats that as a
policy failure. VBW never touches credentials and cannot leak what it never sees.

## Status

| Check | Description |
|-------|-------------|
| CI | `cargo fmt` + `clippy` + `test` + `audit` + `deny` |
| License | Apache-2.0 |
| MSRV | 1.88.0 |

## Quick Start

### Build

```bash
cargo build --release
```

### Install External Tools (optional but recommended)

```bash
# SLSA verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# in-toto
pip install in-toto

# Sigstore (cosign)
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

### Verify the Example Bundle

The example runs without external tooling:

```bash
./target/release/vbw verify examples/minimal-bundle \
    --no-external --dry-run --slsa-mode schema-only
cat examples/minimal-bundle/vbw/report.json
```

### Verify a Real Bundle (full mode)

```bash
vbw verify ./bundle \
    --artifact ./bundle/myapp \
    --source-uri github.com/org/repo
```

### Inspect an Attestation

```bash
vbw show \
    --attestation bundle/vbw/vbw-attestation.json \
    --sigstore-bundle bundle/vbw/vbw-attestation.sigstore.bundle
```

## Bundle Structure

```
bundle/
  provenance.json          # SLSA provenance
  layout.json              # in-toto layout
  links/                   # in-toto attestations (*.link)
  artifacts/               # (optional) binaries to verify
  vbw-policy.json          # (optional) custom policy
  vbw/                     # VBW output
    vbw-attestation.json
    vbw-attestation.sigstore.bundle
    report.json
```

## Policy Configuration

Create `vbw-policy.json` (see `vbw-policy.json.example`):

```json
{
  "allowed_builder_prefixes": [
    "https://github.com/",
    "https://gitlab.com/"
  ],
  "builder_allowlist_is_warning": true,
  "forbid_private_network_refs": true,
  "forbid_secrets": true,
  "require_digests": true
}
```

## Development

```bash
# Run all quality gates (mirrors CI)
make check

# Individual targets
make fmt         # Check formatting
make clippy      # Lint
make test        # Tests (debug + release)
make audit       # Security audit
make deny        # License/ban/advisory/source checks
make build       # Debug build
make release     # Release build
```

## Repository Standards

This repository follows banking-grade operational standards:

- **Pinned CI actions**: All GitHub Actions pinned to SHA, not mutable tags
- **Supply chain policy**: `cargo-deny` enforces license, advisory, ban, and source rules
- **Automated audits**: Daily `cargo-audit` + `cargo-deny` via scheduled workflow
- **Dependency updates**: Dependabot for Cargo and GitHub Actions
- **DCO enforcement**: All commits require Developer Certificate of Origin sign-off
- **Code ownership**: CODEOWNERS enforces mandatory review by domain experts
- **Branch protection**: Requires 2 approvals, signed commits, linear history
- **SBOM generation**: CycloneDX SBOM included in every release
- **Reproducible toolchain**: `rust-toolchain.toml` pins compiler version
- **Strict formatting**: `rustfmt.toml` + `clippy.toml` with zero-warning policy

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) -- Composition model and threat boundaries
- [`AUDIT-BOUNDARY.md`](AUDIT-BOUNDARY.md) -- IP delineation and third-party audit scope
- [`SECURITY.md`](SECURITY.md) -- Vulnerability disclosure and security model
- [`CONTRIBUTING.md`](CONTRIBUTING.md) -- Contribution guidelines and quality requirements
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) -- Community standards
- [`examples/DEMO.md`](examples/DEMO.md) -- Reproducible demo workflow
- [`DCO`](DCO) -- Developer Certificate of Origin

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
