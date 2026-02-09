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

1. **No access required** -- we cannot leak what we never see
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

## Supply Chain Security

- All CI/CD GitHub Actions are **pinned to SHA** (not mutable tags)
- Dependencies are audited via `cargo-audit` and `cargo-deny` on every PR and daily
- Only crates from crates.io are permitted (no git dependencies)
- Only OSI-approved permissive licenses are allowed (see `deny.toml`)
- Release binaries include SHA256 checksums and SBOM
