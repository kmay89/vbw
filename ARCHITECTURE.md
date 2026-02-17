# Architecture

VBW (Verified Build Witness) is intentionally small: ~1,300 lines of novel
Rust code with zero `unsafe` blocks.

## Data Flow

```
                          ┌─────────────┐
                          │ Bundle Dir  │  (untrusted input)
                          │             │
                          │ provenance  │
                          │ layout      │
                          │ links/      │
                          │ artifacts/  │
                          │ policy      │
                          └──────┬──────┘
                                 │
                    ┌────────────▼────────────┐
                    │ fs_guard::read_validated │ ← symlink-safe, size-bounded
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                   │
    ┌─────────▼──────┐  ┌───────▼────────┐  ┌──────▼──────────┐
    │ SLSA Verifier  │  │ in-toto Verify │  │ Independence    │
    │ (external)     │  │ (external)     │  │ Engine (VBW IP) │
    └─────────┬──────┘  └───────┬────────┘  └──────┬──────────┘
              │                  │                   │
              └──────────────────┼──────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Bundle Hash (SHA-256) │ ← deterministic, streaming
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Report + Attestation   │
                    │  (in-toto Statement v1) │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Sigstore Signing       │ ← cosign (external)
                    │  (keyless + transparency│
                    │   log)                  │
                    └─────────────────────────┘
```

## Inputs (provided by build owner)

- **SLSA provenance** (`provenance.json`) -- evidence of build origin and
  materials, following the [SLSA provenance](https://slsa.dev/provenance/)
  specification.
- **in-toto layout + link metadata** (`layout.json`, `links/`) -- supply
  chain workflow evidence following the
  [in-toto](https://in-toto.io/) specification.
- **Sigstore signatures** -- keyless signing with transparency log anchoring,
  provided by [cosign](https://github.com/sigstore/cosign).

## VBW Processing Layer

VBW runs three classes of checks:

### 1. Cryptographic and Workflow Checks (Delegated)

These are performed by **external tools invoked as subprocesses**. VBW does
not link against their code, does not parse their internal data structures,
and does not modify their behavior. VBW only inspects their exit code and
sanitized stderr.

| Tool | Purpose | Invocation |
|------|---------|------------|
| `slsa-verifier` | SLSA provenance verification | `Command::new("slsa-verifier")` |
| `in-toto-verify` | in-toto layout + link verification | `Command::new("in-toto-verify")` |
| `cosign` | Sigstore signing + verification | `Command::new("cosign")` |

**No shell is invoked** -- `std::process::Command` passes arguments as
separate OS strings, making shell injection structurally impossible.

### 2. Independence Enforcement (VBW Novel IP)

This is the core VBW value-add. VBW scans SLSA provenance for indicators
that the build was not independently reproducible:

| Check | What It Detects | Policy Knob |
|-------|----------------|-------------|
| Secret detection | AWS keys, GitHub PATs, private keys, passwords, bearer tokens | `forbid_secrets` |
| Network detection | RFC 1918 addresses, localhost, `.local` domains | `forbid_private_network_refs` |
| Digest requirement | Missing `sha256`/`digest` keys in provenance | `require_digests` |
| Builder allowlist | Builder ID not matching policy URI prefixes | `allowed_builder_prefixes` |

All regex patterns use the `regex` crate which guarantees **linear-time**
matching. Catastrophic backtracking (ReDoS) is structurally impossible.

### 3. Attestation Output

VBW emits an **in-toto Statement v1** (`vbw-attestation.json`) with a
VBW-specific predicate (`https://scqcs.dev/vbw/predicate/v1`) and a
deterministic SHA-256 hash of the input evidence bundle.

## Cryptographic Inventory

### Classical Operations

| Operation | Crate | Algorithm | Notes |
|-----------|-------|-----------|-------|
| Bundle hashing | `sha2` 0.10 (RustCrypto) | SHA-256 | Pure Rust, no FFI, not FIPS certified |
| Hex encoding | `hex` 0.4 | N/A | Trivial encoding utility |
| Ed25519 verification | `ed25519-dalek` 2 | Ed25519 | Strict verification mode |
| Signing | delegated to `cosign` | Sigstore keyless | External process, not VBW code |
| SLSA verification | delegated to `slsa-verifier` | Various | External process, not VBW code |

### Post-Quantum Cryptographic (PQC) Operations

VBW includes a **crypto-agile verification layer** (`src/crypto/`) that implements
NIST post-quantum standards for signature verification and key encapsulation.
VBW **never signs** -- it only verifies signatures produced by external build systems.

| FIPS | Algorithm | Crate | Type | Status |
|------|-----------|-------|------|--------|
| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | `ml-kem` | KEM | Implemented |
| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | `ml-dsa` | Signature | Implemented |
| FIPS 205 | SLH-DSA (SPHINCS+) | `slh-dsa` | Signature | Implemented |
| FIPS 206 | FN-DSA (FALCON) | -- | Signature | Stub (draft standard) |
| TBD | HQC | -- | KEM | Stub (expected ~2027) |

All PQC crates are from the **RustCrypto** project: pure Rust, no C FFI, no `unsafe`,
NIST KAT-tested.

### Hybrid Composition

VBW supports **hybrid signatures** (classical + PQC) and **dual-PQC signatures**
(two PQC algorithms from different mathematical families). Hybrid verification
requires both components to pass (AND logic). Cross-family enforcement prevents
a single mathematical breakthrough from compromising both components.

| Composition | Example | Math Families |
|-------------|---------|---------------|
| Hybrid (classical + PQC) | Ed25519 + ML-DSA-65 | Elliptic Curve + Lattice |
| Dual-PQC | ML-DSA-65 + SLH-DSA-256s | Lattice + Hash-Based |

Hybrid KEM shared secrets are combined using **HKDF-SHA-384** per NIST SP 800-56C Rev. 2.

### Crypto Module Structure

```
src/crypto/
├── mod.rs              # CryptoProvider trait, opaque key/sig wrappers
├── algorithm.rs        # SignatureAlgorithm, KemAlgorithm, HashAlgorithm enums
├── policy.rs           # CryptoPolicy: security level, mode, deprecation
├── registry.rs         # AlgorithmRegistry: maps IDs to providers
├── hybrid.rs           # Hybrid/dual-PQC verification, cross-family enforcement
├── kdf.rs              # HKDF-SHA-384 for hybrid KEM secret combination
├── envelope.rs         # CryptoEnvelope: attestation crypto metadata format
├── errors.rs           # CryptoError enum
└── providers/
    ├── mod.rs
    ├── rustcrypto.rs   # ML-DSA, SLH-DSA, ML-KEM, SHA-2 (RustCrypto)
    ├── ed25519.rs      # Ed25519 verification (ed25519-dalek)
    └── stub.rs         # FN-DSA, HQC, ECDSA placeholders
```

### CNSA 2.0 Compliance

VBW's PQC layer is designed for NSA CNSA 2.0 compliance:

- ML-KEM-1024 available for key establishment
- ML-DSA-87 available for digital signatures
- SLH-DSA available as hash-based backup
- AES-256 for symmetric encryption
- SHA-384 minimum for hashing

## Threat Model Boundary

### VBW Does NOT Claim to Prove

- That the source code is correct or free of vulnerabilities
- That the builder is honest or uncompromised
- That the build environment is secure
- That the artifacts function as intended

### VBW DOES Claim to Prove

- The submitted evidence is internally consistent and policy-compliant
- The evidence does not contain embedded secrets or private network references
- The VBW attestation is cryptographically bound to an immutable evidence
  bundle hash (SHA-256)
- The VBW output is verifiable (and optionally transparency-logged via Sigstore)

### Trust Boundaries

| Component | Trust Level | Rationale |
|-----------|------------|-----------|
| Bundle contents | **Untrusted** | Adversarial input; all checks apply |
| Local filesystem | **Trusted** | See TOCTOU risk acceptance in `AUDIT-BOUNDARY.md` |
| External tools | **Trusted binaries** | VBW checks exit code only; does not parse internal state |
| VBW itself | **Auditable** | ~1,300 lines of Rust, `#![forbid(unsafe_code)]` |
| Rust compiler | **Trusted** | Pinned to exact version via `rust-toolchain.toml` |
| crates.io dependencies | **Policy-governed** | Enforced by `cargo-audit` + `cargo-deny` |

## Defensive Input Limits

| Resource | Limit | Enforced In |
|----------|-------|-------------|
| JSON file size | 20 MB | `main.rs` via `fs_guard` |
| Policy file size | 1 MB | `policy.rs` via `fs_guard` |
| Tool stderr | 8 KB | `main.rs` (truncated + redacted) |
| File in bundle | 100 MB | `bundlehash.rs` |
| Files in bundle | 10,000 | `bundlehash.rs` |
| Total bundle size | 2 GB | `bundlehash.rs` |
| Key files in directory | 256 | `main.rs` (`collect_key_paths`) |

## RustSec Alignment

VBW's security posture is designed to align with RustSec advisory database
guidelines and Google's `cargo vet` auditing standards:

- **UB-risk-0**: Zero `unsafe` code (`#![forbid(unsafe_code)]`)
- **No known advisories**: `cargo-audit` and `cargo-deny` run on every PR
  and daily via scheduled workflow
- **Minimal dependency surface**: 9 production dependencies, all from
  crates.io, all with permissive licenses
- **No FFI**: All dependencies are pure Rust (OpenSSL is explicitly banned)
- **Linear-time input processing**: All regex matching is guaranteed
  linear-time by the `regex` crate
