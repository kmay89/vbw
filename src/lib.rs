//! # VBW -- Verified Build Witness
//!
//! Zero-knowledge build integrity verification using SLSA + in-toto + Sigstore.
//!
//! VBW is a thin, auditable policy layer that enforces **independence**: if
//! build evidence requires internal access, private networks, or embedded
//! secrets, VBW treats that as a policy failure. VBW never touches credentials
//! and cannot leak what it never sees.
//!
//! ## Security Properties
//!
//! - **`#![forbid(unsafe_code)]`**: No `unsafe` blocks anywhere in VBW.
//! - **Zero credential access**: VBW never requests, stores, or logs secrets.
//! - **Defensive input handling**: All file I/O is symlink-checked and
//!   size-bounded via [`fs_guard::read_validated`].
//! - **Linear-time regex**: The `regex` crate guarantees no catastrophic
//!   backtracking (`ReDoS` is structurally impossible).
//! - **Delegated crypto**: Signing and signature verification are performed
//!   by external tools (`cosign`, `slsa-verifier`, `in-toto-verify`), not
//!   by VBW itself. VBW's only cryptographic operation is SHA-256 hashing
//!   via the `sha2` crate (`RustCrypto`, pure Rust, no FFI).
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`fs_guard`] | Symlink-safe, size-bounded file reads |
//! | [`policy`] | Policy loading and secure defaults |
//! | [`independence`] | Secret/network/digest/builder checks |
//! | [`bundlehash`] | Deterministic SHA-256 evidence hashing |
//! | [`attest`] | in-toto Statement v1 generation |
//!
//! ## Audit Guidance
//!
//! See `AUDIT-BOUNDARY.md` for the recommended module review order and
//! the IP delineation between VBW novel code and delegated external tools.

/// Symlink-safe, size-bounded file reads. Single source of truth for all
/// untrusted file I/O in VBW.
pub mod fs_guard;

/// Policy model: loads `vbw-policy.json`, provides secure defaults, and
/// defines the five policy knobs that control independence enforcement.
pub mod policy;

/// Core independence enforcement engine. Scans SLSA provenance for embedded
/// secrets, private network references, missing digests, and builder identity.
pub mod independence;

/// Deterministic SHA-256 hashing of evidence bundles. Walks the bundle
/// directory, validates file sizes and symlinks, and produces a reproducible
/// bundle-level digest.
pub mod bundlehash;

/// Attestation generation. Produces an in-toto Statement v1 with a VBW
/// predicate binding the verification results to the evidence bundle hash.
pub mod attest;
