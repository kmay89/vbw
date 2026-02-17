//! Concrete `CryptoProvider` implementations for VBW.
//!
//! VBW ships with three provider backends:
//!
//! | Provider | Algorithms | Status |
//! |----------|-----------|--------|
//! | [`rustcrypto`] | ML-DSA (44/65/87), SLH-DSA (all 12 variants), ML-KEM (512/768/1024), SHA-2/SHA-3 | Production |
//! | [`ed25519`] | Ed25519 | Production |
//! | [`stub`] | FN-DSA (512/1024), HQC (128/192/256), ECDSA (P-256/P-384) | Placeholder |
//!
//! Two independent backends (`RustCrypto` + ed25519-dalek) enable cross-validation
//! of critical attestations using different implementations (defense-in-depth).

pub mod ed25519;
pub mod rustcrypto;
pub mod stub;
