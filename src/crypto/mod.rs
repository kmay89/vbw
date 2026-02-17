//! Post-quantum crypto-agile signing and verification layer for VBW.
//!
//! This module provides VBW with quantum-resistant, hybrid-capable, and
//! algorithmically agile cryptographic verification. It follows the `ERRERlabs`
//! security axiom: *"The safest capabilities are the ones that don't exist."*
//!
//! ## Core Principles
//!
//! 1. **VBW never signs** — only verifies. Key generation and signing happen
//!    in the builder's CI environment. VBW receives public keys and signatures.
//! 2. **Hybrid-by-default** — every verification path supports composite
//!    (classical + PQC) signatures today, with a clean migration to pure PQC.
//! 3. **Algorithm agility** — algorithms are selected by policy (runtime config),
//!    not by hard-coded imports.
//! 4. **Cross-family enforcement** — hybrid compositions must combine algorithms
//!    from different mathematical families (e.g., lattice + hash-based).
//!
//! ## Module Structure
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`algorithm`] | Algorithm enums, NIST levels, math families |
//! | [`errors`] | `CryptoError` type for all crypto operations |
//! | [`policy`] | Crypto policy parsing, deprecation, security level enforcement |
//! | [`registry`] | Runtime algorithm-to-provider mapping |
//! | [`hybrid`] | Hybrid/dual-PQC verification and cross-family enforcement |
//! | [`kdf`] | HKDF-SHA-384 for hybrid KEM secret combination |
//! | [`envelope`] | Attestation crypto envelope serialization |
//! | [`providers`] | Concrete `CryptoProvider` implementations |
//!
//! ## NIST PQC Standards Implemented
//!
//! | FIPS | Algorithm | Status |
//! |------|-----------|--------|
//! | FIPS 203 | ML-KEM (CRYSTALS-Kyber) | Implemented |
//! | FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | Implemented |
//! | FIPS 205 | SLH-DSA (SPHINCS+) | Implemented |
//! | FIPS 206 | FN-DSA (FALCON) | Stub (draft standard) |
//! | TBD | HQC | Stub (expected ~2027) |

#![forbid(unsafe_code)]

pub mod algorithm;
pub mod envelope;
pub mod errors;
pub mod hybrid;
pub mod kdf;
pub mod policy;
pub mod providers;
pub mod registry;

pub use algorithm::{AlgorithmDescriptor, HashAlgorithm, KemAlgorithm, SignatureAlgorithm};
pub use errors::CryptoError;

/// Opaque wrapper for public key bytes. Does not implement `Display`
/// to prevent accidental logging of key material.
#[derive(Clone)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl std::fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKeyBytes([{} bytes])", self.0.len())
    }
}

/// Opaque wrapper for signature bytes.
#[derive(Clone)]
pub struct SignatureBytes(pub Vec<u8>);

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignatureBytes([{} bytes])", self.0.len())
    }
}

/// Opaque wrapper for KEM ciphertext bytes.
#[derive(Clone)]
pub struct CiphertextBytes(pub Vec<u8>);

impl std::fmt::Debug for CiphertextBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CiphertextBytes([{} bytes])", self.0.len())
    }
}

/// Opaque wrapper for KEM decapsulation key bytes.
/// Implements `Zeroize` + `Drop` to clear memory when no longer needed.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DecapsulationKey(pub Vec<u8>);

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecapsulationKey([REDACTED])")
    }
}

/// Shared secret derived from KEM decapsulation.
/// Implements `Zeroize` + `Drop` to clear memory when no longer needed.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret(pub Vec<u8>);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// Hash digest output.
#[derive(Clone, PartialEq, Eq)]
pub struct DigestBytes(pub Vec<u8>);

impl std::fmt::Debug for DigestBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DigestBytes([{} bytes])", self.0.len())
    }
}

impl DigestBytes {
    /// Returns the hex-encoded digest string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Result of a signature verification operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid (the message or key doesn't match).
    Invalid {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

impl VerificationResult {
    /// Returns `true` if the verification passed.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// The core abstraction for all cryptographic operations in VBW.
///
/// All crypto operations are dispatched through this trait. VBW never
/// calls algorithm-specific functions directly — the provider is selected
/// by the policy engine at runtime.
///
/// **VBW only verifies; it never signs.** The `verify_signature` method
/// checks existing signatures. There is intentionally no `sign` method.
pub trait CryptoProvider: Send + Sync {
    /// Returns a unique identifier for this provider (e.g., `"rustcrypto"`, `"ed25519-dalek"`).
    fn provider_id(&self) -> &'static str;

    /// Lists all algorithms supported by this provider.
    fn supported_algorithms(&self) -> Vec<AlgorithmDescriptor>;

    /// Verifies a signature against a public key and message.
    ///
    /// Returns `Ok(VerificationResult::Valid)` if the signature is valid,
    /// `Ok(VerificationResult::Invalid)` if the signature is well-formed but
    /// does not match, or `Err(CryptoError)` if the operation itself fails
    /// (unsupported algorithm, malformed key, etc.).
    fn verify_signature(
        &self,
        algorithm: &SignatureAlgorithm,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<VerificationResult, CryptoError>;

    /// Decapsulates a KEM ciphertext to recover a shared secret.
    ///
    /// Returns `Err(CryptoError::UnsupportedAlgorithm)` if this provider
    /// does not support the requested KEM.
    fn decapsulate(
        &self,
        algorithm: &KemAlgorithm,
        secret_key: &DecapsulationKey,
        ciphertext: &CiphertextBytes,
    ) -> Result<SharedSecret, CryptoError>;

    /// Computes a cryptographic hash of the given data.
    fn hash(&self, algorithm: &HashAlgorithm, data: &[u8]) -> Result<DigestBytes, CryptoError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn public_key_bytes_debug_redacts_content() {
        let pk = PublicKeyBytes(vec![1, 2, 3, 4]);
        let debug = format!("{:?}", pk);
        assert!(debug.contains("4 bytes"));
        assert!(!debug.contains("[1, 2, 3, 4]"));
    }

    #[test]
    fn decapsulation_key_debug_redacts() {
        let dk = DecapsulationKey(vec![0xDE, 0xAD]);
        let debug = format!("{:?}", dk);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("DE"));
    }

    #[test]
    fn shared_secret_debug_redacts() {
        let ss = SharedSecret(vec![0xFF; 32]);
        let debug = format!("{:?}", ss);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn digest_bytes_hex_encoding() {
        let d = DigestBytes(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(d.to_hex(), "cafebabe");
    }

    #[test]
    fn verification_result_valid() {
        assert!(VerificationResult::Valid.is_valid());
    }

    #[test]
    fn verification_result_invalid() {
        let r = VerificationResult::Invalid {
            reason: "bad sig".into(),
        };
        assert!(!r.is_valid());
    }
}
