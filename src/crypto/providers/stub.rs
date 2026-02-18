//! Stub provider for future/draft post-quantum algorithms.
//!
//! This provider registers algorithm entries for FN-DSA (FIPS 206, draft)
//! and HQC (expected ~2027) so that the algorithm registry and policy engine
//! can reference them, but all operations return `UnsupportedAlgorithm`.
//!
//! When these standards are finalized and `RustCrypto` publishes production
//! implementations, the stubs will be replaced with real providers.

use crate::crypto::algorithm::{
    AlgorithmDescriptor, HashAlgorithm, KemAlgorithm, MathFamily, NistLevel, SignatureAlgorithm,
};
use crate::crypto::errors::CryptoError;
use crate::crypto::{
    CiphertextBytes, CryptoProvider, DecapsulationKey, DigestBytes, PublicKeyBytes, SharedSecret,
    SignatureBytes, VerificationResult,
};

/// Stub provider for draft/future algorithms.
///
/// Registers FN-DSA (FALCON, FIPS 206 draft) and HQC (code-based KEM,
/// selected by NIST March 2025, standard expected ~2027). All operations
/// return `UnsupportedAlgorithm` until real implementations are available.
pub struct StubProvider;

impl CryptoProvider for StubProvider {
    fn provider_id(&self) -> &'static str {
        "stub-future"
    }

    fn supported_algorithms(&self) -> Vec<AlgorithmDescriptor> {
        vec![
            // FN-DSA (FALCON) — FIPS 206 draft
            AlgorithmDescriptor {
                id: "fn-dsa-512".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: None,
            },
            AlgorithmDescriptor {
                id: "fn-dsa-1024".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: None,
            },
            // HQC — code-based KEM (NIST Round 4 selection)
            AlgorithmDescriptor {
                id: "hqc-128".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::CodeBased,
                quantum_safe: true,
                oid: None,
            },
            AlgorithmDescriptor {
                id: "hqc-192".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::CodeBased,
                quantum_safe: true,
                oid: None,
            },
            AlgorithmDescriptor {
                id: "hqc-256".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::CodeBased,
                quantum_safe: true,
                oid: None,
            },
            // LMS/XMSS — SP 800-208 stateful hash-based signatures
            // Required by CNSA 2.0 for firmware signing.
            AlgorithmDescriptor {
                id: "lms".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::StatefulHashBased,
                quantum_safe: true,
                oid: None,
            },
            AlgorithmDescriptor {
                id: "xmss".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::StatefulHashBased,
                quantum_safe: true,
                oid: None,
            },
            // ECDSA — not yet implemented in VBW, registered for policy awareness
            AlgorithmDescriptor {
                id: "ecdsa-p256".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::EllipticCurve,
                quantum_safe: false,
                oid: Some("1.2.840.10045.4.3.2".into()),
            },
            AlgorithmDescriptor {
                id: "ecdsa-p384".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::EllipticCurve,
                quantum_safe: false,
                oid: Some("1.2.840.10045.4.3.3".into()),
            },
        ]
    }

    fn verify_signature(
        &self,
        algorithm: &SignatureAlgorithm,
        _public_key: &PublicKeyBytes,
        _message: &[u8],
        _signature: &SignatureBytes,
    ) -> Result<VerificationResult, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(format!(
            "{} is not yet implemented (standard pending finalization)",
            algorithm.id()
        )))
    }

    fn decapsulate(
        &self,
        algorithm: &KemAlgorithm,
        _secret_key: &DecapsulationKey,
        _ciphertext: &CiphertextBytes,
    ) -> Result<SharedSecret, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(format!(
            "{} is not yet implemented (standard pending finalization)",
            algorithm.id()
        )))
    }

    fn hash(&self, algorithm: &HashAlgorithm, _data: &[u8]) -> Result<DigestBytes, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(format!(
            "hash {} not supported by stub provider",
            algorithm.id()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stub_provider_id() {
        assert_eq!(StubProvider.provider_id(), "stub-future");
    }

    #[test]
    fn fn_dsa_512_returns_unsupported() {
        let result = StubProvider.verify_signature(
            &SignatureAlgorithm::FnDsa512,
            &PublicKeyBytes(vec![]),
            b"msg",
            &SignatureBytes(vec![]),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[test]
    fn hqc_128_returns_unsupported() {
        let result = StubProvider.decapsulate(
            &KemAlgorithm::Hqc128,
            &DecapsulationKey(vec![]),
            &CiphertextBytes(vec![]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn stub_lists_future_algorithms() {
        let algs = StubProvider.supported_algorithms();
        let ids: Vec<&str> = algs.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"fn-dsa-512"));
        assert!(ids.contains(&"fn-dsa-1024"));
        assert!(ids.contains(&"hqc-128"));
        assert!(ids.contains(&"hqc-192"));
        assert!(ids.contains(&"hqc-256"));
        assert!(ids.contains(&"lms"));
        assert!(ids.contains(&"xmss"));
        assert!(ids.contains(&"ecdsa-p256"));
        assert!(ids.contains(&"ecdsa-p384"));
    }
}
