//! RustCrypto-backed provider for post-quantum algorithms.
//!
//! Implements verification for:
//! - **ML-DSA** (FIPS 204): CRYSTALS-Dilithium lattice-based signatures
//! - **SLH-DSA** (FIPS 205): SPHINCS+ hash-based signatures
//! - **ML-KEM** (FIPS 203): CRYSTALS-Kyber key encapsulation
//! - **SHA-2 / SHA-3**: Cryptographic hash functions
//!
//! All implementations are pure Rust with no C FFI, no `unsafe` code,
//! and NIST KAT-tested by the `RustCrypto` project.

use sha2::Digest;

use crate::crypto::algorithm::{
    AlgorithmDescriptor, HashAlgorithm, KemAlgorithm, MathFamily, NistLevel, SignatureAlgorithm,
};
use crate::crypto::errors::CryptoError;
use crate::crypto::{
    CiphertextBytes, CryptoProvider, DecapsulationKey, DigestBytes, PublicKeyBytes, SharedSecret,
    SignatureBytes, VerificationResult,
};

/// RustCrypto-backed provider for PQC and hash algorithms.
pub struct RustCryptoProvider;

// ---------------------------------------------------------------------------
// ML-DSA signature verification (FIPS 204)
// ---------------------------------------------------------------------------

/// Verifies an ML-DSA signature for a specific parameter set.
///
/// This is a generic helper that handles the byte-level deserialization
/// and dispatches to the `signature::Verifier` trait implementation.
///
/// # Constant-time audit note
///
/// ML-DSA verification in the `ml-dsa` crate uses the algebraic verification
/// equation (checking that Az = c·t + w) rather than byte comparison of
/// signature data. The internal field arithmetic uses constant-time operations
/// provided by the `ml-dsa` crate. No raw byte comparison of signatures
/// occurs in this path.
fn verify_ml_dsa<P>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<VerificationResult, CryptoError>
where
    P: ml_dsa::MlDsaParams,
{
    use ml_dsa::signature::Verifier;

    // Deserialize verifying key
    let vk_encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| {
        CryptoError::InvalidKeyMaterial(format!(
            "ML-DSA verifying key has wrong length: expected {}, got {}",
            std::mem::size_of::<ml_dsa::EncodedVerifyingKey<P>>(),
            public_key.len()
        ))
    })?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&vk_encoded);

    // Deserialize signature
    let sig = ml_dsa::Signature::<P>::try_from(signature).map_err(|e| {
        CryptoError::VerificationFailed {
            algorithm: "ml-dsa".into(),
            reason: format!("malformed ML-DSA signature: {e}"),
        }
    })?;

    // Verify
    match vk.verify(message, &sig) {
        Ok(()) => Ok(VerificationResult::Valid),
        Err(_) => Ok(VerificationResult::Invalid {
            reason: "ML-DSA signature verification failed".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA signature verification (FIPS 205)
// ---------------------------------------------------------------------------

/// Verifies an SLH-DSA signature for a specific parameter set.
///
/// # Constant-time audit note
///
/// SLH-DSA verification in the `slh-dsa` crate recomputes the FORS/WOTS+
/// authentication path from the signature and compares the resulting root
/// against the public key root. Hash computations are inherently
/// constant-time (no secret-dependent branches). The `slh-dsa` crate does
/// not perform raw byte comparison of secret data in the verification path.
fn verify_slh_dsa<P>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<VerificationResult, CryptoError>
where
    P: slh_dsa::ParameterSet,
{
    use slh_dsa::signature::Verifier;

    let vk = slh_dsa::VerifyingKey::<P>::try_from(public_key).map_err(|e| {
        CryptoError::InvalidKeyMaterial(format!("invalid SLH-DSA verifying key: {e}"))
    })?;

    let sig = slh_dsa::Signature::<P>::try_from(signature).map_err(|e| {
        CryptoError::VerificationFailed {
            algorithm: "slh-dsa".into(),
            reason: format!("malformed SLH-DSA signature: {e}"),
        }
    })?;

    match vk.verify(message, &sig) {
        Ok(()) => Ok(VerificationResult::Valid),
        Err(_) => Ok(VerificationResult::Invalid {
            reason: "SLH-DSA signature verification failed".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// ML-KEM decapsulation (FIPS 203)
// ---------------------------------------------------------------------------

/// Macro to implement ML-KEM decapsulation for a specific parameter set.
/// This avoids complex generic trait bounds by using concrete types directly.
macro_rules! impl_ml_kem_decap {
    ($fn_name:ident, $param:ty) => {
        fn $fn_name(secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, CryptoError> {
            use ml_kem::Decapsulate;

            let seed = ml_kem::Seed::try_from(secret_key).map_err(|_| {
                CryptoError::InvalidKeyMaterial(format!(
                    "ML-KEM decapsulation key seed must be 64 bytes, got {}",
                    secret_key.len()
                ))
            })?;

            let dk = ml_kem::DecapsulationKey::<$param>::from_seed(seed);

            let ct = ml_kem::Ciphertext::<$param>::try_from(ciphertext).map_err(|_| {
                CryptoError::DecapsulationFailed(format!(
                    "ML-KEM ciphertext has wrong length: got {}",
                    ciphertext.len()
                ))
            })?;

            let shared_key = dk.decapsulate(&ct);
            Ok(SharedSecret(shared_key.to_vec()))
        }
    };
}

impl_ml_kem_decap!(decapsulate_ml_kem_512, ml_kem::MlKem512);
impl_ml_kem_decap!(decapsulate_ml_kem_768, ml_kem::MlKem768);
impl_ml_kem_decap!(decapsulate_ml_kem_1024, ml_kem::MlKem1024);

// ---------------------------------------------------------------------------
// CryptoProvider implementation
// ---------------------------------------------------------------------------

impl CryptoProvider for RustCryptoProvider {
    fn provider_id(&self) -> &'static str {
        "rustcrypto"
    }

    fn supported_algorithms(&self) -> Vec<AlgorithmDescriptor> {
        vec![
            // ML-DSA (FIPS 204)
            AlgorithmDescriptor {
                id: "ml-dsa-44".into(),
                nist_level: NistLevel::L2,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.17".into()),
            },
            AlgorithmDescriptor {
                id: "ml-dsa-65".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.18".into()),
            },
            AlgorithmDescriptor {
                id: "ml-dsa-87".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.19".into()),
            },
            // SLH-DSA SHA-2 variants (FIPS 205)
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-128s".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.20".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-128f".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.21".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-192s".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.22".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-192f".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.23".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-256s".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.24".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-sha2-256f".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.25".into()),
            },
            // SLH-DSA SHAKE variants
            AlgorithmDescriptor {
                id: "slh-dsa-shake-128s".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.26".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-shake-128f".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.27".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-shake-192s".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.28".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-shake-192f".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.29".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-shake-256s".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.30".into()),
            },
            AlgorithmDescriptor {
                id: "slh-dsa-shake-256f".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.3.31".into()),
            },
            // ML-KEM (FIPS 203)
            // OIDs per NIST CSOR: 2.16.840.1.101.3.4.4.{1,2,3}
            AlgorithmDescriptor {
                id: "ml-kem-512".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.4.1".into()),
            },
            AlgorithmDescriptor {
                id: "ml-kem-768".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.4.2".into()),
            },
            AlgorithmDescriptor {
                id: "ml-kem-1024".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::Lattice,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.4.3".into()),
            },
            // Hash algorithms
            AlgorithmDescriptor {
                id: "sha-256".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.1".into()),
            },
            AlgorithmDescriptor {
                id: "sha-384".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.2".into()),
            },
            AlgorithmDescriptor {
                id: "sha-512".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.3".into()),
            },
            // SHA-3 hash algorithms
            AlgorithmDescriptor {
                id: "sha3-256".into(),
                nist_level: NistLevel::L1,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.8".into()),
            },
            AlgorithmDescriptor {
                id: "sha3-384".into(),
                nist_level: NistLevel::L3,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.9".into()),
            },
            AlgorithmDescriptor {
                id: "sha3-512".into(),
                nist_level: NistLevel::L5,
                math_family: MathFamily::HashBased,
                quantum_safe: true,
                oid: Some("2.16.840.1.101.3.4.2.10".into()),
            },
        ]
    }

    fn verify_signature(
        &self,
        algorithm: &SignatureAlgorithm,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<VerificationResult, CryptoError> {
        match algorithm {
            // ML-DSA variants
            SignatureAlgorithm::MlDsa44 => {
                verify_ml_dsa::<ml_dsa::MlDsa44>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::MlDsa65 => {
                verify_ml_dsa::<ml_dsa::MlDsa65>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::MlDsa87 => {
                verify_ml_dsa::<ml_dsa::MlDsa87>(&public_key.0, message, &signature.0)
            }

            // SLH-DSA SHA-2 variants
            SignatureAlgorithm::SlhDsaSha2_128s => {
                verify_slh_dsa::<slh_dsa::Sha2_128s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaSha2_128f => {
                verify_slh_dsa::<slh_dsa::Sha2_128f>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaSha2_192s => {
                verify_slh_dsa::<slh_dsa::Sha2_192s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaSha2_192f => {
                verify_slh_dsa::<slh_dsa::Sha2_192f>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaSha2_256s => {
                verify_slh_dsa::<slh_dsa::Sha2_256s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaSha2_256f => {
                verify_slh_dsa::<slh_dsa::Sha2_256f>(&public_key.0, message, &signature.0)
            }

            // SLH-DSA SHAKE variants
            SignatureAlgorithm::SlhDsaShake128s => {
                verify_slh_dsa::<slh_dsa::Shake128s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaShake128f => {
                verify_slh_dsa::<slh_dsa::Shake128f>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaShake192s => {
                verify_slh_dsa::<slh_dsa::Shake192s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaShake192f => {
                verify_slh_dsa::<slh_dsa::Shake192f>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaShake256s => {
                verify_slh_dsa::<slh_dsa::Shake256s>(&public_key.0, message, &signature.0)
            }
            SignatureAlgorithm::SlhDsaShake256f => {
                verify_slh_dsa::<slh_dsa::Shake256f>(&public_key.0, message, &signature.0)
            }

            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.id())),
        }
    }

    fn decapsulate(
        &self,
        algorithm: &KemAlgorithm,
        secret_key: &DecapsulationKey,
        ciphertext: &CiphertextBytes,
    ) -> Result<SharedSecret, CryptoError> {
        match algorithm {
            KemAlgorithm::MlKem512 => decapsulate_ml_kem_512(&secret_key.0, &ciphertext.0),
            KemAlgorithm::MlKem768 => decapsulate_ml_kem_768(&secret_key.0, &ciphertext.0),
            KemAlgorithm::MlKem1024 => decapsulate_ml_kem_1024(&secret_key.0, &ciphertext.0),
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.id())),
        }
    }

    fn hash(&self, algorithm: &HashAlgorithm, data: &[u8]) -> Result<DigestBytes, CryptoError> {
        match algorithm {
            HashAlgorithm::Sha256 => Ok(DigestBytes(sha2::Sha256::digest(data).to_vec())),
            HashAlgorithm::Sha384 => Ok(DigestBytes(sha2::Sha384::digest(data).to_vec())),
            HashAlgorithm::Sha512 => Ok(DigestBytes(sha2::Sha512::digest(data).to_vec())),
            HashAlgorithm::Sha3_256 => Ok(DigestBytes(
                <sha3::Sha3_256 as sha3::digest::Digest>::digest(data).to_vec(),
            )),
            HashAlgorithm::Sha3_384 => Ok(DigestBytes(
                <sha3::Sha3_384 as sha3::digest::Digest>::digest(data).to_vec(),
            )),
            HashAlgorithm::Sha3_512 => Ok(DigestBytes(
                <sha3::Sha3_512 as sha3::digest::Digest>::digest(data).to_vec(),
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ML-DSA tests
    // -----------------------------------------------------------------------

    #[test]
    fn ml_dsa_44_sign_verify_roundtrip() {
        use ml_dsa::signature::{Signer, Verifier};
        use ml_dsa::{KeyGen, MlDsa44};

        let provider = RustCryptoProvider;
        let seed = ml_dsa::B32::default();
        let kp = MlDsa44::from_seed(&seed);
        let vk = kp.verifying_key();
        let sk = kp.signing_key();

        let message = b"VBW PQC attestation test";
        let sig = sk.sign(message);

        // Verify directly first
        assert!(vk.verify(message, &sig).is_ok());

        // Verify via provider
        let vk_bytes = vk.encode().to_vec();
        let sig_bytes = sig.encode().to_vec();

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::MlDsa44,
                &PublicKeyBytes(vk_bytes),
                message,
                &SignatureBytes(sig_bytes),
            )
            .unwrap();
        assert!(result.is_valid(), "ML-DSA-44 verification should pass");
    }

    #[test]
    fn ml_dsa_65_sign_verify_roundtrip() {
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyGen, MlDsa65};

        let provider = RustCryptoProvider;
        let seed = ml_dsa::B32::default();
        let kp = MlDsa65::from_seed(&seed);
        let vk = kp.verifying_key();
        let sk = kp.signing_key();

        let message = b"ML-DSA-65 hybrid attestation test";
        let sig = sk.sign(message);

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::MlDsa65,
                &PublicKeyBytes(vk.encode().to_vec()),
                message,
                &SignatureBytes(sig.encode().to_vec()),
            )
            .unwrap();
        assert!(result.is_valid(), "ML-DSA-65 verification should pass");
    }

    #[test]
    fn ml_dsa_87_sign_verify_roundtrip() {
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyGen, MlDsa87};

        let provider = RustCryptoProvider;
        let seed = ml_dsa::B32::default();
        let kp = MlDsa87::from_seed(&seed);
        let vk = kp.verifying_key();
        let sk = kp.signing_key();

        let message = b"ML-DSA-87 CNSA 2.0 test";
        let sig = sk.sign(message);

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::MlDsa87,
                &PublicKeyBytes(vk.encode().to_vec()),
                message,
                &SignatureBytes(sig.encode().to_vec()),
            )
            .unwrap();
        assert!(result.is_valid(), "ML-DSA-87 verification should pass");
    }

    #[test]
    fn ml_dsa_65_tampered_signature_rejected() {
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyGen, MlDsa65};

        let provider = RustCryptoProvider;
        let seed = ml_dsa::B32::default();
        let kp = MlDsa65::from_seed(&seed);
        let vk = kp.verifying_key();
        let sk = kp.signing_key();

        let message = b"tamper test";
        let sig = sk.sign(message);
        let mut sig_bytes = sig.encode().to_vec();
        // Tamper with the signature
        sig_bytes[0] ^= 0xFF;

        let result = provider.verify_signature(
            &SignatureAlgorithm::MlDsa65,
            &PublicKeyBytes(vk.encode().to_vec()),
            message,
            &SignatureBytes(sig_bytes),
        );

        // Either verification fails or returns Invalid (tampered bytes may not parse)
        if let Ok(r) = result {
            assert!(!r.is_valid());
        }
    }

    #[test]
    fn ml_dsa_wrong_algorithm_rejected() {
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyGen, MlDsa44};

        let provider = RustCryptoProvider;
        let seed = ml_dsa::B32::default();
        let kp = MlDsa44::from_seed(&seed);
        let vk = kp.verifying_key();
        let sk = kp.signing_key();

        let sig = sk.sign(b"test");

        // Try to verify ML-DSA-44 sig with ML-DSA-65 algorithm
        let result = provider.verify_signature(
            &SignatureAlgorithm::MlDsa65,
            &PublicKeyBytes(vk.encode().to_vec()),
            b"test",
            &SignatureBytes(sig.encode().to_vec()),
        );

        // Should fail: key/sig sizes are wrong for ML-DSA-65
        assert!(result.is_err() || !result.unwrap().is_valid());
    }

    // -----------------------------------------------------------------------
    // SLH-DSA tests
    // -----------------------------------------------------------------------

    #[test]
    fn slh_dsa_sha2_128s_sign_verify_roundtrip() {
        use slh_dsa::signature::{Keypair, Signer};

        let provider = RustCryptoProvider;
        let mut rng = test_rng(42);
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut rng);
        let vk = sk.verifying_key();

        let message = b"SLH-DSA SHA2-128s test for VBW";
        let sig = sk.sign(message);

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::SlhDsaSha2_128s,
                &PublicKeyBytes(vk.to_bytes().to_vec()),
                message,
                &SignatureBytes(sig.to_bytes().to_vec()),
            )
            .unwrap();
        assert!(
            result.is_valid(),
            "SLH-DSA-SHA2-128s verification should pass"
        );
    }

    #[test]
    fn slh_dsa_sha2_128s_tampered_rejected() {
        use slh_dsa::signature::{Keypair, Signer};

        let provider = RustCryptoProvider;
        let mut rng = test_rng(99);
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut rng);
        let vk = sk.verifying_key();

        let sig = sk.sign(b"original");
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[100] ^= 0xFF; // tamper deep in the signature

        let result = provider.verify_signature(
            &SignatureAlgorithm::SlhDsaSha2_128s,
            &PublicKeyBytes(vk.to_bytes().to_vec()),
            b"original",
            &SignatureBytes(sig_bytes),
        );

        // Either verification fails or returns Invalid (tampered bytes may not parse)
        if let Ok(r) = result {
            assert!(!r.is_valid());
        }
    }

    // -----------------------------------------------------------------------
    // ML-KEM tests
    // -----------------------------------------------------------------------

    #[test]
    fn ml_kem_768_encapsulate_decapsulate_roundtrip() {
        use ml_kem::{Encapsulate, MlKem768};

        let provider = RustCryptoProvider;

        // Create a decapsulation key from a deterministic seed
        let seed = ml_kem::Seed::default(); // 64 zero bytes
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        // Encapsulate using test RNG
        let mut rng = test_rng(7);
        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);

        // Decapsulate via provider (uses same seed)
        let result = provider
            .decapsulate(
                &KemAlgorithm::MlKem768,
                &DecapsulationKey(ml_kem::Seed::default().to_vec()),
                &CiphertextBytes(ct.to_vec()),
            )
            .unwrap();

        // Shared secrets must match
        assert_eq!(
            result.0,
            k_send.as_slice(),
            "ML-KEM-768 shared secrets must match"
        );
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        use ml_kem::{Encapsulate, MlKem1024};

        let provider = RustCryptoProvider;
        let seed = ml_kem::Seed::default();
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        let mut rng = test_rng(13);
        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);

        let result = provider
            .decapsulate(
                &KemAlgorithm::MlKem1024,
                &DecapsulationKey(ml_kem::Seed::default().to_vec()),
                &CiphertextBytes(ct.to_vec()),
            )
            .unwrap();
        assert_eq!(result.0, k_send.as_slice());
    }

    // -----------------------------------------------------------------------
    // Hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn sha256_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha256, b"hello").unwrap();
        assert_eq!(digest.0.len(), 32);
        // Known SHA-256 of "hello"
        assert_eq!(
            digest.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha384_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha384, b"hello").unwrap();
        assert_eq!(digest.0.len(), 48);
    }

    #[test]
    fn sha512_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha512, b"hello").unwrap();
        assert_eq!(digest.0.len(), 64);
    }

    #[test]
    fn sha3_256_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha3_256, b"hello").unwrap();
        assert_eq!(digest.0.len(), 32);
    }

    #[test]
    fn sha3_384_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha3_384, b"hello").unwrap();
        assert_eq!(digest.0.len(), 48);
    }

    #[test]
    fn sha3_512_hash() {
        let provider = RustCryptoProvider;
        let digest = provider.hash(&HashAlgorithm::Sha3_512, b"hello").unwrap();
        assert_eq!(digest.0.len(), 64);
    }

    #[test]
    fn hash_deterministic() {
        let provider = RustCryptoProvider;
        let a = provider.hash(&HashAlgorithm::Sha384, b"data").unwrap();
        let b = provider.hash(&HashAlgorithm::Sha384, b"data").unwrap();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Provider metadata tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_id() {
        assert_eq!(RustCryptoProvider.provider_id(), "rustcrypto");
    }

    #[test]
    fn supported_algorithms_comprehensive() {
        let algs = RustCryptoProvider.supported_algorithms();
        let ids: Vec<&str> = algs.iter().map(|a| a.id.as_str()).collect();

        // ML-DSA
        assert!(ids.contains(&"ml-dsa-44"));
        assert!(ids.contains(&"ml-dsa-65"));
        assert!(ids.contains(&"ml-dsa-87"));

        // SLH-DSA SHA-2
        assert!(ids.contains(&"slh-dsa-sha2-128s"));
        assert!(ids.contains(&"slh-dsa-sha2-256s"));

        // SLH-DSA SHAKE
        assert!(ids.contains(&"slh-dsa-shake-128s"));
        assert!(ids.contains(&"slh-dsa-shake-256f"));

        // ML-KEM
        assert!(ids.contains(&"ml-kem-512"));
        assert!(ids.contains(&"ml-kem-768"));
        assert!(ids.contains(&"ml-kem-1024"));

        // Hashes (SHA-2)
        assert!(ids.contains(&"sha-256"));
        assert!(ids.contains(&"sha-384"));
        assert!(ids.contains(&"sha-512"));

        // Hashes (SHA-3)
        assert!(ids.contains(&"sha3-256"));
        assert!(ids.contains(&"sha3-384"));
        assert!(ids.contains(&"sha3-512"));
    }

    // -----------------------------------------------------------------------
    // Test RNG helper
    // -----------------------------------------------------------------------

    /// Creates a deterministic test RNG from a u64 seed.
    /// NOT cryptographically secure; only for reproducible test key generation.
    fn test_rng(seed: u64) -> TestRng {
        TestRng { state: seed }
    }

    struct TestRng {
        state: u64,
    }

    impl TestRng {
        fn splitmix64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            #[allow(clippy::cast_possible_truncation)]
            let val = self.splitmix64() as u32;
            Ok(val)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.splitmix64())
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            let mut i = 0;
            while i < dest.len() {
                let val = self.splitmix64().to_le_bytes();
                let remaining = dest.len() - i;
                let to_copy = remaining.min(8);
                dest[i..i + to_copy].copy_from_slice(&val[..to_copy]);
                i += to_copy;
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for TestRng {}
}
