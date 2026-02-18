//! Ed25519 signature verification provider using `ed25519-dalek`.
//!
//! This provider handles classical Ed25519 signature verification. It is
//! used as the classical component in hybrid (Ed25519 + ML-DSA) compositions
//! and as a standalone verifier for legacy attestations.
//!
//! ## Security
//!
//! Uses `verify_strict()` which rejects weak public keys and non-canonical
//! signatures. This is the recommended verification mode for new applications.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::crypto::algorithm::{
    AlgorithmDescriptor, HashAlgorithm, KemAlgorithm, MathFamily, NistLevel, SignatureAlgorithm,
};
use crate::crypto::errors::CryptoError;
use crate::crypto::{
    CiphertextBytes, CryptoProvider, DecapsulationKey, DigestBytes, PublicKeyBytes, SharedSecret,
    SignatureBytes, VerificationResult,
};

/// Ed25519 signature verification provider backed by `ed25519-dalek`.
pub struct Ed25519Provider;

impl CryptoProvider for Ed25519Provider {
    fn provider_id(&self) -> &'static str {
        "ed25519-dalek"
    }

    fn supported_algorithms(&self) -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            id: "ed25519".into(),
            nist_level: NistLevel::L1,
            math_family: MathFamily::EllipticCurve,
            quantum_safe: false,
            oid: Some("1.3.101.112".into()),
        }]
    }

    fn verify_signature(
        &self,
        algorithm: &SignatureAlgorithm,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<VerificationResult, CryptoError> {
        if *algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CryptoError::UnsupportedAlgorithm(algorithm.id()));
        }

        // Parse public key (32 bytes)
        let pk_bytes: &[u8; 32] = public_key.0.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidKeyMaterial(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.0.len()
            ))
        })?;

        let vk = VerifyingKey::from_bytes(pk_bytes).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!("invalid Ed25519 public key: {e}"))
        })?;

        // Parse signature (64 bytes)
        let sig = Signature::try_from(signature.0.as_slice()).map_err(|e| {
            CryptoError::VerificationFailed {
                algorithm: "ed25519".into(),
                reason: format!("malformed signature: {e}"),
            }
        })?;

        // Strict verification (rejects weak keys and non-canonical signatures).
        //
        // Constant-time audit note:
        // `ed25519-dalek` uses `verify_strict()` which internally computes
        // the verification equation R = [s]B - [H(R,A,M)]A using Edwards
        // curve arithmetic. The final comparison uses `CtEq` (constant-time
        // equality from the `subtle` crate) to compare the computed R against
        // the claimed R in the signature, preventing timing side-channels.
        match vk.verify_strict(message, &sig) {
            Ok(()) => Ok(VerificationResult::Valid),
            Err(_) => Ok(VerificationResult::Invalid {
                reason: "Ed25519 signature verification failed".into(),
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: &KemAlgorithm,
        _secret_key: &DecapsulationKey,
        _ciphertext: &CiphertextBytes,
    ) -> Result<SharedSecret, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(format!(
            "Ed25519 provider does not support KEM: {}",
            algorithm.id()
        )))
    }

    fn hash(&self, algorithm: &HashAlgorithm, _data: &[u8]) -> Result<DigestBytes, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(format!(
            "Ed25519 provider does not support hashing: {}",
            algorithm.id()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::similar_names)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
        // Deterministic seed for reproducible tests
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn verify_valid_ed25519_signature() {
        let provider = Ed25519Provider;
        let (sk, vk) = generate_test_keypair();
        let message = b"test message for VBW PQC layer";
        let sig = sk.sign(message);

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::Ed25519,
                &PublicKeyBytes(vk.to_bytes().to_vec()),
                message,
                &SignatureBytes(sig.to_bytes().to_vec()),
            )
            .unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn reject_tampered_ed25519_signature() {
        let provider = Ed25519Provider;
        let (sk, vk) = generate_test_keypair();
        let message = b"test message";
        let sig = sk.sign(message);

        // Tamper with the signature
        let mut tampered = sig.to_bytes().to_vec();
        tampered[0] ^= 0xFF;

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::Ed25519,
                &PublicKeyBytes(vk.to_bytes().to_vec()),
                message,
                &SignatureBytes(tampered),
            )
            .unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn reject_wrong_message() {
        let provider = Ed25519Provider;
        let (sk, vk) = generate_test_keypair();
        let sig = sk.sign(b"original message");

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::Ed25519,
                &PublicKeyBytes(vk.to_bytes().to_vec()),
                b"different message",
                &SignatureBytes(sig.to_bytes().to_vec()),
            )
            .unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn reject_wrong_key() {
        let provider = Ed25519Provider;
        let (sk, _) = generate_test_keypair();
        let message = b"test";
        let sig = sk.sign(message);

        // Use a different key
        let other_sk = SigningKey::from_bytes(&[0xAA; 32]);
        let other_vk = other_sk.verifying_key();

        let result = provider
            .verify_signature(
                &SignatureAlgorithm::Ed25519,
                &PublicKeyBytes(other_vk.to_bytes().to_vec()),
                message,
                &SignatureBytes(sig.to_bytes().to_vec()),
            )
            .unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn reject_wrong_algorithm() {
        let provider = Ed25519Provider;
        let result = provider.verify_signature(
            &SignatureAlgorithm::MlDsa65,
            &PublicKeyBytes(vec![0; 32]),
            b"msg",
            &SignatureBytes(vec![0; 64]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_key_length() {
        let provider = Ed25519Provider;
        let result = provider.verify_signature(
            &SignatureAlgorithm::Ed25519,
            &PublicKeyBytes(vec![0; 33]), // wrong length
            b"msg",
            &SignatureBytes(vec![0; 64]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn provider_id_is_correct() {
        assert_eq!(Ed25519Provider.provider_id(), "ed25519-dalek");
    }

    #[test]
    fn supported_algorithms_lists_ed25519() {
        let algs = Ed25519Provider.supported_algorithms();
        assert_eq!(algs.len(), 1);
        assert_eq!(algs[0].id, "ed25519");
        assert!(!algs[0].quantum_safe);
    }

    #[test]
    fn kem_unsupported() {
        let result = Ed25519Provider.decapsulate(
            &KemAlgorithm::MlKem768,
            &DecapsulationKey(vec![]),
            &CiphertextBytes(vec![]),
        );
        assert!(result.is_err());
    }
}
