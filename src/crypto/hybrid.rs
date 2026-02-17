//! Hybrid and dual-PQC verification engine.
//!
//! This module implements the composition logic for hybrid (classical + PQC)
//! and dual-PQC (e.g., lattice + hash-based) signature verification. It
//! enforces the **cross-family requirement**: composite components must come
//! from different mathematical families.
//!
//! ## Verification Logic
//!
//! For any composite signature:
//! 1. Parse the concatenated signature into its component parts.
//! 2. Verify **each** component independently using its provider.
//! 3. **Both** components must pass (AND logic).
//! 4. If either fails, the composite verification fails.
//!
//! This ensures that a composite signature is at least as strong as its
//! strongest component.

use super::algorithm::{MathFamily, SignatureAlgorithm};
use super::errors::CryptoError;
use super::policy::CryptoPolicy;
use super::registry::AlgorithmRegistry;
use super::{PublicKeyBytes, SignatureBytes, VerificationResult};

/// Metadata describing the byte layout of a composite signature.
#[derive(Clone, Debug)]
pub struct CompositeSignatureLayout {
    /// Byte offset where the first component starts.
    pub first_offset: usize,
    /// Byte length of the first component.
    pub first_length: usize,
    /// Byte offset where the second component starts.
    pub second_offset: usize,
    /// Byte length of the second component.
    pub second_length: usize,
}

/// Metadata describing the byte layout of composite public keys.
#[derive(Clone, Debug)]
pub struct CompositeKeyLayout {
    /// Byte offset where the first component key starts.
    pub first_offset: usize,
    /// Byte length of the first component key.
    pub first_length: usize,
    /// Byte offset where the second component key starts.
    pub second_offset: usize,
    /// Byte length of the second component key.
    pub second_length: usize,
}

/// Validates that a hybrid or dual-PQC composition satisfies cross-family
/// requirements.
///
/// This enforces the architectural rule: if one mathematical family is broken,
/// the other component must still provide security.
pub fn validate_cross_family(
    families: &[MathFamily],
    policy: &CryptoPolicy,
) -> Result<(), CryptoError> {
    policy.check_hybrid_composition(families)
}

/// Verifies a hybrid (classical + PQC) signature.
///
/// Both the classical and PQC components must verify successfully.
/// The signature bytes are split according to the provided layout.
pub fn verify_hybrid_signature(
    registry: &AlgorithmRegistry,
    classical: &SignatureAlgorithm,
    pqc: &SignatureAlgorithm,
    classical_key: &PublicKeyBytes,
    pqc_key: &PublicKeyBytes,
    message: &[u8],
    sig_layout: &CompositeSignatureLayout,
    signature: &SignatureBytes,
    policy: &CryptoPolicy,
) -> Result<VerificationResult, CryptoError> {
    // 1. Enforce cross-family requirement
    let mut families = classical.math_family();
    families.extend(pqc.math_family());
    validate_cross_family(&families, policy)?;

    // 2. Split signature bytes
    let sig_bytes = &signature.0;

    let first_end = sig_layout
        .first_offset
        .checked_add(sig_layout.first_length)
        .ok_or_else(|| CryptoError::InvalidEnvelope("signature layout overflow".into()))?;
    let second_end = sig_layout
        .second_offset
        .checked_add(sig_layout.second_length)
        .ok_or_else(|| CryptoError::InvalidEnvelope("signature layout overflow".into()))?;

    if first_end > sig_bytes.len() || second_end > sig_bytes.len() {
        return Err(CryptoError::InvalidEnvelope(format!(
            "signature too short: {} bytes, need at least {}",
            sig_bytes.len(),
            std::cmp::max(first_end, second_end)
        )));
    }

    let classical_sig = SignatureBytes(
        sig_bytes
            .get(sig_layout.first_offset..first_end)
            .ok_or_else(|| CryptoError::InvalidEnvelope("classical sig slice failed".into()))?
            .to_vec(),
    );
    let pqc_sig = SignatureBytes(
        sig_bytes
            .get(sig_layout.second_offset..second_end)
            .ok_or_else(|| CryptoError::InvalidEnvelope("PQC sig slice failed".into()))?
            .to_vec(),
    );

    // 3. Verify classical component
    let classical_result =
        registry.verify_signature(classical, classical_key, message, &classical_sig)?;
    if !classical_result.is_valid() {
        return Ok(VerificationResult::Invalid {
            reason: format!("classical component ({}) failed", classical.id()),
        });
    }

    // 4. Verify PQC component
    let pqc_result = registry.verify_signature(pqc, pqc_key, message, &pqc_sig)?;
    if !pqc_result.is_valid() {
        return Ok(VerificationResult::Invalid {
            reason: format!("PQC component ({}) failed", pqc.id()),
        });
    }

    // Both passed
    Ok(VerificationResult::Valid)
}

/// Verifies a dual-PQC signature (two PQC algorithms from different families).
///
/// Uses the same AND logic as hybrid: both must verify.
pub fn verify_dual_pqc_signature(
    registry: &AlgorithmRegistry,
    primary: &SignatureAlgorithm,
    backup: &SignatureAlgorithm,
    primary_key: &PublicKeyBytes,
    backup_key: &PublicKeyBytes,
    message: &[u8],
    sig_layout: &CompositeSignatureLayout,
    signature: &SignatureBytes,
    policy: &CryptoPolicy,
) -> Result<VerificationResult, CryptoError> {
    // 1. Enforce cross-family requirement
    let mut families = primary.math_family();
    families.extend(backup.math_family());
    validate_cross_family(&families, policy)?;

    // 2. Split signature bytes
    let sig_bytes = &signature.0;

    let first_end = sig_layout
        .first_offset
        .checked_add(sig_layout.first_length)
        .ok_or_else(|| CryptoError::InvalidEnvelope("signature layout overflow".into()))?;
    let second_end = sig_layout
        .second_offset
        .checked_add(sig_layout.second_length)
        .ok_or_else(|| CryptoError::InvalidEnvelope("signature layout overflow".into()))?;

    if first_end > sig_bytes.len() || second_end > sig_bytes.len() {
        return Err(CryptoError::InvalidEnvelope(format!(
            "signature too short: {} bytes, need at least {}",
            sig_bytes.len(),
            std::cmp::max(first_end, second_end)
        )));
    }

    let primary_sig = SignatureBytes(
        sig_bytes
            .get(sig_layout.first_offset..first_end)
            .ok_or_else(|| CryptoError::InvalidEnvelope("primary sig slice failed".into()))?
            .to_vec(),
    );
    let backup_sig = SignatureBytes(
        sig_bytes
            .get(sig_layout.second_offset..second_end)
            .ok_or_else(|| CryptoError::InvalidEnvelope("backup sig slice failed".into()))?
            .to_vec(),
    );

    // 3. Verify primary component
    let primary_result = registry.verify_signature(primary, primary_key, message, &primary_sig)?;
    if !primary_result.is_valid() {
        return Ok(VerificationResult::Invalid {
            reason: format!("primary PQC component ({}) failed", primary.id()),
        });
    }

    // 4. Verify backup component
    let backup_result = registry.verify_signature(backup, backup_key, message, &backup_sig)?;
    if !backup_result.is_valid() {
        return Ok(VerificationResult::Invalid {
            reason: format!("backup PQC component ({}) failed", backup.id()),
        });
    }

    Ok(VerificationResult::Valid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cross_family_validation_same_family_rejected() {
        let policy = CryptoPolicy::default();
        let result = validate_cross_family(&[MathFamily::Lattice, MathFamily::Lattice], &policy);
        assert!(result.is_err());
    }

    #[test]
    fn cross_family_validation_different_families_ok() {
        let policy = CryptoPolicy::default();
        let result =
            validate_cross_family(&[MathFamily::EllipticCurve, MathFamily::Lattice], &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn cross_family_validation_lattice_hashbased_ok() {
        let policy = CryptoPolicy::default();
        let result = validate_cross_family(&[MathFamily::Lattice, MathFamily::HashBased], &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn composite_signature_layout_overflow_check() {
        let layout = CompositeSignatureLayout {
            first_offset: usize::MAX,
            first_length: 1,
            second_offset: 0,
            second_length: 0,
        };
        let registry = super::super::registry::default_registry();
        let policy = CryptoPolicy::default();

        let result = verify_hybrid_signature(
            &registry,
            &SignatureAlgorithm::Ed25519,
            &SignatureAlgorithm::MlDsa65,
            &PublicKeyBytes(vec![0; 32]),
            &PublicKeyBytes(vec![0; 1952]),
            b"test",
            &layout,
            &SignatureBytes(vec![0; 100]),
            &policy,
        );
        assert!(result.is_err());
    }
}
