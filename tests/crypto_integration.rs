//! Integration tests for VBW's post-quantum crypto-agile layer.
//!
//! These tests validate that the crypto subsystem works as a whole:
//! registry + providers + policy + algorithms interoperate correctly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use vbw::crypto::algorithm::KemAlgorithm;
use vbw::crypto::errors::CryptoError;
use vbw::crypto::policy::CryptoPolicy;
use vbw::crypto::registry::default_registry;

/// Every KEM algorithm listed in the default policy's preference list must have
/// a registered (non-stub) provider. This test catches "phantom default" bugs
/// where a default preference references an algorithm with no provider.
#[test]
fn default_kem_preferences_all_have_providers() {
    let registry = default_registry();
    let policy = CryptoPolicy::default();

    for kem_id in &policy.kem_algorithms {
        let kem = KemAlgorithm::from_id(kem_id)
            .unwrap_or_else(|| panic!("default KEM preference '{}' is not a valid KEM ID", kem_id));

        assert!(
            registry.supports_kem(&kem),
            "default KEM preference '{}' has no registered provider — \
             this is a phantom default bug",
            kem_id,
        );
    }
}

/// Every signature algorithm listed in the default policy must parse and have
/// a registered provider (for at least the leaf components).
#[test]
fn default_signature_preferences_all_parseable() {
    let policy = CryptoPolicy::default();
    let parsed = policy.preferred_signature_algorithms();

    assert_eq!(
        parsed.len(),
        policy.signature_algorithms.len(),
        "all default signature algorithms must parse successfully"
    );
}

/// Attempting to decapsulate with a KEM that has no provider should return
/// `UnsupportedAlgorithm`, not panic.
#[test]
fn unregistered_kem_returns_unsupported_error() {
    let registry = default_registry();
    let result = registry.decapsulate(
        &KemAlgorithm::Hqc128,
        &vbw::crypto::DecapsulationKey(vec![0; 64]),
        &vbw::crypto::CiphertextBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("hqc-128") || msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}
