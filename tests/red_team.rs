//! Red team attack surface tests for VBW's post-quantum crypto-agile layer.
//!
//! These tests simulate adversarial inputs to verify that the crypto subsystem
//! handles them gracefully — returning proper errors rather than panicking,
//! accepting invalid inputs, or leaking internal state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use vbw::crypto::algorithm::{KemAlgorithm, MathFamily, SignatureAlgorithm};
use vbw::crypto::errors::CryptoError;
use vbw::crypto::hybrid::{verify_hybrid_signature, CompositeSignatureLayout};
use vbw::crypto::policy::{CryptoMode, CryptoPolicy, PolicyVerdict};
use vbw::crypto::registry::default_registry;
use vbw::crypto::{PublicKeyBytes, SignatureBytes};

// -------------------------------------------------------------------------
// (a) Algorithm confusion: ML-DSA-44 signature claiming to be ML-DSA-87
// -------------------------------------------------------------------------

#[test]
fn algorithm_confusion_ml_dsa_44_as_87() {
    use ml_dsa::signature::Signer;
    use ml_dsa::{KeyGen, MlDsa44};

    let registry = default_registry();

    // Generate ML-DSA-44 key and signature
    let seed = ml_dsa::B32::default();
    let kp = MlDsa44::from_seed(&seed);
    let vk = kp.verifying_key();
    let sk = kp.signing_key();
    let message = b"algorithm confusion test";
    let sig = sk.sign(message);

    // Submit ML-DSA-44 sig/key claiming to be ML-DSA-87
    let result = registry.verify_signature(
        &SignatureAlgorithm::MlDsa87,
        &PublicKeyBytes(vk.encode().to_vec()),
        message,
        &SignatureBytes(sig.encode().to_vec()),
    );

    // Must fail: wrong key/sig length for ML-DSA-87
    assert!(
        result.is_err() || !result.unwrap().is_valid(),
        "ML-DSA-44 sig must not verify as ML-DSA-87"
    );
}

// -------------------------------------------------------------------------
// (b) Downgrade attack: Ed25519-only signature against hybrid Level 3 policy
// -------------------------------------------------------------------------

#[test]
fn downgrade_attack_ed25519_in_hybrid_level3_policy() {
    let policy = CryptoPolicy::default(); // hybrid mode, min level 3
    let alg = SignatureAlgorithm::Ed25519;
    let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");

    // Ed25519 is Level 1, policy requires Level 3 minimum → rejected
    assert!(
        matches!(verdict, PolicyVerdict::Rejected(_)),
        "Ed25519-only signature must be rejected by hybrid mode Level 3 policy"
    );
}

// -------------------------------------------------------------------------
// (c) Cross-family bypass: Hybrid{Lattice, Lattice} composite
// -------------------------------------------------------------------------

#[test]
fn cross_family_bypass_lattice_lattice() {
    let policy = CryptoPolicy::default();

    // Attempt ML-DSA-65 + FN-DSA-512: both are Lattice
    let result = policy.check_hybrid_composition(&[MathFamily::Lattice, MathFamily::Lattice]);
    assert!(
        result.is_err(),
        "Hybrid{{Lattice, Lattice}} must be rejected by cross-family check"
    );

    // Verify the error is specifically about cross-family
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("different math families"),
        "error should mention math families: {err}"
    );
}

// -------------------------------------------------------------------------
// (d) Truncated composite: second component is 0 bytes
// -------------------------------------------------------------------------

#[test]
fn truncated_composite_second_component_empty() {
    let registry = default_registry();
    let policy = CryptoPolicy::default();

    // Layout claims 64 bytes for classical + 3309 bytes for PQC,
    // but only provide 64 bytes total (PQC component missing)
    let layout = CompositeSignatureLayout {
        first_offset: 0,
        first_length: 64,
        second_offset: 64,
        second_length: 0,
    };

    let result = verify_hybrid_signature(
        &registry,
        &SignatureAlgorithm::Ed25519,
        &SignatureAlgorithm::MlDsa65,
        &PublicKeyBytes(vec![0; 32]),
        &PublicKeyBytes(vec![0; 1952]),
        b"truncated test",
        &layout,
        &SignatureBytes(vec![0; 64]),
        &policy,
    );

    // Must return an error (InvalidEnvelope or verification failure), not panic
    // A 0-byte signature should fail gracefully
    match result {
        Ok(vr) => assert!(
            !vr.is_valid(),
            "truncated composite must not verify as valid"
        ),
        Err(e) => {
            // Expected: the verification fails cleanly
            let msg = e.to_string();
            assert!(!msg.is_empty(), "error should have a meaningful message");
        }
    }
}

// -------------------------------------------------------------------------
// (e) Empty key material: 0-byte public keys and signatures
// -------------------------------------------------------------------------

#[test]
fn empty_key_material_ed25519() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::Ed25519,
        &PublicKeyBytes(vec![]),
        b"msg",
        &SignatureBytes(vec![]),
    );
    // Must not panic
    assert!(result.is_err(), "empty Ed25519 key must fail");
}

#[test]
fn empty_key_material_ml_dsa_44() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::MlDsa44,
        &PublicKeyBytes(vec![]),
        b"msg",
        &SignatureBytes(vec![]),
    );
    assert!(result.is_err(), "empty ML-DSA-44 key must fail");
}

#[test]
fn empty_key_material_ml_dsa_65() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::MlDsa65,
        &PublicKeyBytes(vec![]),
        b"msg",
        &SignatureBytes(vec![]),
    );
    assert!(result.is_err(), "empty ML-DSA-65 key must fail");
}

#[test]
fn empty_key_material_ml_dsa_87() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::MlDsa87,
        &PublicKeyBytes(vec![]),
        b"msg",
        &SignatureBytes(vec![]),
    );
    assert!(result.is_err(), "empty ML-DSA-87 key must fail");
}

#[test]
fn empty_key_material_slh_dsa_sha2_128s() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::SlhDsaSha2_128s,
        &PublicKeyBytes(vec![]),
        b"msg",
        &SignatureBytes(vec![]),
    );
    assert!(result.is_err(), "empty SLH-DSA key must fail");
}

// -------------------------------------------------------------------------
// (f) Integer overflow in CompositeSignatureLayout
// -------------------------------------------------------------------------

#[test]
fn integer_overflow_first_offset() {
    let registry = default_registry();
    let policy = CryptoPolicy::default();

    let layout = CompositeSignatureLayout {
        first_offset: usize::MAX,
        first_length: 1,
        second_offset: 0,
        second_length: 0,
    };

    let result = verify_hybrid_signature(
        &registry,
        &SignatureAlgorithm::Ed25519,
        &SignatureAlgorithm::MlDsa65,
        &PublicKeyBytes(vec![0; 32]),
        &PublicKeyBytes(vec![0; 1952]),
        b"overflow test",
        &layout,
        &SignatureBytes(vec![0; 100]),
        &policy,
    );

    assert!(
        result.is_err(),
        "first_offset=MAX must cause overflow error"
    );
    assert!(
        result.unwrap_err().to_string().contains("overflow"),
        "error should mention overflow"
    );
}

#[test]
fn integer_overflow_second_offset() {
    let registry = default_registry();
    let policy = CryptoPolicy::default();

    let layout = CompositeSignatureLayout {
        first_offset: 0,
        first_length: 0,
        second_offset: usize::MAX,
        second_length: 1,
    };

    let result = verify_hybrid_signature(
        &registry,
        &SignatureAlgorithm::Ed25519,
        &SignatureAlgorithm::MlDsa65,
        &PublicKeyBytes(vec![0; 32]),
        &PublicKeyBytes(vec![0; 1952]),
        b"overflow test 2",
        &layout,
        &SignatureBytes(vec![0; 100]),
        &policy,
    );

    assert!(
        result.is_err(),
        "second_offset=MAX must cause overflow error"
    );
    assert!(
        result.unwrap_err().to_string().contains("overflow"),
        "error should mention overflow"
    );
}

// -------------------------------------------------------------------------
// (g) Policy injection: minimum_security_level=0, classical-only
// -------------------------------------------------------------------------

#[test]
fn policy_injection_level_zero() {
    let json = r#"{
        "minimum_security_level": 0,
        "mode": "classical-only"
    }"#;
    let policy: CryptoPolicy = serde_json::from_str(json).unwrap();

    // NistLevel::from_u8(0) returns None, so policy should fall back to Level 3
    let alg = SignatureAlgorithm::MlDsa44; // Level 2
    let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");

    // With fallback to Level 3, ML-DSA-44 (Level 2) should be rejected
    assert!(
        matches!(verdict, PolicyVerdict::Rejected(ref msg) if msg.contains("level")),
        "level 0 should fall back to Level 3, rejecting Level 2 algorithm: {verdict:?}"
    );
}

#[test]
fn policy_injection_classical_only_mode() {
    let json = r#"{
        "minimum_security_level": 0,
        "mode": "classical-only"
    }"#;
    let policy: CryptoPolicy = serde_json::from_str(json).unwrap();
    assert_eq!(policy.mode, CryptoMode::ClassicalOnly);
    // Classical-only mode allows everything, but the min level enforcement
    // still applies (falls back to Level 3)
}

// -------------------------------------------------------------------------
// (h) Future algorithm probe: all stubbed algorithms
// -------------------------------------------------------------------------

#[test]
fn stubbed_fn_dsa_512_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::FnDsa512,
        &PublicKeyBytes(vec![0; 100]),
        b"probe",
        &SignatureBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_fn_dsa_1024_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::FnDsa1024,
        &PublicKeyBytes(vec![0; 100]),
        b"probe",
        &SignatureBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_ecdsa_p256_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::EcdsaP256,
        &PublicKeyBytes(vec![0; 64]),
        b"probe",
        &SignatureBytes(vec![0; 64]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_ecdsa_p384_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::EcdsaP384,
        &PublicKeyBytes(vec![0; 96]),
        b"probe",
        &SignatureBytes(vec![0; 96]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_hqc_128_returns_unsupported() {
    let registry = default_registry();
    let result = registry.decapsulate(
        &KemAlgorithm::Hqc128,
        &vbw::crypto::DecapsulationKey(vec![0; 64]),
        &vbw::crypto::CiphertextBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_hqc_192_returns_unsupported() {
    let registry = default_registry();
    let result = registry.decapsulate(
        &KemAlgorithm::Hqc192,
        &vbw::crypto::DecapsulationKey(vec![0; 64]),
        &vbw::crypto::CiphertextBytes(vec![0; 100]),
    );
    assert!(result.is_err());
}

#[test]
fn stubbed_hqc_256_returns_unsupported() {
    let registry = default_registry();
    let result = registry.decapsulate(
        &KemAlgorithm::Hqc256,
        &vbw::crypto::DecapsulationKey(vec![0; 64]),
        &vbw::crypto::CiphertextBytes(vec![0; 100]),
    );
    assert!(result.is_err());
}

#[test]
fn stubbed_lms_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::Lms,
        &PublicKeyBytes(vec![0; 100]),
        b"probe",
        &SignatureBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}

#[test]
fn stubbed_xmss_returns_unsupported() {
    let registry = default_registry();
    let result = registry.verify_signature(
        &SignatureAlgorithm::Xmss,
        &PublicKeyBytes(vec![0; 100]),
        b"probe",
        &SignatureBytes(vec![0; 100]),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::UnsupportedAlgorithm(msg) => {
            assert!(msg.contains("not yet implemented"));
        }
        other => panic!("expected UnsupportedAlgorithm, got: {other}"),
    }
}
