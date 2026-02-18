//! Algorithm Migration Demo for VBW's Post-Quantum Crypto-Agile Layer
//!
//! This example demonstrates the migration path VBW supports:
//!
//! 1. Classical-only (Ed25519) — policy warns
//! 2. Hybrid (Ed25519 + ML-DSA-65) — passes hybrid policy
//! 3. Dual-PQC (ML-DSA-65 + SLH-DSA-256s) — pure post-quantum
//! 4. PQC-only mode — classical-only is rejected
//!
//! Each step uses the same registry but changes only the policy mode,
//! demonstrating crypto-agility without code changes.
//!
//! Run with: `cargo run --example algorithm-migration`

#![allow(clippy::unwrap_used)]

use vbw::crypto::algorithm::SignatureAlgorithm;
use vbw::crypto::policy::{CryptoMode, CryptoPolicy, PolicyVerdict};
use vbw::crypto::registry::default_registry;

fn main() {
    let registry = default_registry();

    println!("=== VBW Algorithm Migration Demo ===");
    println!();

    // Validate that the default policy has no phantom defaults
    let default_policy = CryptoPolicy::default();
    let warnings = registry.validate_defaults(&default_policy);
    if warnings.is_empty() {
        println!("[OK] Default policy has no unusable algorithm preferences.");
    } else {
        println!("[WARN] Default policy has unusable preferences:");
        for w in &warnings {
            println!("  - {w}");
        }
    }
    println!();

    // ---- Step 1: Classical-only (Ed25519) with hybrid policy ----
    println!("--- Step 1: Classical-only (Ed25519) with Hybrid policy ---");
    let hybrid_policy = CryptoPolicy {
        minimum_security_level: 1, // lower to show mode check
        mode: CryptoMode::Hybrid,
        ..CryptoPolicy::default()
    };

    let ed25519 = SignatureAlgorithm::Ed25519;
    let verdict = hybrid_policy.check_signature_algorithm(&ed25519, "2025-06-01");
    print_verdict("Ed25519", &verdict);
    // Expected: Warn (classical-only in hybrid mode, before deadline)
    println!();

    // ---- Step 2: Hybrid (Ed25519 + ML-DSA-65) ----
    println!("--- Step 2: Hybrid (Ed25519 + ML-DSA-65) ---");
    let hybrid_alg = SignatureAlgorithm::from_id("ed25519+ml-dsa-65").unwrap();
    let verdict = hybrid_policy.check_signature_algorithm(&hybrid_alg, "2025-06-01");
    print_verdict("ed25519+ml-dsa-65", &verdict);
    println!("  Quantum-safe: {}", hybrid_alg.is_quantum_safe());
    println!("  Composite: {}", hybrid_alg.is_composite());
    println!("  NIST Level: {}", hybrid_alg.nist_level().value());
    println!();

    // ---- Step 3: Dual-PQC (ML-DSA-65 + SLH-DSA-256s) ----
    println!("--- Step 3: Dual-PQC (ML-DSA-65 + SLH-DSA-256s) ---");
    let dual_pqc = SignatureAlgorithm::from_id("ml-dsa-65+slh-dsa-sha2-256s").unwrap();
    let verdict = hybrid_policy.check_signature_algorithm(&dual_pqc, "2025-06-01");
    print_verdict("ml-dsa-65+slh-dsa-sha2-256s", &verdict);
    println!("  Quantum-safe: {}", dual_pqc.is_quantum_safe());
    println!("  Families: {:?}", dual_pqc.math_family());
    println!();

    // ---- Step 4: PQC-only mode — classical-only rejected ----
    println!("--- Step 4: PQC-only mode ---");
    let pqc_policy = CryptoPolicy {
        minimum_security_level: 1,
        mode: CryptoMode::PqcOnly,
        ..CryptoPolicy::default()
    };

    let verdict = pqc_policy.check_signature_algorithm(&ed25519, "2025-06-01");
    print_verdict("Ed25519 in PQC-only", &verdict);
    // Expected: Rejected

    let ml_dsa_65 = SignatureAlgorithm::MlDsa65;
    let verdict = pqc_policy.check_signature_algorithm(&ml_dsa_65, "2025-06-01");
    print_verdict("ML-DSA-65 in PQC-only", &verdict);
    // Expected: Allowed
    println!();

    // ---- Bonus: CNSA 2.0 mode ----
    println!("--- Bonus: CNSA 2.0 mode ---");
    let cnsa2_policy = CryptoPolicy {
        minimum_security_level: 1,
        mode: CryptoMode::CnSa2,
        ..CryptoPolicy::default()
    };

    let verdict =
        cnsa2_policy.check_signature_algorithm(&SignatureAlgorithm::MlDsa87, "2025-06-01");
    print_verdict("ML-DSA-87 in CNSA 2.0", &verdict);

    let verdict =
        cnsa2_policy.check_signature_algorithm(&SignatureAlgorithm::MlDsa65, "2025-06-01");
    print_verdict("ML-DSA-65 in CNSA 2.0", &verdict);
    // Expected: Rejected (Level 3 < Level 5 required)

    println!();
    println!("=== Migration demo complete ===");
    println!("VBW supports migrating from classical → hybrid → pure PQC → CNSA 2.0");
    println!("by changing only the policy configuration. No code changes needed.");
}

fn print_verdict(label: &str, verdict: &PolicyVerdict) {
    match verdict {
        PolicyVerdict::Allowed => println!("  [ALLOWED]  {label}"),
        PolicyVerdict::Warn(msg) => println!("  [WARN]     {label}: {msg}"),
        PolicyVerdict::Rejected(msg) => println!("  [REJECTED] {label}: {msg}"),
    }
}
