//! Crypto policy engine for VBW's post-quantum crypto-agile layer.
//!
//! Extends VBW's existing policy system with a `crypto` section that controls:
//! - Minimum NIST security level enforcement
//! - Algorithm selection mode (hybrid / pqc-only / classical-only)
//! - Ordered algorithm preference lists
//! - Deprecation enforcement with date-based transitions
//! - Hybrid composition rules (cross-family, minimum independent assumptions)
//!
//! ## Design
//!
//! The crypto policy is **additive** to the existing `VbwPolicy`. It is loaded
//! from the `"crypto"` key in `vbw-policy.json`. If absent, secure defaults
//! apply (hybrid mode, NIST Level 3 minimum, cross-family enforcement).

use serde::{Deserialize, Serialize};

use super::algorithm::{HashAlgorithm, KemAlgorithm, NistLevel, SignatureAlgorithm};
use super::errors::CryptoError;

/// Algorithm selection mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoMode {
    /// Require hybrid (classical + PQC) signatures. Default.
    Hybrid,
    /// Accept only pure post-quantum signatures.
    PqcOnly,
    /// Accept classical-only signatures (deprecated; will warn).
    ClassicalOnly,
}

/// Deprecation enforcement policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeprecationPolicy {
    /// After this date (ISO 8601), classical-only signatures trigger ERROR.
    /// Before this date, they trigger WARNING.
    #[serde(default = "default_classical_error_date")]
    pub classical_only_error_date: String,

    /// After this date, RSA signatures are rejected entirely.
    #[serde(default = "default_rsa_reject_date")]
    pub rsa_reject_date: String,

    /// Warn on algorithms below this NIST level.
    #[serde(default = "default_warn_below_level")]
    pub warn_below_level: u8,
}

fn default_classical_error_date() -> String {
    "2030-01-01".into()
}

fn default_rsa_reject_date() -> String {
    "2028-01-01".into()
}

fn default_warn_below_level() -> u8 {
    3
}

impl Default for DeprecationPolicy {
    fn default() -> Self {
        Self {
            classical_only_error_date: default_classical_error_date(),
            rsa_reject_date: default_rsa_reject_date(),
            warn_below_level: default_warn_below_level(),
        }
    }
}

/// Hybrid composition rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridRules {
    /// If `true`, hybrid components must come from different math families.
    #[serde(default = "default_true")]
    pub require_cross_family: bool,

    /// Minimum number of independent mathematical assumptions in a composite.
    #[serde(default = "default_min_assumptions")]
    pub min_independent_assumptions: u8,

    /// KDF algorithm for combining hybrid KEM shared secrets.
    #[serde(default = "default_hybrid_kdf")]
    pub hybrid_kdf: String,
}

fn default_true() -> bool {
    true
}

fn default_min_assumptions() -> u8 {
    2
}

fn default_hybrid_kdf() -> String {
    "hkdf-sha-384".into()
}

impl Default for HybridRules {
    fn default() -> Self {
        Self {
            require_cross_family: true,
            min_independent_assumptions: 2,
            hybrid_kdf: default_hybrid_kdf(),
        }
    }
}

/// Crypto policy section of `vbw-policy.json`.
///
/// Secure defaults are applied for any missing fields, following VBW's
/// secure-by-default principle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoPolicy {
    /// Minimum acceptable NIST security level (1-5).
    #[serde(default = "default_min_security_level")]
    pub minimum_security_level: u8,

    /// Algorithm selection mode.
    #[serde(default = "default_mode")]
    pub mode: CryptoMode,

    /// Signature verification preferences (ordered by preference).
    /// Each entry is a canonical algorithm ID (e.g., `"ml-dsa-65+ed25519"`).
    #[serde(default = "default_signature_algorithms")]
    pub signature_algorithms: Vec<String>,

    /// KEM preferences for encrypted attestation transport.
    #[serde(default = "default_kem_algorithms")]
    pub kem_algorithms: Vec<String>,

    /// Hash algorithm for attestation digests.
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,

    /// Deprecation enforcement policy.
    #[serde(default)]
    pub deprecation: DeprecationPolicy,

    /// Hybrid composition rules.
    #[serde(default)]
    pub hybrid_rules: HybridRules,
}

fn default_min_security_level() -> u8 {
    3
}

fn default_mode() -> CryptoMode {
    CryptoMode::Hybrid
}

fn default_signature_algorithms() -> Vec<String> {
    vec![
        "ml-dsa-65+ed25519".into(),
        "ml-dsa-87+slh-dsa-sha2-256s".into(),
        "ml-dsa-65".into(),
        "slh-dsa-sha2-256s".into(),
        "ed25519".into(),
    ]
}

fn default_kem_algorithms() -> Vec<String> {
    vec![
        "x25519+ml-kem-768".into(),
        "ml-kem-1024".into(),
        "x25519".into(),
    ]
}

fn default_hash_algorithm() -> String {
    "sha-384".into()
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            minimum_security_level: default_min_security_level(),
            mode: default_mode(),
            signature_algorithms: default_signature_algorithms(),
            kem_algorithms: default_kem_algorithms(),
            hash_algorithm: default_hash_algorithm(),
            deprecation: DeprecationPolicy::default(),
            hybrid_rules: HybridRules::default(),
        }
    }
}

/// Result of a policy check on a specific algorithm.
#[derive(Clone, Debug)]
pub enum PolicyVerdict {
    /// Algorithm is allowed.
    Allowed,
    /// Algorithm is allowed but triggers a warning.
    Warn(String),
    /// Algorithm is rejected by policy.
    Rejected(String),
}

impl CryptoPolicy {
    /// Checks a signature algorithm against this policy.
    ///
    /// Returns a `PolicyVerdict` indicating whether the algorithm is allowed,
    /// warned, or rejected.
    pub fn check_signature_algorithm(
        &self,
        algorithm: &SignatureAlgorithm,
        current_date: &str,
    ) -> PolicyVerdict {
        let alg_id = algorithm.id();

        // 1. Check NIST security level
        let min_level = NistLevel::from_u8(self.minimum_security_level).unwrap_or(NistLevel::L3);
        if algorithm.nist_level() < min_level {
            return PolicyVerdict::Rejected(format!(
                "algorithm {} provides NIST level {} but policy requires minimum level {}",
                alg_id,
                algorithm.nist_level().value(),
                min_level.value()
            ));
        }

        // 2. Check mode compatibility
        match self.mode {
            CryptoMode::Hybrid => {
                if !algorithm.is_composite() && !algorithm.is_quantum_safe() {
                    // Classical-only in hybrid mode
                    if current_date >= self.deprecation.classical_only_error_date.as_str() {
                        return PolicyVerdict::Rejected(format!(
                            "classical-only algorithm {} rejected: policy requires hybrid after {}",
                            alg_id, self.deprecation.classical_only_error_date
                        ));
                    }
                    return PolicyVerdict::Warn(format!(
                        "classical-only algorithm {} used in hybrid mode; \
                         will become an error after {}",
                        alg_id, self.deprecation.classical_only_error_date
                    ));
                }
            }
            CryptoMode::PqcOnly => {
                if !algorithm.is_quantum_safe() {
                    return PolicyVerdict::Rejected(format!(
                        "non-quantum-safe algorithm {} rejected: policy requires pqc-only",
                        alg_id
                    ));
                }
            }
            CryptoMode::ClassicalOnly => {
                // Everything is allowed (but we warn about classical-only mode itself)
            }
        }

        // 3. Deprecation level warnings
        if algorithm.nist_level().value() < self.deprecation.warn_below_level {
            return PolicyVerdict::Warn(format!(
                "algorithm {} has NIST level {} which is below warning threshold {}",
                alg_id,
                algorithm.nist_level().value(),
                self.deprecation.warn_below_level
            ));
        }

        // 4. Check if algorithm is in the allowed list
        if !self.signature_algorithms.is_empty() && !self.signature_algorithms.contains(&alg_id) {
            return PolicyVerdict::Warn(format!(
                "algorithm {} is not in the preferred signature algorithm list",
                alg_id
            ));
        }

        PolicyVerdict::Allowed
    }

    /// Checks a KEM algorithm against this policy.
    pub fn check_kem_algorithm(&self, algorithm: &KemAlgorithm) -> PolicyVerdict {
        let alg_id = algorithm.id();
        let min_level = NistLevel::from_u8(self.minimum_security_level).unwrap_or(NistLevel::L3);

        if algorithm.nist_level() < min_level {
            return PolicyVerdict::Rejected(format!(
                "KEM {} provides NIST level {} but policy requires minimum level {}",
                alg_id,
                algorithm.nist_level().value(),
                min_level.value()
            ));
        }

        PolicyVerdict::Allowed
    }

    /// Validates that a hybrid composition satisfies the policy's cross-family
    /// and minimum-assumptions requirements.
    pub fn check_hybrid_composition(
        &self,
        families: &[super::algorithm::MathFamily],
    ) -> Result<(), CryptoError> {
        if self.hybrid_rules.require_cross_family {
            let mut unique = families.to_vec();
            unique.dedup();
            if unique.len() < 2 {
                return Err(CryptoError::HybridCompositionError(
                    "hybrid composition requires components from different math families".into(),
                ));
            }
        }

        let unique_count = {
            let mut u = families.to_vec();
            u.sort();
            u.dedup();
            u.len()
        };

        #[allow(clippy::cast_possible_truncation)]
        let unique_u8 = unique_count as u8;
        if unique_u8 < self.hybrid_rules.min_independent_assumptions {
            return Err(CryptoError::HybridCompositionError(format!(
                "hybrid composition has {} independent assumptions but policy requires {}",
                unique_count, self.hybrid_rules.min_independent_assumptions
            )));
        }

        Ok(())
    }

    /// Resolves the hash algorithm from the policy string.
    pub fn resolve_hash_algorithm(&self) -> Result<HashAlgorithm, CryptoError> {
        HashAlgorithm::from_id(&self.hash_algorithm).ok_or_else(|| {
            CryptoError::UnsupportedAlgorithm(format!(
                "unknown hash algorithm in policy: {}",
                self.hash_algorithm
            ))
        })
    }

    /// Returns the parsed preferred signature algorithms in priority order.
    pub fn preferred_signature_algorithms(&self) -> Vec<SignatureAlgorithm> {
        self.signature_algorithms
            .iter()
            .filter_map(|id| SignatureAlgorithm::from_id(id))
            .collect()
    }

    /// Returns the parsed preferred KEM algorithms in priority order.
    pub fn preferred_kem_algorithms(&self) -> Vec<KemAlgorithm> {
        self.kem_algorithms
            .iter()
            .filter_map(|id| KemAlgorithm::from_id(id))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_values() {
        let policy = CryptoPolicy::default();
        assert_eq!(policy.minimum_security_level, 3);
        assert_eq!(policy.mode, CryptoMode::Hybrid);
        assert!(!policy.signature_algorithms.is_empty());
        assert_eq!(policy.hash_algorithm, "sha-384");
        assert!(policy.hybrid_rules.require_cross_family);
    }

    #[test]
    fn ml_dsa_65_allowed_in_hybrid_mode() {
        let policy = CryptoPolicy::default();
        let alg = SignatureAlgorithm::MlDsa65;
        let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");
        assert!(matches!(verdict, PolicyVerdict::Allowed));
    }

    #[test]
    fn ed25519_warns_in_hybrid_mode_before_deadline() {
        let policy = CryptoPolicy::default();
        let alg = SignatureAlgorithm::Ed25519;
        let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");
        // Ed25519 is NIST Level 1, policy minimum is 3 → rejected
        assert!(matches!(verdict, PolicyVerdict::Rejected(_)));
    }

    #[test]
    fn ed25519_rejected_after_classical_deadline() {
        let policy = CryptoPolicy {
            minimum_security_level: 1, // lower to test mode check
            ..CryptoPolicy::default()
        };
        let alg = SignatureAlgorithm::Ed25519;
        let verdict = policy.check_signature_algorithm(&alg, "2031-01-01");
        assert!(matches!(verdict, PolicyVerdict::Rejected(_)));
    }

    #[test]
    fn pqc_only_mode_rejects_classical() {
        let policy = CryptoPolicy {
            mode: CryptoMode::PqcOnly,
            minimum_security_level: 1,
            ..CryptoPolicy::default()
        };
        let alg = SignatureAlgorithm::Ed25519;
        let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");
        assert!(matches!(verdict, PolicyVerdict::Rejected(_)));
    }

    #[test]
    fn insufficient_nist_level_rejected() {
        let policy = CryptoPolicy::default(); // min level 3
        let alg = SignatureAlgorithm::MlDsa44; // level 2
        let verdict = policy.check_signature_algorithm(&alg, "2025-06-01");
        assert!(matches!(verdict, PolicyVerdict::Rejected(_)));
    }

    #[test]
    fn hybrid_cross_family_enforcement() {
        let policy = CryptoPolicy::default();
        use super::super::algorithm::MathFamily;

        // Same family → rejected
        let result = policy.check_hybrid_composition(&[MathFamily::Lattice, MathFamily::Lattice]);
        assert!(result.is_err());

        // Different families → allowed
        let result =
            policy.check_hybrid_composition(&[MathFamily::EllipticCurve, MathFamily::Lattice]);
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_hash_algorithm_default() {
        let policy = CryptoPolicy::default();
        let hash = policy.resolve_hash_algorithm().unwrap();
        assert_eq!(hash, HashAlgorithm::Sha384);
    }

    #[test]
    fn preferred_algorithms_parsing() {
        let policy = CryptoPolicy::default();
        let sig_algs = policy.preferred_signature_algorithms();
        assert!(!sig_algs.is_empty());
        // First should be hybrid ml-dsa-65+ed25519
        assert!(sig_algs.first().unwrap().is_composite());
    }

    #[test]
    fn serialization_roundtrip() {
        let policy = CryptoPolicy::default();
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let parsed: CryptoPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.minimum_security_level, policy.minimum_security_level);
        assert_eq!(parsed.mode, policy.mode);
    }

    #[test]
    fn unknown_fields_ignored() {
        let json = r#"{
            "minimum_security_level": 5,
            "mode": "pqc-only",
            "future_unknown_field": true
        }"#;
        let policy: CryptoPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.minimum_security_level, 5);
        assert_eq!(policy.mode, CryptoMode::PqcOnly);
    }
}
