//! Algorithm taxonomy for VBW's post-quantum crypto-agile layer.
//!
//! This module defines the full enum hierarchy for signature, KEM, and hash
//! algorithms. Each algorithm carries metadata about its NIST security level
//! and mathematical family, enabling the policy engine and hybrid composition
//! engine to enforce cross-family diversity and minimum security requirements.
//!
//! ## Design Rationale
//!
//! - **Enums over strings**: Algorithm selection is a closed set at any given
//!   VBW version. Enums give exhaustive match checking, preventing silent
//!   misrouting to a wrong algorithm.
//! - **`MathFamily` tagging**: Every algorithm declares which mathematical
//!   problem family it relies on. Hybrid compositions *must* combine
//!   algorithms from different families so that a single mathematical
//!   breakthrough cannot break both components.
//! - **Tiered support**: Finalized FIPS algorithms are fully implemented;
//!   draft algorithms (FN-DSA, HQC) are represented in the type system
//!   but return `UnsupportedAlgorithm` at runtime until their standards
//!   are finalized.

use serde::{Deserialize, Serialize};

/// Mathematical problem family underlying a cryptographic algorithm.
///
/// Hybrid compositions must combine algorithms from *different* families.
/// If one family's underlying hard problem is broken (e.g., lattice
/// problems fall to a quantum algorithm), the other family's component
/// still provides security.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MathFamily {
    /// Lattice-based (ML-KEM, ML-DSA, FN-DSA). Relies on Module-LWE / Module-SIS.
    Lattice,
    /// Hash-based (SLH-DSA, LMS, XMSS). Security reduces to hash function properties.
    HashBased,
    /// Code-based (HQC, Classic `McEliece`). Relies on decoding random linear codes.
    CodeBased,
    /// Elliptic curve (Ed25519, ECDSA). Classical; vulnerable to Shor's algorithm.
    EllipticCurve,
    /// Integer factoring (RSA). Classical; vulnerable to Shor's algorithm.
    Factoring,
}

/// NIST security levels (1-5) as defined in the PQC standardization process.
///
/// - Level 1: At least as hard to break as AES-128 (NIST category 1)
/// - Level 2: At least as hard to break as SHA-256 collision (NIST category 2)
/// - Level 3: At least as hard to break as AES-192 (NIST category 3)
/// - Level 4: At least as hard to break as SHA-384 collision (NIST category 4)
/// - Level 5: At least as hard to break as AES-256 (NIST category 5)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NistLevel(u8);

impl NistLevel {
    /// NIST Level 1 (~AES-128 equivalent).
    pub const L1: Self = Self(1);
    /// NIST Level 2 (~SHA-256 collision equivalent).
    pub const L2: Self = Self(2);
    /// NIST Level 3 (~AES-192 equivalent).
    pub const L3: Self = Self(3);
    /// NIST Level 4 (~SHA-384 collision equivalent).
    pub const L4: Self = Self(4);
    /// NIST Level 5 (~AES-256 equivalent).
    pub const L5: Self = Self(5);

    /// Returns the raw numeric level (1-5).
    pub fn value(self) -> u8 {
        self.0
    }

    /// Creates a `NistLevel` from a raw u8, clamping to the valid range 1-5.
    /// Returns `None` if the value is outside 1-5.
    pub fn from_u8(v: u8) -> Option<Self> {
        if (1..=5).contains(&v) {
            Some(Self(v))
        } else {
            None
        }
    }
}

/// Descriptor for an algorithm, combining its string identifier with metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlgorithmDescriptor {
    /// Canonical string identifier (e.g., `"ml-dsa-65"`, `"ed25519"`).
    pub id: String,
    /// NIST security level.
    pub nist_level: NistLevel,
    /// Mathematical problem family.
    pub math_family: MathFamily,
    /// Whether this algorithm is quantum-safe.
    pub quantum_safe: bool,
    /// OID (Object Identifier) if standardized.
    pub oid: Option<String>,
}

// ---------------------------------------------------------------------------
// Signature algorithms
// ---------------------------------------------------------------------------

/// Signature algorithm identifiers.
///
/// Each variant maps to a specific parameterization of a signature scheme.
/// Hybrid and dual-PQC compositions are first-class variants so that the
/// type system tracks composite algorithms explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    // -- FIPS 204: ML-DSA (CRYSTALS-Dilithium) --
    /// ML-DSA-44 (NIST Level 2).
    MlDsa44,
    /// ML-DSA-65 (NIST Level 3).
    MlDsa65,
    /// ML-DSA-87 (NIST Level 5).
    MlDsa87,

    // -- FIPS 205: SLH-DSA (SPHINCS+) SHA-2 variants --
    /// SLH-DSA-SHA2-128s (NIST Level 1, small signatures).
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (NIST Level 1, fast signing).
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (NIST Level 3, small signatures).
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (NIST Level 3, fast signing).
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (NIST Level 5, small signatures).
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (NIST Level 5, fast signing).
    SlhDsaSha2_256f,

    // -- FIPS 205: SLH-DSA (SPHINCS+) SHAKE variants --
    /// SLH-DSA-SHAKE-128s (NIST Level 1, small signatures).
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (NIST Level 1, fast signing).
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s (NIST Level 3, small signatures).
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f (NIST Level 3, fast signing).
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s (NIST Level 5, small signatures).
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (NIST Level 5, fast signing).
    SlhDsaShake256f,

    // -- FIPS 206 (draft): FN-DSA (FALCON) --
    /// FN-DSA-512 (NIST Level 1). Stub: not yet implemented.
    FnDsa512,
    /// FN-DSA-1024 (NIST Level 5). Stub: not yet implemented.
    FnDsa1024,

    // -- Classical (hybrid partners, deprecation path) --
    /// Ed25519 (classical, ~128-bit security pre-quantum).
    Ed25519,
    /// ECDSA with NIST P-256 (classical, ~128-bit security pre-quantum).
    EcdsaP256,
    /// ECDSA with NIST P-384 (classical, ~192-bit security pre-quantum).
    EcdsaP384,

    // -- Hybrid composites --
    /// Hybrid: classical + PQC. Both signatures must verify (AND logic).
    /// Components must be from different `MathFamily` values.
    Hybrid {
        /// Classical component (e.g., Ed25519).
        classical: Box<SignatureAlgorithm>,
        /// Post-quantum component (e.g., ML-DSA-65).
        pqc: Box<SignatureAlgorithm>,
    },

    /// Dual-PQC composite: two PQC algorithms from different math families.
    /// Both signatures must verify (AND logic).
    DualPqc {
        /// Primary PQC component (e.g., ML-DSA-65, lattice-based).
        primary: Box<SignatureAlgorithm>,
        /// Backup PQC component (e.g., SLH-DSA-256s, hash-based).
        backup: Box<SignatureAlgorithm>,
    },
}

impl SignatureAlgorithm {
    /// Returns the NIST security level for this algorithm.
    /// For composites, returns the *minimum* of the components.
    pub fn nist_level(&self) -> NistLevel {
        match self {
            Self::MlDsa44 => NistLevel::L2,

            Self::MlDsa65
            | Self::SlhDsaSha2_192s
            | Self::SlhDsaSha2_192f
            | Self::SlhDsaShake192s
            | Self::SlhDsaShake192f
            | Self::EcdsaP384 => NistLevel::L3,

            Self::MlDsa87
            | Self::SlhDsaSha2_256s
            | Self::SlhDsaSha2_256f
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f
            | Self::FnDsa1024 => NistLevel::L5,

            Self::SlhDsaSha2_128s
            | Self::SlhDsaSha2_128f
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::FnDsa512
            | Self::Ed25519
            | Self::EcdsaP256 => NistLevel::L1,

            Self::Hybrid { classical, pqc } => {
                std::cmp::min(classical.nist_level(), pqc.nist_level())
            }
            Self::DualPqc { primary, backup } => {
                std::cmp::min(primary.nist_level(), backup.nist_level())
            }
        }
    }

    /// Returns the mathematical family for this algorithm.
    /// For composites, returns the families of both components.
    pub fn math_family(&self) -> Vec<MathFamily> {
        match self {
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => {
                vec![MathFamily::Lattice]
            }
            Self::FnDsa512 | Self::FnDsa1024 => vec![MathFamily::Lattice],

            Self::SlhDsaSha2_128s
            | Self::SlhDsaSha2_128f
            | Self::SlhDsaSha2_192s
            | Self::SlhDsaSha2_192f
            | Self::SlhDsaSha2_256s
            | Self::SlhDsaSha2_256f
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake192s
            | Self::SlhDsaShake192f
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f => vec![MathFamily::HashBased],

            Self::Ed25519 | Self::EcdsaP256 | Self::EcdsaP384 => {
                vec![MathFamily::EllipticCurve]
            }

            Self::Hybrid { classical, pqc } => {
                let mut families = classical.math_family();
                families.extend(pqc.math_family());
                families
            }
            Self::DualPqc { primary, backup } => {
                let mut families = primary.math_family();
                families.extend(backup.math_family());
                families
            }
        }
    }

    /// Returns `true` if this algorithm (or all components of a composite)
    /// is quantum-safe. Hybrid compositions are considered quantum-safe
    /// because the PQC component provides post-quantum security (the
    /// classical component provides transitional security).
    pub fn is_quantum_safe(&self) -> bool {
        !matches!(self, Self::Ed25519 | Self::EcdsaP256 | Self::EcdsaP384)
    }

    /// Returns `true` if this is a composite (hybrid or dual-PQC) algorithm.
    pub fn is_composite(&self) -> bool {
        matches!(self, Self::Hybrid { .. } | Self::DualPqc { .. })
    }

    /// Returns the canonical string identifier for this algorithm.
    pub fn id(&self) -> String {
        match self {
            Self::MlDsa44 => "ml-dsa-44".into(),
            Self::MlDsa65 => "ml-dsa-65".into(),
            Self::MlDsa87 => "ml-dsa-87".into(),

            Self::SlhDsaSha2_128s => "slh-dsa-sha2-128s".into(),
            Self::SlhDsaSha2_128f => "slh-dsa-sha2-128f".into(),
            Self::SlhDsaSha2_192s => "slh-dsa-sha2-192s".into(),
            Self::SlhDsaSha2_192f => "slh-dsa-sha2-192f".into(),
            Self::SlhDsaSha2_256s => "slh-dsa-sha2-256s".into(),
            Self::SlhDsaSha2_256f => "slh-dsa-sha2-256f".into(),

            Self::SlhDsaShake128s => "slh-dsa-shake-128s".into(),
            Self::SlhDsaShake128f => "slh-dsa-shake-128f".into(),
            Self::SlhDsaShake192s => "slh-dsa-shake-192s".into(),
            Self::SlhDsaShake192f => "slh-dsa-shake-192f".into(),
            Self::SlhDsaShake256s => "slh-dsa-shake-256s".into(),
            Self::SlhDsaShake256f => "slh-dsa-shake-256f".into(),

            Self::FnDsa512 => "fn-dsa-512".into(),
            Self::FnDsa1024 => "fn-dsa-1024".into(),

            Self::Ed25519 => "ed25519".into(),
            Self::EcdsaP256 => "ecdsa-p256".into(),
            Self::EcdsaP384 => "ecdsa-p384".into(),

            Self::Hybrid { classical, pqc } => {
                format!("{}+{}", classical.id(), pqc.id())
            }
            Self::DualPqc { primary, backup } => {
                format!("{}+{}", primary.id(), backup.id())
            }
        }
    }

    /// Parses a canonical algorithm string (e.g., `"ml-dsa-65+ed25519"`)
    /// into a `SignatureAlgorithm`.
    pub fn from_id(id: &str) -> Option<Self> {
        // Check for composite algorithms (contains '+')
        if let Some((left, right)) = id.split_once('+') {
            let left_alg = Self::from_id(left)?;
            let right_alg = Self::from_id(right)?;

            // Determine if this is Hybrid (classical+PQC) or DualPqc
            let left_qs = left_alg.is_quantum_safe();
            let right_qs = right_alg.is_quantum_safe();

            if !left_qs && right_qs {
                // classical + PQC
                return Some(Self::Hybrid {
                    classical: Box::new(left_alg),
                    pqc: Box::new(right_alg),
                });
            }
            if left_qs && !right_qs {
                // PQC + classical (normalize to classical first)
                return Some(Self::Hybrid {
                    classical: Box::new(right_alg),
                    pqc: Box::new(left_alg),
                });
            }
            if left_qs && right_qs {
                // Both PQC: dual-PQC
                return Some(Self::DualPqc {
                    primary: Box::new(left_alg),
                    backup: Box::new(right_alg),
                });
            }
            // Both classical: not a valid hybrid
            return None;
        }

        match id {
            "ml-dsa-44" => Some(Self::MlDsa44),
            "ml-dsa-65" => Some(Self::MlDsa65),
            "ml-dsa-87" => Some(Self::MlDsa87),

            "slh-dsa-sha2-128s" => Some(Self::SlhDsaSha2_128s),
            "slh-dsa-sha2-128f" => Some(Self::SlhDsaSha2_128f),
            "slh-dsa-sha2-192s" => Some(Self::SlhDsaSha2_192s),
            "slh-dsa-sha2-192f" => Some(Self::SlhDsaSha2_192f),
            "slh-dsa-sha2-256s" => Some(Self::SlhDsaSha2_256s),
            "slh-dsa-sha2-256f" => Some(Self::SlhDsaSha2_256f),

            "slh-dsa-shake-128s" => Some(Self::SlhDsaShake128s),
            "slh-dsa-shake-128f" => Some(Self::SlhDsaShake128f),
            "slh-dsa-shake-192s" => Some(Self::SlhDsaShake192s),
            "slh-dsa-shake-192f" => Some(Self::SlhDsaShake192f),
            "slh-dsa-shake-256s" => Some(Self::SlhDsaShake256s),
            "slh-dsa-shake-256f" => Some(Self::SlhDsaShake256f),

            "fn-dsa-512" => Some(Self::FnDsa512),
            "fn-dsa-1024" => Some(Self::FnDsa1024),

            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            "ecdsa-p384" => Some(Self::EcdsaP384),

            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// KEM algorithms
// ---------------------------------------------------------------------------

/// Key Encapsulation Mechanism algorithm identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KemAlgorithm {
    // -- FIPS 203: ML-KEM (CRYSTALS-Kyber) --
    /// ML-KEM-512 (NIST Level 1).
    MlKem512,
    /// ML-KEM-768 (NIST Level 3).
    MlKem768,
    /// ML-KEM-1024 (NIST Level 5).
    MlKem1024,

    // -- Future: HQC (code-based KEM) --
    /// HQC-128 (NIST Level 1). Stub: not yet standardized.
    Hqc128,
    /// HQC-192 (NIST Level 3). Stub: not yet standardized.
    Hqc192,
    /// HQC-256 (NIST Level 5). Stub: not yet standardized.
    Hqc256,

    // -- Classical --
    /// X25519 (classical Diffie-Hellman on Curve25519).
    X25519,

    // -- Hybrid --
    /// Hybrid KEM: classical + PQC. Shared secrets are combined via HKDF.
    HybridKem {
        /// Classical KEM component (e.g., X25519).
        classical: Box<KemAlgorithm>,
        /// Post-quantum KEM component (e.g., ML-KEM-768).
        pqc: Box<KemAlgorithm>,
    },
}

impl KemAlgorithm {
    /// Returns the NIST security level for this KEM.
    pub fn nist_level(&self) -> NistLevel {
        match self {
            Self::MlKem512 | Self::Hqc128 | Self::X25519 => NistLevel::L1,
            Self::MlKem768 | Self::Hqc192 => NistLevel::L3,
            Self::MlKem1024 | Self::Hqc256 => NistLevel::L5,

            Self::HybridKem { classical, pqc } => {
                std::cmp::min(classical.nist_level(), pqc.nist_level())
            }
        }
    }

    /// Returns the mathematical families for this KEM.
    pub fn math_family(&self) -> Vec<MathFamily> {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => {
                vec![MathFamily::Lattice]
            }
            Self::Hqc128 | Self::Hqc192 | Self::Hqc256 => {
                vec![MathFamily::CodeBased]
            }
            Self::X25519 => vec![MathFamily::EllipticCurve],
            Self::HybridKem { classical, pqc } => {
                let mut families = classical.math_family();
                families.extend(pqc.math_family());
                families
            }
        }
    }

    /// Returns `true` if this KEM is quantum-safe.
    pub fn is_quantum_safe(&self) -> bool {
        !matches!(self, Self::X25519)
    }

    /// Returns the canonical string identifier.
    pub fn id(&self) -> String {
        match self {
            Self::MlKem512 => "ml-kem-512".into(),
            Self::MlKem768 => "ml-kem-768".into(),
            Self::MlKem1024 => "ml-kem-1024".into(),
            Self::Hqc128 => "hqc-128".into(),
            Self::Hqc192 => "hqc-192".into(),
            Self::Hqc256 => "hqc-256".into(),
            Self::X25519 => "x25519".into(),
            Self::HybridKem { classical, pqc } => {
                format!("{}+{}", classical.id(), pqc.id())
            }
        }
    }

    /// Parses a canonical KEM algorithm string.
    pub fn from_id(id: &str) -> Option<Self> {
        if let Some((left, right)) = id.split_once('+') {
            let left_alg = Self::from_id(left)?;
            let right_alg = Self::from_id(right)?;

            let left_qs = left_alg.is_quantum_safe();
            let right_qs = right_alg.is_quantum_safe();

            if !left_qs && right_qs {
                return Some(Self::HybridKem {
                    classical: Box::new(left_alg),
                    pqc: Box::new(right_alg),
                });
            }
            if left_qs && !right_qs {
                return Some(Self::HybridKem {
                    classical: Box::new(right_alg),
                    pqc: Box::new(left_alg),
                });
            }
            return None;
        }

        match id {
            "ml-kem-512" => Some(Self::MlKem512),
            "ml-kem-768" => Some(Self::MlKem768),
            "ml-kem-1024" => Some(Self::MlKem1024),
            "hqc-128" => Some(Self::Hqc128),
            "hqc-192" => Some(Self::Hqc192),
            "hqc-256" => Some(Self::Hqc256),
            "x25519" => Some(Self::X25519),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Hash algorithms
// ---------------------------------------------------------------------------

/// Hash algorithm identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlgorithm {
    /// SHA-256 (NIST Level 1 for collision resistance).
    Sha256,
    /// SHA-384 (NIST Level 3+; recommended for long-term security).
    Sha384,
    /// SHA-512 (NIST Level 5 for collision resistance).
    Sha512,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
}

impl HashAlgorithm {
    /// Returns the output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    /// Returns the canonical string identifier.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }

    /// Parses a canonical hash algorithm string.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "sha-256" | "sha256" => Some(Self::Sha256),
            "sha-384" | "sha384" => Some(Self::Sha384),
            "sha-512" | "sha512" => Some(Self::Sha512),
            "sha3-256" => Some(Self::Sha3_256),
            "sha3-384" => Some(Self::Sha3_384),
            "sha3-512" => Some(Self::Sha3_512),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_65_properties() {
        let alg = SignatureAlgorithm::MlDsa65;
        assert_eq!(alg.nist_level(), NistLevel::L3);
        assert_eq!(alg.math_family(), vec![MathFamily::Lattice]);
        assert!(alg.is_quantum_safe());
        assert!(!alg.is_composite());
        assert_eq!(alg.id(), "ml-dsa-65");
    }

    #[test]
    fn slh_dsa_256s_properties() {
        let alg = SignatureAlgorithm::SlhDsaSha2_256s;
        assert_eq!(alg.nist_level(), NistLevel::L5);
        assert_eq!(alg.math_family(), vec![MathFamily::HashBased]);
        assert!(alg.is_quantum_safe());
    }

    #[test]
    fn ed25519_is_classical() {
        let alg = SignatureAlgorithm::Ed25519;
        assert_eq!(alg.nist_level(), NistLevel::L1);
        assert_eq!(alg.math_family(), vec![MathFamily::EllipticCurve]);
        assert!(!alg.is_quantum_safe());
    }

    #[test]
    fn hybrid_ed25519_ml_dsa_65() {
        let alg = SignatureAlgorithm::Hybrid {
            classical: Box::new(SignatureAlgorithm::Ed25519),
            pqc: Box::new(SignatureAlgorithm::MlDsa65),
        };
        // Minimum of L1 (Ed25519) and L3 (ML-DSA-65) = L1
        assert_eq!(alg.nist_level(), NistLevel::L1);
        assert!(alg.is_quantum_safe());
        assert!(alg.is_composite());
        assert_eq!(alg.id(), "ed25519+ml-dsa-65");
        let families = alg.math_family();
        assert!(families.contains(&MathFamily::EllipticCurve));
        assert!(families.contains(&MathFamily::Lattice));
    }

    #[test]
    fn dual_pqc_lattice_hashbased() {
        let alg = SignatureAlgorithm::DualPqc {
            primary: Box::new(SignatureAlgorithm::MlDsa65),
            backup: Box::new(SignatureAlgorithm::SlhDsaSha2_256s),
        };
        assert!(alg.is_quantum_safe());
        assert!(alg.is_composite());
        assert_eq!(alg.id(), "ml-dsa-65+slh-dsa-sha2-256s");
    }

    #[test]
    fn parse_simple_algorithm_ids() {
        assert_eq!(
            SignatureAlgorithm::from_id("ml-dsa-44"),
            Some(SignatureAlgorithm::MlDsa44)
        );
        assert_eq!(
            SignatureAlgorithm::from_id("ed25519"),
            Some(SignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            SignatureAlgorithm::from_id("slh-dsa-sha2-256s"),
            Some(SignatureAlgorithm::SlhDsaSha2_256s)
        );
        assert!(SignatureAlgorithm::from_id("unknown-algorithm").is_none());
    }

    #[test]
    fn parse_hybrid_algorithm_id() {
        let alg = SignatureAlgorithm::from_id("ed25519+ml-dsa-65");
        assert!(alg.is_some());
        let alg = alg.unwrap();
        assert!(matches!(alg, SignatureAlgorithm::Hybrid { .. }));
        assert_eq!(alg.id(), "ed25519+ml-dsa-65");
    }

    #[test]
    fn parse_hybrid_pqc_first() {
        // If PQC is listed first, it should normalize to classical first
        let alg = SignatureAlgorithm::from_id("ml-dsa-65+ed25519");
        assert!(alg.is_some());
        let alg = alg.unwrap();
        // Normalized: classical first
        assert_eq!(alg.id(), "ed25519+ml-dsa-65");
    }

    #[test]
    fn parse_dual_pqc_algorithm_id() {
        let alg = SignatureAlgorithm::from_id("ml-dsa-65+slh-dsa-sha2-256s");
        assert!(alg.is_some());
        let alg = alg.unwrap();
        assert!(matches!(alg, SignatureAlgorithm::DualPqc { .. }));
    }

    #[test]
    fn classical_plus_classical_rejected() {
        // Two classical algorithms cannot form a valid hybrid
        assert!(SignatureAlgorithm::from_id("ed25519+ecdsa-p256").is_none());
    }

    #[test]
    fn kem_ml_kem_768_properties() {
        let kem = KemAlgorithm::MlKem768;
        assert_eq!(kem.nist_level(), NistLevel::L3);
        assert!(kem.is_quantum_safe());
        assert_eq!(kem.id(), "ml-kem-768");
    }

    #[test]
    fn kem_hybrid_x25519_ml_kem_768() {
        let kem = KemAlgorithm::HybridKem {
            classical: Box::new(KemAlgorithm::X25519),
            pqc: Box::new(KemAlgorithm::MlKem768),
        };
        assert_eq!(kem.id(), "x25519+ml-kem-768");
        assert!(kem.is_quantum_safe());
    }

    #[test]
    fn parse_hybrid_kem_id() {
        let kem = KemAlgorithm::from_id("x25519+ml-kem-768");
        assert!(kem.is_some());
        assert!(matches!(kem.unwrap(), KemAlgorithm::HybridKem { .. }));
    }

    #[test]
    fn hash_algorithm_output_lengths() {
        assert_eq!(HashAlgorithm::Sha256.output_len(), 32);
        assert_eq!(HashAlgorithm::Sha384.output_len(), 48);
        assert_eq!(HashAlgorithm::Sha512.output_len(), 64);
    }

    #[test]
    fn hash_algorithm_parsing() {
        assert_eq!(
            HashAlgorithm::from_id("sha-384"),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            HashAlgorithm::from_id("sha384"),
            Some(HashAlgorithm::Sha384)
        );
        assert!(HashAlgorithm::from_id("md5").is_none());
    }

    #[test]
    fn nist_level_ordering() {
        assert!(NistLevel::L1 < NistLevel::L3);
        assert!(NistLevel::L3 < NistLevel::L5);
    }

    #[test]
    fn nist_level_from_u8_validates() {
        assert!(NistLevel::from_u8(0).is_none());
        assert!(NistLevel::from_u8(6).is_none());
        assert_eq!(NistLevel::from_u8(3), Some(NistLevel::L3));
    }
}
