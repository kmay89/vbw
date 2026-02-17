//! Cryptographic error types for VBW's post-quantum crypto-agile layer.
//!
//! All errors from the crypto subsystem are represented by [`CryptoError`],
//! which is designed to be informative for operators without leaking
//! sensitive internal state (no key material in error messages).

use std::fmt;

/// Errors produced by VBW cryptographic operations.
///
/// These errors are intentionally opaque about internal key material:
/// they describe *what* failed (algorithm mismatch, verification failure)
/// but never include raw key bytes or signature data in their `Display`
/// output. This prevents accidental leakage via logs or reports.
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// The requested algorithm is not supported by any registered provider.
    UnsupportedAlgorithm(String),

    /// Signature verification failed (signature is invalid for the given
    /// message and public key). This is a *normal* outcome for tampered
    /// data and must not be treated as a bug.
    VerificationFailed {
        /// Which algorithm was used.
        algorithm: String,
        /// Human-readable reason.
        reason: String,
    },

    /// A hybrid or dual-PQC composition violates cross-family requirements.
    HybridCompositionError(String),

    /// The requested NIST security level is below the policy minimum.
    InsufficientSecurityLevel {
        /// Algorithm that was requested.
        algorithm: String,
        /// Level provided by the algorithm.
        provided: u8,
        /// Minimum level required by policy.
        required: u8,
    },

    /// An algorithm is deprecated and rejected by policy.
    DeprecatedAlgorithm {
        /// The deprecated algorithm identifier.
        algorithm: String,
        /// Human-readable deprecation message.
        message: String,
    },

    /// KEM decapsulation failed.
    DecapsulationFailed(String),

    /// Hash computation failed (should be rare; indicates a bug or
    /// unsupported algorithm).
    HashError(String),

    /// Key material is malformed (wrong length, invalid encoding).
    InvalidKeyMaterial(String),

    /// The crypto envelope format is invalid or cannot be parsed.
    InvalidEnvelope(String),

    /// An internal provider error that doesn't fit other categories.
    ProviderError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {alg}")
            }
            Self::VerificationFailed { algorithm, reason } => {
                write!(f, "verification failed ({algorithm}): {reason}")
            }
            Self::HybridCompositionError(msg) => {
                write!(f, "hybrid composition error: {msg}")
            }
            Self::InsufficientSecurityLevel {
                algorithm,
                provided,
                required,
            } => {
                write!(
                    f,
                    "security level too low for {algorithm}: level {provided} < required {required}"
                )
            }
            Self::DeprecatedAlgorithm { algorithm, message } => {
                write!(f, "deprecated algorithm {algorithm}: {message}")
            }
            Self::DecapsulationFailed(msg) => {
                write!(f, "KEM decapsulation failed: {msg}")
            }
            Self::HashError(msg) => write!(f, "hash error: {msg}"),
            Self::InvalidKeyMaterial(msg) => {
                write!(f, "invalid key material: {msg}")
            }
            Self::InvalidEnvelope(msg) => {
                write!(f, "invalid crypto envelope: {msg}")
            }
            Self::ProviderError(msg) => write!(f, "provider error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn error_display_unsupported_algorithm() {
        let err = CryptoError::UnsupportedAlgorithm("fn-dsa-512".into());
        assert_eq!(err.to_string(), "unsupported algorithm: fn-dsa-512");
    }

    #[test]
    fn error_display_verification_failed() {
        let err = CryptoError::VerificationFailed {
            algorithm: "ml-dsa-65".into(),
            reason: "invalid signature bytes".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ml-dsa-65"));
        assert!(msg.contains("invalid signature bytes"));
    }

    #[test]
    fn error_display_insufficient_level() {
        let err = CryptoError::InsufficientSecurityLevel {
            algorithm: "ml-dsa-44".into(),
            provided: 2,
            required: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("level 2 < required 3"));
    }

    #[test]
    fn error_display_deprecated() {
        let err = CryptoError::DeprecatedAlgorithm {
            algorithm: "rsa-2048".into(),
            message: "rejected after 2028-01-01".into(),
        };
        assert!(err.to_string().contains("rsa-2048"));
    }

    #[test]
    fn crypto_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CryptoError>();
    }
}
