//! Key Derivation Functions for hybrid KEM secret combination.
//!
//! When two KEM shared secrets are combined (e.g., X25519 + ML-KEM-768),
//! the raw secrets are concatenated and passed through HKDF-SHA-384
//! (per NIST SP 800-56C Rev. 2) to derive a single combined key.
//!
//! ## Security Properties
//!
//! - Uses HKDF with SHA-384 as the PRF (Grover's algorithm halves effective
//!   hash security; SHA-384 retains 192-bit post-quantum collision resistance).
//! - The `info` parameter encodes both algorithm IDs to prevent domain
//!   confusion attacks.
//! - All intermediate key material is zeroized on drop.

use hmac::Hmac;
use sha2::Sha384;
use zeroize::Zeroize;

use super::errors::CryptoError;
use super::SharedSecret;

type HkdfSha384 = hkdf::Hkdf<Sha384, Hmac<Sha384>>;

/// Combines two shared secrets from a hybrid KEM using HKDF-SHA-384.
///
/// This implements the "KDF combiner" pattern recommended by NIST SP 800-56C:
/// 1. Concatenate both shared secrets: `classical_ss || pqc_ss`
/// 2. Use HKDF-Extract with the concatenation as IKM
/// 3. Use HKDF-Expand with algorithm identifiers as info
/// 4. Output a 48-byte (384-bit) combined secret
///
/// # Arguments
///
/// - `classical_ss`: Classical shared secret (e.g., from X25519).
/// - `pqc_ss`: Post-quantum shared secret (e.g., from ML-KEM).
/// - `classical_alg_id`: String ID of the classical algorithm (for domain separation).
/// - `pqc_alg_id`: String ID of the PQC algorithm (for domain separation).
///
/// # Security
///
/// The concatenated input is zeroized after extraction. The output retains
/// security as long as *either* input secret is secure (this is the key
/// property that makes hybrid KEM safe against partial compromise).
pub fn combine_hybrid_secrets(
    classical_ss: &SharedSecret,
    pqc_ss: &SharedSecret,
    classical_alg_id: &str,
    pqc_alg_id: &str,
) -> Result<SharedSecret, CryptoError> {
    // Concatenate both shared secrets
    let mut ikm = Vec::with_capacity(classical_ss.0.len() + pqc_ss.0.len());
    ikm.extend_from_slice(&classical_ss.0);
    ikm.extend_from_slice(&pqc_ss.0);

    // Build info string for domain separation
    let info = format!("vbw-hybrid-kem:{classical_alg_id}+{pqc_alg_id}");

    // HKDF-Extract + Expand
    let hk = HkdfSha384::new(None, &ikm);
    let mut output = vec![0u8; 48]; // 384 bits
    hk.expand(info.as_bytes(), &mut output).map_err(|_| {
        CryptoError::ProviderError("HKDF-SHA-384 expand failed (output too long)".into())
    })?;

    // Zeroize the concatenated IKM
    ikm.zeroize();

    Ok(SharedSecret(output))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::similar_names)]
mod tests {
    use super::*;

    #[test]
    fn combine_produces_48_byte_output() {
        let ss1 = SharedSecret(vec![0xAA; 32]);
        let ss2 = SharedSecret(vec![0xBB; 32]);
        let combined = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-768").unwrap();
        assert_eq!(combined.0.len(), 48);
    }

    #[test]
    fn combine_is_deterministic() {
        let ss1 = SharedSecret(vec![0xAA; 32]);
        let ss2 = SharedSecret(vec![0xBB; 32]);
        let a = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-768").unwrap();
        let b = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-768").unwrap();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn different_algorithms_produce_different_output() {
        let ss1 = SharedSecret(vec![0xAA; 32]);
        let ss2 = SharedSecret(vec![0xBB; 32]);
        let a = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-768").unwrap();
        let b = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-1024").unwrap();
        assert_ne!(
            a.0, b.0,
            "different algorithm IDs must produce different output"
        );
    }

    #[test]
    fn different_secrets_produce_different_output() {
        let ss1a = SharedSecret(vec![0xAA; 32]);
        let ss1b = SharedSecret(vec![0xCC; 32]);
        let ss2 = SharedSecret(vec![0xBB; 32]);
        let a = combine_hybrid_secrets(&ss1a, &ss2, "x25519", "ml-kem-768").unwrap();
        let b = combine_hybrid_secrets(&ss1b, &ss2, "x25519", "ml-kem-768").unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn order_matters() {
        let ss1 = SharedSecret(vec![0xAA; 32]);
        let ss2 = SharedSecret(vec![0xBB; 32]);
        let a = combine_hybrid_secrets(&ss1, &ss2, "x25519", "ml-kem-768").unwrap();
        let b = combine_hybrid_secrets(&ss2, &ss1, "x25519", "ml-kem-768").unwrap();
        assert_ne!(
            a.0, b.0,
            "swapping secret order must produce different output"
        );
    }
}
