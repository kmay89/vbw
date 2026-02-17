//! Algorithm registry for VBW's crypto-agile layer.
//!
//! The `AlgorithmRegistry` is the central dispatch table that maps algorithm
//! identifiers to `CryptoProvider` implementations. It enables algorithm
//! agility: the policy engine selects algorithms by name, and the registry
//! routes operations to the correct provider backend.
//!
//! ## Thread Safety
//!
//! The registry is `Send + Sync` and designed to be created once at startup,
//! then shared immutably across verification operations.

use std::collections::HashMap;
use std::sync::Arc;

use super::algorithm::{AlgorithmDescriptor, KemAlgorithm, SignatureAlgorithm};
use super::errors::CryptoError;
use super::{
    CiphertextBytes, CryptoProvider, DecapsulationKey, DigestBytes, HashAlgorithm, PublicKeyBytes,
    SharedSecret, SignatureBytes, VerificationResult,
};

/// Central registry mapping algorithm identifiers to provider implementations.
///
/// Providers are registered at startup. The registry does not own the providers
/// — it holds `Arc` references so providers can be shared across registries
/// (e.g., for cross-validation using independent backends).
#[allow(clippy::struct_field_names)]
pub struct AlgorithmRegistry {
    /// Maps signature algorithm ID → provider.
    sig_providers: HashMap<String, Arc<dyn CryptoProvider>>,
    /// Maps KEM algorithm ID → provider.
    kem_providers: HashMap<String, Arc<dyn CryptoProvider>>,
    /// Maps hash algorithm ID → provider.
    hash_providers: HashMap<String, Arc<dyn CryptoProvider>>,
}

impl AlgorithmRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            sig_providers: HashMap::new(),
            kem_providers: HashMap::new(),
            hash_providers: HashMap::new(),
        }
    }

    /// Registers a `CryptoProvider`. All algorithms declared by
    /// `provider.supported_algorithms()` are indexed for dispatch.
    pub fn register(&mut self, provider: Arc<dyn CryptoProvider>) {
        for desc in provider.supported_algorithms() {
            // Determine which map(s) to insert into based on ID patterns.
            // Signature algorithms:
            if SignatureAlgorithm::from_id(&desc.id).is_some() {
                self.sig_providers
                    .insert(desc.id.clone(), Arc::clone(&provider));
            }
            // KEM algorithms:
            if KemAlgorithm::from_id(&desc.id).is_some() {
                self.kem_providers
                    .insert(desc.id.clone(), Arc::clone(&provider));
            }
            // Hash algorithms:
            if HashAlgorithm::from_id(&desc.id).is_some() {
                self.hash_providers
                    .insert(desc.id.clone(), Arc::clone(&provider));
            }
        }
    }

    /// Returns all registered algorithm descriptors.
    pub fn all_algorithms(&self) -> Vec<AlgorithmDescriptor> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        for provider in self
            .sig_providers
            .values()
            .chain(self.kem_providers.values())
            .chain(self.hash_providers.values())
        {
            for desc in provider.supported_algorithms() {
                if seen.insert(desc.id.clone()) {
                    result.push(desc);
                }
            }
        }
        result
    }

    /// Verifies a signature using the registered provider for the given algorithm.
    pub fn verify_signature(
        &self,
        algorithm: &SignatureAlgorithm,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<VerificationResult, CryptoError> {
        let alg_id = algorithm.id();
        let provider = self
            .sig_providers
            .get(&alg_id)
            .ok_or_else(|| CryptoError::UnsupportedAlgorithm(alg_id.clone()))?;
        provider.verify_signature(algorithm, public_key, message, signature)
    }

    /// Decapsulates using the registered KEM provider.
    pub fn decapsulate(
        &self,
        algorithm: &KemAlgorithm,
        secret_key: &DecapsulationKey,
        ciphertext: &CiphertextBytes,
    ) -> Result<SharedSecret, CryptoError> {
        let alg_id = algorithm.id();
        let provider = self
            .kem_providers
            .get(&alg_id)
            .ok_or_else(|| CryptoError::UnsupportedAlgorithm(alg_id.clone()))?;
        provider.decapsulate(algorithm, secret_key, ciphertext)
    }

    /// Computes a hash using the registered hash provider.
    pub fn hash(&self, algorithm: &HashAlgorithm, data: &[u8]) -> Result<DigestBytes, CryptoError> {
        let alg_id = algorithm.id().to_string();
        let provider = self
            .hash_providers
            .get(&alg_id)
            .ok_or_else(|| CryptoError::UnsupportedAlgorithm(alg_id.clone()))?;
        provider.hash(algorithm, data)
    }

    /// Returns the provider for a specific signature algorithm, if registered.
    pub fn signature_provider(
        &self,
        algorithm: &SignatureAlgorithm,
    ) -> Option<Arc<dyn CryptoProvider>> {
        self.sig_providers.get(&algorithm.id()).cloned()
    }

    /// Returns `true` if the given signature algorithm has a registered provider.
    pub fn supports_signature(&self, algorithm: &SignatureAlgorithm) -> bool {
        self.sig_providers.contains_key(&algorithm.id())
    }

    /// Returns `true` if the given KEM algorithm has a registered provider.
    pub fn supports_kem(&self, algorithm: &KemAlgorithm) -> bool {
        self.kem_providers.contains_key(&algorithm.id())
    }
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a default registry with all available providers.
///
/// This is the main entry point for creating a fully-loaded registry.
/// It registers the `RustCrypto` PQC provider, the Ed25519 provider,
/// and the stub provider for future algorithms.
pub fn default_registry() -> AlgorithmRegistry {
    let mut registry = AlgorithmRegistry::new();

    // Register the RustCrypto PQC provider (ML-DSA, SLH-DSA, ML-KEM, hashes)
    registry.register(Arc::new(super::providers::rustcrypto::RustCryptoProvider));

    // Register the Ed25519 provider
    registry.register(Arc::new(super::providers::ed25519::Ed25519Provider));

    // Register stub provider for future algorithms (FN-DSA, HQC)
    registry.register(Arc::new(super::providers::stub::StubProvider));

    registry
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_supports_ml_dsa() {
        let reg = default_registry();
        assert!(reg.supports_signature(&SignatureAlgorithm::MlDsa44));
        assert!(reg.supports_signature(&SignatureAlgorithm::MlDsa65));
        assert!(reg.supports_signature(&SignatureAlgorithm::MlDsa87));
    }

    #[test]
    fn default_registry_supports_slh_dsa() {
        let reg = default_registry();
        assert!(reg.supports_signature(&SignatureAlgorithm::SlhDsaSha2_128s));
        assert!(reg.supports_signature(&SignatureAlgorithm::SlhDsaSha2_256s));
    }

    #[test]
    fn default_registry_supports_ed25519() {
        let reg = default_registry();
        assert!(reg.supports_signature(&SignatureAlgorithm::Ed25519));
    }

    #[test]
    fn default_registry_supports_ml_kem() {
        let reg = default_registry();
        assert!(reg.supports_kem(&KemAlgorithm::MlKem512));
        assert!(reg.supports_kem(&KemAlgorithm::MlKem768));
        assert!(reg.supports_kem(&KemAlgorithm::MlKem1024));
    }

    #[test]
    fn unsupported_algorithm_returns_error() {
        let reg = default_registry();
        let alg = SignatureAlgorithm::EcdsaP256;
        let result = reg.verify_signature(
            &alg,
            &PublicKeyBytes(vec![]),
            b"msg",
            &SignatureBytes(vec![]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn all_algorithms_non_empty() {
        let reg = default_registry();
        let algs = reg.all_algorithms();
        assert!(!algs.is_empty());
    }

    #[test]
    fn empty_registry_supports_nothing() {
        let reg = AlgorithmRegistry::new();
        assert!(!reg.supports_signature(&SignatureAlgorithm::MlDsa65));
        assert!(!reg.supports_kem(&KemAlgorithm::MlKem768));
    }
}
