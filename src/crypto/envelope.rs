//! Attestation crypto envelope format for VBW.
//!
//! The `CryptoEnvelope` carries algorithm metadata alongside the attestation,
//! enabling verifiers to select the correct algorithm and providing forward
//! compatibility for future algorithm migrations.
//!
//! ## Forward Compatibility
//!
//! The envelope uses `#[serde(default)]` and ignores unknown fields, so older
//! verifiers can skip algorithm fields they don't recognize. The `schema_version`
//! field enables breaking changes if needed in the future.

use serde::{Deserialize, Serialize};

/// Top-level crypto envelope wrapping an attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    /// Schema version for this envelope format.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Signatures on the attestation body.
    #[serde(default)]
    pub signatures: Vec<EnvelopeSignature>,

    /// KEM-wrapped content key (if attestation body is encrypted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EnvelopeEncryption>,

    /// Digest of the attestation body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<EnvelopeDigest>,

    /// Algorithm migration and compliance metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agility_metadata: Option<AgilityMetadata>,
}

fn default_schema_version() -> String {
    "1.0".into()
}

/// A single signature entry in the crypto envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    /// Canonical algorithm identifier (e.g., `"ml-dsa-65+ed25519"`).
    pub algorithm: String,

    /// OIDs for the algorithm components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_oids: Option<AlgorithmOids>,

    /// Identifier for the public key used (e.g., `"sha384:abcdef..."`).
    pub public_key_id: String,

    /// Base64-encoded signature bytes.
    pub signature_bytes: String,

    /// Composition layout for hybrid/dual-PQC signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composition: Option<SignatureComposition>,
}

/// OIDs for composite algorithm components.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlgorithmOids {
    /// OID for the PQC component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    /// OID for the classical component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classical: Option<String>,
}

/// Describes the byte layout of a composite signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureComposition {
    /// Composition mode (e.g., `"hybrid-concatenated"`).
    pub mode: String,
    /// Byte offset of the PQC signature within the concatenated blob.
    pub pqc_sig_offset: usize,
    /// Byte length of the PQC signature.
    pub pqc_sig_length: usize,
    /// Byte offset of the classical signature.
    pub classical_sig_offset: usize,
    /// Byte length of the classical signature.
    pub classical_sig_length: usize,
}

/// KEM encryption metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeEncryption {
    /// KEM algorithm identifier (e.g., `"x25519+ml-kem-768"`).
    pub algorithm: String,
    /// Base64-encoded encapsulated key.
    pub encapsulated_key: String,
    /// Content encryption algorithm (e.g., `"aes-256-gcm"`).
    pub content_encryption: String,
    /// Base64-encoded nonce.
    pub nonce: String,
}

/// Digest of the attestation body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeDigest {
    /// Hash algorithm (e.g., `"sha-384"`).
    pub algorithm: String,
    /// Hash value with algorithm prefix (e.g., `"sha384:abcdef..."`).
    pub value: String,
}

/// Algorithm agility and compliance metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgilityMetadata {
    /// NIST compliance level of the strongest algorithm used.
    pub nist_compliance_level: u8,
    /// Math families used in the signatures.
    pub math_families_used: Vec<String>,
    /// Whether the attestation is quantum-safe.
    pub quantum_safe: bool,
    /// Whether hybrid composition was used.
    pub hybrid: bool,
    /// Free-form migration note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_note: Option<String>,
}

impl CryptoEnvelope {
    /// Creates a new empty envelope with the default schema version.
    pub fn new() -> Self {
        Self {
            schema_version: default_schema_version(),
            signatures: Vec::new(),
            encryption: None,
            digest: None,
            agility_metadata: None,
        }
    }

    /// Serializes the envelope to a JSON `serde_json::Value`.
    pub fn to_json(&self) -> Result<serde_json::Value, super::errors::CryptoError> {
        serde_json::to_value(self)
            .map_err(|e| super::errors::CryptoError::InvalidEnvelope(e.to_string()))
    }

    /// Deserializes a `CryptoEnvelope` from a JSON value.
    /// Unknown fields are silently ignored (forward compatibility).
    pub fn from_json(value: &serde_json::Value) -> Result<Self, super::errors::CryptoError> {
        serde_json::from_value(value.clone())
            .map_err(|e| super::errors::CryptoError::InvalidEnvelope(e.to_string()))
    }
}

impl Default for CryptoEnvelope {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::similar_names)]
mod tests {
    use super::*;

    #[test]
    fn empty_envelope_serializes() {
        let env = CryptoEnvelope::new();
        let json = env.to_json().unwrap();
        assert_eq!(json["schema_version"], "1.0");
        assert!(json["signatures"].as_array().unwrap().is_empty());
    }

    #[test]
    fn envelope_with_signature_roundtrips() {
        let mut env = CryptoEnvelope::new();
        env.signatures.push(EnvelopeSignature {
            algorithm: "ml-dsa-65+ed25519".into(),
            algorithm_oids: Some(AlgorithmOids {
                pqc: Some("2.16.840.1.101.3.4.3.17".into()),
                classical: Some("1.3.101.112".into()),
            }),
            public_key_id: "sha384:abcdef".into(),
            signature_bytes: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"fake-sig-bytes",
            ),
            composition: Some(SignatureComposition {
                mode: "hybrid-concatenated".into(),
                pqc_sig_offset: 0,
                pqc_sig_length: 3309,
                classical_sig_offset: 3309,
                classical_sig_length: 64,
            }),
        });
        env.digest = Some(EnvelopeDigest {
            algorithm: "sha-384".into(),
            value: "sha384:123456".into(),
        });
        env.agility_metadata = Some(AgilityMetadata {
            nist_compliance_level: 3,
            math_families_used: vec!["lattice".into(), "elliptic-curve".into()],
            quantum_safe: true,
            hybrid: true,
            migration_note: Some("Ready for pure PQC".into()),
        });

        let json = env.to_json().unwrap();
        let parsed = CryptoEnvelope::from_json(&json).unwrap();
        assert_eq!(parsed.signatures.len(), 1);
        assert_eq!(parsed.signatures[0].algorithm, "ml-dsa-65+ed25519");
        assert!(parsed.digest.is_some());
        assert!(parsed.agility_metadata.is_some());
    }

    #[test]
    fn envelope_unknown_fields_ignored() {
        let json = serde_json::json!({
            "schema_version": "1.0",
            "signatures": [],
            "future_field": "this should be ignored",
            "another_unknown": 42
        });
        let parsed = CryptoEnvelope::from_json(&json).unwrap();
        assert_eq!(parsed.schema_version, "1.0");
    }

    #[test]
    fn envelope_missing_optional_fields_default() {
        let json = serde_json::json!({
            "signatures": []
        });
        let parsed = CryptoEnvelope::from_json(&json).unwrap();
        assert_eq!(parsed.schema_version, "1.0");
        assert!(parsed.encryption.is_none());
        assert!(parsed.digest.is_none());
    }

    #[test]
    fn encryption_metadata_roundtrips() {
        let mut env = CryptoEnvelope::new();
        env.encryption = Some(EnvelopeEncryption {
            algorithm: "x25519+ml-kem-768".into(),
            encapsulated_key: "base64key==".into(),
            content_encryption: "aes-256-gcm".into(),
            nonce: "base64nonce==".into(),
        });

        let json = env.to_json().unwrap();
        let parsed = CryptoEnvelope::from_json(&json).unwrap();
        let enc = parsed.encryption.unwrap();
        assert_eq!(enc.algorithm, "x25519+ml-kem-768");
        assert_eq!(enc.content_encryption, "aes-256-gcm");
    }
}
