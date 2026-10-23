use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;

/// Operator-curated offline metadata, not FIDO MDS provenance. Enrollment only.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackedAttestationPolicy {
    pub metadata: AttestationMetadata,
    #[serde(default)]
    pub limits: AttestationLimits,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationMetadata {
    /// Unix seconds, inclusive.
    pub not_before: u64,
    /// Unix seconds, exclusive; checked at finish, not just startup/start.
    pub expires_at: u64,
    #[serde(deserialize_with = "unique_models")]
    pub models: BTreeMap<String, AttestationModel>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationModel {
    pub status: AttestationModelStatus,
    /// Standard padded base64 DER certificates. These are pinned trust anchors.
    pub roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationModelStatus {
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationLimits {
    pub evidence_bytes: usize,
    pub client_data_bytes: usize,
    pub certificates: usize,
    pub certificate_bytes: usize,
    pub models: usize,
    pub roots_per_model: usize,
}

impl Default for AttestationLimits {
    fn default() -> Self {
        Self {
            evidence_bytes: 16384,
            client_data_bytes: 4096,
            certificates: 4,
            certificate_bytes: 4096,
            models: 128,
            roots_per_model: 4,
        }
    }
}

/// Only canonical lower-case UUID spelling is accepted, so aliases cannot disagree.
pub fn attestation_model_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .fold(String::new(), |mut s, (i, b)| {
            if matches!(i, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl PackedAttestationPolicy {
    pub fn validate(&self, enabled: bool) -> QidResult<()> {
        let invalid = || {
            QidError::Config {
            message: concat!(
                "passkeys.attestation requires enabled passkeys, ordered metadata times, ",
                "canonical AAGUIDs, nonempty bounded models/roots, DER certificates and nonzero limits"
            ).into(),
        }
        };
        let l = &self.limits;
        if !enabled
            || self.metadata.not_before >= self.metadata.expires_at
            || self.metadata.models.is_empty()
            || self.metadata.models.len() > l.models
            || [
                l.evidence_bytes,
                l.client_data_bytes,
                l.certificates,
                l.certificate_bytes,
                l.models,
                l.roots_per_model,
            ]
            .contains(&0)
        {
            return Err(invalid());
        }
        for (id, model) in &self.metadata.models {
            if id.len() != 36 {
                return Err(invalid());
            }
            let hex = id.replace('-', "");
            let bytes: Option<Vec<u8>> = (0..hex.len())
                .step_by(2)
                .map(|i| {
                    hex.get(i..i + 2)
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                })
                .collect();
            if !bytes
                .as_ref()
                .is_some_and(|b| b.len() == 16 && attestation_model_id(b) == *id)
                || model.roots.is_empty()
                || model.roots.len() > l.roots_per_model
            {
                return Err(invalid());
            }
            for root in &model.roots {
                if root.len()
                    > l.certificate_bytes
                        .saturating_add(2)
                        .saturating_div(3)
                        .saturating_mul(4)
                {
                    return Err(invalid());
                }
                let der = STANDARD.decode(root).map_err(|_| invalid())?;
                if der.len() > l.certificate_bytes {
                    return Err(invalid());
                }
                // Use the runtime's anchor extraction, not path-member validation.
                webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(der))
                    .map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
}

fn unique_models<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, AttestationModel>, D::Error> {
    struct Models;
    impl<'de> serde::de::Visitor<'de> for Models {
        type Value = BTreeMap<String, AttestationModel>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique canonical AAGUID model keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut models = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                if models.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate attestation model"));
                }
            }
            Ok(models)
        }
    }
    deserializer.deserialize_map(Models)
}
