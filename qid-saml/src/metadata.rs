use qid_core::{
    config::SamlServiceProviderConfig,
    error::{QidError, QidResult},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    HTTP_POST_BINDING, attr_value_after, entity_category_values, entity_descriptor_xml_fragments,
    find_service_location, key_descriptor_certificates, reject_insecure_saml_xml, text_values,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlServiceProviderMetadata {
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub name_id_formats: Vec<String>,
    #[serde(default)]
    pub attribute_release_policy: Vec<String>,
    pub signing_certificates: Vec<String>,
    pub encryption_certificates: Vec<String>,
    pub want_assertions_signed: bool,
    #[serde(default)]
    pub entity_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlMetadataImportRejection {
    pub index: usize,
    pub entity_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlMetadataAggregateImport {
    pub service_providers: Vec<SamlServiceProviderMetadata>,
    pub rejected: Vec<SamlMetadataImportRejection>,
    pub duplicate_entity_ids: Vec<String>,
    pub rollover_entity_ids: Vec<String>,
    pub entity_category_index: BTreeMap<String, Vec<String>>,
}

pub fn import_sp_metadata(xml: &str) -> QidResult<SamlServiceProviderMetadata> {
    reject_insecure_saml_xml(xml)?;
    let entity_id = attr_value_after(xml, "EntityDescriptor", "entityID").ok_or_else(|| {
        QidError::BadRequest {
            message: "SAML metadata entityID is required".to_string(),
        }
    })?;
    let acs_url = find_service_location(xml, "AssertionConsumerService", HTTP_POST_BINDING)
        .or_else(|| attr_value_after(xml, "AssertionConsumerService", "Location"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML metadata AssertionConsumerService Location is required".to_string(),
        })?;
    let slo_url = find_service_location(xml, "SingleLogoutService", HTTP_POST_BINDING)
        .or_else(|| attr_value_after(xml, "SingleLogoutService", "Location"));
    let name_id_formats = text_values(xml, "NameIDFormat");
    let signing_certificates = key_descriptor_certificates(xml, Some("signing"));
    let encryption_certificates = key_descriptor_certificates(xml, Some("encryption"));
    let signing_certificates = if signing_certificates.is_empty() {
        key_descriptor_certificates(xml, None)
    } else {
        signing_certificates
    };
    let want_assertions_signed = attr_value_after(xml, "SPSSODescriptor", "WantAssertionsSigned")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let entity_categories = entity_category_values(xml);
    Ok(SamlServiceProviderMetadata {
        entity_id,
        acs_url,
        slo_url,
        name_id_formats,
        signing_certificates,
        encryption_certificates,
        want_assertions_signed,
        attribute_release_policy: Vec::new(),
        entity_categories,
    })
}

pub fn import_sp_metadata_aggregate(xml: &str) -> QidResult<SamlMetadataAggregateImport> {
    reject_insecure_saml_xml(xml)?;
    let descriptors = entity_descriptor_xml_fragments(xml);
    if descriptors.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML metadata aggregate must contain at least one EntityDescriptor"
                .to_string(),
        });
    }

    let mut service_providers = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut duplicate_entity_ids = BTreeSet::new();
    let mut rollover_entity_ids = BTreeSet::new();
    let mut entity_category_index: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (index, descriptor) in descriptors.iter().enumerate() {
        match import_sp_metadata(descriptor) {
            Ok(sp) => {
                if !seen.insert(sp.entity_id.clone()) {
                    duplicate_entity_ids.insert(sp.entity_id.clone());
                    rejected.push(SamlMetadataImportRejection {
                        index,
                        entity_id: Some(sp.entity_id),
                        reason: "duplicate_entity_id".to_string(),
                    });
                    continue;
                }
                if sp.signing_certificates.len() > 1 || sp.encryption_certificates.len() > 1 {
                    rollover_entity_ids.insert(sp.entity_id.clone());
                }
                for category in &sp.entity_categories {
                    entity_category_index
                        .entry(category.clone())
                        .or_default()
                        .push(sp.entity_id.clone());
                }
                service_providers.push(sp);
            }
            Err(error) => rejected.push(SamlMetadataImportRejection {
                index,
                entity_id: attr_value_after(descriptor, "EntityDescriptor", "entityID"),
                reason: error.to_string(),
            }),
        }
    }

    Ok(SamlMetadataAggregateImport {
        service_providers,
        rejected,
        duplicate_entity_ids: duplicate_entity_ids.into_iter().collect(),
        rollover_entity_ids: rollover_entity_ids.into_iter().collect(),
        entity_category_index,
    })
}

pub fn service_provider_from_config(
    config: &SamlServiceProviderConfig,
) -> SamlServiceProviderMetadata {
    SamlServiceProviderMetadata {
        entity_id: config.entity_id.clone(),
        acs_url: config.acs_url.clone(),
        slo_url: config.slo_url.clone(),
        name_id_formats: config.name_id_formats.clone(),
        attribute_release_policy: config.attribute_release_policy.clone(),
        signing_certificates: config.signing_certificates.clone(),
        encryption_certificates: config.encryption_certificates.clone(),
        want_assertions_signed: config.want_assertions_signed,
        entity_categories: Vec::new(),
    }
}
