use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

use crate::error::{QidError, QidResult};

use super::validation::{
    is_lower_hex_sha256, require_json_string, require_json_string_url, require_non_empty,
    validate_custom_domain_status, validate_hex_color, validate_hostname, validate_optional_uri,
};

pub fn default_custom_domain_verification_status() -> String {
    "pending".to_string()
}

/// A custom domain binding for large-scale SaaS deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomDomain {
    pub id: String,
    pub tenant_id: String,
    pub realm_id: String,
    pub hostname: String,
    pub certificate_ref: String,
    pub verified: bool,
    #[serde(default = "default_custom_domain_verification_status")]
    pub verification_status: String,
    #[serde(default)]
    pub dns_challenge_name: Option<String>,
    #[serde(default)]
    pub dns_challenge_value: Option<String>,
    #[serde(default)]
    pub certificate_expires_at: Option<u64>,
    #[serde(default)]
    pub certificate_renew_after: Option<u64>,
    #[serde(default)]
    pub last_verified_at: Option<u64>,
}

impl CustomDomain {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("custom domain id", &self.id)?;
        require_non_empty("custom domain tenant_id", &self.tenant_id)?;
        require_non_empty("custom domain realm_id", &self.realm_id)?;
        validate_hostname("custom domain hostname", &self.hostname)?;
        validate_custom_domain_status(&self.verification_status)?;
        if self.verified
            && self.verification_status != "verified"
            && self.verification_status != "active"
        {
            return Err(QidError::BadRequest {
                message: "custom domain verified flag requires verified or active status"
                    .to_string(),
            });
        }
        if self.verification_status == "pending"
            && (self.dns_challenge_name.is_none() || self.dns_challenge_value.is_none())
        {
            return Err(QidError::BadRequest {
                message: "custom domain pending verification requires DNS challenge".to_string(),
            });
        }
        if let Some(name) = &self.dns_challenge_name {
            require_non_empty("custom domain dns_challenge_name", name)?;
        }
        if let Some(value) = &self.dns_challenge_value {
            require_non_empty("custom domain dns_challenge_value", value)?;
        }
        if let (Some(renew_after), Some(expires_at)) =
            (self.certificate_renew_after, self.certificate_expires_at)
            && renew_after >= expires_at
        {
            return Err(QidError::BadRequest {
                message: "custom domain certificate_renew_after must be before expiry".to_string(),
            });
        }
        if self.verified || self.verification_status == "active" {
            self.validate_activation()?;
        }
        Ok(())
    }

    pub fn validate_activation(&self) -> QidResult<()> {
        require_non_empty("custom domain certificate_ref", &self.certificate_ref)?;
        if !self.verified || self.verification_status != "active" {
            return Err(QidError::BadRequest {
                message: "custom domain activation requires verified active status".to_string(),
            });
        }
        if self.last_verified_at.is_none() {
            return Err(QidError::BadRequest {
                message: "custom domain activation requires last_verified_at".to_string(),
            });
        }
        let Some(expires_at) = self.certificate_expires_at else {
            return Err(QidError::BadRequest {
                message: "custom domain activation requires certificate_expires_at".to_string(),
            });
        };
        let Some(renew_after) = self.certificate_renew_after else {
            return Err(QidError::BadRequest {
                message: "custom domain activation requires certificate_renew_after".to_string(),
            });
        };
        if renew_after >= expires_at {
            return Err(QidError::BadRequest {
                message: "custom domain certificate_renew_after must be before expiry".to_string(),
            });
        }
        Ok(())
    }
}

/// A CIAM brand profile for multi-brand customer identity deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamBrand {
    pub id: String,
    pub tenant_id: String,
    pub realm_id: String,
    pub display_name: String,
    pub primary_color: String,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub privacy_policy_uri: Option<String>,
    #[serde(default)]
    pub support_uri: Option<String>,
    #[serde(default)]
    pub terms_version: Option<String>,
    pub active: bool,
}

impl CiamBrand {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("CIAM brand id", &self.id)?;
        require_non_empty("CIAM brand tenant_id", &self.tenant_id)?;
        require_non_empty("CIAM brand realm_id", &self.realm_id)?;
        require_non_empty("CIAM brand display_name", &self.display_name)?;
        validate_hex_color("CIAM brand primary_color", &self.primary_color)?;
        validate_optional_uri("CIAM brand logo_uri", self.logo_uri.as_deref())?;
        validate_optional_uri(
            "CIAM brand privacy_policy_uri",
            self.privacy_policy_uri.as_deref(),
        )?;
        validate_optional_uri("CIAM brand support_uri", self.support_uri.as_deref())?;
        if let Some(terms_version) = &self.terms_version {
            require_non_empty("CIAM brand terms_version", terms_version)?;
        }
        Ok(())
    }
}

/// An application catalog entry exposed to tenant administrators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppCatalogEntry {
    pub id: String,
    pub tenant_id: String,
    pub realm_id: String,
    pub display_name: String,
    pub category: String,
    pub oidc_client_id: Option<String>,
    pub saml_entity_id: Option<String>,
    pub scim_enabled: bool,
    pub marketplace_connector_id: Option<String>,
}

impl AppCatalogEntry {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("app catalog id", &self.id)?;
        require_non_empty("app catalog tenant_id", &self.tenant_id)?;
        require_non_empty("app catalog realm_id", &self.realm_id)?;
        require_non_empty("app catalog display_name", &self.display_name)?;
        require_non_empty("app catalog category", &self.category)?;
        if let Some(oidc_client_id) = &self.oidc_client_id {
            require_non_empty("app catalog oidc_client_id", oidc_client_id)?;
        }
        if let Some(saml_entity_id) = &self.saml_entity_id {
            require_non_empty("app catalog saml_entity_id", saml_entity_id)?;
            Url::parse(saml_entity_id).map_err(|e| QidError::BadRequest {
                message: format!("app catalog saml_entity_id must be a valid URL: {e}"),
            })?;
        }
        if let Some(connector_id) = &self.marketplace_connector_id {
            require_non_empty("app catalog marketplace_connector_id", connector_id)?;
        }
        if self.oidc_client_id.is_none() && self.saml_entity_id.is_none() {
            return Err(QidError::BadRequest {
                message: "app catalog entry must reference an OIDC client or SAML entity"
                    .to_string(),
            });
        }
        if self.oidc_client_id.is_some() && self.saml_entity_id.is_some() {
            return Err(QidError::BadRequest {
                message: "app catalog entry must not reference both an OIDC client and SAML entity"
                    .to_string(),
            });
        }
        if self.scim_enabled && self.marketplace_connector_id.is_none() {
            return Err(QidError::BadRequest {
                message:
                    "app catalog entry with SCIM enabled must reference a marketplace connector"
                        .to_string(),
            });
        }
        Ok(())
    }
}

/// A marketplace connector declaration for provisioning or federation integrations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceConnector {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub connector_type: MarketplaceConnectorType,
    pub config_json: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceConnectorType {
    Scim,
    Saml,
    Oidc,
    Webhook,
}

impl MarketplaceConnector {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("marketplace connector id", &self.id)?;
        require_non_empty("marketplace connector tenant_id", &self.tenant_id)?;
        require_non_empty("marketplace connector provider", &self.provider)?;
        if !self.config_json.is_object() {
            return Err(QidError::BadRequest {
                message: "marketplace connector config_json must be an object".to_string(),
            });
        }
        if self.enabled {
            match self.connector_type {
                MarketplaceConnectorType::Scim => {
                    require_json_string_url(&self.config_json, "base_url")?;
                    require_json_string(&self.config_json, "token_ref")?;
                }
                MarketplaceConnectorType::Saml => {
                    require_json_string(&self.config_json, "entity_id")?;
                    require_json_string_url(&self.config_json, "metadata_url")?;
                }
                MarketplaceConnectorType::Oidc => {
                    require_json_string(&self.config_json, "issuer")?;
                    require_json_string(&self.config_json, "client_id")?;
                }
                MarketplaceConnectorType::Webhook => {
                    require_json_string_url(&self.config_json, "endpoint")?;
                    require_json_string(&self.config_json, "secret_ref")?;
                }
            }
        }
        Ok(())
    }
}

/// A usage event suitable for billing and metering hooks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageBillingEvent {
    pub id: String,
    pub tenant_id: String,
    pub meter: String,
    pub quantity: u64,
    pub occurred_at: u64,
    pub idempotency_key: String,
    #[serde(default)]
    pub dimensions: BTreeMap<String, String>,
}

impl UsageBillingEvent {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("usage billing id", &self.id)?;
        require_non_empty("usage billing tenant_id", &self.tenant_id)?;
        require_non_empty("usage billing meter", &self.meter)?;
        require_non_empty("usage billing idempotency_key", &self.idempotency_key)?;
        if self.quantity == 0 {
            return Err(QidError::BadRequest {
                message: "usage billing quantity must be greater than zero".to_string(),
            });
        }
        if self.occurred_at == 0 {
            return Err(QidError::BadRequest {
                message: "usage billing occurred_at must be set".to_string(),
            });
        }
        for key in self.dimensions.keys() {
            require_non_empty("usage billing dimension key", key)?;
        }
        Ok(())
    }
}

/// A compliance evidence package descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceEvidencePack {
    pub id: String,
    pub tenant_id: String,
    pub period_start: u64,
    pub period_end: u64,
    pub controls: Vec<String>,
    pub object_uri: String,
    pub sha256_hex: String,
    pub generated_at: u64,
}

impl ComplianceEvidencePack {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("compliance evidence id", &self.id)?;
        require_non_empty("compliance evidence tenant_id", &self.tenant_id)?;
        if self.period_start >= self.period_end {
            return Err(QidError::BadRequest {
                message: "compliance evidence period_start must be before period_end".to_string(),
            });
        }
        if self.controls.is_empty() {
            return Err(QidError::BadRequest {
                message: "compliance evidence controls must not be empty".to_string(),
            });
        }
        for control in &self.controls {
            require_non_empty("compliance evidence control", control)?;
        }
        require_non_empty("compliance evidence object_uri", &self.object_uri)?;
        if !(self.object_uri.starts_with("s3://")
            || self.object_uri.starts_with("gs://")
            || self.object_uri.starts_with("file://"))
        {
            return Err(QidError::BadRequest {
                message: "compliance evidence object_uri must use s3, gs, or file scheme"
                    .to_string(),
            });
        }
        if !is_lower_hex_sha256(&self.sha256_hex) {
            return Err(QidError::BadRequest {
                message: "compliance evidence sha256_hex must be 64 lowercase hex characters"
                    .to_string(),
            });
        }
        if self.generated_at == 0 {
            return Err(QidError::BadRequest {
                message: "compliance evidence generated_at must be set".to_string(),
            });
        }
        Ok(())
    }
}

/// A tenant-scoped delegated administrator grant for SaaS operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegatedTenantAdmin {
    pub id: String,
    pub tenant_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub allowed_realm_ids: Vec<String>,
    pub granted_by: String,
    pub granted_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

impl DelegatedTenantAdmin {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("delegated tenant admin id", &self.id)?;
        require_non_empty("delegated tenant admin tenant_id", &self.tenant_id)?;
        require_non_empty("delegated tenant admin subject", &self.subject)?;
        require_non_empty("delegated tenant admin granted_by", &self.granted_by)?;
        if self.roles.is_empty() {
            return Err(QidError::BadRequest {
                message: "delegated tenant admin roles must not be empty".to_string(),
            });
        }
        for role in &self.roles {
            require_non_empty("delegated tenant admin role", role)?;
            if !matches!(
                role.as_str(),
                "tenant.owner" | "realm.admin" | "app.admin" | "directory.admin" | "auditor"
            ) {
                return Err(QidError::BadRequest {
                    message: "delegated tenant admin role is not allowed".to_string(),
                });
            }
        }
        for realm_id in &self.allowed_realm_ids {
            require_non_empty("delegated tenant admin allowed_realm_id", realm_id)?;
        }
        if self.granted_at == 0 {
            return Err(QidError::BadRequest {
                message: "delegated tenant admin granted_at must be set".to_string(),
            });
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= self.granted_at)
        {
            return Err(QidError::BadRequest {
                message: "delegated tenant admin expires_at must be after granted_at".to_string(),
            });
        }
        Ok(())
    }
}

/// A compiled policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub id: String,
    pub realm_id: String,
    pub name: String,
    pub source_hash: String,
    pub compiled_json: serde_json::Value,
    pub version: u64,
    pub active: bool,
}
#[cfg(test)]
mod saas_tests {
    use super::*;

    #[test]
    fn custom_domain_requires_verified_bare_hostname() {
        let domain = CustomDomain {
            id: "dom_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            realm_id: "corp".to_string(),
            hostname: "login.example.com".to_string(),
            certificate_ref: "cert://tenant/login".to_string(),
            verified: true,
            verification_status: "active".to_string(),
            dns_challenge_name: Some("_qid.login.example.com".to_string()),
            dns_challenge_value: Some("qid-domain-proof".to_string()),
            certificate_expires_at: Some(1_900_000_000),
            certificate_renew_after: Some(1_880_000_000),
            last_verified_at: Some(1_800_000_000),
        };
        domain.validate().unwrap();

        let mut invalid = domain.clone();
        invalid.hostname = "login.example.com/path".to_string();
        assert!(invalid.validate().is_err());

        invalid = domain;
        invalid.verified = false;
        invalid.verification_status = "pending".to_string();
        invalid.certificate_ref = String::new();
        invalid.certificate_expires_at = None;
        invalid.certificate_renew_after = None;
        invalid.last_verified_at = None;
        invalid.validate().unwrap();

        let mut invalid_pending = invalid;
        invalid_pending.dns_challenge_value = None;
        assert!(invalid_pending.validate().is_err());
    }

    #[test]
    fn app_catalog_requires_protocol_reference() {
        let entry = AppCatalogEntry {
            id: "app_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            realm_id: "realm_1".to_string(),
            display_name: "Payroll".to_string(),
            category: "hr".to_string(),
            oidc_client_id: Some("payroll-client".to_string()),
            saml_entity_id: None,
            scim_enabled: true,
            marketplace_connector_id: Some("connector_1".to_string()),
        };
        entry.validate().unwrap();

        let mut invalid = entry.clone();
        invalid.oidc_client_id = None;
        invalid.saml_entity_id = None;
        assert!(invalid.validate().is_err());

        let mut invalid = entry.clone();
        invalid.saml_entity_id = Some("https://sp.example.com/metadata".to_string());
        assert!(invalid.validate().is_err());

        let mut invalid = entry.clone();
        invalid.oidc_client_id = None;
        invalid.saml_entity_id = Some("not a URL".to_string());
        assert!(invalid.validate().is_err());

        let mut invalid = entry.clone();
        invalid.oidc_client_id = Some(" ".to_string());
        assert!(invalid.validate().is_err());

        let mut invalid = entry;
        invalid.marketplace_connector_id = None;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn marketplace_connector_requires_type_specific_config_when_enabled() {
        let connector = MarketplaceConnector {
            id: "conn_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            provider: "example-saas".to_string(),
            connector_type: MarketplaceConnectorType::Scim,
            config_json: serde_json::json!({
                "base_url": "https://scim.example.com/v2",
                "token_ref": "secret://scim-token"
            }),
            enabled: true,
        };
        connector.validate().unwrap();

        let mut invalid = connector;
        invalid.config_json = serde_json::json!({ "base_url": "ftp://scim.example.com/v2" });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn usage_billing_event_requires_positive_quantity_and_idempotency() {
        let event = UsageBillingEvent {
            id: "usage_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            meter: "monthly_active_users".to_string(),
            quantity: 42,
            occurred_at: 1_700_000_000,
            idempotency_key: "tenant_1:mau:1700000000".to_string(),
            dimensions: BTreeMap::from([("realm".to_string(), "corp".to_string())]),
        };
        event.validate().unwrap();

        let mut invalid = event;
        invalid.quantity = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn compliance_evidence_pack_rejects_bad_period_and_digest() {
        let pack = ComplianceEvidencePack {
            id: "evidence_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            period_start: 1_700_000_000,
            period_end: 1_700_086_400,
            controls: vec!["SOC2-CC6.1".to_string()],
            object_uri: "s3://qid-evidence/tenant_1/pack.json".to_string(),
            sha256_hex: "a".repeat(64),
            generated_at: 1_700_086_401,
        };
        pack.validate().unwrap();

        let mut invalid = pack.clone();
        invalid.period_end = invalid.period_start;
        assert!(invalid.validate().is_err());

        invalid = pack;
        invalid.sha256_hex = "A".repeat(64);
        assert!(invalid.validate().is_err());
    }
}
