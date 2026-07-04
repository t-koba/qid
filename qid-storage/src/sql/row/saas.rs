use qid_core::models::*;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CustomDomainRow {
    id: String,
    tenant_id: String,
    realm_id: String,
    hostname: String,
    certificate_ref: String,
    verified: i64,
    verification_status: String,
    dns_challenge_name: Option<String>,
    dns_challenge_value: Option<String>,
    certificate_expires_at: Option<i64>,
    certificate_renew_after: Option<i64>,
    last_verified_at: Option<i64>,
}

impl From<CustomDomainRow> for CustomDomain {
    fn from(row: CustomDomainRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            realm_id: row.realm_id,
            hostname: row.hostname,
            certificate_ref: row.certificate_ref,
            verified: row.verified != 0,
            verification_status: row.verification_status,
            dns_challenge_name: row.dns_challenge_name,
            dns_challenge_value: row.dns_challenge_value,
            certificate_expires_at: row.certificate_expires_at.map(|value| value as u64),
            certificate_renew_after: row.certificate_renew_after.map(|value| value as u64),
            last_verified_at: row.last_verified_at.map(|value| value as u64),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CiamBrandRow {
    id: String,
    tenant_id: String,
    realm_id: String,
    display_name: String,
    primary_color: String,
    logo_uri: Option<String>,
    privacy_policy_uri: Option<String>,
    support_uri: Option<String>,
    terms_version: Option<String>,
    active: i64,
}

impl From<CiamBrandRow> for CiamBrand {
    fn from(row: CiamBrandRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            realm_id: row.realm_id,
            display_name: row.display_name,
            primary_color: row.primary_color,
            logo_uri: row.logo_uri,
            privacy_policy_uri: row.privacy_policy_uri,
            support_uri: row.support_uri,
            terms_version: row.terms_version,
            active: row.active != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AppCatalogEntryRow {
    id: String,
    tenant_id: String,
    realm_id: String,
    display_name: String,
    category: String,
    oidc_client_id: Option<String>,
    saml_entity_id: Option<String>,
    scim_enabled: i64,
    marketplace_connector_id: Option<String>,
}

impl From<AppCatalogEntryRow> for AppCatalogEntry {
    fn from(row: AppCatalogEntryRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            realm_id: row.realm_id,
            display_name: row.display_name,
            category: row.category,
            oidc_client_id: row.oidc_client_id,
            saml_entity_id: row.saml_entity_id,
            scim_enabled: row.scim_enabled != 0,
            marketplace_connector_id: row.marketplace_connector_id,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct MarketplaceConnectorRow {
    id: String,
    tenant_id: String,
    provider: String,
    connector_type: String,
    config_json: String,
    enabled: i64,
}

impl From<MarketplaceConnectorRow> for MarketplaceConnector {
    fn from(row: MarketplaceConnectorRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            provider: row.provider,
            connector_type: marketplace_connector_type_from_str(&row.connector_type),
            config_json: serde_json::from_str(&row.config_json).unwrap_or_default(),
            enabled: row.enabled != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct UsageBillingEventRow {
    id: String,
    tenant_id: String,
    meter: String,
    quantity: i64,
    occurred_at: i64,
    idempotency_key: String,
    dimensions_json: String,
}

impl From<UsageBillingEventRow> for UsageBillingEvent {
    fn from(row: UsageBillingEventRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            meter: row.meter,
            quantity: row.quantity as u64,
            occurred_at: row.occurred_at as u64,
            idempotency_key: row.idempotency_key,
            dimensions: serde_json::from_str(&row.dimensions_json).unwrap_or_default(),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ComplianceEvidencePackRow {
    id: String,
    tenant_id: String,
    period_start: i64,
    period_end: i64,
    controls_json: String,
    object_uri: String,
    sha256_hex: String,
    generated_at: i64,
}

impl From<ComplianceEvidencePackRow> for ComplianceEvidencePack {
    fn from(row: ComplianceEvidencePackRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            period_start: row.period_start as u64,
            period_end: row.period_end as u64,
            controls: serde_json::from_str(&row.controls_json).unwrap_or_default(),
            object_uri: row.object_uri,
            sha256_hex: row.sha256_hex,
            generated_at: row.generated_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct DelegatedTenantAdminRow {
    id: String,
    tenant_id: String,
    subject: String,
    roles_json: String,
    allowed_realm_ids_json: String,
    granted_by: String,
    granted_at: i64,
    expires_at: Option<i64>,
    revoked: i64,
}

impl From<DelegatedTenantAdminRow> for DelegatedTenantAdmin {
    fn from(row: DelegatedTenantAdminRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            roles: serde_json::from_str(&row.roles_json).unwrap_or_default(),
            allowed_realm_ids: serde_json::from_str(&row.allowed_realm_ids_json)
                .unwrap_or_default(),
            granted_by: row.granted_by,
            granted_at: row.granted_at as u64,
            expires_at: row.expires_at.map(|value| value as u64),
            revoked: row.revoked != 0,
        }
    }
}

pub(in crate::sql) fn marketplace_connector_type_as_str(
    connector_type: &MarketplaceConnectorType,
) -> &'static str {
    match connector_type {
        MarketplaceConnectorType::Scim => "scim",
        MarketplaceConnectorType::Saml => "saml",
        MarketplaceConnectorType::Oidc => "oidc",
        MarketplaceConnectorType::Webhook => "webhook",
    }
}

pub(in crate::sql) fn marketplace_connector_type_from_str(value: &str) -> MarketplaceConnectorType {
    match value {
        "saml" => MarketplaceConnectorType::Saml,
        "oidc" => MarketplaceConnectorType::Oidc,
        "webhook" => MarketplaceConnectorType::Webhook,
        _ => MarketplaceConnectorType::Scim,
    }
}
