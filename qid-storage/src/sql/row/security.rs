use base64::Engine;
use qid_core::models::*;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct WebAuthnCredentialRow {
    id: String,
    user_id: String,
    credential_id: String,
    public_key: String,
    counter: i64,
    aaguid: String,
    device_name: Option<String>,
    created_at: i64,
}

impl TryFrom<WebAuthnCredentialRow> for WebAuthnCredential {
    type Error = String;

    fn try_from(row: WebAuthnCredentialRow) -> Result<Self, Self::Error> {
        let credential_id = base64::engine::general_purpose::STANDARD
            .decode(&row.credential_id)
            .map_err(|e| format!("invalid base64 credential_id: {e}"))?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&row.public_key)
            .map_err(|e| format!("invalid base64 public_key: {e}"))?;
        let aaguid = base64::engine::general_purpose::STANDARD
            .decode(&row.aaguid)
            .map_err(|e| format!("invalid base64 aaguid: {e}"))?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            credential_id,
            public_key,
            counter: row.counter as u64,
            aaguid,
            device_name: row.device_name,
            created_at: row.created_at as u64,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ServiceAccountRow {
    id: String,
    client_id: String,
    realm_id: String,
    description: Option<String>,
    created_at: i64,
}

impl From<ServiceAccountRow> for ServiceAccount {
    fn from(row: ServiceAccountRow) -> Self {
        Self {
            id: row.id,
            client_id: row.client_id,
            realm_id: row.realm_id,
            description: row.description,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct PolicyBundleRow {
    id: String,
    realm_id: String,
    name: String,
    source_hash: String,
    compiled_json: String,
    version: i64,
    active: i64,
}

impl From<PolicyBundleRow> for PolicyBundle {
    fn from(row: PolicyBundleRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            name: row.name,
            source_hash: row.source_hash,
            compiled_json: serde_json::from_str(&row.compiled_json).unwrap_or_default(),
            version: row.version as u64,
            active: row.active != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AuditEventRow {
    id: String,
    realm_id: Option<String>,
    actor: String,
    action: String,
    target_type: String,
    target_id: String,
    reason: String,
    metadata_json: String,
    created_at: i64,
    previous_hash: Option<String>,
    event_hash: Option<String>,
}

impl From<AuditEventRow> for AuditEvent {
    fn from(row: AuditEventRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            actor: row.actor,
            action: row.action,
            target_type: row.target_type,
            target_id: row.target_id,
            reason: row.reason,
            metadata_json: serde_json::from_str(&row.metadata_json).unwrap_or_default(),
            created_at: row.created_at as u64,
            previous_hash: row.previous_hash,
            event_hash: row.event_hash,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AuditRetentionConfigRow {
    realm_id: Option<String>,
    retention_days: i64,
    legal_hold: i64,
    updated_by: String,
    reason: String,
    updated_at: i64,
}

impl From<AuditRetentionConfigRow> for AuditRetentionConfig {
    fn from(row: AuditRetentionConfigRow) -> Self {
        Self {
            realm_id: row.realm_id,
            retention_days: row.retention_days as u64,
            legal_hold: row.legal_hold != 0,
            updated_by: row.updated_by,
            reason: row.reason,
            updated_at: row.updated_at as u64,
        }
    }
}

pub(in crate::sql) fn audit_retention_stream_id(realm_id: Option<&str>) -> String {
    realm_id.unwrap_or("__global__").to_string()
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct TotpCredentialRow {
    id: String,
    user_id: String,
    secret: String,
    algorithm: String,
    digits: i64,
    period: i64,
    enabled: i64,
    last_used_step: Option<i64>,
}

impl From<TotpCredentialRow> for TotpCredential {
    fn from(row: TotpCredentialRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            secret: row.secret,
            algorithm: row.algorithm,
            digits: row.digits as u32,
            period: row.period as u64,
            enabled: row.enabled != 0,
            last_used_step: row.last_used_step.map(|v| v as u64),
            created_at: 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct DeviceRow {
    id: String,
    user_id: String,
    realm_id: String,
    device_name: Option<String>,
    device_type: String,
    posture: String,
    registered_at: i64,
    last_seen_at: i64,
}

impl From<DeviceRow> for Device {
    fn from(row: DeviceRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            realm_id: row.realm_id,
            device_name: row.device_name,
            device_type: row.device_type,
            posture: serde_json::from_str(&row.posture).unwrap_or_default(),
            registered_at: row.registered_at as u64,
            last_seen_at: row.last_seen_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ParRequestRow {
    request_uri: String,
    client_id: String,
    realm_id: String,
    params_json: String,
    expires_at: i64,
    used: i64,
    created_at: i64,
}

impl From<ParRequestRow> for ParRequest {
    fn from(row: ParRequestRow) -> Self {
        Self {
            request_uri: row.request_uri,
            client_id: row.client_id,
            realm_id: row.realm_id,
            params_json: serde_json::from_str(&row.params_json).unwrap_or_default(),
            expires_at: row.expires_at as u64,
            used: row.used != 0,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ScimUserRow {
    id: String,
    realm_id: String,
    external_id: Option<String>,
    user_name: String,
    name_json: String,
    emails_json: String,
    enterprise_json: String,
    active: i64,
}

impl From<ScimUserRow> for ScimUser {
    fn from(row: ScimUserRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            external_id: row.external_id,
            user_name: row.user_name,
            name_json: serde_json::from_str(&row.name_json).unwrap_or_default(),
            emails_json: serde_json::from_str(&row.emails_json).unwrap_or_default(),
            enterprise_json: serde_json::from_str(&row.enterprise_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            active: row.active != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ScimGroupRow {
    id: String,
    realm_id: String,
    display_name: String,
    members_json: String,
}

impl From<ScimGroupRow> for ScimGroup {
    fn from(row: ScimGroupRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            display_name: row.display_name,
            members_json: serde_json::from_str(&row.members_json).unwrap_or_default(),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct FedCmIdentityRow {
    id: String,
    realm_id: String,
    account_id: String,
    email: String,
    name: Option<String>,
    given_name: Option<String>,
    picture_url: Option<String>,
    approved_clients: String,
}

impl From<FedCmIdentityRow> for FedCmIdentity {
    fn from(row: FedCmIdentityRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            account_id: row.account_id,
            email: row.email,
            name: row.name,
            given_name: row.given_name,
            picture_url: row.picture_url,
            approved_clients: serde_json::from_str(&row.approved_clients).unwrap_or_default(),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct WorkloadIdentityRow {
    id: String,
    realm_id: String,
    spiffe_id: String,
    description: Option<String>,
    trust_domain: String,
    authorities_json: String,
}

impl From<WorkloadIdentityRow> for WorkloadIdentity {
    fn from(row: WorkloadIdentityRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            spiffe_id: row.spiffe_id,
            description: row.description,
            trust_domain: row.trust_domain,
            authorities_json: serde_json::from_str(&row.authorities_json).unwrap_or_default(),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct WorkloadCertificateRow {
    id: String,
    realm_id: String,
    workload_id: String,
    spiffe_id: String,
    serial_number: String,
    x5t_s256: String,
    csr_sha256: String,
    certificate_pem: String,
    issuer_key_ref: String,
    issued_at: i64,
    not_before: i64,
    not_after: i64,
    revoked_at: Option<i64>,
}

impl From<WorkloadCertificateRow> for WorkloadCertificate {
    fn from(row: WorkloadCertificateRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            workload_id: row.workload_id,
            spiffe_id: row.spiffe_id,
            serial_number: row.serial_number,
            x5t_s256: row.x5t_s256,
            csr_sha256: row.csr_sha256,
            certificate_pem: row.certificate_pem,
            issuer_key_ref: row.issuer_key_ref,
            issued_at: row.issued_at as u64,
            not_before: row.not_before as u64,
            not_after: row.not_after as u64,
            revoked_at: row.revoked_at.map(|value| value as u64),
        }
    }
}
