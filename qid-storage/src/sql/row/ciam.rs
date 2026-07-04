use qid_core::models::*;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct VcCredentialStatusRow {
    credential_id: String,
    realm_id: String,
    subject: String,
    issuer: String,
    status_list_uri: String,
    issued_at: i64,
    expires_at: i64,
    revoked: i64,
    revocation_reason: Option<String>,
    revoked_at: Option<i64>,
}

impl From<VcCredentialStatusRow> for VcCredentialStatusRecord {
    fn from(row: VcCredentialStatusRow) -> Self {
        Self {
            credential_id: row.credential_id,
            realm_id: row.realm_id,
            subject: row.subject,
            issuer: row.issuer,
            status_list_uri: row.status_list_uri,
            issued_at: row.issued_at as u64,
            expires_at: row.expires_at as u64,
            revoked: row.revoked != 0,
            revocation_reason: row.revocation_reason,
            revoked_at: row.revoked_at.map(|value| value as u64),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CiamConsentGrantRow {
    id: String,
    realm_id: String,
    user_id: String,
    client_id: String,
    granted_claims_json: String,
    terms_version: Option<String>,
    granted_at_epoch_seconds: i64,
    revoked: i64,
}

impl From<CiamConsentGrantRow> for CiamConsentGrant {
    fn from(row: CiamConsentGrantRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            client_id: row.client_id,
            granted_claims: serde_json::from_str(&row.granted_claims_json).unwrap_or_default(),
            terms_version: row.terms_version,
            granted_at_epoch_seconds: row.granted_at_epoch_seconds as u64,
            revoked: row.revoked != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CiamVerificationChallengeRow {
    id: String,
    realm_id: String,
    user_id: String,
    channel: String,
    address: String,
    purpose: String,
    code_hash: String,
    expires_at_epoch_seconds: i64,
    consumed_at_epoch_seconds: Option<i64>,
    created_at_epoch_seconds: i64,
}

impl From<CiamVerificationChallengeRow> for CiamVerificationChallengeRecord {
    fn from(row: CiamVerificationChallengeRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            channel: row.channel,
            address: row.address,
            purpose: row.purpose,
            code_hash: row.code_hash,
            expires_at_epoch_seconds: row.expires_at_epoch_seconds as u64,
            consumed_at_epoch_seconds: row.consumed_at_epoch_seconds.map(|value| value as u64),
            created_at_epoch_seconds: row.created_at_epoch_seconds as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CiamIdentityLinkRow {
    id: String,
    realm_id: String,
    user_id: String,
    provider: String,
    external_subject: String,
    external_email: Option<String>,
    profile_json: String,
    linked_at_epoch_seconds: i64,
    verified: i64,
}

impl From<CiamIdentityLinkRow> for CiamIdentityLink {
    fn from(row: CiamIdentityLinkRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            provider: row.provider,
            external_subject: row.external_subject,
            external_email: row.external_email,
            profile_json: serde_json::from_str(&row.profile_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            linked_at_epoch_seconds: row.linked_at_epoch_seconds as u64,
            verified: row.verified != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct CiamProgressiveProfileRow {
    id: String,
    realm_id: String,
    user_id: String,
    profile_json: String,
    passwordless_migrated_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl From<CiamProgressiveProfileRow> for CiamProgressiveProfile {
    fn from(row: CiamProgressiveProfileRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            profile_json: serde_json::from_str(&row.profile_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            passwordless_migrated_at: row.passwordless_migrated_at.map(|v| v as u64),
            created_at: row.created_at as u64,
            updated_at: row.updated_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct PasswordResetTokenRow {
    id: String,
    realm_id: String,
    user_id: String,
    token_hash: String,
    device_id: Option<String>,
    risk_json: String,
    expires_at_epoch_seconds: i64,
    consumed_at_epoch_seconds: Option<i64>,
    created_at_epoch_seconds: i64,
}

impl From<PasswordResetTokenRow> for PasswordResetToken {
    fn from(row: PasswordResetTokenRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            device_id: row.device_id,
            risk_json: serde_json::from_str(&row.risk_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            expires_at_epoch_seconds: row.expires_at_epoch_seconds as u64,
            consumed_at_epoch_seconds: row.consumed_at_epoch_seconds.map(|value| value as u64),
            created_at_epoch_seconds: row.created_at_epoch_seconds as u64,
        }
    }
}
