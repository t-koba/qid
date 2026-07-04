use qid_core::models::*;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct UserRow {
    id: String,
    realm_id: String,
    email: Option<String>,
    email_verified: i64,
    display_name: Option<String>,
    failed_login_attempts: i64,
    locked_until: Option<i64>,
    org: Option<String>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            email: row.email,
            email_verified: row.email_verified != 0,
            display_name: row.display_name,
            failed_login_attempts: row.failed_login_attempts as u32,
            locked_until: row.locked_until.map(|v| v as u64),
            org: row.org,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct ClientRow {
    id: String,
    realm_id: String,
    client_id: String,
    client_type: String,
    token_endpoint_auth_method: Option<String>,
    client_secret_hash: Option<String>,
    mtls_certificate_thumbprints: Option<String>,
    jwks: String,
    redirect_uris: String,
    grant_types: String,
    client_name: Option<String>,
    client_uri: Option<String>,
    logo_uri: Option<String>,
    contacts: Option<String>,
    post_logout_redirect_uris: Option<String>,
    default_max_age: Option<i64>,
    require_auth_time: i64,
    sector_identifier_uri: Option<String>,
    subject_type: Option<String>,
    backchannel_logout_uri: Option<String>,
    frontchannel_logout_uri: Option<String>,
    backchannel_client_notification_endpoint: Option<String>,
}

impl From<ClientRow> for Client {
    fn from(row: ClientRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            client_id: row.client_id,
            client_type: match row.client_type.as_str() {
                "public" => ClientType::Public,
                _ => ClientType::Confidential,
            },
            token_endpoint_auth_method: row.token_endpoint_auth_method.unwrap_or_else(|| match row
                .client_type
                .as_str()
            {
                "public" => "none".to_string(),
                _ => qid_core::models::default_token_endpoint_auth_method(),
            }),
            client_secret_hash: row.client_secret_hash,
            mtls_certificate_thumbprints: row
                .mtls_certificate_thumbprints
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            jwks: serde_json::from_str(&row.jwks)
                .unwrap_or_else(|_| qid_core::models::default_client_jwks()),
            redirect_uris: serde_json::from_str(&row.redirect_uris).unwrap_or_default(),
            grant_types: serde_json::from_str(&row.grant_types).unwrap_or_default(),
            client_name: row.client_name,
            client_uri: row.client_uri,
            logo_uri: row.logo_uri,
            contacts: row
                .contacts
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            post_logout_redirect_uris: row
                .post_logout_redirect_uris
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            default_max_age: row.default_max_age.map(|v| v as u64),
            require_auth_time: row.require_auth_time != 0,
            sector_identifier_uri: row.sector_identifier_uri,
            subject_type: row.subject_type,
            backchannel_logout_uri: row.backchannel_logout_uri,
            frontchannel_logout_uri: row.frontchannel_logout_uri,
            backchannel_client_notification_endpoint: row.backchannel_client_notification_endpoint,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct SessionRow {
    id: String,
    realm_id: String,
    user_id: String,
    auth_time: i64,
    acr: Option<String>,
    amr: String,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    revoked: i64,
    created_at: i64,
    cnf: Option<String>,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            user_id: row.user_id,
            auth_time: row.auth_time as u64,
            acr: row.acr,
            amr: serde_json::from_str(&row.amr).unwrap_or_default(),
            idle_expires_at: row.idle_expires_at as u64,
            absolute_expires_at: row.absolute_expires_at as u64,
            revoked: row.revoked != 0,
            created_at: row.created_at as u64,
            cnf: row.cnf.and_then(|v| serde_json::from_str(&v).ok()),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AuthCodeRow {
    code_hash: String,
    client_id: String,
    user_id: String,
    realm_id: String,
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    auth_time: Option<i64>,
    acr: Option<String>,
    amr: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scopes: String,
    resource: Option<String>,
    authorization_details: Option<String>,
    expires_at: i64,
    used: i64,
    created_at: i64,
}

impl From<AuthCodeRow> for AuthorizationCode {
    fn from(row: AuthCodeRow) -> Self {
        Self {
            code_hash: row.code_hash,
            client_id: row.client_id,
            user_id: row.user_id,
            realm_id: row.realm_id,
            redirect_uri: row.redirect_uri,
            state: row.state,
            nonce: row.nonce,
            auth_time: row.auth_time.map(|value| value as u64),
            acr: row.acr,
            amr: row
                .amr
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
            resource: row
                .resource
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            authorization_details: row
                .authorization_details
                .and_then(|value| serde_json::from_str(&value).ok()),
            expires_at: row.expires_at as u64,
            used: row.used != 0,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct TokenFamilyRow {
    id: String,
    user_id: String,
    client_id: String,
    realm_id: String,
    current_refresh_hash: String,
    audience: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    sender_constraint: Option<String>,
    issued_at: i64,
    revoked: i64,
}

impl From<TokenFamilyRow> for TokenFamily {
    fn from(row: TokenFamilyRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            client_id: row.client_id,
            realm_id: row.realm_id,
            current_refresh_hash: row.current_refresh_hash,
            audience: row
                .audience
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            resource: row
                .resource
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            authorization_details: row
                .authorization_details
                .and_then(|value| serde_json::from_str(&value).ok()),
            sender_constraint: row
                .sender_constraint
                .and_then(|value| serde_json::from_str(&value).ok()),
            issued_at: row.issued_at as u64,
            revoked: row.revoked != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AccessTokenRow {
    jti: String,
    family_id: Option<String>,
    user_id: String,
    client_id: String,
    realm_id: String,
    scopes: String,
    audience: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    cnf: Option<String>,
    auth_time: Option<i64>,
    acr: Option<String>,
    amr: Option<String>,
    nonce: Option<String>,
    sender_constraint: Option<String>,
    token_format: Option<String>,
    expires_at: i64,
    revoked: i64,
    issued_at: i64,
}

impl From<AccessTokenRow> for AccessToken {
    fn from(row: AccessTokenRow) -> Self {
        Self {
            jti: row.jti,
            family_id: row.family_id,
            user_id: row.user_id,
            client_id: row.client_id,
            realm_id: row.realm_id,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
            audience: row
                .audience
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            resource: row
                .resource
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            authorization_details: row
                .authorization_details
                .and_then(|value| serde_json::from_str(&value).ok()),
            cnf: row.cnf.and_then(|value| serde_json::from_str(&value).ok()),
            auth_time: row.auth_time.map(|value| value as u64),
            acr: row.acr,
            amr: row
                .amr
                .and_then(|value| serde_json::from_str(&value).ok())
                .unwrap_or_default(),
            nonce: row.nonce,
            sender_constraint: row
                .sender_constraint
                .and_then(|value| serde_json::from_str(&value).ok()),
            token_format: token_format_from_str(row.token_format.as_deref()),
            expires_at: row.expires_at as u64,
            revoked: row.revoked != 0,
            issued_at: row.issued_at as u64,
        }
    }
}

pub(in crate::sql) fn token_format_to_str(format: qid_core::models::TokenFormat) -> &'static str {
    match format {
        qid_core::models::TokenFormat::Jwt => "jwt",
        qid_core::models::TokenFormat::Opaque => "opaque",
    }
}

pub(in crate::sql) fn token_format_from_str(value: Option<&str>) -> qid_core::models::TokenFormat {
    match value {
        Some("opaque") => qid_core::models::TokenFormat::Opaque,
        _ => qid_core::models::TokenFormat::Jwt,
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct DeviceAuthorizationGrantRow {
    device_code_hash: String,
    user_code: String,
    client_id: String,
    realm_id: String,
    scopes: String,
    user_id: Option<String>,
    expires_at: i64,
    approved_at: Option<i64>,
    consumed: i64,
    last_poll_at: Option<i64>,
    poll_interval_seconds: i64,
    created_at: i64,
}

impl From<DeviceAuthorizationGrantRow> for DeviceAuthorizationGrant {
    fn from(row: DeviceAuthorizationGrantRow) -> Self {
        Self {
            device_code_hash: row.device_code_hash,
            user_code: row.user_code,
            client_id: row.client_id,
            realm_id: row.realm_id,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
            user_id: row.user_id,
            expires_at: row.expires_at as u64,
            approved_at: row.approved_at.map(|approved_at| approved_at as u64),
            consumed: row.consumed != 0,
            last_poll_at: row.last_poll_at.map(|polled_at| polled_at as u64),
            poll_interval_seconds: row.poll_interval_seconds as u64,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct BackchannelAuthenticationGrantRow {
    auth_req_id_hash: String,
    client_id: String,
    realm_id: String,
    login_hint: String,
    binding_message: Option<String>,
    scopes: String,
    user_id: Option<String>,
    expires_at: i64,
    approved_at: Option<i64>,
    consumed: i64,
    last_poll_at: Option<i64>,
    poll_interval_seconds: i64,
    created_at: i64,
}

impl From<BackchannelAuthenticationGrantRow> for BackchannelAuthenticationGrant {
    fn from(row: BackchannelAuthenticationGrantRow) -> Self {
        Self {
            auth_req_id_hash: row.auth_req_id_hash,
            client_id: row.client_id,
            realm_id: row.realm_id,
            login_hint: row.login_hint,
            binding_message: row.binding_message,
            scopes: serde_json::from_str(&row.scopes).unwrap_or_default(),
            user_id: row.user_id,
            expires_at: row.expires_at as u64,
            approved_at: row.approved_at.map(|approved_at| approved_at as u64),
            consumed: row.consumed != 0,
            last_poll_at: row.last_poll_at.map(|polled_at| polled_at as u64),
            poll_interval_seconds: row.poll_interval_seconds as u64,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AdminRow {
    id: String,
    tenant_id: String,
    subject: String,
    roles_json: String,
    created_at: i64,
}

impl From<AdminRow> for Admin {
    fn from(row: AdminRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            roles: serde_json::from_str(&row.roles_json).unwrap_or_default(),
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AdminElevationRow {
    id: String,
    tenant_id: String,
    admin_id: String,
    acr: Option<String>,
    amr_json: String,
    elevation_expires_at: i64,
    created_at: i64,
}

impl From<AdminElevationRow> for AdminElevation {
    fn from(row: AdminElevationRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            admin_id: row.admin_id,
            acr: row.acr,
            amr: serde_json::from_str(&row.amr_json).unwrap_or_default(),
            elevation_expires_at: row.elevation_expires_at as u64,
            created_at: row.created_at as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct AdminApprovalRow {
    id: String,
    tenant_id: String,
    approver_admin_id: String,
    target_admin_id: String,
    reason: Option<String>,
    approved_at: i64,
    expires_at: i64,
    consumed: i64,
}

impl From<AdminApprovalRow> for AdminApproval {
    fn from(row: AdminApprovalRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            approver_admin_id: row.approver_admin_id,
            target_admin_id: row.target_admin_id,
            reason: row.reason,
            approved_at: row.approved_at as u64,
            expires_at: row.expires_at as u64,
            consumed: row.consumed != 0,
        }
    }
}
