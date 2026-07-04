//! Storage abstraction for qid.
#![forbid(unsafe_code)]
//!
//! The `Repository` trait hides the underlying storage implementation so that
//! SQL databases, file-backed JSON stores, CockroachDB, or other backends can
//! be plugged in later. The trait is split into domain-specific sub-traits to
//! keep implementations maintainable.

use async_trait::async_trait;
use qid_core::error::{QidError, QidResult};

mod domain;
mod file;
mod sql;
pub mod traits;

pub use file::FileRepository;
pub use sql::SqlRepository;
pub use traits::*;

/// Convenience module that re-exports all repository traits.
pub mod prelude {
    pub use crate::{
        AdminRepository, AuditRepository, CiamRepository, ClientRepository, CredentialRepository,
        DeviceRepository, FedCmRepository, IgaRepository, PolicyRepository, RealmRepository,
        RebacRepository, Repository, SaasRepository, ScimRepository, ServiceAccountRepository,
        SessionRepository, SsfRepository, TokenRepository, UserRepository, VcRepository,
        WorkloadRepository,
    };
}

/// Runtime-selected repository: SQL or file-backed.
///
/// Parses the connection URL to determine which backend to use.
/// URLs starting with `sqlite:` or `postgres:` use SQL; everything
/// else is treated as a file path for `FileRepository`.
pub enum AnyRepository {
    Sql(SqlRepository),
    File(FileRepository),
}

impl AnyRepository {
    pub async fn connect(url_or_path: &str) -> QidResult<Self> {
        if url_or_path.starts_with("sqlite:") || url_or_path.starts_with("postgres:") {
            let repo =
                SqlRepository::connect(url_or_path)
                    .await
                    .map_err(|e| QidError::Internal {
                        message: format!("database connection failed: {e}"),
                    })?;
            SqlRepository::migrate(&repo)
                .await
                .map_err(|e| QidError::Internal {
                    message: format!("database migration failed: {e}"),
                })?;
            Ok(AnyRepository::Sql(repo))
        } else {
            let repo = FileRepository::new(url_or_path).await?;
            FileRepository::migrate(&repo).await?;
            Ok(AnyRepository::File(repo))
        }
    }

    pub async fn migrate(&self) -> QidResult<()> {
        match self {
            AnyRepository::Sql(r) => r.migrate().await.map_err(|e| QidError::Internal {
                message: format!("migration failed: {e}"),
            }),
            AnyRepository::File(r) => r.migrate().await,
        }
    }
}

#[allow(unused_macros)]
macro_rules! file_create {
    ($store:expr, $map:ident, $item:expr, $key:expr) => {{
        let mut store = $store.write().await;
        store.$map.insert($key, $item);
        drop(store);
        self.save().await
    }};
}

#[allow(unused_macros)]
macro_rules! file_get {
    ($store:expr, $map:ident, $key:expr) => {{
        let store = $store.read().await;
        Ok(store.$map.get($key).cloned())
    }};
}

macro_rules! delegate {
    ($trait:ident { $($method:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty);* $(;)? }) => {
        #[async_trait]
        impl $trait for AnyRepository {
            $(
                async fn $method(&self $(, $arg: $ty)*) -> $ret {
                    match self {
                        AnyRepository::Sql(r) => r.$method($($arg),*).await,
                        AnyRepository::File(r) => r.$method($($arg),*).await,
                    }
                }
            )*
        }
    };
}

delegate!(RealmRepository {
    create_realm(&self, tenant: &qid_core::tenant::TenantId, realm_id: &qid_core::tenant::RealmId, issuer: &str, display_name: Option<&str>) -> QidResult<()>;
    get_realm_issuer(&self, id: &qid_core::tenant::RealmId) -> QidResult<Option<String>>;
    get_realm_tenant(&self, id: &qid_core::tenant::RealmId) -> QidResult<Option<String>>;
    list_realms(&self) -> QidResult<Vec<(String, String)>>;
    delete_realm(&self, id: &qid_core::tenant::RealmId) -> QidResult<()>;
});

delegate!(UserRepository {
    create_user(&self, user: &qid_core::models::User) -> QidResult<()>;
    get_user_by_id(&self, id: &str) -> QidResult<Option<qid_core::models::User>>;
    get_user_by_email(&self, realm_id: &qid_core::tenant::RealmId, email: &str) -> QidResult<Option<qid_core::models::User>>;
    list_users(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::User>>;
    delete_user(&self, id: &str) -> QidResult<()>;
    update_user(&self, user: &qid_core::models::User) -> QidResult<()>;
    store_password_credential(&self, cred: &qid_core::models::PasswordCredential) -> QidResult<()>;
    get_password_credential(&self, user_id: &str) -> QidResult<Option<qid_core::models::PasswordCredential>>;
});

delegate!(ClientRepository {
    create_client(&self, client: &qid_core::models::Client) -> QidResult<()>;
    update_client(&self, client: &qid_core::models::Client) -> QidResult<()>;
    get_client_by_client_id(&self, realm_id: &qid_core::tenant::RealmId, client_id: &str) -> QidResult<Option<qid_core::models::Client>>;
    list_clients(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::Client>>;
    delete_client(&self, id: &str) -> QidResult<()>;
});

delegate!(SessionRepository {
    create_session(&self, session: &qid_core::models::Session) -> QidResult<()>;
    get_session(&self, id: &str) -> QidResult<Option<qid_core::models::Session>>;
    update_session_idle_expiry(&self, id: &str, idle_expires_at: u64) -> QidResult<()>;
    revoke_session(&self, id: &str) -> QidResult<()>;
    list_sessions(&self, realm_id: &str, user_id: Option<&str>) -> QidResult<Vec<qid_core::models::Session>>;
});

delegate!(TokenRepository {
    create_authorization_code(&self, code: &qid_core::models::AuthorizationCode) -> QidResult<()>;
    get_authorization_code(&self, code_hash: &str) -> QidResult<Option<qid_core::models::AuthorizationCode>>;
    mark_authorization_code_used(&self, code_hash: &str) -> QidResult<()>;
    create_token_family(&self, family: &qid_core::models::TokenFamily) -> QidResult<()>;
    get_token_family(&self, id: &str) -> QidResult<Option<qid_core::models::TokenFamily>>;
    update_token_family_refresh_hash(&self, id: &str, refresh_hash: &str) -> QidResult<()>;
    revoke_token_family(&self, id: &str) -> QidResult<()>;
    list_token_families(&self, realm_id: &str, user_id: Option<&str>, client_id: Option<&str>) -> QidResult<Vec<qid_core::models::TokenFamily>>;
    create_access_token(&self, token: &qid_core::models::AccessToken) -> QidResult<()>;
    get_access_token(&self, jti: &str) -> QidResult<Option<qid_core::models::AccessToken>>;
    revoke_access_token(&self, jti: &str) -> QidResult<()>;
    store_par_request(&self, req: &qid_core::models::ParRequest) -> QidResult<()>;
    get_par_request(&self, request_uri: &str) -> QidResult<Option<qid_core::models::ParRequest>>;
    mark_par_request_used(&self, request_uri: &str) -> QidResult<()>;
    store_device_authorization_grant(&self, grant: &qid_core::models::DeviceAuthorizationGrant) -> QidResult<()>;
    get_device_authorization_grant(&self, device_code_hash: &str) -> QidResult<Option<qid_core::models::DeviceAuthorizationGrant>>;
    get_device_authorization_grant_by_user_code(&self, user_code: &str) -> QidResult<Option<qid_core::models::DeviceAuthorizationGrant>>;
    approve_device_authorization_grant(&self, user_code: &str, user_id: &str, approved_at: u64) -> QidResult<()>;
    record_device_authorization_poll(&self, device_code_hash: &str, polled_at: u64, poll_interval_seconds: u64) -> QidResult<()>;
    consume_device_authorization_grant(&self, device_code_hash: &str) -> QidResult<()>;
    store_backchannel_authentication_grant(&self, grant: &qid_core::models::BackchannelAuthenticationGrant) -> QidResult<()>;
    get_backchannel_authentication_grant(&self, auth_req_id_hash: &str) -> QidResult<Option<qid_core::models::BackchannelAuthenticationGrant>>;
    approve_backchannel_authentication_grant(&self, auth_req_id_hash: &str, user_id: &str, approved_at: u64) -> QidResult<()>;
    record_backchannel_authentication_poll(&self, auth_req_id_hash: &str, polled_at: u64, poll_interval_seconds: u64) -> QidResult<()>;
    consume_backchannel_authentication_grant(&self, auth_req_id_hash: &str) -> QidResult<()>;
});

delegate!(CredentialRepository {
    get_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<qid_core::models::WebAuthnCredential>>;
    store_webauthn_credential(&self, cred: &qid_core::models::WebAuthnCredential) -> QidResult<()>;
    update_webauthn_credential_counter(&self, id: &str, counter: u64) -> QidResult<()>;
    delete_webauthn_credential(&self, id: &str) -> QidResult<()>;
    list_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<qid_core::models::WebAuthnCredential>>;
    store_totp_credential(&self, cred: &qid_core::models::TotpCredential) -> QidResult<()>;
    get_totp_credential(&self, user_id: &str) -> QidResult<Option<qid_core::models::TotpCredential>>;
    update_totp_credential_last_used_step(&self, user_id: &str, last_used_step: u64) -> QidResult<()>;
    delete_totp_credential(&self, user_id: &str) -> QidResult<()>;
    list_totp_credentials(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::TotpCredential>>;
});

delegate!(VcRepository {
    store_vc_credential_status(&self, status: &qid_core::models::VcCredentialStatusRecord) -> QidResult<()>;
    get_vc_credential_status(&self, credential_id: &str) -> QidResult<Option<qid_core::models::VcCredentialStatusRecord>>;
    revoke_vc_credential(&self, credential_id: &str, reason: &str, revoked_at: u64) -> QidResult<()>;
});

delegate!(ServiceAccountRepository {
    create_service_account(&self, sa: &qid_core::models::ServiceAccount) -> QidResult<()>;
    get_service_account_by_client_id(&self, realm_id: &str, client_id: &str) -> QidResult<Option<qid_core::models::ServiceAccount>>;
    list_service_accounts(&self, realm_id: &str) -> QidResult<Vec<qid_core::models::ServiceAccount>>;
    delete_service_account(&self, id: &str) -> QidResult<()>;
});

delegate!(PolicyRepository {
    create_policy_bundle(&self, bundle: &qid_core::models::PolicyBundle) -> QidResult<()>;
    get_active_policy_bundle(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Option<qid_core::models::PolicyBundle>>;
    list_policy_bundles(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::PolicyBundle>>;
    delete_policy_bundle(&self, id: &str) -> QidResult<()>;
});

delegate!(AuditRepository {
    append_audit_event(&self, event: &qid_core::models::AuditEvent) -> QidResult<()>;
    list_audit_events(&self, realm_id: Option<&qid_core::tenant::RealmId>, limit: usize) -> QidResult<Vec<qid_core::models::AuditEvent>>;
    verify_audit_chain(&self, realm_id: Option<&qid_core::tenant::RealmId>) -> QidResult<qid_core::models::AuditChainVerification>;
    set_audit_retention_config(&self, config: &qid_core::models::AuditRetentionConfig) -> QidResult<()>;
    get_audit_retention_config(&self, realm_id: Option<&qid_core::tenant::RealmId>) -> QidResult<Option<qid_core::models::AuditRetentionConfig>>;
    plan_audit_retention(&self, realm_id: Option<&qid_core::tenant::RealmId>, now_epoch: u64) -> QidResult<Option<qid_core::models::AuditRetentionEnforcementPlan>>;
});

delegate!(DeviceRepository {
    register_device(&self, device: &qid_core::models::Device) -> QidResult<()>;
    get_device(&self, device_id: &str) -> QidResult<Option<qid_core::models::Device>>;
    get_user_devices(&self, user_id: &str) -> QidResult<Vec<qid_core::models::Device>>;
    update_device_last_seen(&self, device_id: &str, last_seen_at: u64) -> QidResult<()>;
});

delegate!(ScimRepository {
    create_scim_user(&self, user: &qid_core::models::ScimUser) -> QidResult<()>;
    get_scim_user(&self, id: &str) -> QidResult<Option<qid_core::models::ScimUser>>;
    list_scim_users(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::ScimUser>>;
    update_scim_user(&self, user: &qid_core::models::ScimUser) -> QidResult<()>;
    delete_scim_user(&self, id: &str) -> QidResult<()>;
    create_scim_group(&self, group: &qid_core::models::ScimGroup) -> QidResult<()>;
    list_scim_groups(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::ScimGroup>>;
    get_scim_group(&self, id: &str) -> QidResult<Option<qid_core::models::ScimGroup>>;
    update_scim_group(&self, group: &qid_core::models::ScimGroup) -> QidResult<()>;
    delete_scim_group(&self, id: &str) -> QidResult<()>;
    upsert_scim_device(&self, device: &crate::traits::ScimDeviceRecord) -> QidResult<()>;
    get_scim_device(&self, id: &str) -> QidResult<Option<crate::traits::ScimDeviceRecord>>;
    list_scim_devices(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<crate::traits::ScimDeviceRecord>>;
    delete_scim_device(&self, id: &str) -> QidResult<bool>;
    upsert_scim_event_subscription(&self, subscription: &crate::traits::ScimEventSubscriptionRecord) -> QidResult<()>;
    get_scim_event_subscription(&self, id: &str) -> QidResult<Option<crate::traits::ScimEventSubscriptionRecord>>;
    list_scim_event_subscriptions(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<crate::traits::ScimEventSubscriptionRecord>>;
    delete_scim_event_subscription(&self, id: &str) -> QidResult<bool>;
});

delegate!(FedCmRepository {
    store_fedcm_identity(&self, identity: &qid_core::models::FedCmIdentity) -> QidResult<()>;
    get_fedcm_identities(&self, realm_id: &qid_core::tenant::RealmId, account_id: &str) -> QidResult<Vec<qid_core::models::FedCmIdentity>>;
    delete_fedcm_identity(&self, id: &str) -> QidResult<()>;
});

delegate!(CiamRepository {
    store_ciam_consent_grant(&self, grant: &qid_core::models::CiamConsentGrant) -> QidResult<()>;
    list_ciam_consent_grants(&self, realm_id: &qid_core::tenant::RealmId, user_id: &str, client_id: Option<&str>) -> QidResult<Vec<qid_core::models::CiamConsentGrant>>;
    revoke_ciam_consent_grant(&self, id: &str, revoked_at: u64) -> QidResult<()>;
    store_ciam_verification_challenge(&self, challenge: &qid_core::models::CiamVerificationChallengeRecord) -> QidResult<()>;
    get_ciam_verification_challenge(&self, id: &str) -> QidResult<Option<qid_core::models::CiamVerificationChallengeRecord>>;
    consume_ciam_verification_challenge(&self, id: &str, consumed_at: u64) -> QidResult<()>;
    store_ciam_identity_link(&self, link: &qid_core::models::CiamIdentityLink) -> QidResult<()>;
    list_ciam_identity_links(&self, realm_id: &qid_core::tenant::RealmId, user_id: &str) -> QidResult<Vec<qid_core::models::CiamIdentityLink>>;
    get_ciam_identity_link(&self, realm_id: &qid_core::tenant::RealmId, id: &str) -> QidResult<Option<qid_core::models::CiamIdentityLink>>;
    get_ciam_identity_link_by_external_subject(&self, realm_id: &qid_core::tenant::RealmId, provider: &str, external_subject: &str) -> QidResult<Option<qid_core::models::CiamIdentityLink>>;
    delete_ciam_identity_link(&self, realm_id: &qid_core::tenant::RealmId, id: &str) -> QidResult<()>;
    store_password_reset_token(&self, token: &qid_core::models::PasswordResetToken) -> QidResult<()>;
    get_password_reset_token(&self, id: &str) -> QidResult<Option<qid_core::models::PasswordResetToken>>;
    consume_password_reset_token(&self, id: &str, consumed_at: u64) -> QidResult<()>;
    get_ciam_progressive_profile(&self, realm_id: &qid_core::tenant::RealmId, user_id: &str) -> QidResult<Option<qid_core::models::CiamProgressiveProfile>>;
    store_ciam_progressive_profile(&self, profile: &qid_core::models::CiamProgressiveProfile) -> QidResult<()>;
    delete_ciam_progressive_profile(&self, realm_id: &qid_core::tenant::RealmId, user_id: &str) -> QidResult<()>;
    list_ciam_passwordless_migrations(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::CiamProgressiveProfile>>;
});

delegate!(WorkloadRepository {
    create_workload_identity(&self, wi: &qid_core::models::WorkloadIdentity) -> QidResult<()>;
    get_workload_identity_by_spiffe(&self, realm_id: &qid_core::tenant::RealmId, spiffe_id: &str) -> QidResult<Option<qid_core::models::WorkloadIdentity>>;
    list_workload_identities(&self, realm_id: &qid_core::tenant::RealmId) -> QidResult<Vec<qid_core::models::WorkloadIdentity>>;
    delete_workload_identity(&self, id: &str) -> QidResult<()>;
    store_workload_certificate(&self, certificate: &qid_core::models::WorkloadCertificate) -> QidResult<()>;
    list_workload_certificates(&self, realm_id: &qid_core::tenant::RealmId, workload_id: Option<&str>) -> QidResult<Vec<qid_core::models::WorkloadCertificate>>;
    revoke_workload_certificate(&self, realm_id: &qid_core::tenant::RealmId, id: &str, revoked_at: u64) -> QidResult<()>;
});

delegate!(SaasRepository {
    list_saas_tenant_ids(&self) -> QidResult<Vec<String>>;
    store_custom_domain(&self, domain: &qid_core::models::CustomDomain) -> QidResult<()>;
    list_custom_domains(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::CustomDomain>>;
    delete_custom_domain(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_ciam_brand(&self, brand: &qid_core::models::CiamBrand) -> QidResult<()>;
    list_ciam_brands(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::CiamBrand>>;
    delete_ciam_brand(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_app_catalog_entry(&self, entry: &qid_core::models::AppCatalogEntry) -> QidResult<()>;
    list_app_catalog_entries(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::AppCatalogEntry>>;
    delete_app_catalog_entry(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_marketplace_connector(&self, connector: &qid_core::models::MarketplaceConnector) -> QidResult<()>;
    list_marketplace_connectors(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::MarketplaceConnector>>;
    delete_marketplace_connector(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_usage_billing_event(&self, event: &qid_core::models::UsageBillingEvent) -> QidResult<()>;
    list_usage_billing_events(&self, tenant_id: &str, limit: usize) -> QidResult<Vec<qid_core::models::UsageBillingEvent>>;
    store_compliance_evidence_pack(&self, pack: &qid_core::models::ComplianceEvidencePack) -> QidResult<()>;
    list_compliance_evidence_packs(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::ComplianceEvidencePack>>;
    store_delegated_tenant_admin(&self, admin: &qid_core::models::DelegatedTenantAdmin) -> QidResult<()>;
    list_delegated_tenant_admins(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::DelegatedTenantAdmin>>;
    revoke_delegated_tenant_admin(&self, tenant_id: &str, id: &str) -> QidResult<()>;
});

delegate!(IgaRepository {
    store_iga_entitlement(&self, entitlement: &qid_core::models::IgaEntitlementRecord) -> QidResult<()>;
    list_iga_entitlements(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::IgaEntitlementRecord>>;
    delete_iga_entitlement(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_iga_access_package(&self, package: &qid_core::models::IgaAccessPackageRecord) -> QidResult<()>;
    list_iga_access_packages(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::IgaAccessPackageRecord>>;
    delete_iga_access_package(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_iga_access_request(&self, request: &qid_core::models::IgaAccessRequestRecord) -> QidResult<()>;
    get_iga_access_request(&self, tenant_id: &str, id: &str) -> QidResult<Option<qid_core::models::IgaAccessRequestRecord>>;
    update_iga_access_request_status(&self, tenant_id: &str, id: &str, status: &str) -> QidResult<()>;
    list_iga_access_requests(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::IgaAccessRequestRecord>>;
    store_iga_approval(&self, approval: &qid_core::models::IgaApprovalRecord) -> QidResult<()>;
    list_iga_approvals(&self, tenant_id: &str, request_id: &str) -> QidResult<Vec<qid_core::models::IgaApprovalRecord>>;
    store_iga_access_grant(&self, grant: &qid_core::models::IgaAccessGrantRecord) -> QidResult<()>;
    list_iga_access_grants(&self, tenant_id: &str, subject: Option<&str>) -> QidResult<Vec<qid_core::models::IgaAccessGrantRecord>>;
    revoke_iga_access_grant(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_iga_jit_privilege_grant(&self, grant: &qid_core::models::IgaJitPrivilegeGrantRecord) -> QidResult<()>;
    list_iga_jit_privilege_grants(&self, tenant_id: &str, subject: Option<&str>) -> QidResult<Vec<qid_core::models::IgaJitPrivilegeGrantRecord>>;
    revoke_iga_jit_privilege_grant(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_iga_access_review_campaign(&self, campaign: &qid_core::models::IgaAccessReviewCampaignRecord) -> QidResult<()>;
    get_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<Option<qid_core::models::IgaAccessReviewCampaignRecord>>;
    list_iga_access_review_campaigns(&self, tenant_id: &str) -> QidResult<Vec<qid_core::models::IgaAccessReviewCampaignRecord>>;
    close_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    store_iga_access_review_decision(&self, decision: &qid_core::models::IgaAccessReviewDecisionRecord) -> QidResult<()>;
    list_iga_access_review_decisions(&self, tenant_id: &str, campaign_id: &str) -> QidResult<Vec<qid_core::models::IgaAccessReviewDecisionRecord>>;
    store_iga_certification(&self, certification: &qid_core::models::IgaCertificationRecord) -> QidResult<()>;
    list_iga_certifications(&self, tenant_id: &str, certification_type: Option<&str>) -> QidResult<Vec<qid_core::models::IgaCertificationRecord>>;
    store_iga_finding(&self, finding: &qid_core::models::IgaFindingRecord) -> QidResult<()>;
    list_iga_findings(&self, tenant_id: &str, finding_type: Option<&str>) -> QidResult<Vec<qid_core::models::IgaFindingRecord>>;
    resolve_iga_finding(&self, id: &str) -> QidResult<()>;
});

delegate!(AdminRepository {
    get_admin(&self, tenant_id: &str, subject: &str) -> QidResult<Option<qid_core::models::Admin>>;
    get_admin_by_id(&self, id: &str) -> QidResult<Option<qid_core::models::Admin>>;
    upsert_admin(&self, admin: &qid_core::models::Admin) -> QidResult<()>;
    get_admin_elevation(&self, id: &str) -> QidResult<Option<qid_core::models::AdminElevation>>;
    store_admin_elevation(&self, elevation: &qid_core::models::AdminElevation) -> QidResult<()>;
    get_admin_approval(&self, id: &str) -> QidResult<Option<qid_core::models::AdminApproval>>;
    store_admin_approval(&self, approval: &qid_core::models::AdminApproval) -> QidResult<()>;
    consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool>;
});

delegate!(SsfRepository {
    upsert_ssf_stream(&self, stream: &crate::traits::SsfStreamRecord) -> QidResult<()>;
    list_ssf_streams(&self, realm_id: &str) -> QidResult<Vec<crate::traits::SsfStreamRecord>>;
    get_ssf_stream(&self, realm_id: &str, stream_id: &str) -> QidResult<Option<crate::traits::SsfStreamRecord>>;
    delete_ssf_stream(&self, realm_id: &str, stream_id: &str) -> QidResult<bool>;
    record_ssf_set_jti(&self, realm_id: &str, issuer: &str, stream_id: &str, jti: &str, expires_at: u64, now: u64) -> QidResult<bool>;
});

delegate!(RebacRepository {
    create_relationship_tuple(&self, tuple: &qid_core::models::RelationshipTuple) -> QidResult<()>;
    delete_relationship_tuple(&self, tuple: &qid_core::models::RelationshipTuple) -> QidResult<()>;
    list_relationship_tuples(&self, namespace: &str, object_id: &str, relation: Option<&str>) -> QidResult<Vec<qid_core::models::RelationshipTuple>>;
    list_relationship_tuples_by_subject(&self, namespace: &str, object_id: &str, relation: &str, subject_namespace: &str, subject_id: &str, subject_relation: Option<&str>) -> QidResult<Vec<qid_core::models::RelationshipTuple>>;
});

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
}

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => StorageError::NotFound("row not found".to_string()),
            _ => StorageError::Database(err.to_string()),
        }
    }
}

impl From<StorageError> for QidError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound(resource) => Self::NotFound { resource },
            StorageError::Conflict(message) => Self::BadRequest { message },
            StorageError::Database(message) => Self::Storage { message },
        }
    }
}
