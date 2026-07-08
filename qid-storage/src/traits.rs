//! Domain-specific repository traits.
//!
//! `Repository` is a convenience supertrait that aggregates all domain traits.
//! New storage backends only need to implement the domain traits; `Repository`
//! is derived automatically.

use async_trait::async_trait;
use qid_core::{
    error::QidResult,
    models::*,
    tenant::{RealmId, TenantId},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SsfStreamRecord {
    pub realm_id: String,
    pub stream_id: String,
    pub delivery_json: serde_json::Value,
    pub events_requested: Vec<String>,
    pub transmitter_issuer: String,
    pub transmitter_jwks_json: serde_json::Value,
    pub transmitter_alg: String,
    pub audience: String,
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimDeviceRecord {
    pub id: String,
    pub realm_id: String,
    pub display_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimEventSubscriptionRecord {
    pub id: String,
    pub realm_id: String,
    pub callback_url: String,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiemDeliveryStatus {
    Pending,
    Delivered,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiemDeliveryRecord {
    pub id: String,
    pub realm_id: Option<String>,
    pub endpoint_url: String,
    pub payload_json: serde_json::Value,
    pub attempts: u32,
    pub next_retry_at: Option<u64>,
    pub status: SiemDeliveryStatus,
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[async_trait]
pub trait RealmRepository: Send + Sync + 'static {
    async fn create_realm(
        &self,
        tenant: &TenantId,
        realm_id: &RealmId,
        issuer: &str,
        display_name: Option<&str>,
    ) -> QidResult<()>;
    async fn get_realm_issuer(&self, id: &RealmId) -> QidResult<Option<String>>;
    async fn get_realm_tenant(&self, id: &RealmId) -> QidResult<Option<String>>;
    async fn list_realms(&self) -> QidResult<Vec<(String, String)>>;
    async fn delete_realm(&self, id: &RealmId) -> QidResult<()>;
}

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn create_user(&self, user: &User) -> QidResult<()>;
    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>>;
    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>>;
    async fn list_users(&self, realm_id: &RealmId) -> QidResult<Vec<User>> {
        self.list_users_page(realm_id, 0, usize::MAX).await
    }
    async fn list_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<User>>;
    async fn delete_user(&self, id: &str) -> QidResult<()>;
    async fn update_user(&self, user: &User) -> QidResult<()>;
    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()>;
    async fn get_password_credential(&self, user_id: &str)
    -> QidResult<Option<PasswordCredential>>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync + 'static {
    async fn create_client(&self, client: &Client) -> QidResult<()>;
    async fn update_client(&self, client: &Client) -> QidResult<()>;
    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>>;
    async fn list_clients(&self, realm_id: &RealmId) -> QidResult<Vec<Client>> {
        self.list_clients_page(realm_id, 0, usize::MAX).await
    }
    async fn list_clients_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<Client>>;
    async fn delete_client(&self, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    async fn create_session(&self, session: &Session) -> QidResult<()>;
    async fn get_session(&self, id: &str) -> QidResult<Option<Session>>;
    async fn update_session_idle_expiry(&self, id: &str, idle_expires_at: u64) -> QidResult<()>;
    async fn revoke_session(&self, id: &str) -> QidResult<()>;
    async fn list_sessions(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
    ) -> QidResult<Vec<Session>> {
        let _ = realm_id;
        let _ = user_id;
        Ok(Vec::new())
    }
}

#[async_trait]
pub trait TokenRepository: Send + Sync + 'static {
    async fn create_authorization_code(&self, code: &AuthorizationCode) -> QidResult<()>;
    async fn get_authorization_code(&self, code_hash: &str)
    -> QidResult<Option<AuthorizationCode>>;
    async fn mark_authorization_code_used(&self, code_hash: &str) -> QidResult<()>;
    async fn create_token_family(&self, family: &TokenFamily) -> QidResult<()>;
    async fn get_token_family(&self, id: &str) -> QidResult<Option<TokenFamily>>;
    async fn update_token_family_refresh_hash(&self, id: &str, refresh_hash: &str)
    -> QidResult<()>;
    async fn revoke_token_family(&self, id: &str) -> QidResult<()>;
    async fn list_token_families(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
        client_id: Option<&str>,
    ) -> QidResult<Vec<TokenFamily>> {
        let _ = realm_id;
        let _ = user_id;
        let _ = client_id;
        Ok(Vec::new())
    }
    async fn create_access_token(&self, token: &AccessToken) -> QidResult<()>;
    async fn get_access_token(&self, jti: &str) -> QidResult<Option<AccessToken>>;
    async fn revoke_access_token(&self, jti: &str) -> QidResult<()>;
    async fn store_par_request(&self, req: &ParRequest) -> QidResult<()>;
    async fn get_par_request(&self, request_uri: &str) -> QidResult<Option<ParRequest>>;
    async fn mark_par_request_used(&self, request_uri: &str) -> QidResult<()>;
    async fn store_device_authorization_grant(
        &self,
        grant: &DeviceAuthorizationGrant,
    ) -> QidResult<()>;
    async fn get_device_authorization_grant(
        &self,
        device_code_hash: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>>;
    async fn get_device_authorization_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>>;
    async fn approve_device_authorization_grant(
        &self,
        user_code: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()>;
    async fn record_device_authorization_poll(
        &self,
        device_code_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()>;
    async fn consume_device_authorization_grant(&self, device_code_hash: &str) -> QidResult<()>;
    async fn store_backchannel_authentication_grant(
        &self,
        grant: &BackchannelAuthenticationGrant,
    ) -> QidResult<()>;
    async fn get_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<Option<BackchannelAuthenticationGrant>>;
    async fn approve_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()>;
    async fn record_backchannel_authentication_poll(
        &self,
        auth_req_id_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()>;
    async fn consume_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync + 'static {
    async fn get_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>>;
    async fn store_webauthn_credential(&self, cred: &WebAuthnCredential) -> QidResult<()>;
    async fn update_webauthn_credential_counter(&self, id: &str, counter: u64) -> QidResult<()>;
    async fn delete_webauthn_credential(&self, id: &str) -> QidResult<()>;
    async fn list_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>>;
    async fn store_totp_credential(&self, cred: &TotpCredential) -> QidResult<()>;
    async fn get_totp_credential(&self, user_id: &str) -> QidResult<Option<TotpCredential>>;
    async fn update_totp_credential_last_used_step(
        &self,
        user_id: &str,
        last_used_step: u64,
    ) -> QidResult<()>;
    async fn delete_totp_credential(&self, user_id: &str) -> QidResult<()>;
    async fn list_totp_credentials(&self, realm_id: &RealmId) -> QidResult<Vec<TotpCredential>>;
}

#[async_trait]
pub trait VcRepository: Send + Sync + 'static {
    async fn store_vc_credential_status(&self, status: &VcCredentialStatusRecord) -> QidResult<()>;
    async fn get_vc_credential_status(
        &self,
        credential_id: &str,
    ) -> QidResult<Option<VcCredentialStatusRecord>>;
    async fn revoke_vc_credential(
        &self,
        credential_id: &str,
        reason: &str,
        revoked_at: u64,
    ) -> QidResult<()>;
}

#[async_trait]
pub trait ServiceAccountRepository: Send + Sync + 'static {
    async fn create_service_account(&self, sa: &ServiceAccount) -> QidResult<()>;
    async fn get_service_account_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> QidResult<Option<ServiceAccount>>;
    async fn list_service_accounts(&self, realm_id: &str) -> QidResult<Vec<ServiceAccount>>;
    async fn delete_service_account(&self, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait PolicyRepository: Send + Sync + 'static {
    async fn create_policy_bundle(&self, bundle: &PolicyBundle) -> QidResult<()>;
    async fn get_active_policy_bundle(&self, realm_id: &RealmId)
    -> QidResult<Option<PolicyBundle>>;
    async fn list_policy_bundles(&self, realm_id: &RealmId) -> QidResult<Vec<PolicyBundle>>;
    async fn delete_policy_bundle(&self, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait AuditRepository: Send + Sync + 'static {
    async fn append_audit_event(&self, event: &AuditEvent) -> QidResult<()>;
    async fn list_audit_events(
        &self,
        realm_id: Option<&RealmId>,
        limit: usize,
    ) -> QidResult<Vec<AuditEvent>>;
    async fn verify_audit_chain(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<AuditChainVerification>;
    async fn set_audit_retention_config(&self, config: &AuditRetentionConfig) -> QidResult<()>;
    async fn get_audit_retention_config(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<Option<AuditRetentionConfig>>;
    async fn plan_audit_retention(
        &self,
        realm_id: Option<&RealmId>,
        now_epoch: u64,
    ) -> QidResult<Option<AuditRetentionEnforcementPlan>>;
}

#[async_trait]
pub trait DeviceRepository: Send + Sync + 'static {
    async fn register_device(&self, device: &Device) -> QidResult<()>;
    async fn get_device(&self, device_id: &str) -> QidResult<Option<Device>>;
    async fn get_user_devices(&self, user_id: &str) -> QidResult<Vec<Device>>;
    async fn update_device_last_seen(&self, device_id: &str, last_seen_at: u64) -> QidResult<()>;
}

#[async_trait]
pub trait ScimRepository: Send + Sync + 'static {
    async fn create_scim_user(&self, user: &ScimUser) -> QidResult<()>;
    async fn get_scim_user(&self, id: &str) -> QidResult<Option<ScimUser>>;
    async fn list_scim_users(&self, realm_id: &RealmId) -> QidResult<Vec<ScimUser>> {
        self.list_scim_users_page(realm_id, 0, usize::MAX).await
    }
    async fn list_scim_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<ScimUser>>;
    async fn count_scim_users(&self, realm_id: &RealmId) -> QidResult<usize> {
        Ok(self.list_scim_users(realm_id).await?.len())
    }
    async fn update_scim_user(&self, user: &ScimUser) -> QidResult<()>;
    async fn delete_scim_user(&self, id: &str) -> QidResult<()>;
    async fn create_scim_group(&self, group: &ScimGroup) -> QidResult<()>;
    async fn list_scim_groups(&self, realm_id: &RealmId) -> QidResult<Vec<ScimGroup>> {
        self.list_scim_groups_page(realm_id, 0, usize::MAX).await
    }
    async fn list_scim_groups_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<ScimGroup>>;
    async fn count_scim_groups(&self, realm_id: &RealmId) -> QidResult<usize> {
        Ok(self.list_scim_groups(realm_id).await?.len())
    }
    async fn get_scim_group(&self, id: &str) -> QidResult<Option<ScimGroup>>;
    async fn update_scim_group(&self, group: &ScimGroup) -> QidResult<()>;
    async fn delete_scim_group(&self, id: &str) -> QidResult<()>;
    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()>;
    async fn get_scim_device(&self, id: &str) -> QidResult<Option<ScimDeviceRecord>>;
    async fn list_scim_devices(&self, realm_id: &RealmId) -> QidResult<Vec<ScimDeviceRecord>>;
    async fn delete_scim_device(&self, id: &str) -> QidResult<bool>;
    async fn upsert_scim_event_subscription(
        &self,
        subscription: &ScimEventSubscriptionRecord,
    ) -> QidResult<()>;
    async fn get_scim_event_subscription(
        &self,
        id: &str,
    ) -> QidResult<Option<ScimEventSubscriptionRecord>>;
    async fn list_scim_event_subscriptions(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<ScimEventSubscriptionRecord>>;
    async fn delete_scim_event_subscription(&self, id: &str) -> QidResult<bool>;
}

#[async_trait]
pub trait FedCmRepository: Send + Sync + 'static {
    async fn store_fedcm_identity(&self, identity: &FedCmIdentity) -> QidResult<()>;
    async fn get_fedcm_identities(
        &self,
        realm_id: &RealmId,
        account_id: &str,
    ) -> QidResult<Vec<FedCmIdentity>>;
    async fn delete_fedcm_identity(&self, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait CiamRepository: Send + Sync + 'static {
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()>;
    async fn list_ciam_consent_grants(
        &self,
        realm_id: &RealmId,
        user_id: &str,
        client_id: Option<&str>,
    ) -> QidResult<Vec<CiamConsentGrant>>;
    async fn revoke_ciam_consent_grant(&self, id: &str, revoked_at: u64) -> QidResult<()>;
    async fn store_ciam_verification_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
    ) -> QidResult<()>;
    async fn get_ciam_verification_challenge(
        &self,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>>;
    async fn consume_ciam_verification_challenge(
        &self,
        id: &str,
        consumed_at: u64,
    ) -> QidResult<()>;
    async fn store_ciam_identity_link(&self, link: &CiamIdentityLink) -> QidResult<()>;
    async fn list_ciam_identity_links(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Vec<CiamIdentityLink>>;
    async fn get_ciam_identity_link(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamIdentityLink>>;
    async fn get_ciam_identity_link_by_external_subject(
        &self,
        realm_id: &RealmId,
        provider: &str,
        external_subject: &str,
    ) -> QidResult<Option<CiamIdentityLink>>;
    async fn delete_ciam_identity_link(&self, realm_id: &RealmId, id: &str) -> QidResult<()>;
    async fn store_password_reset_token(&self, token: &PasswordResetToken) -> QidResult<()>;
    async fn get_password_reset_token(&self, id: &str) -> QidResult<Option<PasswordResetToken>>;
    async fn consume_password_reset_token(&self, id: &str, consumed_at: u64) -> QidResult<()>;
    async fn get_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Option<CiamProgressiveProfile>>;
    async fn store_ciam_progressive_profile(
        &self,
        profile: &CiamProgressiveProfile,
    ) -> QidResult<()>;
    async fn delete_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<()>;
    async fn list_ciam_passwordless_migrations(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<CiamProgressiveProfile>>;
}

#[async_trait]
pub trait WorkloadRepository: Send + Sync + 'static {
    async fn create_workload_identity(&self, wi: &WorkloadIdentity) -> QidResult<()>;
    async fn get_workload_identity_by_spiffe(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> QidResult<Option<WorkloadIdentity>>;
    async fn list_workload_identities(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<WorkloadIdentity>>;
    async fn delete_workload_identity(&self, id: &str) -> QidResult<()>;
    async fn store_workload_certificate(&self, certificate: &WorkloadCertificate) -> QidResult<()>;
    async fn list_workload_certificates(
        &self,
        realm_id: &RealmId,
        workload_id: Option<&str>,
    ) -> QidResult<Vec<WorkloadCertificate>>;
    async fn revoke_workload_certificate(
        &self,
        realm_id: &RealmId,
        id: &str,
        revoked_at: u64,
    ) -> QidResult<()>;
}

#[async_trait]
pub trait SaasRepository: Send + Sync + 'static {
    async fn list_saas_tenant_ids(&self) -> QidResult<Vec<String>>;
    async fn store_custom_domain(&self, domain: &CustomDomain) -> QidResult<()>;
    async fn list_custom_domains(&self, tenant_id: &str) -> QidResult<Vec<CustomDomain>>;
    async fn delete_custom_domain(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_ciam_brand(&self, brand: &CiamBrand) -> QidResult<()>;
    async fn list_ciam_brands(&self, tenant_id: &str) -> QidResult<Vec<CiamBrand>>;
    async fn delete_ciam_brand(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_app_catalog_entry(&self, entry: &AppCatalogEntry) -> QidResult<()>;
    async fn list_app_catalog_entries(&self, tenant_id: &str) -> QidResult<Vec<AppCatalogEntry>>;
    async fn delete_app_catalog_entry(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_marketplace_connector(&self, connector: &MarketplaceConnector) -> QidResult<()>;
    async fn list_marketplace_connectors(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<MarketplaceConnector>>;
    async fn delete_marketplace_connector(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_usage_billing_event(&self, event: &UsageBillingEvent) -> QidResult<()>;
    async fn list_usage_billing_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> QidResult<Vec<UsageBillingEvent>>;
    async fn store_compliance_evidence_pack(&self, pack: &ComplianceEvidencePack) -> QidResult<()>;
    async fn list_compliance_evidence_packs(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<ComplianceEvidencePack>>;
    async fn store_delegated_tenant_admin(&self, admin: &DelegatedTenantAdmin) -> QidResult<()>;
    async fn list_delegated_tenant_admins(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<DelegatedTenantAdmin>>;
    async fn revoke_delegated_tenant_admin(&self, tenant_id: &str, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait IgaRepository: Send + Sync + 'static {
    async fn store_iga_entitlement(&self, entitlement: &IgaEntitlementRecord) -> QidResult<()>;
    async fn list_iga_entitlements(&self, tenant_id: &str) -> QidResult<Vec<IgaEntitlementRecord>>;
    async fn delete_iga_entitlement(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_iga_access_package(&self, package: &IgaAccessPackageRecord) -> QidResult<()>;
    async fn list_iga_access_packages(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessPackageRecord>>;
    async fn delete_iga_access_package(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_iga_access_request(&self, request: &IgaAccessRequestRecord) -> QidResult<()>;
    async fn get_iga_access_request(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessRequestRecord>>;
    async fn update_iga_access_request_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> QidResult<()>;
    async fn list_iga_access_requests(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessRequestRecord>>;
    async fn store_iga_approval(&self, approval: &IgaApprovalRecord) -> QidResult<()>;
    async fn list_iga_approvals(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> QidResult<Vec<IgaApprovalRecord>>;
    async fn store_iga_access_grant(&self, grant: &IgaAccessGrantRecord) -> QidResult<()>;
    async fn list_iga_access_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaAccessGrantRecord>>;
    async fn revoke_iga_access_grant(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_iga_jit_privilege_grant(
        &self,
        grant: &IgaJitPrivilegeGrantRecord,
    ) -> QidResult<()>;
    async fn list_iga_jit_privilege_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaJitPrivilegeGrantRecord>>;
    async fn revoke_iga_jit_privilege_grant(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_iga_access_review_campaign(
        &self,
        campaign: &IgaAccessReviewCampaignRecord,
    ) -> QidResult<()>;
    async fn get_iga_access_review_campaign(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessReviewCampaignRecord>>;
    async fn list_iga_access_review_campaigns(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewCampaignRecord>>;
    async fn close_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    async fn store_iga_access_review_decision(
        &self,
        decision: &IgaAccessReviewDecisionRecord,
    ) -> QidResult<()>;
    async fn list_iga_access_review_decisions(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewDecisionRecord>>;
    async fn store_iga_certification(
        &self,
        certification: &IgaCertificationRecord,
    ) -> QidResult<()>;
    async fn list_iga_certifications(
        &self,
        tenant_id: &str,
        certification_type: Option<&str>,
    ) -> QidResult<Vec<IgaCertificationRecord>>;
    async fn store_iga_finding(&self, finding: &IgaFindingRecord) -> QidResult<()>;
    async fn list_iga_findings(
        &self,
        tenant_id: &str,
        finding_type: Option<&str>,
    ) -> QidResult<Vec<IgaFindingRecord>>;
    async fn resolve_iga_finding(&self, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait RebacRepository: Send + Sync + 'static {
    async fn create_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()>;
    async fn delete_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()>;
    async fn list_relationship_tuples(
        &self,
        namespace: &str,
        object_id: &str,
        relation: Option<&str>,
    ) -> QidResult<Vec<RelationshipTuple>>;
    async fn list_relationship_tuples_by_subject(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_namespace: &str,
        subject_id: &str,
        subject_relation: Option<&str>,
    ) -> QidResult<Vec<RelationshipTuple>>;
}

#[async_trait]
pub trait AdminRepository: Send + Sync + 'static {
    async fn get_admin(&self, tenant_id: &str, subject: &str) -> QidResult<Option<Admin>>;
    async fn get_admin_by_id(&self, id: &str) -> QidResult<Option<Admin>>;
    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()>;
    async fn get_admin_elevation(&self, id: &str) -> QidResult<Option<AdminElevation>>;
    async fn store_admin_elevation(&self, elevation: &AdminElevation) -> QidResult<()>;
    async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>>;
    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()>;
    async fn consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool>;
}

#[async_trait]
pub trait SsfRepository: Send + Sync + 'static {
    async fn upsert_ssf_stream(&self, stream: &SsfStreamRecord) -> QidResult<()>;
    async fn list_ssf_streams(&self, realm_id: &str) -> QidResult<Vec<SsfStreamRecord>>;
    async fn get_ssf_stream(
        &self,
        realm_id: &str,
        stream_id: &str,
    ) -> QidResult<Option<SsfStreamRecord>>;
    async fn delete_ssf_stream(&self, realm_id: &str, stream_id: &str) -> QidResult<bool>;
    async fn record_ssf_set_jti(
        &self,
        realm_id: &str,
        issuer: &str,
        stream_id: &str,
        jti: &str,
        expires_at: u64,
        now: u64,
    ) -> QidResult<bool>;
}

#[async_trait]
pub trait SiemDeliveryRepository: Send + Sync + 'static {
    async fn upsert_siem_delivery(&self, delivery: &SiemDeliveryRecord) -> QidResult<()>;
    async fn get_siem_delivery(&self, id: &str) -> QidResult<Option<SiemDeliveryRecord>>;
    async fn list_siem_deliveries(
        &self,
        realm_id: Option<&str>,
        status: Option<SiemDeliveryStatus>,
        limit: usize,
    ) -> QidResult<Vec<SiemDeliveryRecord>>;
    async fn mark_siem_delivery_status(
        &self,
        id: &str,
        status: SiemDeliveryStatus,
        attempts: u32,
        next_retry_at: Option<u64>,
        last_error: Option<&str>,
        updated_at: u64,
    ) -> QidResult<()>;
}

/// Aggregate trait implemented automatically by any type that implements all
/// domain-specific repository traits.
pub trait Repository:
    RealmRepository
    + UserRepository
    + ClientRepository
    + SessionRepository
    + TokenRepository
    + CredentialRepository
    + VcRepository
    + ServiceAccountRepository
    + PolicyRepository
    + AuditRepository
    + DeviceRepository
    + ScimRepository
    + FedCmRepository
    + CiamRepository
    + WorkloadRepository
    + SaasRepository
    + IgaRepository
    + RebacRepository
    + AdminRepository
    + SsfRepository
    + SiemDeliveryRepository
    + Send
    + Sync
    + 'static
{
}

impl<T> Repository for T where
    T: RealmRepository
        + UserRepository
        + ClientRepository
        + SessionRepository
        + TokenRepository
        + CredentialRepository
        + VcRepository
        + ServiceAccountRepository
        + PolicyRepository
        + AuditRepository
        + DeviceRepository
        + ScimRepository
        + FedCmRepository
        + CiamRepository
        + WorkloadRepository
        + SaasRepository
        + IgaRepository
        + RebacRepository
        + AdminRepository
        + SsfRepository
        + SiemDeliveryRepository
        + Send
        + Sync
        + 'static
{
}
