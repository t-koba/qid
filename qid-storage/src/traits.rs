//! Domain-specific repository traits.
//!
//! `Repository` is a convenience supertrait that aggregates all domain traits.
//! New storage backends only need to implement the domain traits; `Repository`
//! is derived automatically.

use async_trait::async_trait;
use qid_core::{
    error::{QidError, QidResult},
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
    /// Idempotently remove the realm and its live owned state, including users
    /// and their authentication dependents. Audit/retention/delivery history and
    /// independently tenant/global-scoped records survive. Reusing the realm ID
    /// does not restore deleted live records.
    async fn delete_realm(&self, id: &RealmId) -> QidResult<()>;
}

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn create_user(&self, user: &User) -> QidResult<()>;
    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>>;
    /// A foreign-realm ID is indistinguishable from an unknown ID.
    async fn get_user_by_id_in_realm(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<User>>;
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
    /// Delete a user and their live authentication state atomically, including
    /// codes/families bound to their sessions and tokens in those families.
    /// Preserve unrelated subjects, pending unowned grants and audit history.
    /// A supplied realm must own the current user or this returns NotFound without mutation;
    /// None permits unrestricted, idempotent cleanup, including orphaned state.
    async fn delete_user(&self, id: &str, realm: Option<&str>) -> QidResult<()>;
    async fn update_user(&self, user: &User, realm: Option<&str>) -> QidResult<()>;
    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()>;
    async fn get_password_credential(&self, user_id: &str)
    -> QidResult<Option<PasswordCredential>>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync + 'static {
    /// Create a client.
    ///
    /// A client id names one client in a realm, so a client whose record ID
    /// is taken, or whose client id the realm already holds, is refused and
    /// the incumbent stays as it is.
    async fn create_client(&self, client: &Client) -> QidResult<()>;
    /// Update a client's mutable metadata.
    ///
    /// The update is permitted only when `(realm_id, client_id)` also match
    /// the incumbent record ID; a mismatched realm or client ID is refused
    /// with `Conflict` and changes no field. Same-identity metadata updates,
    /// including an identical retry, succeed. A missing record ID is a legacy
    /// difference the slice preserves: the file backend inserts, the SQL
    /// backend is a silent no-op.
    async fn update_client(&self, client: &Client) -> QidResult<()>;
    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>>;
    /// Every client that carries this client id in the given realms.
    ///
    /// A client id is unique within a realm, so one id can name a client in
    /// more than one realm. The answer is every client the id names in the
    /// named realms, so a caller that needs a single client can see that the
    /// id is ambiguous. A realm outside the list is never read.
    async fn find_clients_by_client_id(
        &self,
        realm_ids: &[RealmId],
        client_id: &str,
    ) -> QidResult<Vec<Client>>;
    async fn list_clients(&self, realm_id: &RealmId) -> QidResult<Vec<Client>> {
        self.list_clients_page(realm_id, 0, usize::MAX).await
    }
    async fn list_clients_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<Client>>;
    /// Delete only a client in this realm; a missing or foreign ID is a no-op.
    async fn delete_client(&self, realm_id: &RealmId, id: &str) -> QidResult<()>;
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
    async fn update_token_family_refresh_hash(
        &self,
        id: &str,
        expected_refresh_hash: &str,
        refresh_hash: &str,
        refresh_expires_at: u64,
    ) -> QidResult<()>;
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
    /// Store a unique `request_uri`; duplicates return `Conflict` without
    /// replacing the incumbent or resetting its single-use state.
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
    async fn update_webauthn_credential_counter(
        &self,
        user_id: &str,
        id: &str,
        counter: u64,
    ) -> QidResult<()>;
    async fn delete_webauthn_credential(&self, user_id: &str, id: &str) -> QidResult<()>;
    async fn list_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        self.get_webauthn_credentials(user_id).await
    }
    async fn store_totp_credential(&self, cred: &TotpCredential) -> QidResult<()>;
    async fn get_totp_credential(&self, user_id: &str) -> QidResult<Option<TotpCredential>>;
    /// Atomically advance `last_used_step` to `step` when it is still
    /// fresh. Returns whether this caller won the claim; losers and unknown
    /// credentials both fail closed; the credential binds its user and record ID.
    async fn consume_totp_step(&self, cred: &TotpCredential, step: u64) -> QidResult<bool>;
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
    /// Create a policy bundle.
    ///
    /// A bundle ID names one bundle globally and a name names one bundle in
    /// a realm; either taken key is `Conflict` and the incumbent is unchanged.
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

/// A synchronous caller decision evaluated at the storage serialization point.
/// Storage deliberately knows nothing about ETags or SCIM match policy.
pub enum ScimMutation<T> {
    Reject,
    Replace(T),
    Delete,
}

pub type ScimMutator<'a, T> = Box<dyn FnOnce(&T) -> QidResult<ScimMutation<T>> + Send + 'a>;

#[async_trait]
pub trait ScimRepository: Send + Sync + 'static {
    async fn get_hr_receipt(
        &self,
        realm_id: &str,
        provider_id: &str,
    ) -> QidResult<Option<crate::HrReceipt>>;
    /// Atomically revalidate targets, mutate users and advance the durable receipt.
    /// Errors on uncertain storage outcomes require retrying identical sequence/body.
    async fn apply_hr_batch(&self, batch: &crate::HrBatch) -> QidResult<crate::HrBatchResult>;

    /// Create a SCIM user.
    ///
    /// Creation is create-only: the record `id` is globally unique and
    /// `user_name` is unique within its realm. A write whose record ID is
    /// taken, or whose user name the realm already holds, is refused with
    /// [`qid_core::error::QidError::Conflict`] and leaves every incumbent
    /// unchanged. The same user name in another realm is allowed. Use
    /// `update_scim_user` or `mutate_scim_user` to change an existing user.
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
    /// Delete only within the expected realm, or unrestricted when absent. Missing/mismatched rows return None.
    async fn delete_scim_user(&self, id: &str, realm: Option<&str>) -> QidResult<Option<ScimUser>> {
        self.mutate_scim_user(
            id,
            Box::new(|current| {
                Ok(match realm {
                    Some(r) if r != current.realm_id => ScimMutation::Reject,
                    _ => ScimMutation::Delete,
                })
            }),
        )
        .await
    }
    /// Evaluate against the current row under the storage lock/transaction.
    /// Missing/rejected rows return None; replacement returns the new row,
    /// deletion the removed row. Callbacks must not re-enter storage and must
    /// preserve id and realm. SQL errors/cancellation roll back the transaction.
    async fn mutate_scim_user(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimUser>,
    ) -> QidResult<Option<ScimUser>>;
    /// Create a SCIM group.
    ///
    /// Creation is create-only: the record `id` is globally unique and
    /// `display_name` is unique within its realm. A write whose record ID is
    /// taken, or whose display name the realm already holds, is refused with
    /// [`qid_core::error::QidError::Conflict`] and leaves every incumbent
    /// unchanged. The same display name in another realm is allowed. Use
    /// `update_scim_group` or `mutate_scim_group` to change an existing group.
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
    /// Delete only within the expected realm, or unrestricted when absent. Missing/mismatched rows return None.
    async fn delete_scim_group(
        &self,
        id: &str,
        realm: Option<&str>,
    ) -> QidResult<Option<ScimGroup>> {
        self.mutate_scim_group(
            id,
            Box::new(|current| {
                Ok(match realm {
                    Some(r) if r != current.realm_id => ScimMutation::Reject,
                    _ => ScimMutation::Delete,
                })
            }),
        )
        .await
    }
    /// Group counterpart of `mutate_scim_user`.
    async fn mutate_scim_group(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimGroup>,
    ) -> QidResult<Option<ScimGroup>>;
    /// Insert or update within the owning realm. A globally colliding ID from another
    /// realm must atomically return `QidError::Conflict` without changing the record.
    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()>;
    async fn get_scim_device(&self, id: &str) -> QidResult<Option<ScimDeviceRecord>>;
    async fn list_scim_devices(&self, realm_id: &RealmId) -> QidResult<Vec<ScimDeviceRecord>>;
    async fn delete_scim_device(&self, id: &str, realm: Option<&str>) -> QidResult<bool>;
    /// Insert or update within the owning realm, with the same atomic ID ownership
    /// contract as `upsert_scim_device`.
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
    async fn delete_scim_event_subscription(
        &self,
        id: &str,
        realm: Option<&str>,
    ) -> QidResult<bool>;
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
    /// Store a CIAM consent grant.
    ///
    /// Grant IDs are global: an existing ID is bound to its incumbent owner
    /// tuple `(realm_id, user_id, client_id)`. A store with the same ID but a
    /// different owner tuple fails with [`qid_core::error::QidError::Conflict`]
    /// and leaves the incumbent unchanged. Same-owner stores upsert.
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()>;
    async fn list_ciam_consent_grants(
        &self,
        realm_id: &RealmId,
        user_id: &str,
        client_id: Option<&str>,
    ) -> QidResult<Vec<CiamConsentGrant>>;
    /// Revoke a CIAM consent grant by record ID.
    ///
    /// Unknown IDs are a silent `Ok` no-op that creates nothing; an existing
    /// grant becomes `revoked = true` and stays revoked on repeat.
    async fn revoke_ciam_consent_grant(&self, id: &str, revoked_at: u64) -> QidResult<()>;
    /// Store a single-use verification challenge with an immutable global ID.
    /// Reusing an ID returns `Conflict` and leaves the original challenge, including
    /// its consumption state, unchanged.
    async fn store_ciam_verification_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
    ) -> QidResult<()>;
    /// Read a verification challenge only within its owning realm.
    async fn get_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>>;
    /// Atomically records an attempt against the exact challenge snapshot read by the caller.
    /// Active attempts increment the persisted count; a verified attempt consumes the challenge.
    /// Expired, consumed, stale or exhausted rows conflict; unknown/foreign IDs are `NotFound`.
    async fn attempt_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
        expected_code_hash: &str,
        verified: bool,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<()>;
    /// Atomically confirm email ownership and consume its challenge. Returns false
    /// for unavailable/foreign/expired (including equality)/stale-email challenges.
    /// Active mismatches increment the durable bounded counter and return false.
    /// Success increments once, consumes once and verifies only the bound current
    /// email of this realm/user, in the same lock/transaction. Candidate hashes
    /// are compared in constant time, never using caller-supplied verified flags.
    async fn confirm_ciam_email_verification(
        &self,
        realm_id: &RealmId,
        id: &str,
        user_id: &str,
        candidate_hash: &str,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<bool>;
    /// Atomically admit a fresh email challenge under a rolling
    /// per-(realm,user,purpose) budget. Count all records of that purpose created
    /// at or after `created_at.saturating_sub(window_seconds - 1)`, including
    /// consumed, expired, failed-delivery and newer records (clock rollback).
    /// Server-authored creation/expiry must fit i64; max_issuances must be positive
    /// and window_seconds must be 1..=86400, as for password-reset admission.
    /// `email_magic_link` needs the digest-pair proof and verified email;
    /// `email_verification` forbids the proof and needs the same email unverified.
    /// False without writing on suppression/ineligibility; duplicates are Conflict.
    /// Fresh attempts are zero, unconsumed; persistence errors are errors.
    async fn try_issue_email_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool>;
    /// Redeem only an email/email_magic_link challenge bound to its current
    /// realm/user's exact stored email and email_verified=true. The candidate
    /// hash is `ml2:<binding digest>:<token digest>` (two lowercase SHA-256 hex
    /// digests, separately domain-separated and bound to challenge identity by
    /// the caller). Compare binding first under the same lock/transaction:
    /// missing, malformed, legacy or wrong binding proofs never write or spend
    /// attempts. Only a matching binding permits a token comparison and durable
    /// increment, whether the token matches or not.
    /// Active means unconsumed, created_at <= attempted_at <= expires_at
    /// (inclusive expiry, matching email verification), and attempts < max_attempts.
    /// The caller supplies server time/policy, never a verified flag. Hashes are
    /// compared in constant time. Success increments once and consumes once;
    /// return the bound User only after durable commit. Unavailable, foreign,
    /// stale-email, unverified, expired or exhausted challenges return None
    /// without writing. Storage errors never authenticate.
    async fn redeem_email_magic_link_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
        candidate_hash: &str,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<Option<User>>;
    /// Trusted federation callers must validate provider proof before storing verified links.
    /// Session-only API callers cannot create or update links, regardless of verified status.
    /// External subjects are unique per realm/provider among verified links only;
    /// legacy unverified rows do not reserve a subject or prevent a trusted mapping.
    /// Store a link, atomically binding its global ID to its realm, user, provider and
    /// external subject. Reuse with another owner or identity key returns Conflict.
    /// Same-owner profile/contact updates are allowed; verified cannot revert to false.
    /// Rejected updates leave the incumbent unchanged.
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
    /// Resolve only verified links for authentication; ignore legacy unverified rows.
    async fn get_ciam_identity_link_by_external_subject(
        &self,
        realm_id: &RealmId,
        provider: &str,
        external_subject: &str,
    ) -> QidResult<Option<CiamIdentityLink>>;
    async fn delete_ciam_identity_link(&self, realm_id: &RealmId, id: &str) -> QidResult<()>;
    /// Store a single-use password-reset token with an immutable global ID.
    /// Reusing an ID returns `Conflict` and leaves the original token, including
    /// its consumption state, unchanged.
    async fn store_password_reset_token(&self, token: &PasswordResetToken) -> QidResult<()>;
    /// Atomically insert under a rolling per-(realm,user) issuance budget.
    /// `true` means inserted; `false` means suppressed with no write. Duplicate
    /// IDs and storage errors are errors, never suppression. Count every record
    /// (including consumed/expired/failed delivery) created at or after created-window+1. Newer records also count if
    /// requests arrive out of order or server time moves backwards.
    /// The caller must supply server-authored creation time and policy.
    async fn try_issue_password_reset_token(
        &self,
        token: &PasswordResetToken,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool>;
    async fn get_password_reset_token(&self, id: &str) -> QidResult<Option<PasswordResetToken>>;
    /// Atomically consume a single-use token.
    /// Unknown IDs return `NotFound`; repeated consumption returns `Conflict`.
    /// Rejected calls leave the token unchanged.
    async fn consume_password_reset_token(&self, id: &str, consumed_at: u64) -> QidResult<()>;
    /// Validate an unused, unexpired, owner/device/hash-bound reset token and
    /// replace its owner's credential in the same atomic storage operation.
    /// `token_hash` is the digest of the presented token, never the raw secret.
    /// Expiry is inclusive: a token is valid at its expiry second.
    async fn replace_password_with_reset_token(
        &self,
        id: &str,
        realm_id: &RealmId,
        token_hash: &str,
        device_id: Option<&str>,
        credential: &PasswordCredential,
        consumed_at: u64,
    ) -> QidResult<()>;

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
    /// Create or update a workload identity for its realm and SPIFFE ID.
    /// A global ID collision with another identity returns `Conflict`; a SPIFFE ID
    /// already registered in the realm is refused. Neither changes the incumbent.
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
    /// Delete the workload identity of one realm.
    /// An identity that belongs to another realm, or an unknown ID, is `NotFound`.
    async fn delete_workload_identity(&self, realm_id: &RealmId, id: &str) -> QidResult<()>;
    /// Create or update a certificate only for its incumbent realm/workload/SPIFFE binding;
    /// a global ID collision with another identity returns `Conflict` without changing it.
    async fn store_workload_certificate(&self, certificate: &WorkloadCertificate) -> QidResult<()>;
    async fn list_workload_certificates(
        &self,
        realm_id: &RealmId,
        workload_id: Option<&str>,
    ) -> QidResult<Vec<WorkloadCertificate>>;
    /// Set or replace `revoked_at` only when it is not earlier than `issued_at`.
    /// Invalid timestamps do not mutate the record; unknown or foreign-realm IDs are `NotFound`.
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
    /// Create or update a domain only under its incumbent tenant owner; a global ID
    /// collision with another tenant returns Conflict without modifying the domain.
    async fn store_custom_domain(&self, domain: &CustomDomain) -> QidResult<()>;
    async fn list_custom_domains(&self, tenant_id: &str) -> QidResult<Vec<CustomDomain>>;
    async fn delete_custom_domain(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    /// Create or update a brand only under its incumbent tenant owner; a global ID
    /// collision with another tenant returns Conflict without modifying the brand.
    async fn store_ciam_brand(&self, brand: &CiamBrand) -> QidResult<()>;
    async fn list_ciam_brands(&self, tenant_id: &str) -> QidResult<Vec<CiamBrand>>;
    async fn delete_ciam_brand(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    /// Create an entry with a globally unique ID; duplicate IDs return Conflict
    /// without changing the existing entry.
    async fn store_app_catalog_entry(&self, entry: &AppCatalogEntry) -> QidResult<()>;
    async fn list_app_catalog_entries(&self, tenant_id: &str) -> QidResult<Vec<AppCatalogEntry>>;
    async fn delete_app_catalog_entry(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    /// Create a connector with a globally unique ID; duplicate IDs return `Conflict`
    /// without changing the incumbent connector or its app-catalog references.
    async fn store_marketplace_connector(&self, connector: &MarketplaceConnector) -> QidResult<()>;
    async fn list_marketplace_connectors(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<MarketplaceConnector>>;
    async fn delete_marketplace_connector(&self, tenant_id: &str, id: &str) -> QidResult<()>;
    /// Create an event with a globally unique ID; duplicate IDs return `Conflict`
    /// without changing recorded usage. Idempotency keys remain unique per tenant.
    async fn store_usage_billing_event(&self, event: &UsageBillingEvent) -> QidResult<()>;
    async fn list_usage_billing_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> QidResult<Vec<UsageBillingEvent>>;
    /// Create a pack with a globally unique ID; duplicate IDs return `Conflict`
    /// without changing the incumbent pack or its listing.
    async fn store_compliance_evidence_pack(&self, pack: &ComplianceEvidencePack) -> QidResult<()>;
    async fn list_compliance_evidence_packs(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<ComplianceEvidencePack>>;
    /// Create or update a delegated admin only under its incumbent tenant owner; a
    /// global ID collision with another tenant returns Conflict without modifying
    /// the grant.
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
    /// Store a tenant-owned request with a global ID; duplicate IDs return `Conflict`.
    /// Use the dedicated status and grant methods for later lifecycle changes.
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
    /// Store an immutable tenant-owned approval with a global ID; duplicates return `Conflict`.
    async fn store_iga_approval(&self, approval: &IgaApprovalRecord) -> QidResult<()>;
    async fn list_iga_approvals(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> QidResult<Vec<IgaApprovalRecord>>;
    /// Direct record storage; does not enforce request/entitlement uniqueness.
    async fn store_iga_access_grant(&self, grant: &IgaAccessGrantRecord) -> QidResult<()>;
    /// Atomically materialize a nonempty, complete grant set for one existing
    /// tenant/request/subject, matching its singleton entitlement or package
    /// snapshot, and require the request to be approved. Candidates must be
    /// non-revoked. Validate every candidate before effects; reject mixed scopes,
    /// duplicate IDs/entitlements, and malformed or inconsistent incumbents.
    /// Under a repository serialization boundary, insert only missing bindings
    /// (tenant, request, subject, entitlement). Preserve incumbents exactly,
    /// including revoked/expired records, IDs, expiry and approval evidence.
    /// Return only inserted records, in candidate order; complete replay is
    /// empty. Failure leaves no partial set (Immediate file mode also restores
    /// the prior store on persistence failure; Interval mode marks memory dirty).
    /// This guarantee applies to this operation, not concurrent direct stores.
    async fn ensure_iga_access_grants(
        &self,
        candidates: &[IgaAccessGrantRecord],
    ) -> QidResult<Vec<IgaAccessGrantRecord>>;

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
    /// Close a tenant-scoped access-review campaign.
    /// Returns `true` when a matching campaign existed (now closed, idempotent
    /// for an already-closed campaign) and `false` when no tenant-scoped
    /// campaign exists. Absent and other-tenant IDs are indistinguishable.
    async fn close_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<bool>;
    /// Store an immutable IGA access review decision with a global ID.
    /// Reusing an ID returns `Conflict` and leaves the incumbent decision unchanged.
    async fn store_iga_access_review_decision(
        &self,
        decision: &IgaAccessReviewDecisionRecord,
    ) -> QidResult<()>;
    async fn list_iga_access_review_decisions(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewDecisionRecord>>;
    /// Store an immutable IGA certification with a global ID.
    /// Reusing an ID returns `Conflict` and leaves the incumbent certification unchanged.
    async fn store_iga_certification(
        &self,
        certification: &IgaCertificationRecord,
    ) -> QidResult<()>;
    async fn list_iga_certifications(
        &self,
        tenant_id: &str,
        certification_type: Option<&str>,
    ) -> QidResult<Vec<IgaCertificationRecord>>;
    /// Store an IGA finding with a global ID; duplicate IDs return `Conflict`; `resolve_iga_finding` is the tenant-scoped monotonic resolution transition (unknown/foreign IDs are a safe no-op).
    async fn store_iga_finding(&self, finding: &IgaFindingRecord) -> QidResult<()>;
    async fn list_iga_findings(
        &self,
        tenant_id: &str,
        finding_type: Option<&str>,
    ) -> QidResult<Vec<IgaFindingRecord>>;
    async fn resolve_iga_finding(&self, tenant_id: &str, id: &str) -> QidResult<()>;
}

#[async_trait]
pub trait RebacRepository: Send + Sync + 'static {
    /// Create a unique six-field tuple; duplicates return `Conflict` and leave
    /// the incumbent, including its creation timestamp, unchanged.
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
    /// Insert or update a queued delivery within its incumbent realm scope.
    /// The global ID is bound to the incumbent optional `realm_id`: `Some(realm)`
    /// and `None` (global scope) are distinct bindings. Reuse of an ID under a
    /// different binding returns `QidError::Conflict` and leaves the incumbent
    /// record and listings unchanged. Same-scope upserts retain their existing
    /// backend update behavior, with the original `created_at` retained; status
    /// transitions remain available separately.
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
    + PushRepository
    + OidcContinuationRepository
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
        + PushRepository
        + OidcContinuationRepository
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

/// What a client id names among the realms a deployment serves.
#[derive(Debug)]
pub enum ClientLookup {
    /// Exactly one client carries the id.
    Found(Box<Client>),
    /// No client carries the id.
    Unknown,
    /// More than one client carries the id, so the id names no single
    /// client and no request can be served for it.
    Ambiguous,
}

/// Look a client id up among the realms a deployment serves.
///
/// One read answers the client id in every named realm, and no other realm
/// is read. The id names one client, no client, or more than one; each
/// path words its own refusal of the last two.
pub async fn lookup_client_across_realms<R: ClientRepository + ?Sized>(
    repo: &R,
    realm_ids: &[RealmId],
    client_id: &str,
) -> QidResult<ClientLookup> {
    let clients = repo.find_clients_by_client_id(realm_ids, client_id).await?;
    Ok(match clients.as_slice() {
        [client] => ClientLookup::Found(Box::new(client.clone())),
        [] => ClientLookup::Unknown,
        _ => ClientLookup::Ambiguous,
    })
}

/// Refuse a client id another served realm already holds.
///
/// The request paths resolve the client of a request across the realms the
/// deployment serves and serve no request that names a client id two of
/// them hold, so a creation path asks this before it writes. The refusal
/// names the realm that holds the id. A realm the deployment does not
/// serve holds no client of a request, so an id it carries is no
/// ambiguity.
pub async fn ensure_client_id_unambiguous<R: ClientRepository + ?Sized>(
    repo: &R,
    served_realm_ids: &[RealmId],
    client_id: &str,
    target_realm: &RealmId,
) -> QidResult<()> {
    if !served_realm_ids.iter().any(|realm| realm == target_realm) {
        return Ok(());
    }
    let holders = repo
        .find_clients_by_client_id(served_realm_ids, client_id)
        .await?;
    if let Some(holder) = holders
        .iter()
        .find(|client| client.realm_id != target_realm.as_str())
    {
        return Err(QidError::Conflict {
            message: format!(
                "client id {client_id} already exists in realm {}",
                holder.realm_id
            ),
        });
    }
    Ok(())
}

/// Durable push-MFA state, not a signature verifier or delivery adapter.
///
/// IDs are globally unique within each record kind, immutable and never upserted.
/// A registration ID is also its eventual authenticator ID; revocation retains a
/// tombstone and cannot be undone. Only proof completion enrolls an authenticator.
/// One lifecycle row replaces pending state on enrollment, discarding proof verifiers.
///
/// Before creating a registration the service must authorize recent account-bound
/// reauthentication (including required step-up), validate the candidate public key,
/// then persist pending state and deliver a fresh nonce to its destination.
/// Before passing `verified = true`
/// or `Some(decision)`, it MUST verify the signature with the bound key and exact
/// realm, user, purpose, challenge/transaction ID, nonce, authenticator/destination
/// binding and (for login) decision claims. Check the nonce against the stored
/// SHA-256 verifier. Registration and login signatures must be domain-separated.
/// Provider acceptance is not proof. Store only nonce/browser SHA-256 verifiers.
///
/// Pass the immutable record read for that verification as `expected`; storage
/// checks every immutable field against the current row. Mutable state in that
/// snapshot is ignored, so parallel bad signatures still count independently.
/// All times are trusted server epoch seconds, never device/client timestamps.
/// Expiry is exclusive. Attempt caps are fixed when creating the challenge.
///
/// Attempt methods return true when an attempt was recorded, INCLUDING an invalid
/// signature; this is not an authentication result. `None` records a bad login
/// signature, never a decision. Only a successful redemption authorizes completion
/// of the already password-verified, exact browser-bound login transaction. A login
/// row ID is its transaction ID; create only one row per password login, selecting
/// one enrolled authenticator before issuance rather than creating parallel rows.
#[async_trait]
pub trait PushRepository: Send + Sync + 'static {
    /// Returns pending state only (including expired/exhausted rows), never enrolled state.
    async fn get_push_registration(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushRegistrationChallenge>>;
    async fn attempt_push_registration(
        &self,
        expected: &PushRegistrationChallenge,
        verified: bool,
        now: u64,
    ) -> QidResult<bool>;
    /// Returns enrolled state, including revoked tombstones; pending rows return None.
    async fn get_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushAuthenticator>>;
    /// Includes revoked tombstones; callers select active registrations explicitly.
    async fn list_push_authenticators(
        &self,
        realm: &RealmId,
        user: &str,
    ) -> QidResult<Vec<PushAuthenticator>>;
    async fn revoke_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
        now: u64,
    ) -> QidResult<bool>;
    async fn get_push_login(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushLoginChallenge>>;
    async fn attempt_push_login(
        &self,
        expected: &PushLoginChallenge,
        decision: Option<PushDecision>,
        now: u64,
    ) -> QidResult<bool>;
    /// `binding_verifier` is computed by the service from the browser-held secret.
    async fn redeem_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        now: u64,
    ) -> QidResult<bool>;
    /// Atomically admit a registration issuance under a rolling owner-wide budget.
    /// The budget key is realm + user + purpose (`registration`); the
    /// authenticator ID is never part of the key, so parallel devices share it.
    /// Counts every row of that key issued at or after
    /// `admitted_at.saturating_sub(window_seconds - 1)` — pending, enrolled and
    /// revoked alike — including expired rows. Admission time is sampled from
    /// the trusted server clock only after storage and owner/purpose locks are held,
    /// and persisted separately from lifecycle creation/expiry. Requires
    /// `created_at <= admitted_at < expires_at`; creation is never quota authority. `true` means inserted; `false`
    /// means suppressed with no write. Invalid shape, budget (`max_issuances`
    /// must be positive, `window_seconds` 1..=86400) or timestamps that do not
    /// fit signed storage are `BadRequest`; duplicate IDs and missing accounts
    /// are `Conflict`, never suppression. These are the only issuance entry points.
    async fn try_issue_push_registration(
        &self,
        challenge: &PushRegistrationChallenge,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool>;
    /// Atomically admit a password-login issuance under a rolling owner-wide
    /// budget keyed realm + user + purpose, never the authenticator ID, so one
    /// password success cannot mint independently redeemable per-device rows
    /// beyond the shared budget. Counts every initial/resend send of that key in the window,
    /// including expired, decided, denied, consumed and delivery-failed
    /// (undecided) rows. Requires the bound authenticator to be current.
    /// `true`/`false` and error semantics match `try_issue_push_registration`;
    /// a non-current authenticator is `Conflict`.
    async fn try_issue_push_login(
        &self,
        challenge: &PushLoginChallenge,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool>;
    /// Atomically reserve a send under the initial-send quota and rotate the nonce.
    /// Checks the expected immutable binding, nonce generation and resend history,
    /// plus the separately supplied browser verifier, current enrollment, liveness,
    /// attempts and cooldown (at least one second since the last admitted send).
    /// Trusted time is sampled under durable admission locks. Only the nonce verifier
    /// and resend history change; concurrent attempts are preserved, not overwritten.
    /// Returns the persisted rotated snapshot, or None without mutation on refusal.
    /// Invalid budget parameters are BadRequest; corrupt records fail closed.
    /// Delivery failures after admission are not refunded.
    async fn try_resend_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        nonce_verifier: &str,
        max_issuances: u32,
        window_seconds: u64,
        cooldown_seconds: u64,
    ) -> QidResult<Option<PushLoginChallenge>>;
    /// Delete at most `limit` expired rows that no admissible quota window can
    /// still count, and return the number deleted. Pending registrations require
    /// expiry and `issued_at < now - 86400`; login rows require immutable
    /// `expires_at < now - 86400`. Equality is retained. Never deletes enrolled or revoked
    /// authenticator rows. `limit` must be in 1..=1000 (a hard per-call bound);
    /// `now` must fit signed storage. A future independent worker may schedule
    /// periodic calls; scheduling lives outside qid-storage and qid-worker is
    /// untouched by this slice.
    async fn cleanup_expired_push_records(&self, now: u64, limit: u32) -> QidResult<u64>;
}

/// OIDC-owned immutable validated request context, not proof of authentication.
/// Callers use a trusted server clock and SHA-256 of a browser-held secret.
/// No read/update API: the only retrieval consumes atomically. IDs remain reserved
/// after consumption until bounded expiry cleanup removes them. This contract neither
/// approves factors nor issues codes.
#[async_trait]
pub trait OidcContinuationRepository: Send + Sync + 'static {
    /// Unique insert; even identical duplicate IDs are Conflict, never replacement.
    /// IDs/owner labels are nonempty, <=256 UTF-8 bytes, no whitespace/control.
    /// Context is a nonempty JSON object <=64 KiB. Requires created_at == now
    /// and created_at < expires_at <= i64::MAX. Invalid shape is BadRequest.
    async fn create_oidc_continuation(
        &self,
        record: &OidcAuthorizationContinuation,
        now: u64,
    ) -> QidResult<()>;
    /// Exactly one matching browser/realm/user/client may retrieve the original
    /// envelope while created_at <= now < expires_at. A mismatch, missing,
    /// expired or consumed ID returns None without consuming. now > i64::MAX
    /// is BadRequest. Caller must still verify completed authentication and
    /// current account/client policy before resuming protocol processing.
    async fn consume_oidc_continuation(
        &self,
        realm: &RealmId,
        user: &str,
        client: &str,
        id: &str,
        browser_binding_sha256: &[u8; 32],
        now: u64,
    ) -> QidResult<Option<OidcAuthorizationContinuation>>;
    /// Delete at most `limit` expired records (expiry is inclusive at `now`).
    /// The hard per-call bound is 1..=1000; expired IDs are no longer retained.
    async fn cleanup_expired_oidc_continuations(&self, now: u64, limit: u32) -> QidResult<u64>;
}
