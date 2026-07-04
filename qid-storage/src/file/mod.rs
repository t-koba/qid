use qid_core::{
    error::{QidError, QidResult},
    models::*,
    tenant::{RealmId, TenantId},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;

use crate::{
    AdminRepository, AuditRepository, CiamRepository, ClientRepository, CredentialRepository,
    DeviceRepository, FedCmRepository, IgaRepository, PolicyRepository, RealmRepository,
    RebacRepository, SaasRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, ScimRepository,
    ServiceAccountRepository, SessionRepository, SsfRepository, SsfStreamRecord, TokenRepository,
    UserRepository, VcRepository, WorkloadRepository,
};

mod admin;
mod audit;
mod ciam;
mod client;
mod credential;
mod device;
mod fedcm;
mod iga;
mod policy;
mod realm;
mod rebac;
mod saas;
mod scim;
mod service_account;
mod session;
mod ssf;
mod token;
mod user;
mod vc;
mod workload;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    realm_issuers: HashMap<String, String>,
    #[serde(default)]
    realm_tenants: HashMap<String, String>,
    users: HashMap<String, User>,
    credentials_password: HashMap<String, PasswordCredential>,
    clients: HashMap<String, Client>,
    sessions: HashMap<String, Session>,
    authorization_codes: HashMap<String, AuthorizationCode>,
    token_families: HashMap<String, TokenFamily>,
    access_tokens: HashMap<String, AccessToken>,
    webauthn_credentials: HashMap<String, Vec<WebAuthnCredential>>,
    service_accounts: HashMap<String, ServiceAccount>,
    policy_bundles: HashMap<String, PolicyBundle>,
    totp_credentials: HashMap<String, TotpCredential>,
    #[serde(default)]
    vc_credential_statuses: HashMap<String, VcCredentialStatusRecord>,
    devices: HashMap<String, Device>,
    par_requests: HashMap<String, ParRequest>,
    device_authorization_grants: HashMap<String, DeviceAuthorizationGrant>,
    backchannel_authentication_grants: HashMap<String, BackchannelAuthenticationGrant>,
    scim_users: HashMap<String, ScimUser>,
    scim_groups: HashMap<String, ScimGroup>,
    #[serde(default)]
    scim_devices: HashMap<String, ScimDeviceRecord>,
    #[serde(default)]
    scim_event_subscriptions: HashMap<String, ScimEventSubscriptionRecord>,
    fedcm_identities: HashMap<String, FedCmIdentity>,
    #[serde(default)]
    ciam_consent_grants: HashMap<String, CiamConsentGrant>,
    #[serde(default)]
    ciam_verification_challenges: HashMap<String, CiamVerificationChallengeRecord>,
    #[serde(default)]
    ciam_identity_links: HashMap<String, CiamIdentityLink>,
    #[serde(default)]
    password_reset_tokens: HashMap<String, PasswordResetToken>,
    #[serde(default)]
    ciam_profiles: HashMap<String, CiamProgressiveProfile>,
    workload_identities: HashMap<String, WorkloadIdentity>,
    #[serde(default)]
    workload_certificates: HashMap<String, WorkloadCertificate>,
    custom_domains: HashMap<String, CustomDomain>,
    #[serde(default)]
    ciam_brands: HashMap<String, CiamBrand>,
    app_catalog_entries: HashMap<String, AppCatalogEntry>,
    marketplace_connectors: HashMap<String, MarketplaceConnector>,
    usage_billing_events: HashMap<String, UsageBillingEvent>,
    compliance_evidence_packs: HashMap<String, ComplianceEvidencePack>,
    #[serde(default)]
    delegated_tenant_admins: HashMap<String, DelegatedTenantAdmin>,
    #[serde(default)]
    iga_entitlements: HashMap<String, IgaEntitlementRecord>,
    #[serde(default)]
    iga_access_packages: HashMap<String, IgaAccessPackageRecord>,
    iga_access_requests: HashMap<String, IgaAccessRequestRecord>,
    iga_approvals: HashMap<String, IgaApprovalRecord>,
    iga_access_grants: HashMap<String, IgaAccessGrantRecord>,
    #[serde(default)]
    iga_jit_privilege_grants: HashMap<String, IgaJitPrivilegeGrantRecord>,
    #[serde(default)]
    iga_access_review_campaigns: HashMap<String, IgaAccessReviewCampaignRecord>,
    #[serde(default)]
    iga_access_review_decisions: HashMap<String, IgaAccessReviewDecisionRecord>,
    #[serde(default)]
    iga_certifications: HashMap<String, IgaCertificationRecord>,
    #[serde(default)]
    iga_findings: HashMap<String, IgaFindingRecord>,
    #[serde(default)]
    admins: HashMap<String, Admin>,
    #[serde(default)]
    admin_elevations: HashMap<String, AdminElevation>,
    #[serde(default)]
    admin_approvals: HashMap<String, AdminApproval>,
    #[serde(default)]
    ssf_streams: HashMap<String, SsfStreamRecord>,
    #[serde(default)]
    ssf_set_replay: HashMap<String, u64>,
    #[serde(default)]
    relationship_tuples: Vec<RelationshipTuple>,
    audit_events: Vec<AuditEvent>,
    audit_retention_configs: HashMap<String, AuditRetentionConfig>,
}

/// File-backed repository implementation.
///
/// Persists all data as a single JSON file. Suitable for development
/// and small-scale deployments where SQL is not desired.
#[derive(Debug, Clone)]
pub struct FileRepository {
    store: std::sync::Arc<tokio::sync::RwLock<Store>>,
    path: PathBuf,
}

impl FileRepository {
    pub async fn new(path: &str) -> QidResult<Self> {
        let p = PathBuf::from(path);
        let store = match tokio::fs::read_to_string(&p).await {
            Ok(content) => serde_json::from_str(&content).map_err(|e| QidError::Internal {
                message: format!("failed to parse store file: {e}"),
            })?,
            Err(e) if e.kind() == ErrorKind::NotFound => Store::default(),
            Err(e) => {
                return Err(QidError::Internal {
                    message: format!("failed to read store file: {e}"),
                });
            }
        };
        Ok(Self {
            store: std::sync::Arc::new(tokio::sync::RwLock::new(store)),
            path: p,
        })
    }

    async fn save(&self) -> QidResult<()> {
        let content = {
            let store = self.store.read().await;
            serde_json::to_string_pretty(&*store).map_err(|e| QidError::Internal {
                message: format!("failed to serialize store: {e}"),
            })?
        };
        // Atomic write: temp → fsync → rename (crash-safe)
        let tmp_path = self.path.with_extension("tmp");
        tokio::fs::write(&tmp_path, &content)
            .await
            .map_err(|e| QidError::Internal {
                message: format!("failed to write temp store file: {e}"),
            })?;
        // fsync the file and the directory for durability
        let file = tokio::fs::File::open(&tmp_path)
            .await
            .map_err(|e| QidError::Internal {
                message: format!("failed to open temp file for fsync: {e}"),
            })?;
        file.sync_all().await.map_err(|e| QidError::Internal {
            message: format!("failed to fsync temp store file: {e}"),
        })?;
        std::mem::drop(file);
        tokio::fs::rename(&tmp_path, &self.path)
            .await
            .map_err(|e| QidError::Internal {
                message: format!("failed to rename store file: {e}"),
            })?;
        // fsync the directory to ensure the rename is durable
        if let Some(parent) = self.path.parent()
            && let Ok(dir) = tokio::fs::File::open(parent).await
        {
            dir.sync_all().await.ok();
        }
        Ok(())
    }

    pub async fn migrate(&self) -> QidResult<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| QidError::Internal {
                    message: format!("failed to create store directory: {e}"),
                })?;
        }
        if !self.path.exists() {
            self.save().await?;
        }
        Ok(())
    }
}

fn audit_retention_key(realm_id: Option<&str>) -> String {
    realm_id.unwrap_or("__global__").to_string()
}

fn iga_tenant_scoped_key(tenant_id: &str, id: &str) -> String {
    format!("{tenant_id}:{id}")
}

fn ssf_stream_key(realm_id: &str, stream_id: &str) -> String {
    format!("{realm_id}\u{1f}{stream_id}")
}

fn ssf_set_replay_key(realm_id: &str, issuer: &str, stream_id: &str, jti: &str) -> String {
    format!("{realm_id}\u{1f}{issuer}\u{1f}{stream_id}\u{1f}{jti}")
}
