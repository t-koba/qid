use qid_core::{
    error::{QidError, QidResult},
    models::*,
    tenant::{RealmId, TenantId},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::{
    AdminRepository, AuditRepository, CiamRepository, ClientRepository, CredentialRepository,
    DeviceRepository, FedCmRepository, IgaRepository, PolicyRepository, RealmRepository,
    RebacRepository, SaasRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, ScimRepository,
    ServiceAccountRepository, SessionRepository, SiemDeliveryRecord, SiemDeliveryRepository,
    SiemDeliveryStatus, SsfRepository, SsfStreamRecord, TokenRepository, UserRepository,
    VcRepository, WorkloadRepository,
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
mod siem;
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
    siem_deliveries: HashMap<String, SiemDeliveryRecord>,
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
    store: Arc<tokio::sync::RwLock<Store>>,
    path: PathBuf,
    save_lock: Arc<tokio::sync::Mutex<()>>,
    _process_lock: Arc<ProcessLock>,
    dirty: Arc<AtomicBool>,
    flush_mode: FileFlushMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFlushMode {
    Immediate,
    Interval(Duration),
}

impl FileRepository {
    pub async fn new(path: &str) -> QidResult<Self> {
        Self::new_with_flush_mode(path, FileFlushMode::Immediate).await
    }

    pub async fn new_with_flush_mode(path: &str, flush_mode: FileFlushMode) -> QidResult<Self> {
        let p = PathBuf::from(path);
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| QidError::Internal {
                    message: format!("failed to create store directory: {e}"),
                })?;
        }
        let process_lock = acquire_process_lock(&p)?;
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
        let repo = Self {
            store: Arc::new(tokio::sync::RwLock::new(store)),
            path: p,
            save_lock: Arc::new(tokio::sync::Mutex::new(())),
            _process_lock: Arc::new(process_lock),
            dirty: Arc::new(AtomicBool::new(false)),
            flush_mode,
        };
        if let FileFlushMode::Interval(interval) = flush_mode {
            let repo = repo.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if let Err(error) = repo.flush().await {
                        tracing::warn!(error = %error, "file repository background flush failed");
                    }
                }
            });
        }
        Ok(repo)
    }

    async fn save(&self) -> QidResult<()> {
        match self.flush_mode {
            FileFlushMode::Immediate => self.flush_store().await,
            FileFlushMode::Interval(_) => {
                self.dirty.store(true, Ordering::Release);
                Ok(())
            }
        }
    }

    pub async fn flush(&self) -> QidResult<()> {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        self.flush_store().await
    }

    async fn flush_store(&self) -> QidResult<()> {
        let _save_guard = self.save_lock.lock().await;
        let content = {
            let store = self.store.read().await;
            serde_json::to_string(&*store).map_err(|e| QidError::Internal {
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
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path)
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
            self.flush_store().await?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ProcessLock {
    _file: File,
}

fn acquire_process_lock(path: &std::path::Path) -> QidResult<ProcessLock> {
    let lock_path = path.with_extension("lock");
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lock_path)
            .map_err(|e| QidError::Internal {
                message: format!(
                    "file storage is already locked by another process; use SQL storage for multi-process deployments: {e}"
                ),
            })?;
        return Ok(ProcessLock { _file: file });
    }

    #[cfg(not(windows))]
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| QidError::Internal {
                message: format!("failed to open store lock file: {e}"),
            })?;
        rustix::fs::flock(
            &file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|e| QidError::Internal {
            message: format!(
                "file storage is already locked by another process; use SQL storage for multi-process deployments: {e}"
            ),
        })?;
        Ok(ProcessLock { _file: file })
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
