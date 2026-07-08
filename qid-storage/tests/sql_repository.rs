use qid_core::models::{
    AccessToken, AppCatalogEntry, AuditEvent, AuditRetentionConfig, AuthorizationCode,
    BackchannelAuthenticationGrant, CiamBrand, CiamConsentGrant, CiamIdentityLink,
    CiamVerificationChallengeRecord, Client, ClientType, ComplianceEvidencePack, CustomDomain,
    DelegatedTenantAdmin, DeviceAuthorizationGrant, IgaAccessGrantRecord, IgaAccessPackageRecord,
    IgaAccessRequestRecord, IgaAccessReviewCampaignRecord, IgaAccessReviewDecisionRecord,
    IgaApprovalRecord, IgaCertificationRecord, IgaEntitlementRecord, IgaFindingRecord,
    IgaJitPrivilegeGrantRecord, MarketplaceConnector, MarketplaceConnectorType, PasswordCredential,
    PasswordResetToken, PolicyBundle, ScimGroup, ScimUser, Session, UsageBillingEvent, User,
    VcCredentialStatusRecord, WorkloadCertificate, WorkloadIdentity,
};
use qid_core::tenant::{RealmId, TenantId};
use qid_storage::{FileRepository, SqlRepository, prelude::*};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    // Clean old test databases once per process
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for e in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(e.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

fn vc_status_record(credential_id: &str) -> VcCredentialStatusRecord {
    VcCredentialStatusRecord {
        credential_id: credential_id.to_string(),
        realm_id: "realm-vc".to_string(),
        subject: "user-vc".to_string(),
        issuer: "https://id.example.com".to_string(),
        status_list_uri: format!("https://id.example.com/vc/v1/status/{credential_id}"),
        issued_at: 1_000,
        expires_at: 2_000,
        revoked: false,
        revocation_reason: None,
        revoked_at: None,
    }
}

async fn assert_workload_certificate_round_trip<R>(repo: &R)
where
    R: RealmRepository + WorkloadRepository,
{
    let realm = RealmId("realm-workload".to_string());
    repo.create_realm(
        &TenantId("tenant-workload".to_string()),
        &realm,
        "https://workload.example.com",
        Some("Workload Realm"),
    )
    .await
    .expect("create workload realm failed");
    let workload = WorkloadIdentity {
        id: "workload-api".to_string(),
        realm_id: realm.0.clone(),
        spiffe_id: "spiffe://corp.example/workload/api".to_string(),
        description: Some("API workload".to_string()),
        trust_domain: "corp.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-main"}),
    };
    repo.create_workload_identity(&workload)
        .await
        .expect("create workload identity failed");

    let certificate = WorkloadCertificate {
        id: "cert-api-1".to_string(),
        realm_id: realm.0.clone(),
        workload_id: workload.id.clone(),
        spiffe_id: workload.spiffe_id.clone(),
        serial_number: "01:02:03".to_string(),
        x5t_s256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        csr_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            .to_string(),
        issuer_key_ref: "kms://realm-workload/ca-main".to_string(),
        issued_at: 1_800_000_000,
        not_before: 1_800_000_000,
        not_after: 1_800_003_600,
        revoked_at: None,
    };
    repo.store_workload_certificate(&certificate)
        .await
        .expect("store workload certificate failed");

    let listed = repo
        .list_workload_certificates(&realm, Some(&workload.id))
        .await
        .expect("list workload certificates failed");
    assert_eq!(listed, vec![certificate.clone()]);

    let duplicate = WorkloadCertificate {
        id: "cert-api-duplicate".to_string(),
        ..certificate.clone()
    };
    let err = repo
        .store_workload_certificate(&duplicate)
        .await
        .expect_err("duplicate workload certificate thumbprint must fail");
    assert!(
        err.message()
            .contains("workload certificate thumbprint already exists"),
        "unexpected error: {}",
        err.message()
    );

    repo.revoke_workload_certificate(&realm, &certificate.id, 1_800_000_100)
        .await
        .expect("revoke workload certificate failed");
    let revoked = repo
        .list_workload_certificates(&realm, Some(&workload.id))
        .await
        .expect("list revoked workload certificates failed");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].revoked_at, Some(1_800_000_100));
}

#[tokio::test]
async fn test_connect_and_migrate() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
}

#[tokio::test]
async fn test_migration_plan_reports_pending_and_applied_migrations() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");

    let pending = repo.migration_plan().await.expect("migration plan failed");
    assert!(pending.ready);
    assert_eq!(pending.current_version, None);
    assert!(pending.target_version.is_some());
    assert!(pending.applied.is_empty());
    assert!(!pending.pending.is_empty());
    assert!(pending.divergent.is_empty());
    assert!(pending.unknown_applied.is_empty());

    repo.migrate().await.expect("migration failed");
    let applied = repo.migration_plan().await.expect("migration plan failed");
    assert!(applied.ready);
    assert_eq!(applied.current_version, applied.target_version);
    assert!(applied.pending.is_empty());
    assert!(applied.divergent.is_empty());
    assert!(applied.unknown_applied.is_empty());
    assert!(!applied.applied.is_empty());
}

#[tokio::test]
async fn test_app_catalog_realm_migration_backfills_single_realm_tenant() {
    let url = db_url();
    let _repo = SqlRepository::connect(&url)
        .await
        .expect("create sqlite database failed");
    let pool = sqlx::SqlitePool::connect(&url)
        .await
        .expect("connect failed");
    sqlx::query(
        "CREATE TABLE realms (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            issuer TEXT NOT NULL UNIQUE,
            display_name TEXT,
            config_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(&pool)
    .await
    .expect("create realms table failed");
    sqlx::query(
        "CREATE TABLE app_catalog_entries (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            category TEXT NOT NULL,
            oidc_client_id TEXT,
            saml_entity_id TEXT,
            scim_enabled INTEGER NOT NULL,
            marketplace_connector_id TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("create old app catalog table failed");

    for (id, tenant, issuer) in [
        (
            "realm-single",
            "tenant-single",
            "https://single.example.com",
        ),
        (
            "realm-multi-a",
            "tenant-multi",
            "https://multi-a.example.com",
        ),
        (
            "realm-multi-b",
            "tenant-multi",
            "https://multi-b.example.com",
        ),
    ] {
        sqlx::query("INSERT INTO realms (id, tenant_id, issuer) VALUES (?, ?, ?)")
            .bind(id)
            .bind(tenant)
            .bind(issuer)
            .execute(&pool)
            .await
            .expect("insert realm failed");
    }
    for (id, tenant) in [
        ("app-single", "tenant-single"),
        ("app-multi", "tenant-multi"),
        ("app-none", "tenant-none"),
    ] {
        sqlx::query(
            "INSERT INTO app_catalog_entries (id, tenant_id, display_name, category, oidc_client_id, saml_entity_id, scim_enabled, marketplace_connector_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(tenant)
        .bind("App")
        .bind("sales")
        .bind("client")
        .bind(Option::<String>::None)
        .bind(0_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .expect("insert old app catalog entry failed");
    }

    sqlx::raw_sql(include_str!(
        "../migrations/20250618000028_app_catalog_realm_id.sql"
    ))
    .execute(&pool)
    .await
    .expect("apply app catalog realm migration failed");

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id, realm_id FROM app_catalog_entries ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .expect("select migrated app catalog entries failed");
    assert_eq!(
        rows,
        vec![
            ("app-multi".to_string(), String::new()),
            ("app-none".to_string(), String::new()),
            ("app-single".to_string(), "realm-single".to_string()),
        ]
    );
}

#[tokio::test]
async fn test_realm_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-a".into(),
        "https://id.example.com/realms/a",
        Some("Realm A"),
    )
    .await
    .expect("create realm failed");
    let issuer = repo
        .get_realm_issuer(&"realm-a".into())
        .await
        .unwrap()
        .expect("realm not found");
    assert_eq!(issuer, "https://id.example.com/realms/a");
}

#[tokio::test]
async fn test_audit_event_append_and_list() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-audit".into(),
        "https://id.example.com/realms/audit",
        None,
    )
    .await
    .unwrap();
    let event = AuditEvent {
        id: "audit-1".to_string(),
        realm_id: Some("realm-audit".to_string()),
        actor: "admin@example.com".to_string(),
        action: "user.create".to_string(),
        target_type: "user".to_string(),
        target_id: "user-1".to_string(),
        reason: "ticket-123".to_string(),
        metadata_json: serde_json::json!({ "email": "user@example.com" }),
        created_at: 1_000,
        previous_hash: Some("ignored".to_string()),
        event_hash: Some("ignored".to_string()),
    };
    repo.append_audit_event(&event)
        .await
        .expect("append audit failed");
    let events = repo
        .list_audit_events(Some(&"realm-audit".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, "admin@example.com");
    assert_eq!(events[0].reason, "ticket-123");
    assert_eq!(events[0].metadata_json["email"], "user@example.com");
    assert_eq!(events[0].previous_hash, None);
    assert_ne!(events[0].event_hash.as_deref(), Some("ignored"));
    assert!(events[0].event_hash.is_some());

    let second_event = AuditEvent {
        id: "audit-2".to_string(),
        realm_id: Some("realm-audit".to_string()),
        actor: "admin@example.com".to_string(),
        action: "user.delete".to_string(),
        target_type: "user".to_string(),
        target_id: "user-1".to_string(),
        reason: "ticket-124".to_string(),
        metadata_json: serde_json::json!({}),
        created_at: 1_001,
        previous_hash: None,
        event_hash: None,
    };
    repo.append_audit_event(&second_event)
        .await
        .expect("append second audit failed");
    let events = repo
        .list_audit_events(Some(&"realm-audit".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id, "audit-2");
    assert_eq!(events[0].previous_hash, events[1].event_hash);

    let verification = repo
        .verify_audit_chain(Some(&"realm-audit".into()))
        .await
        .unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checked_events, 2);

    let all_events = repo.list_audit_events(None, 10).await.unwrap();
    assert_eq!(all_events.len(), 2);
    let global_verification = repo.verify_audit_chain(None).await.unwrap();
    assert!(global_verification.valid);
    assert_eq!(global_verification.checked_events, 2);
}

#[tokio::test]
async fn test_audit_retention_config_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");

    let global = AuditRetentionConfig {
        realm_id: None,
        retention_days: 365,
        legal_hold: false,
        updated_by: "admin@example.com".to_string(),
        reason: "ticket-200".to_string(),
        updated_at: 2_000,
    };
    repo.set_audit_retention_config(&global)
        .await
        .expect("set global retention failed");
    let stored_global = repo
        .get_audit_retention_config(None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_global.retention_days, 365);
    assert!(!stored_global.legal_hold);

    let realm = AuditRetentionConfig {
        realm_id: Some("realm-retention".to_string()),
        retention_days: 90,
        legal_hold: true,
        updated_by: "auditor@example.com".to_string(),
        reason: "legal-hold-1".to_string(),
        updated_at: 2_100,
    };
    repo.set_audit_retention_config(&realm)
        .await
        .expect("set realm retention failed");
    let stored_realm = repo
        .get_audit_retention_config(Some(&"realm-retention".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_realm.realm_id.as_deref(), Some("realm-retention"));
    assert_eq!(stored_realm.retention_days, 90);
    assert!(stored_realm.legal_hold);

    let updated = AuditRetentionConfig {
        retention_days: 120,
        legal_hold: false,
        reason: "legal-hold-release".to_string(),
        updated_at: 2_200,
        ..realm
    };
    repo.set_audit_retention_config(&updated)
        .await
        .expect("update realm retention failed");
    let stored_updated = repo
        .get_audit_retention_config(Some(&"realm-retention".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_updated.retention_days, 120);
    assert!(!stored_updated.legal_hold);
    assert_eq!(stored_updated.reason, "legal-hold-release");
}

#[tokio::test]
async fn test_audit_retention_plan_respects_cutoff_and_legal_hold() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-retention-plan".into(),
        "https://id.example.com/realms/retention-plan",
        None,
    )
    .await
    .unwrap();

    for (id, created_at) in [("old", 10_u64), ("new", 200_u64)] {
        repo.append_audit_event(&AuditEvent {
            id: id.to_string(),
            realm_id: Some("realm-retention-plan".to_string()),
            actor: "admin@example.com".to_string(),
            action: "audit.test".to_string(),
            target_type: "audit".to_string(),
            target_id: id.to_string(),
            reason: "test".to_string(),
            metadata_json: serde_json::json!({}),
            created_at,
            previous_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();
    }

    repo.set_audit_retention_config(&AuditRetentionConfig {
        realm_id: Some("realm-retention-plan".to_string()),
        retention_days: 0,
        legal_hold: false,
        updated_by: "admin@example.com".to_string(),
        reason: "retention-test".to_string(),
        updated_at: 300,
    })
    .await
    .unwrap();
    let plan = repo
        .plan_audit_retention(Some(&"realm-retention-plan".into()), 200)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(plan.cutoff_epoch, Some(200));
    assert_eq!(plan.expired_event_ids, vec!["old"]);
    assert_eq!(plan.retained_event_ids, vec!["new"]);

    repo.set_audit_retention_config(&AuditRetentionConfig {
        legal_hold: true,
        reason: "legal-hold".to_string(),
        updated_at: 301,
        ..repo
            .get_audit_retention_config(Some(&"realm-retention-plan".into()))
            .await
            .unwrap()
            .unwrap()
    })
    .await
    .unwrap();
    let held_plan = repo
        .plan_audit_retention(Some(&"realm-retention-plan".into()), 200)
        .await
        .unwrap()
        .unwrap();
    assert!(held_plan.legal_hold);
    assert_eq!(held_plan.cutoff_epoch, None);
    assert!(held_plan.expired_event_ids.is_empty());
    assert_eq!(held_plan.retained_event_ids, vec!["old", "new"]);
}

#[tokio::test]
async fn test_user_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-u".into(),
        "https://id.example.com/realms/u",
        None,
    )
    .await
    .unwrap();
    let user = User {
        id: "user-1".to_string(),
        realm_id: "realm-u".to_string(),
        email: Some("test@example.com".to_string()),
        email_verified: true,
        display_name: Some("Test User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.expect("create user failed");
    let fetched = repo
        .get_user_by_id("user-1")
        .await
        .unwrap()
        .expect("user not found");
    assert_eq!(fetched.email, Some("test@example.com".to_string()));
    assert!(fetched.email_verified);
    let by_email = repo
        .get_user_by_email(&"realm-u".into(), "test@example.com")
        .await
        .unwrap();
    assert!(by_email.is_some());
}

#[tokio::test]
async fn test_password_credential_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-p".into(),
        "https://id.example.com/realms/p",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-pwd".to_string(),
        realm_id: "realm-p".to_string(),
        email: Some("pwd@example.com".to_string()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let cred = PasswordCredential {
        user_id: "user-pwd".to_string(),
        hash: "$argon2id$v=19$m=19456,t=2,p=1$testhash".to_string(),
        algorithm: "argon2id".to_string(),
        pepper_ref: None,
    };
    repo.store_password_credential(&cred)
        .await
        .expect("store credential failed");
    let fetched = repo
        .get_password_credential("user-pwd")
        .await
        .unwrap()
        .expect("credential not found");
    assert_eq!(fetched.algorithm, "argon2id");

    let updated = PasswordCredential {
        user_id: "user-pwd".to_string(),
        hash: "$argon2id$v=19$m=19456,t=2,p=1$updatedhash".to_string(),
        algorithm: "argon2id".to_string(),
        pepper_ref: Some("kms://alias/qid-password-pepper".to_string()),
    };
    repo.store_password_credential(&updated)
        .await
        .expect("update credential failed");
    let fetched = repo
        .get_password_credential("user-pwd")
        .await
        .unwrap()
        .expect("updated credential not found");
    assert_eq!(fetched.hash, updated.hash);
    assert_eq!(fetched.pepper_ref, updated.pepper_ref);
}

async fn assert_ciam_repository_round_trip(
    repo: &(impl RealmRepository + UserRepository + CiamRepository),
) {
    repo.create_realm(
        &"tenant-ciam".into(),
        &"realm-ciam".into(),
        "https://ciam.example.com",
        Some("CIAM realm"),
    )
    .await
    .expect("create CIAM realm failed");
    repo.create_user(&User {
        id: "user-ciam".to_string(),
        realm_id: "realm-ciam".to_string(),
        email: Some("ciam@example.com".to_string()),
        email_verified: false,
        display_name: Some("CIAM User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .expect("create CIAM user failed");

    let consent = CiamConsentGrant {
        id: "consent-1".to_string(),
        realm_id: "realm-ciam".to_string(),
        user_id: "user-ciam".to_string(),
        client_id: "client-ciam".to_string(),
        granted_claims: vec!["email".to_string(), "profile".to_string()],
        terms_version: Some("2026-06".to_string()),
        granted_at_epoch_seconds: 1_800_000_000,
        revoked: false,
    };
    repo.store_ciam_consent_grant(&consent)
        .await
        .expect("store CIAM consent failed");
    let grants = repo
        .list_ciam_consent_grants(
            &RealmId::from("realm-ciam"),
            "user-ciam",
            Some("client-ciam"),
        )
        .await
        .expect("list CIAM consent failed");
    assert_eq!(grants, vec![consent.clone()]);
    repo.revoke_ciam_consent_grant("consent-1", 1_800_000_100)
        .await
        .expect("revoke CIAM consent failed");
    let grants = repo
        .list_ciam_consent_grants(
            &RealmId::from("realm-ciam"),
            "user-ciam",
            Some("client-ciam"),
        )
        .await
        .expect("list revoked CIAM consent failed");
    assert!(grants[0].revoked);

    let challenge = CiamVerificationChallengeRecord {
        id: "verify-1".to_string(),
        realm_id: "realm-ciam".to_string(),
        user_id: "user-ciam".to_string(),
        channel: "email".to_string(),
        address: "ciam@example.com".to_string(),
        purpose: "email_verification".to_string(),
        code_hash: "hash".to_string(),
        expires_at_epoch_seconds: 1_800_000_600,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_800_000_000,
    };
    repo.store_ciam_verification_challenge(&challenge)
        .await
        .expect("store CIAM verification failed");
    repo.consume_ciam_verification_challenge("verify-1", 1_800_000_050)
        .await
        .expect("consume CIAM verification failed");
    let consumed = repo
        .get_ciam_verification_challenge("verify-1")
        .await
        .expect("get CIAM verification failed")
        .expect("CIAM verification missing");
    assert_eq!(consumed.consumed_at_epoch_seconds, Some(1_800_000_050));

    let link = CiamIdentityLink {
        id: "link-1".to_string(),
        realm_id: "realm-ciam".to_string(),
        user_id: "user-ciam".to_string(),
        provider: "google".to_string(),
        external_subject: "google-subject-1".to_string(),
        external_email: Some("social@example.com".to_string()),
        profile_json: serde_json::json!({"name":"Social User"}),
        linked_at_epoch_seconds: 1_800_000_200,
        verified: true,
    };
    repo.store_ciam_identity_link(&link)
        .await
        .expect("store CIAM identity link failed");
    let links = repo
        .list_ciam_identity_links(&RealmId::from("realm-ciam"), "user-ciam")
        .await
        .expect("list CIAM identity links failed");
    assert_eq!(links, vec![link.clone()]);
    let external = repo
        .get_ciam_identity_link_by_external_subject(
            &RealmId::from("realm-ciam"),
            "google",
            "google-subject-1",
        )
        .await
        .expect("lookup CIAM identity link failed")
        .expect("CIAM identity link missing");
    assert_eq!(external.id, "link-1");
    let mut duplicate = link.clone();
    duplicate.id = "link-duplicate".to_string();
    assert!(repo.store_ciam_identity_link(&duplicate).await.is_err());
    let mut invalid = link.clone();
    invalid.id = "link-invalid".to_string();
    invalid.profile_json = serde_json::json!(["not", "object"]);
    assert!(repo.store_ciam_identity_link(&invalid).await.is_err());
    repo.delete_ciam_identity_link(&RealmId::from("realm-ciam"), "link-1")
        .await
        .expect("delete CIAM identity link failed");
    assert!(
        repo.get_ciam_identity_link(&RealmId::from("realm-ciam"), "link-1")
            .await
            .expect("get deleted CIAM identity link failed")
            .is_none()
    );

    let reset = PasswordResetToken {
        id: "reset-1".to_string(),
        realm_id: "realm-ciam".to_string(),
        user_id: "user-ciam".to_string(),
        token_hash: "reset-hash".to_string(),
        device_id: Some("device-1".to_string()),
        risk_json: serde_json::json!({"score": 20}),
        expires_at_epoch_seconds: 1_800_000_900,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_800_000_000,
    };
    repo.store_password_reset_token(&reset)
        .await
        .expect("store password reset token failed");
    repo.consume_password_reset_token("reset-1", 1_800_000_100)
        .await
        .expect("consume password reset token failed");
    let reset = repo
        .get_password_reset_token("reset-1")
        .await
        .expect("get password reset token failed")
        .expect("password reset token missing");
    assert_eq!(reset.consumed_at_epoch_seconds, Some(1_800_000_100));
}

#[tokio::test]
async fn test_sql_ciam_repository_round_trip() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");

    assert_ciam_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_ciam_repository_round_trip() {
    let n = DB_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("test_ciam_{n}.json"));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repo failed");
    repo.migrate().await.expect("file migration failed");

    assert_ciam_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_sql_workload_certificate_round_trip() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");

    assert_workload_certificate_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_workload_certificate_round_trip() {
    let path = std::env::temp_dir().join(format!(
        "qid-file-workload-{}.json",
        DB_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    assert_workload_certificate_round_trip(&repo).await;
}

#[tokio::test]
async fn test_vc_credential_status_crud_and_revocation() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    let status = vc_status_record("credential-sql");

    repo.store_vc_credential_status(&status)
        .await
        .expect("store VC credential status failed");
    let fetched = repo
        .get_vc_credential_status("credential-sql")
        .await
        .unwrap()
        .expect("VC credential status not found");
    assert_eq!(fetched.subject, "user-vc");
    assert!(!fetched.revoked);

    repo.revoke_vc_credential("credential-sql", "account_closed", 1_500)
        .await
        .expect("revoke VC credential failed");
    let revoked = repo
        .get_vc_credential_status("credential-sql")
        .await
        .unwrap()
        .expect("revoked VC credential status not found");
    assert!(revoked.revoked);
    assert_eq!(revoked.revocation_reason.as_deref(), Some("account_closed"));
    assert_eq!(revoked.revoked_at, Some(1_500));
}

#[tokio::test]
async fn test_file_vc_credential_status_round_trip() {
    let path = std::env::temp_dir().join(format!(
        "qid-file-vc-{}.json",
        DB_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");
    let status = vc_status_record("credential-file");

    repo.store_vc_credential_status(&status)
        .await
        .expect("store file VC credential status failed");
    repo.revoke_vc_credential("credential-file", "user_request", 1_600)
        .await
        .expect("revoke file VC credential failed");
    let revoked = repo
        .get_vc_credential_status("credential-file")
        .await
        .unwrap()
        .expect("file VC credential status not found");

    assert!(revoked.revoked);
    assert_eq!(revoked.revocation_reason.as_deref(), Some("user_request"));
    assert_eq!(revoked.revoked_at, Some(1_600));
}

#[tokio::test]
async fn test_session_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-s".into(),
        "https://id.example.com/realms/s",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-sess".to_string(),
        realm_id: "realm-s".to_string(),
        email: Some("sess@example.com".to_string()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let session = Session {
        id: "sess-1".to_string(),
        realm_id: "realm-s".to_string(),
        user_id: "user-sess".to_string(),
        auth_time: 1000,
        acr: Some("urn:qid:acr:password".to_string()),
        amr: vec!["pwd".to_string()],
        idle_expires_at: 2000,
        absolute_expires_at: 10000,
        revoked: false,
        created_at: 1000,
        cnf: None,
    };
    repo.create_session(&session)
        .await
        .expect("create session failed");
    let fetched = repo
        .get_session("sess-1")
        .await
        .unwrap()
        .expect("session not found");
    assert_eq!(fetched.user_id, "user-sess");
    repo.revoke_session("sess-1").await.unwrap();
    let after_revoke = repo.get_session("sess-1").await.unwrap().unwrap();
    assert!(after_revoke.revoked);
}

#[tokio::test]
async fn test_authorization_code_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-ac".into(),
        "https://id.example.com/realms/ac",
        None,
    )
    .await
    .unwrap();
    let code = AuthorizationCode {
        code_hash: "abc123".to_string(),
        client_id: "client-1".to_string(),
        user_id: "user-1".to_string(),
        realm_id: "realm-ac".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: Some("state-1".to_string()),
        nonce: Some("nonce-1".to_string()),
        auth_time: Some(900),
        acr: Some("urn:qid:acr:password".to_string()),
        amr: vec!["pwd".to_string()],
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        resource: vec!["https://api.example.com".to_string()],
        authorization_details: Some(serde_json::json!([{"type":"payment"}])),
        expires_at: 2000,
        used: false,
        created_at: 1000,
    };
    repo.create_authorization_code(&code)
        .await
        .expect("create auth code failed");
    let fetched = repo
        .get_authorization_code("abc123")
        .await
        .unwrap()
        .expect("code not found");
    assert_eq!(fetched.scopes, vec!["openid", "profile"]);
    assert_eq!(fetched.state.as_deref(), Some("state-1"));
    assert_eq!(fetched.nonce.as_deref(), Some("nonce-1"));
    assert_eq!(fetched.auth_time, Some(900));
    assert_eq!(fetched.acr.as_deref(), Some("urn:qid:acr:password"));
    assert_eq!(fetched.amr, vec!["pwd"]);
    assert_eq!(fetched.resource, vec!["https://api.example.com"]);
    assert_eq!(
        fetched.authorization_details,
        Some(serde_json::json!([{"type":"payment"}]))
    );
    repo.mark_authorization_code_used("abc123").await.unwrap();
    let used = repo
        .get_authorization_code("abc123")
        .await
        .unwrap()
        .unwrap();
    assert!(used.used);
}

#[tokio::test]
async fn test_client_crud_preserves_token_endpoint_auth_method() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-client".into(),
        "https://id.example.com/realms/client",
        None,
    )
    .await
    .unwrap();

    let client = Client {
        id: "client-1".to_string(),
        realm_id: "realm-client".to_string(),
        client_id: "confidential-app".to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "tls_client_auth".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: vec![
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
        ],
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
    };

    repo.create_client(&client)
        .await
        .expect("create client failed");

    let fetched = repo
        .get_client_by_client_id(&"realm-client".into(), "confidential-app")
        .await
        .unwrap()
        .expect("client not found");
    assert_eq!(fetched.token_endpoint_auth_method, "tls_client_auth");
    assert_eq!(fetched.client_secret_hash, None);
    assert_eq!(
        fetched.mtls_certificate_thumbprints,
        vec!["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"]
    );
    assert_eq!(
        fetched.redirect_uris,
        vec!["https://app.example.com/callback"]
    );
    assert_eq!(fetched.grant_types, vec!["authorization_code"]);
}

#[tokio::test]
async fn test_device_authorization_grant_polling_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-device".into(),
        "https://id.example.com/realms/device",
        None,
    )
    .await
    .unwrap();

    let grant = DeviceAuthorizationGrant {
        device_code_hash: "device-code-hash".to_string(),
        user_code: "QID-DEVICE".to_string(),
        client_id: "device-client".to_string(),
        realm_id: "realm-device".to_string(),
        scopes: vec!["api".to_string()],
        user_id: None,
        expires_at: 2000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 1000,
    };
    repo.store_device_authorization_grant(&grant)
        .await
        .expect("store device grant failed");

    repo.record_device_authorization_poll("device-code-hash", 1100, 10)
        .await
        .expect("record device poll failed");
    let polled = repo
        .get_device_authorization_grant("device-code-hash")
        .await
        .unwrap()
        .expect("device grant not found");
    assert_eq!(polled.last_poll_at, Some(1100));
    assert_eq!(polled.poll_interval_seconds, 10);

    repo.approve_device_authorization_grant("QID-DEVICE", "user-device", 1200)
        .await
        .unwrap();
    let approved = repo
        .get_device_authorization_grant("device-code-hash")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approved.user_id.as_deref(), Some("user-device"));
    assert_eq!(approved.approved_at, Some(1200));

    repo.consume_device_authorization_grant("device-code-hash")
        .await
        .unwrap();
    let consumed = repo
        .get_device_authorization_grant("device-code-hash")
        .await
        .unwrap()
        .unwrap();
    assert!(consumed.consumed);
}

#[tokio::test]
async fn test_backchannel_authentication_grant_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-ciba".into(),
        "https://id.example.com/realms/ciba",
        None,
    )
    .await
    .unwrap();

    let grant = BackchannelAuthenticationGrant {
        auth_req_id_hash: "auth-req-hash".to_string(),
        client_id: "ciba-client".to_string(),
        realm_id: "realm-ciba".to_string(),
        login_hint: "user@example.com".to_string(),
        binding_message: Some("login-123".to_string()),
        scopes: vec!["openid".to_string()],
        user_id: None,
        expires_at: 2000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 1000,
    };
    repo.store_backchannel_authentication_grant(&grant)
        .await
        .expect("store CIBA grant failed");

    let fetched = repo
        .get_backchannel_authentication_grant("auth-req-hash")
        .await
        .unwrap()
        .expect("CIBA grant not found");
    assert_eq!(fetched.login_hint, "user@example.com");
    assert_eq!(fetched.binding_message.as_deref(), Some("login-123"));
    assert_eq!(fetched.scopes, vec!["openid"]);
    assert!(fetched.approved_at.is_none());
    assert_eq!(fetched.poll_interval_seconds, 5);

    repo.record_backchannel_authentication_poll("auth-req-hash", 1100, 10)
        .await
        .expect("record CIBA poll failed");
    let polled = repo
        .get_backchannel_authentication_grant("auth-req-hash")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(polled.last_poll_at, Some(1100));
    assert_eq!(polled.poll_interval_seconds, 10);

    repo.approve_backchannel_authentication_grant("auth-req-hash", "user-ciba", 1500)
        .await
        .unwrap();
    let approved = repo
        .get_backchannel_authentication_grant("auth-req-hash")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approved.user_id.as_deref(), Some("user-ciba"));
    assert_eq!(approved.approved_at, Some(1500));

    repo.consume_backchannel_authentication_grant("auth-req-hash")
        .await
        .unwrap();
    let consumed = repo
        .get_backchannel_authentication_grant("auth-req-hash")
        .await
        .unwrap()
        .unwrap();
    assert!(consumed.consumed);
}

#[tokio::test]
async fn test_token_family_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-tf".into(),
        "https://id.example.com/realms/tf",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-tf".to_string(),
        realm_id: "realm-tf".to_string(),
        email: Some("tf@example.com".to_string()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let family = qid_core::models::TokenFamily {
        id: "tf-1".to_string(),
        user_id: "user-tf".to_string(),
        client_id: "client-1".to_string(),
        realm_id: "realm-tf".to_string(),
        current_refresh_hash: "hash1".to_string(),
        audience: vec!["api://orders".to_string()],
        resource: vec!["https://api.example.com/orders".to_string()],
        authorization_details: Some(serde_json::json!([
            {"type":"payment_initiation","actions":["read"]}
        ])),
        sender_constraint: Some(serde_json::json!({"jkt":"refresh-thumbprint"})),
        issued_at: 1000,
        revoked: false,
    };
    repo.create_token_family(&family)
        .await
        .expect("create token family failed");
    let fetched = repo
        .get_token_family("tf-1")
        .await
        .unwrap()
        .expect("family not found");
    assert_eq!(fetched.current_refresh_hash, "hash1");
    assert_eq!(fetched.audience, vec!["api://orders"]);
    assert_eq!(fetched.resource, vec!["https://api.example.com/orders"]);
    assert_eq!(
        fetched.authorization_details,
        Some(serde_json::json!([
            {"type":"payment_initiation","actions":["read"]}
        ]))
    );
    assert_eq!(
        fetched.sender_constraint,
        Some(serde_json::json!({"jkt":"refresh-thumbprint"}))
    );
    repo.update_token_family_refresh_hash("tf-1", "hash2")
        .await
        .unwrap();
    let updated = repo.get_token_family("tf-1").await.unwrap().unwrap();
    assert_eq!(updated.current_refresh_hash, "hash2");
    repo.revoke_token_family("tf-1").await.unwrap();
    let revoked = repo.get_token_family("tf-1").await.unwrap().unwrap();
    assert!(revoked.revoked);
}

#[tokio::test]
async fn test_access_token_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-at".into(),
        "https://id.example.com/realms/at",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-at".to_string(),
        realm_id: "realm-at".to_string(),
        email: Some("at@example.com".to_string()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let token = AccessToken {
        jti: "jti-1".to_string(),
        family_id: None,
        user_id: "user-at".to_string(),
        client_id: "client-1".to_string(),
        realm_id: "realm-at".to_string(),
        scopes: vec!["api".to_string()],
        audience: vec!["client-1".to_string()],
        resource: vec!["https://api.example.com".to_string()],
        authorization_details: Some(serde_json::json!([{"type":"account_information"}])),
        cnf: Some(serde_json::json!({"jkt":"thumbprint"})),
        auth_time: Some(900),
        acr: Some("urn:qid:acr:phishing-resistant".to_string()),
        amr: vec!["webauthn".to_string()],
        nonce: Some("nonce-1".to_string()),
        sender_constraint: Some(serde_json::json!({"jkt":"thumbprint"})),
        token_format: qid_core::models::TokenFormat::Jwt,
        expires_at: 2000,
        revoked: false,
        issued_at: 1000,
    };
    repo.create_access_token(&token)
        .await
        .expect("create access token failed");
    let fetched = repo
        .get_access_token("jti-1")
        .await
        .unwrap()
        .expect("token not found");
    assert_eq!(fetched.scopes, vec!["api"]);
    assert_eq!(fetched.audience, vec!["client-1"]);
    assert_eq!(fetched.resource, vec!["https://api.example.com"]);
    assert_eq!(
        fetched.authorization_details,
        Some(serde_json::json!([{"type":"account_information"}]))
    );
    assert_eq!(fetched.cnf, Some(serde_json::json!({"jkt":"thumbprint"})));
    assert_eq!(fetched.auth_time, Some(900));
    assert_eq!(
        fetched.acr.as_deref(),
        Some("urn:qid:acr:phishing-resistant")
    );
    assert_eq!(fetched.amr, vec!["webauthn"]);
    assert_eq!(fetched.nonce.as_deref(), Some("nonce-1"));
    assert_eq!(
        fetched.sender_constraint,
        Some(serde_json::json!({"jkt":"thumbprint"}))
    );
    assert_eq!(fetched.token_format, qid_core::models::TokenFormat::Jwt);
    repo.revoke_access_token("jti-1").await.unwrap();
    let revoked = repo.get_access_token("jti-1").await.unwrap().unwrap();
    assert!(revoked.revoked);
}

#[tokio::test]
async fn test_policy_bundle_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-pb".into(),
        "https://id.example.com/realms/pb",
        None,
    )
    .await
    .unwrap();
    let bundle = PolicyBundle {
        id: "bundle-1".to_string(),
        realm_id: "realm-pb".to_string(),
        name: "default".to_string(),
        source_hash: "hash".to_string(),
        compiled_json: serde_json::json!({"version": "1", "rules": []}),
        version: 1,
        active: true,
    };
    repo.create_policy_bundle(&bundle)
        .await
        .expect("create policy bundle failed");
    let fetched = repo
        .get_active_policy_bundle(&"realm-pb".into())
        .await
        .unwrap()
        .expect("bundle not found");
    assert_eq!(fetched.name, "default");
    assert!(fetched.active);
}

#[tokio::test]
async fn test_scim_user_enterprise_extension_crud() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-scim".into(),
        "https://id.example.com/realms/scim",
        None,
    )
    .await
    .unwrap();
    let user = ScimUser {
        id: "scim-user-1".to_string(),
        realm_id: "realm-scim".to_string(),
        external_id: Some("hr-42".to_string()),
        user_name: "scim@example.com".to_string(),
        name_json: serde_json::json!({"givenName":"Scim"}),
        emails_json: serde_json::json!([{"value":"scim@example.com"}]),
        enterprise_json: serde_json::json!({
            "department": "Engineering",
            "employeeNumber": "E42"
        }),
        active: true,
    };
    repo.create_scim_user(&user)
        .await
        .expect("create scim user failed");
    let fetched = repo
        .get_scim_user("scim-user-1")
        .await
        .unwrap()
        .expect("scim user not found");
    assert_eq!(fetched.external_id, Some("hr-42".to_string()));
    assert_eq!(fetched.enterprise_json["department"], "Engineering");

    let mut updated = fetched;
    updated.enterprise_json = serde_json::json!({"department":"Platform"});
    repo.update_scim_user(&updated)
        .await
        .expect("update scim user failed");
    let fetched = repo.get_scim_user("scim-user-1").await.unwrap().unwrap();
    assert_eq!(fetched.enterprise_json["department"], "Platform");
}

#[tokio::test]
async fn sql_scim_pages_and_counts_are_stable() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    let realm_id = RealmId::from("realm-scim-page");
    repo.create_realm(
        &TenantId::from("tenant-1"),
        &realm_id,
        "https://id.example.com/realms/scim-page",
        None,
    )
    .await
    .unwrap();

    for id in ["scim-user-c", "scim-user-a", "scim-user-b"] {
        repo.create_scim_user(&ScimUser {
            id: id.to_string(),
            realm_id: realm_id.0.clone(),
            external_id: None,
            user_name: format!("{id}@example.com"),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            active: true,
        })
        .await
        .unwrap();
    }
    for id in ["scim-group-c", "scim-group-a", "scim-group-b"] {
        repo.create_scim_group(&ScimGroup {
            id: id.to_string(),
            realm_id: realm_id.0.clone(),
            display_name: id.to_string(),
            members_json: serde_json::json!([]),
        })
        .await
        .unwrap();
    }

    let users = repo.list_scim_users_page(&realm_id, 1, 1).await.unwrap();
    let groups = repo.list_scim_groups_page(&realm_id, 1, 1).await.unwrap();

    assert_eq!(repo.count_scim_users(&realm_id).await.unwrap(), 3);
    assert_eq!(repo.count_scim_groups(&realm_id).await.unwrap(), 3);
    assert_eq!(users[0].id, "scim-user-b");
    assert_eq!(groups[0].id, "scim-group-b");
}

fn sample_custom_domain() -> CustomDomain {
    CustomDomain {
        id: "domain-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        realm_id: "realm-saas".to_string(),
        hostname: "login.customer.example.com".to_string(),
        certificate_ref: "kms://certificates/customer-login".to_string(),
        verified: true,
        verification_status: "active".to_string(),
        dns_challenge_name: Some("_qid.login.customer.example.com".to_string()),
        dns_challenge_value: Some("qid-domain-proof".to_string()),
        certificate_expires_at: Some(1_900_000_000),
        certificate_renew_after: Some(1_880_000_000),
        last_verified_at: Some(1_800_000_000),
    }
}

fn sample_ciam_brand() -> CiamBrand {
    CiamBrand {
        id: "brand-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        realm_id: "realm-saas".to_string(),
        display_name: "Customer Blue".to_string(),
        primary_color: "#2f6fed".to_string(),
        logo_uri: Some("https://cdn.example.com/logo.svg".to_string()),
        privacy_policy_uri: Some("https://www.example.com/privacy".to_string()),
        support_uri: Some("https://support.example.com".to_string()),
        terms_version: Some("2026-06".to_string()),
        active: true,
    }
}

fn sample_app_catalog_entry() -> AppCatalogEntry {
    AppCatalogEntry {
        id: "app-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        realm_id: "realm-saas".to_string(),
        display_name: "Customer CRM".to_string(),
        category: "sales".to_string(),
        oidc_client_id: Some("crm-client".to_string()),
        saml_entity_id: None,
        scim_enabled: true,
        marketplace_connector_id: Some("connector-1".to_string()),
    }
}

fn sample_marketplace_connector() -> MarketplaceConnector {
    MarketplaceConnector {
        id: "connector-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        provider: "example-crm".to_string(),
        connector_type: MarketplaceConnectorType::Scim,
        config_json: serde_json::json!({
            "base_url": "https://crm.example.com/scim/v2",
            "token_ref": "kms://secrets/crm-scim-token"
        }),
        enabled: true,
    }
}

fn sample_saml_marketplace_connector(id: &str, entity_id: &str) -> MarketplaceConnector {
    MarketplaceConnector {
        id: id.to_string(),
        tenant_id: "tenant-saas".to_string(),
        provider: "example-saml".to_string(),
        connector_type: MarketplaceConnectorType::Saml,
        config_json: serde_json::json!({
            "entity_id": entity_id,
            "metadata_url": "https://sp.example.com/metadata.xml"
        }),
        enabled: true,
    }
}

fn sample_usage_billing_event(id: &str, occurred_at: u64) -> UsageBillingEvent {
    UsageBillingEvent {
        id: id.to_string(),
        tenant_id: "tenant-saas".to_string(),
        meter: "active_users".to_string(),
        quantity: 42,
        occurred_at,
        idempotency_key: format!("tenant-saas:{id}"),
        dimensions: BTreeMap::from([("realm".to_string(), "realm-saas".to_string())]),
    }
}

fn sample_compliance_evidence_pack() -> ComplianceEvidencePack {
    ComplianceEvidencePack {
        id: "evidence-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        period_start: 1_700_000_000,
        period_end: 1_702_592_000,
        controls: vec!["SOC2-CC6.1".to_string(), "ISO27001-A.5.15".to_string()],
        object_uri: "s3://qid-evidence/tenant-saas/2026-01.jsonl".to_string(),
        sha256_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        generated_at: 1_702_592_100,
    }
}

fn sample_delegated_tenant_admin() -> DelegatedTenantAdmin {
    DelegatedTenantAdmin {
        id: "delegated-admin-1".to_string(),
        tenant_id: "tenant-saas".to_string(),
        subject: "admin@example.com".to_string(),
        roles: vec!["app.admin".to_string(), "auditor".to_string()],
        allowed_realm_ids: vec!["realm-saas".to_string()],
        granted_by: "owner@example.com".to_string(),
        granted_at: 1_800_000_000,
        expires_at: Some(1_860_000_000),
        revoked: false,
    }
}

fn sample_saas_client() -> Client {
    Client {
        id: "client-saas".to_string(),
        realm_id: "realm-saas".to_string(),
        client_id: "crm-client".to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        client_secret_hash: Some("hash".to_string()),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: serde_json::json!({ "keys": [] }),
        redirect_uris: vec!["https://crm.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
    }
}

async fn assert_saas_repository_round_trip(
    repo: &(impl SaasRepository + RealmRepository + ClientRepository),
) {
    repo.create_realm(
        &TenantId::from("tenant-saas"),
        &RealmId::from("realm-saas"),
        "https://login.customer.example.com",
        Some("SaaS tenant realm"),
    )
    .await
    .expect("create SaaS realm failed");
    repo.create_realm(
        &TenantId::from("tenant-other"),
        &RealmId::from("realm-other"),
        "https://other.customer.example.com",
        Some("Other tenant realm"),
    )
    .await
    .expect("create other tenant realm failed");
    repo.create_client(&sample_saas_client())
        .await
        .expect("create SaaS client failed");

    let domain = sample_custom_domain();
    repo.store_custom_domain(&domain)
        .await
        .expect("store custom domain failed");
    let domains = repo
        .list_custom_domains("tenant-saas")
        .await
        .expect("list custom domains failed");
    assert_eq!(domains, vec![domain.clone()]);
    repo.delete_custom_domain("tenant-other", "domain-1")
        .await
        .expect("cross-tenant custom domain delete failed");
    assert_eq!(
        repo.list_custom_domains("tenant-saas")
            .await
            .expect("list custom domains after cross-tenant delete failed"),
        vec![domain.clone()]
    );

    let mut invalid_domain = domain.clone();
    invalid_domain.id = "domain-invalid".to_string();
    invalid_domain.hostname = "not a valid host".to_string();
    assert!(repo.store_custom_domain(&invalid_domain).await.is_err());
    let mut missing_realm_domain = domain.clone();
    missing_realm_domain.id = "domain-missing-realm".to_string();
    missing_realm_domain.realm_id = "realm-missing".to_string();
    missing_realm_domain.hostname = "missing-realm.customer.example.com".to_string();
    assert!(
        repo.store_custom_domain(&missing_realm_domain)
            .await
            .is_err()
    );
    let mut cross_tenant_realm_domain = domain.clone();
    cross_tenant_realm_domain.id = "domain-cross-tenant-realm".to_string();
    cross_tenant_realm_domain.realm_id = "realm-other".to_string();
    cross_tenant_realm_domain.hostname = "cross-realm.customer.example.com".to_string();
    assert!(
        repo.store_custom_domain(&cross_tenant_realm_domain)
            .await
            .is_err()
    );
    let mut duplicate_hostname = domain.clone();
    duplicate_hostname.id = "domain-duplicate-hostname".to_string();
    duplicate_hostname.tenant_id = "tenant-other".to_string();
    duplicate_hostname.realm_id = "realm-other".to_string();
    assert!(repo.store_custom_domain(&duplicate_hostname).await.is_err());

    let brand = sample_ciam_brand();
    repo.store_ciam_brand(&brand)
        .await
        .expect("store CIAM brand failed");
    let brands = repo
        .list_ciam_brands("tenant-saas")
        .await
        .expect("list CIAM brands failed");
    assert_eq!(brands, vec![brand.clone()]);
    repo.delete_ciam_brand("tenant-other", "brand-1")
        .await
        .expect("cross-tenant CIAM brand delete failed");
    assert_eq!(
        repo.list_ciam_brands("tenant-saas")
            .await
            .expect("list CIAM brands after cross-tenant delete failed"),
        vec![brand.clone()]
    );
    let mut invalid_brand = brand.clone();
    invalid_brand.id = "brand-invalid".to_string();
    invalid_brand.primary_color = "blue".to_string();
    assert!(repo.store_ciam_brand(&invalid_brand).await.is_err());
    let mut cross_tenant_brand = brand.clone();
    cross_tenant_brand.id = "brand-cross-tenant".to_string();
    cross_tenant_brand.tenant_id = "tenant-other".to_string();
    assert!(repo.store_ciam_brand(&cross_tenant_brand).await.is_err());

    let connector = sample_marketplace_connector();
    repo.store_marketplace_connector(&connector)
        .await
        .expect("store marketplace connector failed");
    let connectors = repo
        .list_marketplace_connectors("tenant-saas")
        .await
        .expect("list marketplace connectors failed");
    assert_eq!(connectors, vec![connector.clone()]);
    repo.delete_marketplace_connector("tenant-other", "connector-1")
        .await
        .expect("cross-tenant marketplace connector delete failed");
    assert_eq!(
        repo.list_marketplace_connectors("tenant-saas")
            .await
            .expect("list marketplace connectors after cross-tenant delete failed"),
        vec![connector]
    );

    let mut scim_without_connector = sample_app_catalog_entry();
    scim_without_connector.id = "app-scim-without-connector".to_string();
    scim_without_connector.marketplace_connector_id = None;
    assert!(
        repo.store_app_catalog_entry(&scim_without_connector)
            .await
            .is_err()
    );

    let mut missing_realm_entry = sample_app_catalog_entry();
    missing_realm_entry.id = "app-missing-realm".to_string();
    missing_realm_entry.realm_id = "realm-missing".to_string();
    assert!(
        repo.store_app_catalog_entry(&missing_realm_entry)
            .await
            .is_err()
    );

    let mut cross_tenant_realm_entry = sample_app_catalog_entry();
    cross_tenant_realm_entry.id = "app-cross-tenant-realm".to_string();
    cross_tenant_realm_entry.realm_id = "realm-other".to_string();
    assert!(
        repo.store_app_catalog_entry(&cross_tenant_realm_entry)
            .await
            .is_err()
    );

    let mut missing_oidc_client_entry = sample_app_catalog_entry();
    missing_oidc_client_entry.id = "app-missing-oidc-client".to_string();
    missing_oidc_client_entry.oidc_client_id = Some("client-missing".to_string());
    assert!(
        repo.store_app_catalog_entry(&missing_oidc_client_entry)
            .await
            .is_err()
    );

    let mut missing_connector_entry = sample_app_catalog_entry();
    missing_connector_entry.id = "app-missing-connector".to_string();
    missing_connector_entry.marketplace_connector_id = Some("connector-missing".to_string());
    assert!(
        repo.store_app_catalog_entry(&missing_connector_entry)
            .await
            .is_err()
    );

    let mut other_connector = sample_marketplace_connector();
    other_connector.id = "connector-other".to_string();
    other_connector.tenant_id = "tenant-other".to_string();
    repo.store_marketplace_connector(&other_connector)
        .await
        .expect("store other tenant marketplace connector failed");
    let mut cross_tenant_entry = sample_app_catalog_entry();
    cross_tenant_entry.id = "app-cross-tenant-connector".to_string();
    cross_tenant_entry.marketplace_connector_id = Some("connector-other".to_string());
    assert!(
        repo.store_app_catalog_entry(&cross_tenant_entry)
            .await
            .is_err()
    );

    let mut saml_with_scim_connector = sample_app_catalog_entry();
    saml_with_scim_connector.id = "app-saml-scim-connector".to_string();
    saml_with_scim_connector.oidc_client_id = None;
    saml_with_scim_connector.saml_entity_id = Some("https://sp.example.com/metadata".to_string());
    saml_with_scim_connector.scim_enabled = false;
    saml_with_scim_connector.marketplace_connector_id = Some("connector-1".to_string());
    assert!(
        repo.store_app_catalog_entry(&saml_with_scim_connector)
            .await
            .is_err()
    );

    let mismatched_saml_connector = sample_saml_marketplace_connector(
        "connector-saml-mismatch",
        "https://other-sp.example.com/metadata",
    );
    repo.store_marketplace_connector(&mismatched_saml_connector)
        .await
        .expect("store mismatched SAML marketplace connector failed");
    let mut saml_mismatch_entry = saml_with_scim_connector.clone();
    saml_mismatch_entry.id = "app-saml-mismatch".to_string();
    saml_mismatch_entry.marketplace_connector_id = Some("connector-saml-mismatch".to_string());
    assert!(
        repo.store_app_catalog_entry(&saml_mismatch_entry)
            .await
            .is_err()
    );
    repo.delete_marketplace_connector("tenant-saas", "connector-saml-mismatch")
        .await
        .expect("delete mismatched SAML connector failed");

    let saml_connector =
        sample_saml_marketplace_connector("connector-saml", "https://sp.example.com/metadata");
    repo.store_marketplace_connector(&saml_connector)
        .await
        .expect("store SAML marketplace connector failed");
    let mut saml_entry = saml_with_scim_connector;
    saml_entry.id = "app-saml".to_string();
    saml_entry.marketplace_connector_id = Some("connector-saml".to_string());
    repo.store_app_catalog_entry(&saml_entry)
        .await
        .expect("store SAML app catalog entry failed");
    repo.delete_app_catalog_entry("tenant-saas", "app-saml")
        .await
        .expect("delete SAML app catalog entry failed");
    repo.delete_marketplace_connector("tenant-saas", "connector-saml")
        .await
        .expect("delete SAML connector failed");

    let entry = sample_app_catalog_entry();
    repo.store_app_catalog_entry(&entry)
        .await
        .expect("store app catalog entry failed");
    let entries = repo
        .list_app_catalog_entries("tenant-saas")
        .await
        .expect("list app catalog entries failed");
    assert_eq!(entries, vec![entry.clone()]);
    repo.delete_app_catalog_entry("tenant-other", "app-1")
        .await
        .expect("cross-tenant app catalog delete failed");
    assert_eq!(
        repo.list_app_catalog_entries("tenant-saas")
            .await
            .expect("list app catalog entries after cross-tenant delete failed"),
        vec![entry.clone()]
    );
    assert!(
        repo.delete_marketplace_connector("tenant-saas", "connector-1")
            .await
            .is_err()
    );
    repo.delete_app_catalog_entry("tenant-saas", "app-1")
        .await
        .expect("delete app catalog entry failed");
    assert!(
        repo.list_app_catalog_entries("tenant-saas")
            .await
            .expect("list app catalog entries after delete failed")
            .is_empty()
    );
    repo.delete_marketplace_connector("tenant-saas", "connector-1")
        .await
        .expect("delete unreferenced marketplace connector failed");
    assert!(
        repo.list_marketplace_connectors("tenant-saas")
            .await
            .expect("list marketplace connectors after delete failed")
            .is_empty()
    );

    repo.store_usage_billing_event(&sample_usage_billing_event("usage-older", 100))
        .await
        .expect("store older usage billing event failed");
    repo.store_usage_billing_event(&sample_usage_billing_event("usage-newer", 200))
        .await
        .expect("store newer usage billing event failed");
    let mut duplicate_usage = sample_usage_billing_event("usage-duplicate", 300);
    duplicate_usage.idempotency_key = "tenant-saas:usage-newer".to_string();
    assert!(
        repo.store_usage_billing_event(&duplicate_usage)
            .await
            .is_err()
    );
    let events = repo
        .list_usage_billing_events("tenant-saas", 1)
        .await
        .expect("list usage billing events failed");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "usage-newer");
    assert_eq!(events[0].dimensions["realm"], "realm-saas");

    let pack = sample_compliance_evidence_pack();
    repo.store_compliance_evidence_pack(&pack)
        .await
        .expect("store compliance evidence pack failed");
    let packs = repo
        .list_compliance_evidence_packs("tenant-saas")
        .await
        .expect("list compliance evidence packs failed");
    assert_eq!(packs, vec![pack]);

    let delegated_admin = sample_delegated_tenant_admin();
    repo.store_delegated_tenant_admin(&delegated_admin)
        .await
        .expect("store delegated tenant admin failed");
    let admins = repo
        .list_delegated_tenant_admins("tenant-saas")
        .await
        .expect("list delegated tenant admins failed");
    assert_eq!(admins, vec![delegated_admin.clone()]);
    let mut invalid_role = delegated_admin.clone();
    invalid_role.id = "delegated-admin-invalid-role".to_string();
    invalid_role.roles = vec!["security.admin".to_string()];
    assert!(
        repo.store_delegated_tenant_admin(&invalid_role)
            .await
            .is_err()
    );
    let mut cross_tenant_realm = delegated_admin.clone();
    cross_tenant_realm.id = "delegated-admin-cross-tenant".to_string();
    cross_tenant_realm.allowed_realm_ids = vec!["realm-other".to_string()];
    assert!(
        repo.store_delegated_tenant_admin(&cross_tenant_realm)
            .await
            .is_err()
    );
    repo.revoke_delegated_tenant_admin("tenant-other", "delegated-admin-1")
        .await
        .expect_err("cross-tenant delegated admin revoke should fail");
    repo.revoke_delegated_tenant_admin("tenant-saas", "delegated-admin-1")
        .await
        .expect("revoke delegated tenant admin failed");
    let admins = repo
        .list_delegated_tenant_admins("tenant-saas")
        .await
        .expect("list revoked delegated tenant admins failed");
    assert!(admins[0].revoked);

    repo.delete_custom_domain("tenant-saas", "domain-1")
        .await
        .expect("delete custom domain failed");
    assert!(
        repo.list_custom_domains("tenant-saas")
            .await
            .expect("list custom domains after delete failed")
            .is_empty()
    );
}

fn sample_iga_access_request(id: &str, created_at: u64) -> IgaAccessRequestRecord {
    IgaAccessRequestRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        subject: "user-1".to_string(),
        entitlement: "crm:admin".to_string(),
        reason: Some("Need emergency access".to_string()),
        status: "pending".to_string(),
        approval_steps_json: serde_json::json!([
            {"approver":"manager-1","decision":"approved"},
            {"approver":"security-1","decision":"pending"}
        ]),
        violations_json: serde_json::json!([]),
        expires_at_epoch_seconds: Some(created_at + 86_400),
        created_at_epoch_seconds: created_at,
    }
}

fn sample_iga_entitlement(id: &str, risk_level: &str) -> IgaEntitlementRecord {
    IgaEntitlementRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        display_name: format!("{id} entitlement"),
        owner: "owner-1".to_string(),
        risk_level: risk_level.to_string(),
        conflicting_entitlements: vec!["crm:audit".to_string()],
        max_duration_seconds: Some(3600),
        active: true,
    }
}

fn sample_iga_access_package(id: &str) -> IgaAccessPackageRecord {
    IgaAccessPackageRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        display_name: format!("{id} package"),
        owner: "owner-1".to_string(),
        entitlement_ids: vec!["crm:admin".to_string(), "crm:reporting".to_string()],
        approval_policy_json: serde_json::json!({
            "steps": [
                {"approver": "manager"},
                {"approver": "app_owner"}
            ]
        }),
        max_duration_seconds: Some(7200),
        active: true,
    }
}

fn sample_iga_approval(id: &str, decision: &str, approved_at: u64) -> IgaApprovalRecord {
    IgaApprovalRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        request_id: "req-1".to_string(),
        approver: format!("{id}-approver"),
        decision: decision.to_string(),
        approved_at_epoch_seconds: approved_at,
        expires_at_epoch_seconds: Some(approved_at + 86_400),
        reason: Some("Approved by policy".to_string()),
    }
}

fn sample_iga_access_grant() -> IgaAccessGrantRecord {
    IgaAccessGrantRecord {
        id: "grant-1".to_string(),
        tenant_id: "tenant-iga".to_string(),
        request_id: "req-1".to_string(),
        subject: "user-1".to_string(),
        entitlement: "crm:admin".to_string(),
        granted_at_epoch_seconds: 1_700_000_200,
        expires_at_epoch_seconds: Some(1_700_086_400),
        approval_ids: vec!["approval-1".to_string(), "approval-2".to_string()],
        revoked: false,
    }
}

fn sample_iga_jit_privilege_grant(id: &str, issued_at: u64) -> IgaJitPrivilegeGrantRecord {
    IgaJitPrivilegeGrantRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        subject: "user-1".to_string(),
        entitlement: "crm:admin".to_string(),
        requested_by: "user-1".to_string(),
        approved_by: Some("manager-1".to_string()),
        reason: "Emergency database maintenance".to_string(),
        issued_at_epoch_seconds: issued_at,
        expires_at_epoch_seconds: issued_at + 900,
        revoked: false,
        constraints_json: serde_json::json!({"ticket": "INC-1"}),
    }
}

fn sample_iga_access_review_campaign(id: &str, created_at: u64) -> IgaAccessReviewCampaignRecord {
    IgaAccessReviewCampaignRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        reviewer: "auditor-1".to_string(),
        subjects_json: serde_json::json!([
            {
                "subject": "user-1",
                "entitlements": ["crm:admin"],
                "recommendation": "revoke",
                "reasons": ["sod_conflict:crm:admin+crm:audit"]
            }
        ]),
        status: "open".to_string(),
        created_at_epoch_seconds: created_at,
        due_at_epoch_seconds: Some(created_at + 86_400),
    }
}

fn sample_iga_access_review_decision(id: &str, decided_at: u64) -> IgaAccessReviewDecisionRecord {
    IgaAccessReviewDecisionRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        campaign_id: "review-1".to_string(),
        subject: "user-1".to_string(),
        reviewer: "auditor-1".to_string(),
        decision: "certify".to_string(),
        reason: Some("Access is still required".to_string()),
        decided_at_epoch_seconds: decided_at,
    }
}

fn sample_iga_certification(
    id: &str,
    certification_type: &str,
    decided_at: u64,
) -> IgaCertificationRecord {
    IgaCertificationRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        certification_type: certification_type.to_string(),
        campaign_id: Some("review-1".to_string()),
        subject: "user-1".to_string(),
        entitlement: "crm:admin".to_string(),
        certifier: "manager-1".to_string(),
        decision: "certify".to_string(),
        reason: Some("Access is still required".to_string()),
        evidence_json: serde_json::json!({"source": certification_type}),
        decided_at_epoch_seconds: decided_at,
    }
}

fn sample_iga_finding(id: &str, finding_type: &str, detected_at: u64) -> IgaFindingRecord {
    IgaFindingRecord {
        id: id.to_string(),
        tenant_id: "tenant-iga".to_string(),
        finding_type: finding_type.to_string(),
        subject: "user-1".to_string(),
        severity: "high".to_string(),
        evidence_json: serde_json::json!({"source": finding_type}),
        detected_at_epoch_seconds: detected_at,
        resolved: false,
    }
}

async fn assert_iga_repository_round_trip(repo: &impl IgaRepository) {
    let entitlement = sample_iga_entitlement("crm:admin", "high");
    repo.store_iga_entitlement(&entitlement)
        .await
        .expect("store IGA entitlement failed");
    let entitlements = repo
        .list_iga_entitlements("tenant-iga")
        .await
        .expect("list IGA entitlements failed");
    assert_eq!(entitlements, vec![entitlement.clone()]);

    let mut invalid_entitlement = entitlement.clone();
    invalid_entitlement.id = "crm:invalid".to_string();
    invalid_entitlement.risk_level = "severe".to_string();
    assert!(
        repo.store_iga_entitlement(&invalid_entitlement)
            .await
            .is_err()
    );

    let package = sample_iga_access_package("pkg-admin");
    repo.store_iga_access_package(&package)
        .await
        .expect("store IGA access package failed");
    let packages = repo
        .list_iga_access_packages("tenant-iga")
        .await
        .expect("list IGA access packages failed");
    assert_eq!(packages, vec![package.clone()]);

    let mut invalid_package = package.clone();
    invalid_package.id = "pkg-invalid".to_string();
    invalid_package.approval_policy_json = serde_json::json!([]);
    assert!(
        repo.store_iga_access_package(&invalid_package)
            .await
            .is_err()
    );

    let older_request = sample_iga_access_request("req-older", 1_699_999_000);
    repo.store_iga_access_request(&older_request)
        .await
        .expect("store older IGA access request failed");

    let request = sample_iga_access_request("req-1", 1_700_000_000);
    repo.store_iga_access_request(&request)
        .await
        .expect("store IGA access request failed");
    assert_eq!(
        repo.get_iga_access_request("tenant-iga", "req-1")
            .await
            .expect("get IGA access request failed"),
        Some(request.clone())
    );
    let requests = repo
        .list_iga_access_requests("tenant-iga")
        .await
        .expect("list IGA access requests failed");
    assert_eq!(requests, vec![request.clone(), older_request]);

    let mut invalid_request = request.clone();
    invalid_request.id = "req-invalid".to_string();
    invalid_request.violations_json = serde_json::json!({});
    assert!(
        repo.store_iga_access_request(&invalid_request)
            .await
            .is_err()
    );

    let approval_1 = sample_iga_approval("approval-1", "approved", 1_700_000_100);
    let approval_2 = sample_iga_approval("approval-2", "approved", 1_700_000_110);
    repo.store_iga_approval(&approval_2)
        .await
        .expect("store second IGA approval failed");
    repo.store_iga_approval(&approval_1)
        .await
        .expect("store first IGA approval failed");
    let approvals = repo
        .list_iga_approvals("tenant-iga", "req-1")
        .await
        .expect("list IGA approvals failed");
    assert_eq!(approvals, vec![approval_1.clone(), approval_2]);

    let mut invalid_approval = approval_1;
    invalid_approval.id = "approval-invalid".to_string();
    invalid_approval.expires_at_epoch_seconds = Some(invalid_approval.approved_at_epoch_seconds);
    assert!(repo.store_iga_approval(&invalid_approval).await.is_err());

    let grant = sample_iga_access_grant();
    repo.store_iga_access_grant(&grant)
        .await
        .expect("store IGA access grant failed");
    let grants = repo
        .list_iga_access_grants("tenant-iga", Some("user-1"))
        .await
        .expect("list IGA access grants by subject failed");
    assert_eq!(grants, vec![grant.clone()]);
    assert!(
        repo.list_iga_access_grants("tenant-iga", Some("user-2"))
            .await
            .expect("list IGA access grants for unrelated subject failed")
            .is_empty()
    );

    repo.revoke_iga_access_grant("tenant-iga", "grant-1")
        .await
        .expect("revoke IGA access grant failed");
    let grants = repo
        .list_iga_access_grants("tenant-iga", None)
        .await
        .expect("list IGA access grants after revoke failed");
    assert_eq!(grants.len(), 1);
    assert!(grants[0].revoked);

    let older_jit = sample_iga_jit_privilege_grant("jit-older", 1_700_000_250);
    repo.store_iga_jit_privilege_grant(&older_jit)
        .await
        .expect("store older IGA JIT privilege grant failed");
    let jit = sample_iga_jit_privilege_grant("jit-1", 1_700_000_300);
    repo.store_iga_jit_privilege_grant(&jit)
        .await
        .expect("store IGA JIT privilege grant failed");
    let jit_grants = repo
        .list_iga_jit_privilege_grants("tenant-iga", Some("user-1"))
        .await
        .expect("list IGA JIT privilege grants by subject failed");
    assert_eq!(jit_grants, vec![jit.clone(), older_jit]);
    assert!(
        repo.list_iga_jit_privilege_grants("tenant-iga", Some("user-2"))
            .await
            .expect("list IGA JIT privilege grants for unrelated subject failed")
            .is_empty()
    );

    let mut invalid_jit = jit.clone();
    invalid_jit.id = "jit-invalid".to_string();
    invalid_jit.constraints_json = serde_json::json!([]);
    assert!(
        repo.store_iga_jit_privilege_grant(&invalid_jit)
            .await
            .is_err()
    );

    repo.revoke_iga_jit_privilege_grant("tenant-iga", "jit-1")
        .await
        .expect("revoke IGA JIT privilege grant failed");
    let jit_grants = repo
        .list_iga_jit_privilege_grants("tenant-iga", None)
        .await
        .expect("list IGA JIT privilege grants after revoke failed");
    assert_eq!(jit_grants.len(), 2);
    assert!(jit_grants[0].revoked);

    let older_campaign = sample_iga_access_review_campaign("review-older", 1_699_999_000);
    repo.store_iga_access_review_campaign(&older_campaign)
        .await
        .expect("store older IGA access review campaign failed");
    let campaign = sample_iga_access_review_campaign("review-1", 1_700_000_300);
    repo.store_iga_access_review_campaign(&campaign)
        .await
        .expect("store IGA access review campaign failed");
    assert_eq!(
        repo.get_iga_access_review_campaign("tenant-iga", "review-1")
            .await
            .expect("get IGA access review campaign failed"),
        Some(campaign.clone())
    );
    let campaigns = repo
        .list_iga_access_review_campaigns("tenant-iga")
        .await
        .expect("list IGA access review campaigns failed");
    assert_eq!(campaigns, vec![campaign.clone(), older_campaign]);

    let mut invalid_campaign = campaign;
    invalid_campaign.id = "review-invalid".to_string();
    invalid_campaign.subjects_json = serde_json::json!({});
    assert!(
        repo.store_iga_access_review_campaign(&invalid_campaign)
            .await
            .is_err()
    );

    repo.close_iga_access_review_campaign("tenant-iga", "review-1")
        .await
        .expect("close IGA access review campaign failed");
    let closed = repo
        .get_iga_access_review_campaign("tenant-iga", "review-1")
        .await
        .expect("get closed IGA access review campaign failed")
        .expect("closed IGA access review campaign missing");
    assert_eq!(closed.status, "closed");

    let decision_2 = sample_iga_access_review_decision("decision-2", 1_700_000_500);
    repo.store_iga_access_review_decision(&decision_2)
        .await
        .expect("store second IGA access review decision failed");
    let decision_1 = sample_iga_access_review_decision("decision-1", 1_700_000_400);
    repo.store_iga_access_review_decision(&decision_1)
        .await
        .expect("store first IGA access review decision failed");
    let decisions = repo
        .list_iga_access_review_decisions("tenant-iga", "review-1")
        .await
        .expect("list IGA access review decisions failed");
    assert_eq!(decisions, vec![decision_1.clone(), decision_2]);

    let mut invalid_decision = decision_1;
    invalid_decision.id = "decision-invalid".to_string();
    invalid_decision.decision = "maybe".to_string();
    assert!(
        repo.store_iga_access_review_decision(&invalid_decision)
            .await
            .is_err()
    );

    let certification_2 =
        sample_iga_certification("certification-2", "application_owner", 1_700_000_700);
    repo.store_iga_certification(&certification_2)
        .await
        .expect("store second IGA certification failed");
    let certification_1 = sample_iga_certification("certification-1", "manager", 1_700_000_600);
    repo.store_iga_certification(&certification_1)
        .await
        .expect("store first IGA certification failed");
    let certifications = repo
        .list_iga_certifications("tenant-iga", None)
        .await
        .expect("list IGA certifications failed");
    assert_eq!(
        certifications,
        vec![certification_2.clone(), certification_1.clone()]
    );
    let manager_certifications = repo
        .list_iga_certifications("tenant-iga", Some("manager"))
        .await
        .expect("list IGA manager certifications failed");
    assert_eq!(manager_certifications, vec![certification_1.clone()]);

    let mut invalid_certification = certification_1;
    invalid_certification.id = "certification-invalid".to_string();
    invalid_certification.certification_type = "peer".to_string();
    assert!(
        repo.store_iga_certification(&invalid_certification)
            .await
            .is_err()
    );

    let finding_2 = sample_iga_finding("finding-2", "orphaned_service_account", 1_700_000_900);
    repo.store_iga_finding(&finding_2)
        .await
        .expect("store second IGA finding failed");
    let finding_1 = sample_iga_finding("finding-1", "dormant_account", 1_700_000_800);
    repo.store_iga_finding(&finding_1)
        .await
        .expect("store first IGA finding failed");
    let findings = repo
        .list_iga_findings("tenant-iga", None)
        .await
        .expect("list IGA findings failed");
    assert_eq!(findings, vec![finding_2.clone(), finding_1.clone()]);
    let dormant_findings = repo
        .list_iga_findings("tenant-iga", Some("dormant_account"))
        .await
        .expect("list IGA dormant findings failed");
    assert_eq!(dormant_findings, vec![finding_1.clone()]);
    repo.resolve_iga_finding("finding-1")
        .await
        .expect("resolve IGA finding failed");
    let dormant_findings = repo
        .list_iga_findings("tenant-iga", Some("dormant_account"))
        .await
        .expect("list IGA dormant findings after resolve failed");
    assert!(dormant_findings[0].resolved);

    repo.delete_iga_entitlement("tenant-iga", "crm:admin")
        .await
        .expect("delete IGA entitlement failed");
    assert!(
        repo.list_iga_entitlements("tenant-iga")
            .await
            .expect("list IGA entitlements after delete failed")
            .is_empty()
    );

    repo.delete_iga_access_package("tenant-iga", "pkg-admin")
        .await
        .expect("delete IGA access package failed");
    assert!(
        repo.list_iga_access_packages("tenant-iga")
            .await
            .expect("list IGA access packages after delete failed")
            .is_empty()
    );
}

#[tokio::test]
async fn test_sql_saas_repository_round_trip() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    assert_saas_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_saas_repository_round_trip() {
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_saas_{n}.json"));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");
    assert_saas_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_sql_iga_repository_round_trip() {
    let repo = SqlRepository::connect(&db_url())
        .await
        .expect("connect failed");
    repo.migrate().await.expect("migration failed");
    assert_iga_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_iga_repository_round_trip() {
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_iga_{n}.json"));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");
    assert_iga_repository_round_trip(&repo).await;
}
