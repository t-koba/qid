use qid_core::models::TotpCredential;
use qid_core::models::{
    AccessToken, AppCatalogEntry, AuditEvent, AuditRetentionConfig, AuthorizationCode,
    BackchannelAuthenticationGrant, CiamBrand, CiamConsentGrant, CiamIdentityLink,
    CiamProgressiveProfile, CiamVerificationChallengeRecord, Client, ClientType,
    ComplianceEvidencePack, CustomDomain, DelegatedTenantAdmin, DeviceAuthorizationGrant,
    IgaAccessGrantRecord, IgaAccessPackageRecord, IgaAccessRequestRecord,
    IgaAccessReviewCampaignRecord, IgaAccessReviewDecisionRecord, IgaApprovalRecord,
    IgaCertificationRecord, IgaEntitlementRecord, IgaFindingRecord, IgaJitPrivilegeGrantRecord,
    MarketplaceConnector, MarketplaceConnectorType, PasswordCredential, PasswordResetToken,
    PolicyBundle, ScimGroup, ScimUser, Session, UsageBillingEvent, User, VcCredentialStatusRecord,
    WorkloadCertificate, WorkloadIdentity,
};
use qid_core::tenant::{RealmId, TenantId};
use qid_storage::{
    FileRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, SqlRepository, prelude::*,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

mod support;
use support::*;

#[test]
fn sqlite_database_cleanup_removes_stale_sidecars_without_matching_template() {
    let dir = std::env::temp_dir().join(format!("qid_storage_cleanup_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create storage cleanup fixture dir");
    let test_database = dir.join("test_123.db");
    let template = dir.join("schema_template.db");
    // Unit-test binaries keep live databases below a process directory.
    // The integration sweep must not recurse into it, even for test_*.db.
    let unit_dir = dir.join(format!("sql_unit_{}", std::process::id()));
    std::fs::create_dir(&unit_dir).expect("create unit-test cleanup fixture dir");
    let unit_database = unit_dir.join("test_0.db");
    for (path, suffixes) in [
        (&test_database, &["", "-wal", "-shm", "-journal"][..]),
        (&template, &["", "-wal", "-shm", "-journal"][..]),
        (&unit_database, &["", "-wal", "-shm", "-journal"][..]),
    ] {
        for suffix in suffixes {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(*suffix);
            std::fs::write(PathBuf::from(candidate), b"stale database artifact")
                .expect("write storage cleanup fixture");
        }
    }

    support::clean_storage_test_databases(&dir).expect("clean storage test databases");

    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut test_file = test_database.as_os_str().to_os_string();
        test_file.push(suffix);
        assert!(
            !PathBuf::from(test_file).exists(),
            "stale test database file was not removed"
        );
        let mut unit_file = unit_database.as_os_str().to_os_string();
        unit_file.push(suffix);
        assert!(
            PathBuf::from(unit_file).exists(),
            "live unit-test database must not match integration cleanup"
        );
        let mut template_file = template.as_os_str().to_os_string();
        template_file.push(suffix);
        assert!(
            PathBuf::from(template_file).exists(),
            "schema template must not match test database cleanup"
        );
    }
    support::remove_sqlite_database_files(&template).expect("remove storage cleanup template");
    std::fs::remove_dir_all(&dir).expect("remove storage cleanup fixture dir");
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

    let mut renewed_certificate = certificate.clone();
    renewed_certificate.serial_number = "01:02:04".to_string();
    renewed_certificate.x5t_s256 = "e".repeat(64);
    repo.store_workload_certificate(&renewed_certificate)
        .await
        .expect("same-identity certificate update failed");
    let listed = repo
        .list_workload_certificates(&realm, Some(&workload.id))
        .await
        .expect("list updated workload certificate failed");
    assert_eq!(listed, vec![renewed_certificate.clone()]);
    let certificate = renewed_certificate;

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

    let same_realm_workload = WorkloadIdentity {
        id: "workload-batch".to_string(),
        realm_id: realm.0.clone(),
        spiffe_id: "spiffe://corp.example/workload/batch".to_string(),
        description: Some("Batch workload".to_string()),
        trust_domain: "corp.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-batch"}),
    };
    repo.create_workload_identity(&same_realm_workload)
        .await
        .expect("create same-realm workload identity failed");

    let other_realm = RealmId("realm-workload-other".to_string());
    repo.create_realm(
        &TenantId("tenant-workload-other".to_string()),
        &other_realm,
        "https://other-workload.example.com",
        Some("Other Workload Realm"),
    )
    .await
    .expect("create other workload realm failed");
    let other_workload = WorkloadIdentity {
        id: "workload-other".to_string(),
        realm_id: other_realm.0.clone(),
        spiffe_id: "spiffe://other.example/workload/worker".to_string(),
        description: Some("Other workload".to_string()),
        trust_domain: "other.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-other"}),
    };
    repo.create_workload_identity(&other_workload)
        .await
        .expect("create other workload identity failed");

    for (collision_realm, collision_workload) in [
        (&realm, &same_realm_workload),
        (&other_realm, &other_workload),
    ] {
        let mut collision = certificate.clone();
        collision.realm_id = collision_realm.0.clone();
        collision.workload_id = collision_workload.id.clone();
        collision.spiffe_id = collision_workload.spiffe_id.clone();
        collision.serial_number = format!("collision:{}", collision_workload.id);
        collision.x5t_s256 = "d".repeat(64);
        let err = repo
            .store_workload_certificate(&collision)
            .await
            .expect_err("workload certificate ID collision with another identity must fail");
        assert!(
            matches!(err, qid_core::error::QidError::Conflict { .. }),
            "certificate identity collision must be a conflict, got: {}",
            err.message()
        );
        assert_eq!(
            repo.list_workload_certificates(&realm, Some(&workload.id))
                .await
                .expect("list incumbent workload certificate failed"),
            vec![certificate.clone()],
            "identity collision changed the incumbent certificate"
        );
        assert!(
            repo.list_workload_certificates(collision_realm, Some(&collision_workload.id))
                .await
                .expect("list colliding workload certificates failed")
                .is_empty(),
            "identity collision inserted a certificate for the other workload"
        );
    }

    let invalid_revoked_at = certificate.issued_at - 1;
    let err = repo
        .revoke_workload_certificate(&realm, &certificate.id, invalid_revoked_at)
        .await
        .expect_err("revocation before issuance must fail");
    assert!(
        matches!(
            &err,
            qid_core::error::QidError::BadRequest { message }
                if message == "workload certificate revoked_at must not be before issued_at"
        ),
        "invalid revocation time returned the wrong error: {}",
        err.message()
    );
    assert_eq!(
        repo.list_workload_certificates(&realm, Some(&workload.id))
            .await
            .expect("list certificate after invalid revoke failed"),
        vec![certificate.clone()],
        "invalid revocation changed the incumbent certificate"
    );

    for (revoke_realm, revoke_id) in [
        (&other_realm, certificate.id.as_str()),
        (&realm, "missing-cert"),
    ] {
        let err = repo
            .revoke_workload_certificate(revoke_realm, revoke_id, 1_800_000_100)
            .await
            .expect_err("unknown or foreign-realm certificate must fail");
        assert!(
            matches!(err, qid_core::error::QidError::NotFound { .. }),
            "unknown or foreign-realm certificate must be NotFound, got: {}",
            err.message()
        );
        assert_eq!(
            repo.list_workload_certificates(&realm, Some(&workload.id))
                .await
                .expect("list certificate after failed revoke failed"),
            vec![certificate.clone()],
            "failed revoke changed the incumbent certificate"
        );
    }

    // Equal retries remain successful and valid replacement timestamps keep
    // the existing setter semantics. The high value also exercises the u64
    // ordering preserved by SQL's signed integer representation.
    for revoked_at in [
        certificate.issued_at,
        1_800_000_100,
        1_800_000_100,
        1_800_000_101,
        u64::MAX,
    ] {
        repo.revoke_workload_certificate(&realm, &certificate.id, revoked_at)
            .await
            .expect("valid workload certificate revoke failed");
        let mut expected = certificate.clone();
        expected.revoked_at = Some(revoked_at);
        assert_eq!(
            repo.list_workload_certificates(&realm, Some(&workload.id))
                .await
                .expect("list revoked workload certificates failed"),
            vec![expected]
        );
    }
    let mut previously_revoked = certificate.clone();
    previously_revoked.revoked_at = Some(u64::MAX);
    let err = repo
        .revoke_workload_certificate(&realm, &certificate.id, invalid_revoked_at)
        .await
        .expect_err("invalid replacement revocation timestamp must fail");
    assert!(
        matches!(&err, qid_core::error::QidError::BadRequest { .. }),
        "invalid replacement timestamp must be BadRequest, got: {}",
        err.message()
    );
    assert_eq!(
        repo.list_workload_certificates(&realm, Some(&workload.id))
            .await
            .expect("list certificate after invalid replacement failed"),
        vec![previously_revoked],
        "invalid replacement changed the incumbent revocation"
    );

    let upper_half_certificate = WorkloadCertificate {
        id: "cert-high-timestamp".to_string(),
        workload_id: same_realm_workload.id.clone(),
        spiffe_id: same_realm_workload.spiffe_id.clone(),
        x5t_s256: "f".repeat(64),
        issued_at: u64::MAX - 100,
        not_before: u64::MAX - 100,
        not_after: u64::MAX,
        ..certificate.clone()
    };
    repo.store_workload_certificate(&upper_half_certificate)
        .await
        .expect("store upper-half timestamp certificate failed");
    let invalid_high_revoked_at = upper_half_certificate.issued_at - 1;
    let err = repo
        .revoke_workload_certificate(&realm, &upper_half_certificate.id, invalid_high_revoked_at)
        .await
        .expect_err("upper-half revocation before issuance must fail");
    assert!(
        matches!(
            &err,
            qid_core::error::QidError::BadRequest { message }
                if message == "workload certificate revoked_at must not be before issued_at"
        ),
        "upper-half invalid revocation returned the wrong error: {}",
        err.message()
    );
    assert_eq!(
        repo.list_workload_certificates(&realm, Some(&same_realm_workload.id))
            .await
            .expect("list upper-half certificate after invalid revoke failed"),
        vec![upper_half_certificate.clone()],
        "invalid upper-half revocation changed the incumbent"
    );
    for valid_high_revoked_at in [
        upper_half_certificate.issued_at,
        upper_half_certificate.issued_at + 1,
    ] {
        repo.revoke_workload_certificate(&realm, &upper_half_certificate.id, valid_high_revoked_at)
            .await
            .expect("valid upper-half workload certificate revoke failed");
        let mut expected_upper_half_certificate = upper_half_certificate.clone();
        expected_upper_half_certificate.revoked_at = Some(valid_high_revoked_at);
        assert_eq!(
            repo.list_workload_certificates(&realm, Some(&same_realm_workload.id))
                .await
                .expect("list upper-half revoked certificate failed"),
            vec![expected_upper_half_certificate]
        );
    }
}
#[tokio::test]
async fn test_connect_and_migrate() {
    let url = db_url();
    let repo = SqlRepository::connect(&url).await.expect("connect failed");
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
    sqlx::raw_sql(include_str!("fixtures/legacy_app_catalog.sql"))
        .execute(&pool)
        .await
        .expect("load legacy app catalog fixture failed");

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
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;

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
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
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
        attempt_count: 0,
        expires_at_epoch_seconds: 1_800_000_600,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_800_000_000,
    };
    repo.store_ciam_verification_challenge(&challenge)
        .await
        .expect("store CIAM verification failed");
    let realm = RealmId::from("realm-ciam");
    let wrong_realm = RealmId::from("realm-other");
    assert!(
        repo.get_ciam_verification_challenge(&wrong_realm, "verify-1")
            .await
            .expect("wrong-realm CIAM verification lookup failed")
            .is_none(),
        "verification challenges must be hidden outside their realm"
    );
    assert!(
        repo.attempt_ciam_verification_challenge(
            &wrong_realm,
            "verify-1",
            &challenge.code_hash,
            false,
            1_800_000_040,
            5,
        )
        .await
        .is_err(),
        "wrong realm must not consume a verification challenge"
    );
    let unconsumed = repo
        .get_ciam_verification_challenge(&realm, "verify-1")
        .await
        .expect("get CIAM verification after wrong-realm attempt failed")
        .expect("CIAM verification missing");
    assert_eq!(unconsumed.consumed_at_epoch_seconds, None);

    repo.attempt_ciam_verification_challenge(
        &realm,
        "verify-1",
        &challenge.code_hash,
        true,
        1_800_000_050,
        5,
    )
    .await
    .expect("consume CIAM verification failed");
    let consumed = repo
        .get_ciam_verification_challenge(&realm, "verify-1")
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
    let repo = sql_repo().await;

    assert_ciam_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_ciam_repository_round_trip() {
    let repo = file_repo("test_ciam").await;

    assert_ciam_repository_round_trip(&repo).await;
}

struct CiamDeletionFixture {
    user: User,
    password: PasswordCredential,
    profile: CiamProgressiveProfile,
    consent: CiamConsentGrant,
    challenge: CiamVerificationChallengeRecord,
    reset: PasswordResetToken,
    link: CiamIdentityLink,
}

impl CiamDeletionFixture {
    fn new(id: &str) -> Self {
        Self {
            user: User {
                id: id.into(),
                realm_id: "realm-ciam-delete".into(),
                email: Some(format!("{id}@example.com")),
                email_verified: true,
                display_name: Some(id.into()),
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            },
            password: PasswordCredential {
                user_id: id.into(),
                hash: format!("hash-{id}"),
                algorithm: "argon2id".into(),
            },
            profile: CiamProgressiveProfile {
                id: format!("profile-{id}"),
                realm_id: "realm-ciam-delete".into(),
                user_id: id.into(),
                profile_json: serde_json::json!({"name": id}),
                passwordless_migrated_at: Some(200),
                created_at: 100,
                updated_at: 200,
            },
            consent: CiamConsentGrant {
                id: format!("consent-{id}"),
                realm_id: "realm-ciam-delete".into(),
                user_id: id.into(),
                client_id: "client".into(),
                granted_claims: vec!["email".into()],
                terms_version: Some("v1".into()),
                granted_at_epoch_seconds: 100,
                revoked: false,
            },
            challenge: CiamVerificationChallengeRecord {
                id: format!("challenge-{id}"),
                realm_id: "realm-ciam-delete".into(),
                user_id: id.into(),
                channel: "email".into(),
                address: format!("{id}@example.com"),
                purpose: "email_verification".into(),
                code_hash: "code-hash".into(),
                attempt_count: 0,
                expires_at_epoch_seconds: 900,
                consumed_at_epoch_seconds: None,
                created_at_epoch_seconds: 100,
            },
            reset: PasswordResetToken {
                id: format!("reset-{id}"),
                realm_id: "realm-ciam-delete".into(),
                user_id: id.into(),
                token_hash: "reset-hash".into(),
                device_id: Some("device".into()),
                risk_json: serde_json::json!({"score": 20}),
                expires_at_epoch_seconds: 900,
                consumed_at_epoch_seconds: None,
                created_at_epoch_seconds: 100,
            },
            link: CiamIdentityLink {
                id: format!("link-{id}"),
                realm_id: "realm-ciam-delete".into(),
                user_id: id.into(),
                provider: "google".into(),
                external_subject: format!("subject-{id}"),
                external_email: Some(format!("{id}@example.com")),
                profile_json: serde_json::json!({"name": id}),
                linked_at_epoch_seconds: 200,
                verified: true,
            },
        }
    }

    async fn store(&self, repo: &(impl UserRepository + CiamRepository)) {
        repo.create_user(&self.user).await.unwrap();
        repo.store_password_credential(&self.password)
            .await
            .unwrap();
        repo.store_ciam_progressive_profile(&self.profile)
            .await
            .unwrap();
        repo.store_ciam_consent_grant(&self.consent).await.unwrap();
        repo.store_ciam_verification_challenge(&self.challenge)
            .await
            .unwrap();
        repo.store_password_reset_token(&self.reset).await.unwrap();
        repo.store_ciam_identity_link(&self.link).await.unwrap();
    }

    async fn assert_present(&self, repo: &(impl UserRepository + CiamRepository)) {
        let realm = RealmId::from(self.user.realm_id.as_str());
        assert_eq!(
            serde_json::to_value(repo.get_user_by_id(&self.user.id).await.unwrap()).unwrap(),
            serde_json::to_value(Some(&self.user)).unwrap()
        );
        assert_eq!(
            serde_json::to_value(repo.get_password_credential(&self.user.id).await.unwrap())
                .unwrap(),
            serde_json::to_value(Some(&self.password)).unwrap()
        );
        assert_eq!(
            repo.get_ciam_progressive_profile(&realm, &self.user.id)
                .await
                .unwrap(),
            Some(self.profile.clone())
        );
        assert_eq!(
            repo.list_ciam_consent_grants(&realm, &self.user.id, None)
                .await
                .unwrap(),
            vec![self.consent.clone()]
        );
        assert_eq!(
            repo.get_ciam_verification_challenge(&realm, &self.challenge.id)
                .await
                .unwrap(),
            Some(self.challenge.clone())
        );
        assert_eq!(
            repo.get_password_reset_token(&self.reset.id).await.unwrap(),
            Some(self.reset.clone())
        );
        assert_eq!(
            repo.list_ciam_identity_links(&realm, &self.user.id)
                .await
                .unwrap(),
            vec![self.link.clone()]
        );
        assert_eq!(
            repo.get_ciam_identity_link(&realm, &self.link.id)
                .await
                .unwrap(),
            Some(self.link.clone())
        );
        assert_eq!(
            repo.get_ciam_identity_link_by_external_subject(
                &realm,
                &self.link.provider,
                &self.link.external_subject
            )
            .await
            .unwrap(),
            Some(self.link.clone())
        );
    }

    async fn assert_deleted(&self, repo: &(impl UserRepository + CiamRepository)) {
        let realm = RealmId::from(self.user.realm_id.as_str());
        assert!(repo.get_user_by_id(&self.user.id).await.unwrap().is_none());
        assert!(
            repo.get_password_credential(&self.user.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_ciam_progressive_profile(&realm, &self.user.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.list_ciam_consent_grants(&realm, &self.user.id, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repo.get_ciam_verification_challenge(&realm, &self.challenge.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_password_reset_token(&self.reset.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.list_ciam_identity_links(&realm, &self.user.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repo.get_ciam_identity_link(&realm, &self.link.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !repo
                .list_ciam_passwordless_migrations(&realm)
                .await
                .unwrap()
                .iter()
                .any(|p| p.user_id == self.user.id)
        );
    }
}

async fn assert_ciam_user_deletion(
    repo: &(impl RealmRepository + UserRepository + CiamRepository + SaasRepository + AuditRepository),
) {
    let realm = RealmId::from("realm-ciam-delete");
    repo.create_realm(
        &"tenant-saas".into(),
        &realm,
        "https://ciam.example.com",
        None,
    )
    .await
    .unwrap();
    let victim = CiamDeletionFixture::new("victim");
    let survivor = CiamDeletionFixture::new("survivor");
    victim.store(repo).await;
    survivor.store(repo).await;
    victim.assert_present(repo).await;
    survivor.assert_present(repo).await;
    let brand = CiamBrand {
        realm_id: realm.0.clone(),
        ..sample_ciam_brand()
    };
    repo.store_ciam_brand(&brand).await.unwrap();
    repo.append_audit_event(&AuditEvent {
        id: "audit-victim".into(),
        realm_id: Some(realm.0.clone()),
        actor: victim.user.id.clone(),
        action: "user.create".into(),
        target_type: "user".into(),
        target_id: victim.user.id.clone(),
        reason: "test".into(),
        metadata_json: serde_json::json!({}),
        created_at: 100,
        previous_hash: None,
        event_hash: None,
    })
    .await
    .unwrap();
    let audit_before = repo.list_audit_events(Some(&realm), 10).await.unwrap();

    repo.delete_user(&victim.user.id).await.unwrap();
    victim.assert_deleted(repo).await;
    survivor.assert_present(repo).await;
    assert!(
        repo.get_ciam_identity_link_by_external_subject(
            &realm,
            &victim.link.provider,
            &victim.link.external_subject
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        repo.list_ciam_passwordless_migrations(&realm)
            .await
            .unwrap(),
        vec![survivor.profile.clone()]
    );
    assert_eq!(
        repo.list_ciam_brands(&brand.tenant_id).await.unwrap(),
        vec![brand]
    );
    assert_eq!(
        serde_json::to_value(repo.list_audit_events(Some(&realm), 10).await.unwrap()).unwrap(),
        serde_json::to_value(audit_before).unwrap()
    );
    assert_eq!(
        repo.get_realm_issuer(&realm).await.unwrap().as_deref(),
        Some("https://ciam.example.com")
    );

    let reclaimed = CiamIdentityLink {
        id: "link-reclaimed".into(),
        user_id: survivor.user.id.clone(),
        ..victim.link.clone()
    };
    repo.store_ciam_identity_link(&reclaimed).await.unwrap();
    assert_eq!(
        repo.get_ciam_identity_link_by_external_subject(
            &realm,
            &reclaimed.provider,
            &reclaimed.external_subject
        )
        .await
        .unwrap(),
        Some(reclaimed)
    );
}

#[tokio::test]
async fn test_sql_ciam_user_deletion() {
    assert_ciam_user_deletion(&sql_repo().await).await;
}

#[tokio::test]
async fn test_file_ciam_user_deletion_and_reopen() {
    let path = std::env::temp_dir().join(format!("qid_ciam_delete_{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    repo.migrate().await.unwrap();
    assert_ciam_user_deletion(&repo).await;
    drop(repo);

    let reopened = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    CiamDeletionFixture::new("victim")
        .assert_deleted(&reopened)
        .await;
    let realm = RealmId::from("realm-ciam-delete");
    let reclaimed = reopened
        .get_ciam_identity_link_by_external_subject(&realm, "google", "subject-victim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.user_id, "survivor");
    // Remove only the newly claimed link so the survivor's original state can be compared exactly.
    reopened
        .delete_ciam_identity_link(&realm, &reclaimed.id)
        .await
        .unwrap();
    CiamDeletionFixture::new("survivor")
        .assert_present(&reopened)
        .await;
    assert_eq!(
        reopened
            .list_audit_events(Some(&realm), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        reopened
            .list_ciam_brands("tenant-saas")
            .await
            .unwrap()
            .len(),
        1
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn test_sql_ciam_identity_link_user_lifecycle_migration() {
    let url = db_url();
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    // Reproduce the legacy schema, including the verified-only unique index.
    for sql in [
        include_str!("../migrations/20250101000001_initial_schema.sql"),
        include_str!("../migrations/20250618000031_ciam_identity_links.sql"),
        include_str!("../migrations/20250630000010_ciam_verified_identity_subjects.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    sqlx::raw_sql(
        "INSERT INTO realms (id, tenant_id, issuer) VALUES ('realm', 'tenant', 'https://id.example.com');
         INSERT INTO users (id, realm_id) VALUES ('live', 'realm');
         INSERT INTO ciam_identity_links VALUES
             ('verified', 'realm', 'live', 'google', 'subject', 'social@example.com', '{\"name\":\"Live\"}', 200, 1),
             ('unverified', 'realm', 'live', 'google', 'subject', NULL, '{}', 100, 0),
             ('orphan', 'realm', 'deleted', 'google', 'orphan-subject', NULL, '{}', 100, 1);",
    )
    .execute(&pool)
    .await
    .unwrap();
    let realm = RealmId::from("realm");
    let before = repo.list_ciam_identity_links(&realm, "live").await.unwrap();
    assert_eq!(before.len(), 2);
    assert!(
        repo.get_ciam_identity_link(&realm, "orphan")
            .await
            .unwrap()
            .is_some()
    );

    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20250630000011_ciam_identity_link_user_lifecycle.sql"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        repo.list_ciam_identity_links(&realm, "live").await.unwrap(),
        before
    );
    assert!(
        repo.get_ciam_identity_link(&realm, "orphan")
            .await
            .unwrap()
            .is_none()
    );
    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ciam_identity_links' AND sql IS NOT NULL ORDER BY name",
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(indexes.len(), 2);
    assert_eq!(indexes[0].0, "idx_ciam_identity_links_external_subject");
    assert!(indexes[0].1.contains("UNIQUE"));
    assert!(indexes[0].1.contains("WHERE verified = 1"));
    assert_eq!(indexes[1].0, "idx_ciam_identity_links_user");
    assert!(
        indexes[1]
            .1
            .contains("realm_id, user_id, linked_at_epoch_seconds DESC")
    );
    // Enforce the new FK and verified uniqueness at the database boundary.
    for (id, user, verified) in [("bad-owner", "missing", 0), ("duplicate", "live", 1)] {
        assert!(sqlx::query(
            "INSERT INTO ciam_identity_links VALUES (?, 'realm', ?, 'google', 'subject', NULL, '{}', 300, ?)",
        ).bind(id).bind(user).bind(verified).execute(&pool).await.is_err());
    }
    sqlx::query("INSERT INTO ciam_identity_links VALUES ('another-unverified', 'realm', 'live', 'google', 'subject', NULL, '{}', 300, 0)")
        .execute(&pool).await.unwrap();
    // Exercise the FK directly on this deliberately partial legacy schema.
    sqlx::query("DELETE FROM users WHERE id = 'live'")
        .execute(&pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ciam_identity_links")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "deletion must cascade verified and unverified links"
    );
    pool.close().await;
}

async fn assert_ciam_identity_link_id_binding(
    repo: &(impl RealmRepository + UserRepository + CiamRepository),
) {
    for realm in ["realm-link", "realm-link-other"] {
        repo.create_realm(
            &"tenant-link".into(),
            &realm.into(),
            &format!("https://{realm}.example.com"),
            None,
        )
        .await
        .unwrap();
    }
    for (id, realm) in [
        ("user-link", "realm-link"),
        ("user-link-other", "realm-link"),
        ("user-link-realm", "realm-link-other"),
    ] {
        repo.create_user(&User {
            id: id.to_string(),
            realm_id: realm.to_string(),
            email: Some(format!("{id}@example.com")),
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    let mut incumbent = CiamIdentityLink {
        id: "link-owner-1".to_string(),
        realm_id: "realm-link".to_string(),
        user_id: "user-link".to_string(),
        provider: "google".to_string(),
        external_subject: "subject-1".to_string(),
        external_email: Some("social@example.com".to_string()),
        profile_json: serde_json::json!({"name": "Original"}),
        linked_at_epoch_seconds: 1_800_000_000,
        verified: false,
    };
    repo.store_ciam_identity_link(&incumbent).await.unwrap();
    // Same-owner contact/profile updates and verification promotion remain supported.
    incumbent.external_email = Some("updated@example.com".to_string());
    incumbent.profile_json = serde_json::json!({"name": "Updated"});
    repo.store_ciam_identity_link(&incumbent).await.unwrap();
    incumbent.verified = true;
    repo.store_ciam_identity_link(&incumbent).await.unwrap();
    incumbent.profile_json = serde_json::json!({"name": "Updated after verification"});
    repo.store_ciam_identity_link(&incumbent).await.unwrap();

    let mut cross_user = incumbent.clone();
    cross_user.user_id = "user-link-other".to_string();
    let mut cross_realm = incumbent.clone();
    cross_realm.realm_id = "realm-link-other".to_string();
    cross_realm.user_id = "user-link-realm".to_string();
    let mut changed_provider = incumbent.clone();
    changed_provider.provider = "github".to_string();
    let mut changed_subject = incumbent.clone();
    changed_subject.external_subject = "subject-2".to_string();

    let mut downgrade = incumbent.clone();
    downgrade.verified = false;
    let error = repo.store_ciam_identity_link(&downgrade).await.unwrap_err();
    assert!(matches!(
        error,
        qid_core::error::QidError::BadRequest { .. }
    ));

    for mut collision in [cross_user, cross_realm, changed_provider, changed_subject] {
        collision.profile_json = serde_json::json!({"name": "Must not persist"});
        for verified in [false, true] {
            collision.verified = verified;
            let error = repo.store_ciam_identity_link(&collision).await.unwrap_err();
            assert!(
                matches!(error, qid_core::error::QidError::Conflict { .. }),
                "owner/key reuse must conflict, got {error:?}"
            );
            assert_eq!(
                repo.get_ciam_identity_link(&"realm-link".into(), &incumbent.id)
                    .await
                    .unwrap(),
                Some(incumbent.clone())
            );
            assert_eq!(
                repo.list_ciam_identity_links(&"realm-link".into(), "user-link")
                    .await
                    .unwrap(),
                vec![incumbent.clone()]
            );
            for (realm, user) in [
                ("realm-link", "user-link-other"),
                ("realm-link-other", "user-link-realm"),
            ] {
                assert!(
                    repo.list_ciam_identity_links(&realm.into(), user)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }
    assert_eq!(
        repo.get_ciam_identity_link_by_external_subject(
            &"realm-link".into(),
            "google",
            "subject-1"
        )
        .await
        .unwrap(),
        Some(incumbent.clone())
    );
    // A different ID still cannot claim the same realm/provider/subject.
    let mut duplicate = incumbent.clone();
    duplicate.id = "link-owner-duplicate".to_string();
    let error = repo.store_ciam_identity_link(&duplicate).await.unwrap_err();
    assert!(matches!(
        error,
        qid_core::error::QidError::BadRequest { .. }
    ));
    assert_eq!(
        repo.list_ciam_identity_links(&"realm-link".into(), "user-link")
            .await
            .unwrap(),
        vec![incumbent]
    );
}

#[tokio::test]
async fn test_sql_ciam_identity_link_id_binding() {
    assert_ciam_identity_link_id_binding(&sql_repo().await).await;
}

#[tokio::test]
async fn test_file_ciam_identity_link_id_binding() {
    assert_ciam_identity_link_id_binding(&file_repo("ciam_link_binding").await).await;
}

async fn assert_ciam_only_verified_subjects_authenticate(
    repo: &(impl RealmRepository + UserRepository + CiamRepository),
) {
    let realm = RealmId::from("realm-link-trust");
    repo.create_realm(
        &"tenant-link-trust".into(),
        &realm,
        "https://trust.example.com",
        None,
    )
    .await
    .unwrap();
    for id in ["legacy-owner", "trusted-owner"] {
        repo.create_user(&User {
            id: id.to_string(),
            realm_id: realm.0.clone(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    let mut legacy = CiamIdentityLink {
        id: "legacy-link".to_string(),
        realm_id: realm.0.clone(),
        user_id: "legacy-owner".to_string(),
        provider: "google".to_string(),
        external_subject: "shared-subject".to_string(),
        external_email: None,
        profile_json: serde_json::json!({}),
        linked_at_epoch_seconds: 1_800_000_000,
        verified: false,
    };
    repo.store_ciam_identity_link(&legacy).await.unwrap();
    assert_eq!(
        repo.get_ciam_identity_link_by_external_subject(&realm, "google", "shared-subject")
            .await
            .unwrap(),
        None
    );
    let mut trusted = legacy.clone();
    trusted.id = "trusted-link".to_string();
    trusted.user_id = "trusted-owner".to_string();
    trusted.verified = true;
    // An unverified row owned by someone else cannot reserve the provider subject.
    repo.store_ciam_identity_link(&trusted).await.unwrap();
    // Unverified rows can also be stored after a verified mapping exists.
    legacy.id = "second-legacy-link".to_string();
    repo.store_ciam_identity_link(&legacy).await.unwrap();
    assert_eq!(
        repo.get_ciam_identity_link_by_external_subject(&realm, "google", "shared-subject")
            .await
            .unwrap(),
        Some(trusted.clone())
    );
    // Neither a new verified ID nor promotion of a legacy row may steal the subject.
    let mut duplicate = trusted.clone();
    duplicate.id = "duplicate-verified-link".to_string();
    assert!(repo.store_ciam_identity_link(&duplicate).await.is_err());
    let mut promoted = legacy.clone();
    promoted.verified = true;
    assert!(repo.store_ciam_identity_link(&promoted).await.is_err());
    assert_eq!(
        repo.get_ciam_identity_link(&realm, &legacy.id)
            .await
            .unwrap(),
        Some(legacy)
    );
    assert_eq!(
        repo.get_ciam_identity_link(&realm, &duplicate.id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repo.get_ciam_identity_link_by_external_subject(&realm, "google", "shared-subject")
            .await
            .unwrap(),
        Some(trusted)
    );
}

#[tokio::test]
async fn test_sql_ciam_only_verified_subjects_authenticate() {
    assert_ciam_only_verified_subjects_authenticate(&sql_repo().await).await;
}

#[tokio::test]
async fn test_file_ciam_only_verified_subjects_authenticate() {
    assert_ciam_only_verified_subjects_authenticate(&file_repo("ciam_link_trust").await).await;
}

async fn assert_ciam_progressive_profile_owner_conflict(
    repo: &(impl RealmRepository + UserRepository + CiamRepository),
) {
    for (realm, user) in [("team_blue", "person"), ("team", "blue_person")] {
        repo.create_realm(
            &"tenant-profile".into(),
            &realm.into(),
            &format!("https://{realm}.example.com"),
            None,
        )
        .await
        .unwrap();
        repo.create_user(&User {
            id: user.to_string(),
            realm_id: realm.to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    let mut incumbent = CiamProgressiveProfile {
        id: "team_blue_person".to_string(),
        realm_id: "team_blue".to_string(),
        user_id: "person".to_string(),
        profile_json: serde_json::json!({"name": "Original"}),
        passwordless_migrated_at: None,
        created_at: 100,
        updated_at: 100,
    };
    repo.store_ciam_progressive_profile(&incumbent)
        .await
        .unwrap();
    incumbent.profile_json = serde_json::json!({"name": "Updated"});
    incumbent.passwordless_migrated_at = Some(200);
    incumbent.updated_at = 200;
    repo.store_ciam_progressive_profile(&incumbent)
        .await
        .unwrap();
    let mut incoming = CiamProgressiveProfile {
        realm_id: "team".to_string(),
        user_id: "blue_person".to_string(),
        profile_json: serde_json::json!({"name": "Other owner"}),
        ..incumbent.clone()
    };
    assert!(matches!(
        repo.store_ciam_progressive_profile(&incoming).await,
        Err(qid_core::error::QidError::Conflict { .. })
    ));
    assert_eq!(
        repo.get_ciam_progressive_profile(&"team_blue".into(), "person")
            .await
            .unwrap(),
        Some(incumbent.clone())
    );
    assert!(
        repo.get_ciam_progressive_profile(&"team".into(), "blue_person")
            .await
            .unwrap()
            .is_none()
    );

    // An existing owner cannot silently replace its profile's identity either.
    let changed_id = CiamProgressiveProfile {
        id: "replacement-id".to_string(),
        ..incumbent.clone()
    };
    assert!(matches!(
        repo.store_ciam_progressive_profile(&changed_id).await,
        Err(qid_core::error::QidError::Conflict { .. })
    ));
    incoming.id = "4:teamblue_person".to_string();
    repo.store_ciam_progressive_profile(&incoming)
        .await
        .unwrap();
    assert_eq!(
        repo.get_ciam_progressive_profile(&"team".into(), "blue_person")
            .await
            .unwrap(),
        Some(incoming)
    );
    assert_eq!(
        repo.get_ciam_progressive_profile(&"team_blue".into(), "person")
            .await
            .unwrap(),
        Some(incumbent)
    );
}

async fn assert_ciam_progressive_profile_colon_key(
    repo: &(impl RealmRepository + UserRepository + CiamRepository),
) {
    for (realm, issuer) in [
        ("a:b", "https://first.example.com"),
        ("a", "https://second.example.com"),
    ] {
        repo.create_realm(&"tenant-profile-key".into(), &realm.into(), issuer, None)
            .await
            .unwrap();
    }
    for (user, realm) in [("c", "a:b"), ("b:c", "a")] {
        repo.create_user(&User {
            id: user.to_string(),
            realm_id: realm.to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    let mut first = CiamProgressiveProfile {
        id: "3:a:bc".to_string(),
        realm_id: "a:b".to_string(),
        user_id: "c".to_string(),
        profile_json: serde_json::json!({"owner": "first"}),
        passwordless_migrated_at: None,
        created_at: 100,
        updated_at: 100,
    };
    let second = CiamProgressiveProfile {
        id: "1:ab:c".to_string(),
        realm_id: "a".to_string(),
        user_id: "b:c".to_string(),
        profile_json: serde_json::json!({"owner": "second"}),
        created_at: 100,
        updated_at: 100,
        ..first.clone()
    };
    repo.store_ciam_progressive_profile(&first)
        .await
        .expect("store first colon profile failed");
    repo.store_ciam_progressive_profile(&second)
        .await
        .expect("colon in user ID must not collide with realm separator");
    assert_eq!(
        repo.get_ciam_progressive_profile(&"a:b".into(), "c")
            .await
            .unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        repo.get_ciam_progressive_profile(&"a".into(), "b:c")
            .await
            .unwrap(),
        Some(second.clone())
    );

    first.profile_json = serde_json::json!({"owner": "first-updated"});
    first.updated_at = 200;
    repo.store_ciam_progressive_profile(&first)
        .await
        .expect("same-owner colon profile update failed");
    assert_eq!(
        repo.get_ciam_progressive_profile(&"a".into(), "b:c")
            .await
            .unwrap(),
        Some(second.clone())
    );
    repo.delete_ciam_progressive_profile(&"a:b".into(), "c")
        .await
        .expect("delete first colon profile failed");
    assert!(
        repo.get_ciam_progressive_profile(&"a:b".into(), "c")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_ciam_progressive_profile(&"a".into(), "b:c")
            .await
            .unwrap(),
        Some(second)
    );
}

#[tokio::test]
async fn test_sql_ciam_progressive_profile_colon_key() {
    assert_ciam_progressive_profile_colon_key(&sql_repo().await).await;
}

#[tokio::test]
async fn test_file_ciam_progressive_profile_colon_key() {
    assert_ciam_progressive_profile_colon_key(&file_repo("ciam_profile_colon_key").await).await;
}

#[tokio::test]
async fn test_sql_ciam_progressive_profile_owner_conflict() {
    assert_ciam_progressive_profile_owner_conflict(&sql_repo().await).await;
}

#[tokio::test]
async fn test_file_ciam_progressive_profile_owner_conflict() {
    assert_ciam_progressive_profile_owner_conflict(&file_repo("ciam_profile_owner").await).await;
}
#[tokio::test]
async fn test_sql_ciam_consent_grant_owner_conflict() {
    let repo = sql_repo().await;
    support::assert_ciam_consent_grant_owner_conflict(&repo).await;
}

#[tokio::test]
async fn test_file_ciam_consent_grant_owner_conflict() {
    let repo = file_repo("test_ciam_consent_owner").await;
    support::assert_ciam_consent_grant_owner_conflict(&repo).await;
}

#[tokio::test]
async fn test_sql_workload_certificate_round_trip() {
    let repo = sql_repo().await;

    assert_workload_certificate_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_workload_certificate_round_trip() {
    let path = std::env::temp_dir().join(format!("qid-file-workload-{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    assert_workload_certificate_round_trip(&repo).await;
}

#[tokio::test]
async fn test_sql_workload_identity_ownership() {
    let repo = sql_repo().await;
    support::assert_workload_identity_ownership(&repo).await;
}

#[tokio::test]
async fn test_file_workload_identity_ownership() {
    let path = std::env::temp_dir().join(format!(
        "qid-file-workload-identity-{}.json",
        ulid::Ulid::new()
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    support::assert_workload_identity_ownership(&repo).await;
}
#[tokio::test]
async fn test_sql_client_id_ambiguity() {
    let repo = sql_repo().await;
    support::assert_client_id_ambiguity(&repo).await;
}

#[tokio::test]
async fn test_file_client_id_ambiguity() {
    let path = std::env::temp_dir().join(format!(
        "qid-file-client-ambiguity-{}.json",
        ulid::Ulid::new()
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    support::assert_client_id_ambiguity(&repo).await;
}

#[tokio::test]
async fn test_sql_client_id_uniqueness() {
    let repo = sql_repo().await;
    support::assert_client_id_uniqueness(&repo).await;
}

#[tokio::test]
async fn test_file_client_id_uniqueness() {
    let path =
        std::env::temp_dir().join(format!("qid-file-client-unique-{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    support::assert_client_id_uniqueness(&repo).await;
}
#[tokio::test]
async fn test_sql_workload_identity_delete_scope() {
    let repo = sql_repo().await;
    support::assert_workload_identity_delete_scope(&repo).await;
}

#[tokio::test]
async fn test_file_workload_identity_delete_scope() {
    let path = std::env::temp_dir().join(format!(
        "qid-file-workload-delete-{}.json",
        ulid::Ulid::new()
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");

    support::assert_workload_identity_delete_scope(&repo).await;
}

#[tokio::test]
async fn test_vc_credential_status_crud_and_revocation() {
    let repo = sql_repo().await;
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
    // Statuses are insert-only: re-storing an identifier fails on every backend.
    let duplicate = repo.store_vc_credential_status(&status).await;
    assert!(
        duplicate.is_err(),
        "duplicate credential status must fail closed"
    );
}

#[tokio::test]
async fn test_file_vc_credential_status_round_trip() {
    let path = std::env::temp_dir().join(format!("qid-file-vc-{}.json", ulid::Ulid::new()));
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
    // Statuses are insert-only: re-storing an identifier fails on every backend.
    let duplicate = repo.store_vc_credential_status(&status).await;
    assert!(
        duplicate.is_err(),
        "duplicate credential status must fail closed"
    );
}

#[tokio::test]
async fn test_session_crud() {
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-ac".into(),
        "https://id.example.com/realms/ac",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-1".into(),
        realm_id: "realm-ac".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
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
        session_id: None,
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
    let repo = sql_repo().await;
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
        require_pushed_authorization_requests: false,
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
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-device".into(),
        "https://id.example.com/realms/device",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-device".into(),
        realm_id: "realm-device".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();

    let grant = DeviceAuthorizationGrant {
        resource: Vec::new(),
        audience: Vec::new(),
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
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-ciba".into(),
        "https://id.example.com/realms/ciba",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-ciba".into(),
        realm_id: "realm-ciba".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();

    let grant = BackchannelAuthenticationGrant {
        resource: Vec::new(),
        audience: Vec::new(),
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

fn test_family(
    id: &str,
    user_id: &str,
    realm_id: &str,
    hash: &str,
    issued_at: u64,
    deadline: Option<u64>,
) -> qid_core::models::TokenFamily {
    qid_core::models::TokenFamily {
        id: id.to_string(),
        user_id: user_id.to_string(),
        client_id: "client-1".to_string(),
        realm_id: realm_id.to_string(),
        current_refresh_hash: hash.to_string(),
        scopes: Vec::new(),
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        audience: Vec::new(),
        resource: Vec::new(),
        authorization_details: None,
        sender_constraint: None,
        issued_at,
        refresh_expires_at: deadline,
        session_id: None,
        revoked: false,
    }
}

#[tokio::test]
async fn test_token_family_crud() {
    let repo = sql_repo().await;
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
    let mut family = test_family("tf-1", "user-tf", "realm-tf", "hash1", 1000, Some(4600));
    family.session_id = Some("sess-1".to_string());
    family.scopes = vec!["read".to_string(), "write".to_string()];
    family.auth_time = Some(1234);
    family.acr = Some("urn:qid:acr:password".to_string());
    family.amr = vec!["pwd".to_string()];
    family.audience = vec!["api://orders".to_string()];
    family.resource = vec!["https://api.example.com/orders".to_string()];
    family.authorization_details = Some(serde_json::json!([
        {"type":"payment_initiation","actions":["read"]}
    ]));
    family.sender_constraint = Some(serde_json::json!({"jkt":"refresh-thumbprint"}));
    repo.create_token_family(&family)
        .await
        .expect("create token family failed");
    let fetched = repo
        .get_token_family("tf-1")
        .await
        .unwrap()
        .expect("family not found");
    assert_eq!(fetched.current_refresh_hash, "hash1");
    assert_eq!(
        fetched.scopes,
        vec!["read".to_string(), "write".to_string()]
    );
    assert_eq!(fetched.auth_time, Some(1234));
    assert_eq!(fetched.refresh_expires_at, Some(4600));
    assert_eq!(fetched.session_id, Some("sess-1".to_string()));
    assert_eq!(fetched.acr, Some("urn:qid:acr:password".to_string()));
    assert_eq!(fetched.amr, vec!["pwd".to_string()]);
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
    repo.update_token_family_refresh_hash("tf-1", "hash1", "hash2", 4600)
        .await
        .unwrap();
    let updated = repo.get_token_family("tf-1").await.unwrap().unwrap();
    assert_eq!(updated.current_refresh_hash, "hash2");
    assert_eq!(updated.refresh_expires_at, Some(4600));
    repo.revoke_token_family("tf-1").await.unwrap();
    let revoked = repo.get_token_family("tf-1").await.unwrap().unwrap();
    assert!(revoked.revoked);
}

#[tokio::test]
async fn test_access_token_crud() {
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
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
    let repo = sql_repo().await;
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
        directory_provider_id: Some("ad-main".to_string()),
        deprovisioned_at: None,
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
    assert_eq!(fetched.directory_provider_id, Some("ad-main".to_string()));

    assert_eq!(fetched.deprovisioned_at, None);
    let mut updated = fetched;
    updated.enterprise_json = serde_json::json!({"department":"Platform"});
    updated.directory_provider_id = Some("ad-replica".to_string());
    updated.deprovisioned_at = Some(1_050);
    repo.update_scim_user(&updated)
        .await
        .expect("update scim user failed");
    let fetched = repo.get_scim_user("scim-user-1").await.unwrap().unwrap();
    assert_eq!(fetched.enterprise_json["department"], "Platform");
    assert_eq!(
        fetched.directory_provider_id,
        Some("ad-replica".to_string())
    );
    assert_eq!(fetched.deprovisioned_at, Some(1_050));
}

#[tokio::test]
async fn sql_scim_pages_and_counts_are_stable() {
    let repo = sql_repo().await;
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
            directory_provider_id: None,
            deprovisioned_at: None,
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
        require_pushed_authorization_requests: false,
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
    let mut updated_domain = domain.clone();
    updated_domain.certificate_ref = "kms://certificates/customer-login-renewed".to_string();
    updated_domain.last_verified_at = Some(1_810_000_000);
    repo.store_custom_domain(&updated_domain)
        .await
        .expect("same-owner custom-domain lifecycle update failed");
    assert_eq!(
        repo.list_custom_domains("tenant-saas")
            .await
            .expect("list same-owner updated custom domain failed"),
        vec![updated_domain.clone()]
    );

    let mut colliding_domain = updated_domain.clone();
    colliding_domain.tenant_id = "tenant-other".to_string();
    colliding_domain.realm_id = "realm-other".to_string();
    colliding_domain.hostname = "login.other.customer.example.com".to_string();
    colliding_domain.certificate_ref = "kms://certificates/attacker".to_string();
    let error = repo
        .store_custom_domain(&colliding_domain)
        .await
        .expect_err("cross-tenant duplicate custom-domain ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate ID must have conflict semantics, got {error:?}"
    );
    assert_eq!(
        repo.list_custom_domains("tenant-saas")
            .await
            .expect("list incumbent custom domain after collision failed"),
        vec![updated_domain.clone()]
    );
    assert!(
        repo.list_custom_domains("tenant-other")
            .await
            .expect("list other tenant custom domains failed")
            .is_empty()
    );

    repo.delete_custom_domain("tenant-other", "domain-1")
        .await
        .expect("cross-tenant custom domain delete failed");
    assert_eq!(
        repo.list_custom_domains("tenant-saas")
            .await
            .expect("list custom domains after cross-tenant delete failed"),
        vec![updated_domain.clone()]
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
    let mut updated_brand = brand.clone();
    updated_brand.display_name = "Customer Blue Updated".to_string();
    repo.store_ciam_brand(&updated_brand)
        .await
        .expect("same-owner CIAM brand update failed");
    assert_eq!(
        repo.list_ciam_brands("tenant-saas")
            .await
            .expect("list same-owner updated CIAM brand failed"),
        vec![updated_brand.clone()]
    );

    let mut colliding_brand = updated_brand.clone();
    colliding_brand.tenant_id = "tenant-other".to_string();
    colliding_brand.realm_id = "realm-other".to_string();
    colliding_brand.display_name = "Other tenant overwrite".to_string();
    let error = repo
        .store_ciam_brand(&colliding_brand)
        .await
        .expect_err("cross-tenant duplicate CIAM brand ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate ID must have conflict semantics, got {error:?}"
    );
    assert_eq!(
        repo.list_ciam_brands("tenant-saas")
            .await
            .expect("list incumbent CIAM brand after collision failed"),
        vec![updated_brand.clone()]
    );
    assert!(
        repo.list_ciam_brands("tenant-other")
            .await
            .expect("list other tenant CIAM brands failed")
            .is_empty()
    );

    repo.delete_ciam_brand("tenant-other", "brand-1")
        .await
        .expect("cross-tenant CIAM brand delete failed");
    assert_eq!(
        repo.list_ciam_brands("tenant-saas")
            .await
            .expect("list CIAM brands after cross-tenant delete failed"),
        vec![updated_brand.clone()]
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
        vec![connector.clone()]
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

    let mut colliding_connector = connector.clone();
    colliding_connector.tenant_id = "tenant-other".to_string();
    colliding_connector.provider = "attacker-crm".to_string();
    colliding_connector.config_json = serde_json::json!({
        "base_url": "https://attacker.example.com/scim/v2",
        "token_ref": "kms://secrets/attacker-crm-token"
    });
    let error = repo
        .store_marketplace_connector(&colliding_connector)
        .await
        .expect_err("cross-tenant marketplace connector ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate marketplace connector ID must return Conflict, got {error:?}"
    );
    assert_eq!(
        repo.list_marketplace_connectors("tenant-saas")
            .await
            .expect("list incumbent marketplace connector after collision failed"),
        vec![connector.clone()]
    );
    assert_eq!(
        repo.list_marketplace_connectors("tenant-other")
            .await
            .expect("list other tenant marketplace connectors failed"),
        vec![other_connector.clone()]
    );
    assert_eq!(
        repo.list_app_catalog_entries("tenant-saas")
            .await
            .expect("list app catalog reference after connector collision failed"),
        vec![entry.clone()]
    );

    let mut colliding_entry = entry.clone();
    colliding_entry.tenant_id = "tenant-other".to_string();
    colliding_entry.realm_id = "realm-other".to_string();
    colliding_entry.display_name = "Other tenant overwrite".to_string();
    colliding_entry.oidc_client_id = None;
    colliding_entry.saml_entity_id = Some("https://other-sp.example.com/metadata".to_string());
    colliding_entry.scim_enabled = false;
    colliding_entry.marketplace_connector_id = None;
    let error = repo
        .store_app_catalog_entry(&colliding_entry)
        .await
        .expect_err("global duplicate app catalog ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate ID must have consistent conflict semantics, got {error:?}"
    );
    assert_eq!(
        repo.list_app_catalog_entries("tenant-saas")
            .await
            .expect("list incumbent app catalog entry failed"),
        vec![entry.clone()]
    );
    assert!(
        repo.list_app_catalog_entries("tenant-other")
            .await
            .expect("list other tenant app catalog entries failed")
            .is_empty()
    );

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

    let older_usage = sample_usage_billing_event("usage-older", 100);
    let newer_usage = sample_usage_billing_event("usage-newer", 200);
    repo.store_usage_billing_event(&older_usage)
        .await
        .expect("store older usage billing event failed");
    repo.store_usage_billing_event(&newer_usage)
        .await
        .expect("store newer usage billing event failed");

    // Tenant-scoped idempotency-key uniqueness remains enforced across IDs.
    let mut duplicate_usage = sample_usage_billing_event("usage-duplicate", 300);
    duplicate_usage.idempotency_key = newer_usage.idempotency_key.clone();
    let error = repo
        .store_usage_billing_event(&duplicate_usage)
        .await
        .expect_err("duplicate tenant idempotency key must remain rejected");
    assert!(
        matches!(error, qid_core::error::QidError::Storage { .. }),
        "duplicate tenant idempotency key must keep its storage rejection, got {error:?}"
    );
    let events = repo
        .list_usage_billing_events("tenant-saas", 1)
        .await
        .expect("list usage billing events failed");
    assert_eq!(events, vec![newer_usage.clone()]);

    // Event IDs are create-only even when the tenant and idempotency key match.
    let mut same_tenant_duplicate = newer_usage.clone();
    same_tenant_duplicate.quantity = 999;
    let error = repo
        .store_usage_billing_event(&same_tenant_duplicate)
        .await
        .expect_err("duplicate billing event ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate billing event ID must return Conflict, got {error:?}"
    );

    // A different tenant cannot replace the global ID or alter recorded usage.
    let mut cross_tenant_collision = newer_usage.clone();
    cross_tenant_collision.tenant_id = "tenant-other".to_string();
    cross_tenant_collision.idempotency_key = "tenant-other:usage-newer".to_string();
    cross_tenant_collision.quantity = 999;
    cross_tenant_collision
        .dimensions
        .insert("realm".to_string(), "realm-other".to_string());
    let error = repo
        .store_usage_billing_event(&cross_tenant_collision)
        .await
        .expect_err("cross-tenant billing event ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-tenant billing event ID reuse must return Conflict, got {error:?}"
    );
    assert_eq!(
        repo.list_usage_billing_events("tenant-saas", 10)
            .await
            .expect("list incumbent usage history failed"),
        vec![newer_usage, older_usage]
    );
    assert!(
        repo.list_usage_billing_events("tenant-other", 10)
            .await
            .expect("list other tenant usage history failed")
            .is_empty()
    );

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
    let mut updated_admin = delegated_admin.clone();
    updated_admin.subject = "admin-updated@example.com".to_string();
    updated_admin.roles = vec!["realm.admin".to_string()];
    repo.store_delegated_tenant_admin(&updated_admin)
        .await
        .expect("same-owner delegated admin update failed");
    assert_eq!(
        repo.list_delegated_tenant_admins("tenant-saas")
            .await
            .expect("list same-owner updated delegated admin failed"),
        vec![updated_admin.clone()]
    );
    let mut colliding_admin = updated_admin.clone();
    colliding_admin.tenant_id = "tenant-other".to_string();
    colliding_admin.subject = "attacker@example.com".to_string();
    colliding_admin.allowed_realm_ids = vec!["realm-other".to_string()];
    let error = repo
        .store_delegated_tenant_admin(&colliding_admin)
        .await
        .expect_err("cross-tenant duplicate delegated admin ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate ID must have conflict semantics, got {error:?}"
    );
    assert_eq!(
        repo.list_delegated_tenant_admins("tenant-saas")
            .await
            .expect("list incumbent delegated admin after collision failed"),
        vec![updated_admin.clone()]
    );
    assert!(
        repo.list_delegated_tenant_admins("tenant-other")
            .await
            .expect("list other tenant delegated admins failed")
            .is_empty()
    );
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
        package_entitlement_ids_json: serde_json::json!([]),
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

    assert!(
        repo.close_iga_access_review_campaign("tenant-iga", "review-1")
            .await
            .expect("close IGA access review campaign failed"),
        "closing an open campaign must report success"
    );
    let closed = repo
        .get_iga_access_review_campaign("tenant-iga", "review-1")
        .await
        .expect("get closed IGA access review campaign failed")
        .expect("closed IGA access review campaign missing");
    assert_eq!(closed.status, "closed");
    assert!(
        repo.close_iga_access_review_campaign("tenant-iga", "review-1")
            .await
            .expect("re-closing a closed campaign failed"),
        "closing an already-closed campaign must stay successful and idempotent"
    );
    assert!(
        !repo
            .close_iga_access_review_campaign("tenant-iga", "review-missing")
            .await
            .expect("close missing IGA access review campaign failed"),
        "missing campaign close must report absent"
    );
    assert!(
        repo.get_iga_access_review_campaign("tenant-iga", "review-missing")
            .await
            .expect("get missing IGA access review campaign failed")
            .is_none()
    );
    let mut other_tenant_campaign =
        sample_iga_access_review_campaign("review-other-tenant", 1_700_000_310);
    other_tenant_campaign.tenant_id = "tenant-other".to_string();
    repo.store_iga_access_review_campaign(&other_tenant_campaign)
        .await
        .expect("store other tenant IGA access review campaign failed");
    assert!(
        !repo
            .close_iga_access_review_campaign("tenant-iga", "review-other-tenant")
            .await
            .expect("close other tenant IGA access review campaign failed"),
        "other-tenant campaign close must report absent like a missing ID"
    );
    assert_eq!(
        repo.get_iga_access_review_campaign("tenant-other", "review-other-tenant")
            .await
            .expect("get other tenant IGA access review campaign failed")
            .expect("other tenant campaign must remain")
            .status,
        "open",
        "other-tenant close must not mutate the campaign"
    );

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
    let repo = sql_repo().await;
    assert_saas_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_saas_repository_round_trip() {
    let repo = file_repo("test_saas").await;
    assert_saas_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_sql_iga_repository_round_trip() {
    let repo = sql_repo().await;
    assert_iga_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn test_file_iga_repository_round_trip() {
    let repo = file_repo("test_iga").await;
    assert_iga_repository_round_trip(&repo).await;
}

#[tokio::test]
async fn sql_totp_step_consumption_single_winner() {
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-totp".into(),
        "https://id.example.com/realms/totp",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-totp".to_string(),
        realm_id: "realm-totp".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    repo.store_totp_credential(&TotpCredential {
        id: "totp-1".to_string(),
        user_id: "user-totp".to_string(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        enabled: true,
        last_used_step: None,
        created_at: 1000,
    })
    .await
    .unwrap();
    // Two claims for the same step race; exactly one wins.
    let r1 = repo.consume_totp_step("totp-1", 100);
    let r2 = repo.consume_totp_step("totp-1", 100);
    let (r1, r2) = tokio::join!(r1, r2);
    assert!(r1.unwrap() ^ r2.unwrap(), "exactly one step claim must win");
    // A consumed step never wins again; a later step still advances.
    assert!(!repo.consume_totp_step("totp-1", 100).await.unwrap());
    assert!(repo.consume_totp_step("totp-1", 101).await.unwrap());
    // Unknown credentials fail closed without persisting anything.
    assert!(!repo.consume_totp_step("totp-missing", 1).await.unwrap());
    // Re-storing (enrollment confirmation) upserts instead of conflicting.
    let confirmed = repo
        .get_totp_credential("user-totp")
        .await
        .unwrap()
        .unwrap();
    repo.store_totp_credential(&confirmed).await.unwrap();
    let stored = repo
        .get_totp_credential("user-totp")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.last_used_step, Some(101));
    assert_eq!(stored.created_at, 1000);
}

#[tokio::test]
async fn sql_refresh_rotation_single_winner() {
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-race".into(),
        "https://id.example.com/realms/race",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-race".to_string(),
        realm_id: "realm-race".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let now = qid_core::util::now_seconds();
    let family = test_family("tf-race", "user-race", "realm-race", "hash-v0", now, None);
    repo.create_token_family(&family).await.unwrap();
    // Both requests read "hash-v0" before either update (barrier after read).
    let r1 = repo.update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v1", 7000);
    let r2 = repo.update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v2", 7000);
    let (r1, r2) = tokio::join!(r1, r2);
    assert!(
        r1.is_ok() ^ r2.is_ok(),
        "exactly one overlapping rotation must win, got {r1:?} / {r2:?}"
    );
    // Stale expected hash must not rotate again.
    let stale = repo
        .update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v3", 7000)
        .await;
    assert!(stale.is_err(), "stale expected hash must be rejected");
    let stored = repo.get_token_family("tf-race").await.unwrap().unwrap();
    assert_eq!(
        stored.refresh_expires_at,
        Some(7000),
        "rotation must pin the deadline"
    );
}

#[tokio::test]
async fn sql_refresh_rotation_revoked_stays_revoked() {
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-rev".into(),
        "https://id.example.com/realms/rev",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-rev".to_string(),
        realm_id: "realm-rev".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let now = qid_core::util::now_seconds();
    let family = test_family("tf-revoked", "user-rev", "realm-rev", "hash-v0", now, None);
    repo.create_token_family(&family).await.unwrap();
    repo.revoke_token_family("tf-revoked").await.unwrap();
    // Revoking twice stays idempotent for concurrent reuse handling.
    repo.revoke_token_family("tf-revoked").await.unwrap();
    let result = repo
        .update_token_family_refresh_hash("tf-revoked", "hash-v0", "hash-v1", 7000)
        .await;
    assert!(
        result.is_err(),
        "no successful consumption after revocation"
    );
}

#[tokio::test]
async fn sql_scim_deprovisioned_at_persists_and_defaults_to_none() {
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-scim-deprov".into(),
        "https://id.example.com/realms/scim-deprov",
        None,
    )
    .await
    .unwrap();
    repo.create_scim_user(&ScimUser {
        id: "scim-user-deprov".to_string(),
        realm_id: "realm-scim-deprov".to_string(),
        external_id: Some("hr-deprov".to_string()),
        user_name: "deprov@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({"department": "Engineering"}),
        directory_provider_id: None,
        deprovisioned_at: Some(1_050),
        active: false,
    })
    .await
    .unwrap();
    let fetched = repo
        .get_scim_user("scim-user-deprov")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.deprovisioned_at, Some(1_050));

    let mut cleared = fetched;
    cleared.deprovisioned_at = None;
    repo.update_scim_user(&cleared).await.unwrap();
    let fetched = repo
        .get_scim_user("scim-user-deprov")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.deprovisioned_at, None);
}

async fn assert_scim_device_event_subscription_owner_contract<R>(repo: &R)
where
    R: RealmRepository + ScimRepository,
{
    repo.create_realm(
        &"tenant-owner".into(),
        &"realm-owner-a".into(),
        "https://owner-a.example.com",
        Some("Owner A"),
    )
    .await
    .expect("create owner realm A failed");
    repo.create_realm(
        &"tenant-owner".into(),
        &"realm-owner-b".into(),
        "https://owner-b.example.com",
        Some("Owner B"),
    )
    .await
    .expect("create owner realm B failed");

    // Device: same-realm updates still work.
    let device = ScimDeviceRecord {
        id: "scim-device-shared".to_string(),
        realm_id: "realm-owner-a".to_string(),
        display_name: Some("Phone A".to_string()),
        manufacturer: Some("Acme".to_string()),
        model: Some("One".to_string()),
        os: Some("QidOS".to_string()),
        os_version: Some("1.0".to_string()),
        last_seen: Some(1_000),
    };
    repo.upsert_scim_device(&device)
        .await
        .expect("initial device upsert failed");
    let mut updated_device = device.clone();
    updated_device.display_name = Some("Phone A2".to_string());
    updated_device.last_seen = Some(2_000);
    repo.upsert_scim_device(&updated_device)
        .await
        .expect("same-realm device update failed");
    assert_eq!(
        repo.get_scim_device("scim-device-shared")
            .await
            .expect("get updated device failed")
            .expect("updated device missing"),
        updated_device
    );
    assert_eq!(
        repo.list_scim_devices(&RealmId::from("realm-owner-a"))
            .await
            .expect("list owner realm devices failed"),
        vec![updated_device.clone()]
    );

    // Device: same global ID from another realm conflicts and changes nothing.
    let mut colliding_device = updated_device.clone();
    colliding_device.realm_id = "realm-owner-b".to_string();
    colliding_device.display_name = Some("Attacker phone".to_string());
    let error = repo
        .upsert_scim_device(&colliding_device)
        .await
        .expect_err("cross-realm device ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-realm device reuse must conflict, got {error:?}"
    );
    assert_eq!(
        repo.get_scim_device("scim-device-shared")
            .await
            .expect("get incumbent device after collision failed")
            .expect("incumbent device missing"),
        updated_device
    );
    assert_eq!(
        repo.list_scim_devices(&RealmId::from("realm-owner-a"))
            .await
            .expect("list incumbent devices after collision failed"),
        vec![updated_device.clone()]
    );
    assert!(
        repo.list_scim_devices(&RealmId::from("realm-owner-b"))
            .await
            .expect("list other realm devices failed")
            .is_empty()
    );

    // Event subscription: same-realm updates still work (`created_at` stays stable).
    let subscription = ScimEventSubscriptionRecord {
        id: "scim-sub-shared".to_string(),
        realm_id: "realm-owner-a".to_string(),
        callback_url: "https://a.example.com/hook".to_string(),
        event_types: vec!["user.created".to_string()],
        enabled: true,
        created_at: 1_000,
    };
    repo.upsert_scim_event_subscription(&subscription)
        .await
        .expect("initial subscription upsert failed");
    let mut updated_subscription = subscription.clone();
    updated_subscription.callback_url = "https://a.example.com/hook2".to_string();
    updated_subscription.event_types = vec!["user.created".to_string(), "user.updated".to_string()];
    updated_subscription.enabled = false;
    repo.upsert_scim_event_subscription(&updated_subscription)
        .await
        .expect("same-realm subscription update failed");
    assert_eq!(
        repo.get_scim_event_subscription("scim-sub-shared")
            .await
            .expect("get updated subscription failed")
            .expect("updated subscription missing"),
        updated_subscription
    );
    assert_eq!(
        repo.list_scim_event_subscriptions(&RealmId::from("realm-owner-a"))
            .await
            .expect("list owner realm subscriptions failed"),
        vec![updated_subscription.clone()]
    );

    // Event subscription: same global ID from another realm conflicts.
    let mut colliding_subscription = updated_subscription.clone();
    colliding_subscription.realm_id = "realm-owner-b".to_string();
    colliding_subscription.callback_url = "https://b.example.com/hook".to_string();
    let error = repo
        .upsert_scim_event_subscription(&colliding_subscription)
        .await
        .expect_err("cross-realm subscription ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-realm subscription reuse must conflict, got {error:?}"
    );
    assert_eq!(
        repo.get_scim_event_subscription("scim-sub-shared")
            .await
            .expect("get incumbent subscription after collision failed")
            .expect("incumbent subscription missing"),
        updated_subscription
    );
    assert_eq!(
        repo.list_scim_event_subscriptions(&RealmId::from("realm-owner-a"))
            .await
            .expect("list incumbent subscriptions after collision failed"),
        vec![updated_subscription.clone()]
    );
    assert!(
        repo.list_scim_event_subscriptions(&RealmId::from("realm-owner-b"))
            .await
            .expect("list other realm subscriptions failed")
            .is_empty()
    );
}

#[tokio::test]
async fn test_sql_scim_device_event_subscription_owner_contract() {
    let repo = sql_repo().await;
    assert_scim_device_event_subscription_owner_contract(&repo).await;
}

#[tokio::test]
async fn test_file_scim_device_event_subscription_owner_contract() {
    let repo = file_repo("test_scim_owner_contract").await;
    assert_scim_device_event_subscription_owner_contract(&repo).await;
}

fn siem_delivery_record(
    id: &str,
    realm_id: Option<&str>,
    endpoint_url: &str,
    event_count: u64,
    attempts: u32,
    updated_at: u64,
) -> SiemDeliveryRecord {
    SiemDeliveryRecord {
        id: id.to_string(),
        realm_id: realm_id.map(str::to_string),
        endpoint_url: endpoint_url.to_string(),
        payload_json: serde_json::json!({"event_count": event_count}),
        attempts,
        next_retry_at: None,
        status: SiemDeliveryStatus::Pending,
        last_error: None,
        created_at: 1_000,
        updated_at,
    }
}

async fn assert_siem_delivery_owner_contract<R>(repo: &R)
where
    R: SiemDeliveryRepository,
{
    // Same `Some(realm)` update succeeds and replaces mutable fields.
    let delivery = siem_delivery_record(
        "siem-shared-scoped",
        Some("realm-siem-a"),
        "https://siem.example.com/a",
        1,
        0,
        1_000,
    );
    repo.upsert_siem_delivery(&delivery)
        .await
        .expect("initial scoped SIEM delivery upsert failed");
    let mut updated = delivery.clone();
    updated.payload_json = serde_json::json!({"event_count": 2});
    updated.attempts = 2;
    updated.next_retry_at = Some(2_000);
    updated.last_error = Some("temporary failure".to_string());
    updated.created_at = 1_400;
    updated.updated_at = 1_500;
    repo.upsert_siem_delivery(&updated)
        .await
        .expect("same-scope SIEM delivery update failed");
    let mut incumbent = updated.clone();
    incumbent.created_at = delivery.created_at;
    assert_eq!(
        repo.get_siem_delivery("siem-shared-scoped")
            .await
            .expect("get updated scoped delivery failed")
            .expect("updated scoped delivery missing"),
        incumbent
    );
    assert_eq!(
        repo.list_siem_deliveries(Some("realm-siem-a"), None, 10)
            .await
            .expect("list scoped deliveries failed"),
        vec![incumbent.clone()]
    );

    // Same global ID under another realm conflicts and changes nothing.
    let mut colliding = incumbent.clone();
    colliding.realm_id = Some("realm-siem-b".to_string());
    colliding.endpoint_url = "https://siem.example.com/attacker".to_string();
    colliding.payload_json = serde_json::json!({"event_count": 99});
    let error = repo
        .upsert_siem_delivery(&colliding)
        .await
        .expect_err("cross-realm SIEM delivery ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-realm SIEM reuse must conflict, got {error:?}"
    );
    assert_eq!(
        repo.get_siem_delivery("siem-shared-scoped")
            .await
            .expect("get incumbent delivery after collision failed")
            .expect("incumbent delivery missing"),
        incumbent
    );
    assert_eq!(
        repo.list_siem_deliveries(Some("realm-siem-a"), None, 10)
            .await
            .expect("list incumbent deliveries after collision failed"),
        vec![incumbent.clone()]
    );
    assert!(
        repo.list_siem_deliveries(Some("realm-siem-b"), None, 10)
            .await
            .expect("list other realm deliveries failed")
            .is_empty()
    );

    // Same-scope status lifecycle still works after the ownership guard.
    repo.mark_siem_delivery_status(
        "siem-shared-scoped",
        SiemDeliveryStatus::Delivered,
        3,
        None,
        None,
        2_000,
    )
    .await
    .expect("scoped SIEM status transition failed");
    let delivered = repo
        .get_siem_delivery("siem-shared-scoped")
        .await
        .expect("get delivered SIEM record failed")
        .expect("delivered SIEM record missing");
    assert_eq!(delivered.status, SiemDeliveryStatus::Delivered);
    assert_eq!(delivered.attempts, 3);

    // Same `None` (global scope) update succeeds.
    let global = siem_delivery_record(
        "siem-shared-global",
        None,
        "https://siem.example.com/global",
        1,
        0,
        1_000,
    );
    repo.upsert_siem_delivery(&global)
        .await
        .expect("initial global SIEM delivery upsert failed");
    let mut updated_global = global.clone();
    updated_global.payload_json = serde_json::json!({"event_count": 2});
    updated_global.attempts = 1;
    updated_global.next_retry_at = Some(3_000);
    updated_global.updated_at = 1_500;
    repo.upsert_siem_delivery(&updated_global)
        .await
        .expect("same global-scope SIEM delivery update failed");
    assert_eq!(
        repo.get_siem_delivery("siem-shared-global")
            .await
            .expect("get updated global delivery failed")
            .expect("updated global delivery missing"),
        updated_global
    );

    // `None` incumbent with a `Some(realm)` rewrite conflicts and preserves state.
    let mut global_collision = updated_global.clone();
    global_collision.realm_id = Some("realm-siem-a".to_string());
    global_collision.payload_json = serde_json::json!({"event_count": 99});
    let error = repo
        .upsert_siem_delivery(&global_collision)
        .await
        .expect_err("global-to-realm SIEM delivery ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "global-to-realm SIEM reuse must conflict, got {error:?}"
    );
    assert_eq!(
        repo.get_siem_delivery("siem-shared-global")
            .await
            .expect("get incumbent global delivery after collision failed")
            .expect("incumbent global delivery missing"),
        updated_global
    );

    // `Some(realm)` incumbent with a `None` rewrite conflicts as well.
    let mut scoped_to_global = incumbent.clone();
    scoped_to_global.realm_id = None;
    scoped_to_global.payload_json = serde_json::json!({"event_count": 99});
    let error = repo
        .upsert_siem_delivery(&scoped_to_global)
        .await
        .expect_err("realm-to-global SIEM delivery ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "realm-to-global SIEM reuse must conflict, got {error:?}"
    );
    assert_eq!(
        repo.get_siem_delivery("siem-shared-scoped")
            .await
            .expect("get incumbent scoped delivery after global collision failed")
            .expect("incumbent scoped delivery missing"),
        delivered
    );
}

#[tokio::test]
async fn test_sql_siem_delivery_owner_contract() {
    let repo = sql_repo().await;
    assert_siem_delivery_owner_contract(&repo).await;
}

#[tokio::test]
async fn test_file_siem_delivery_owner_contract() {
    let repo = file_repo("test_siem_owner_contract").await;
    assert_siem_delivery_owner_contract(&repo).await;
}

async fn assert_compliance_evidence_pack_create_only_contract<R>(repo: &R)
where
    R: SaasRepository,
{
    let incumbent = sample_compliance_evidence_pack();
    repo.store_compliance_evidence_pack(&incumbent)
        .await
        .expect("initial compliance evidence pack insert failed");

    let mut cross_tenant_collision = incumbent.clone();
    cross_tenant_collision.tenant_id = "tenant-other".to_string();
    cross_tenant_collision.controls = vec!["ATTACKER-CONTROL".to_string()];
    cross_tenant_collision.object_uri = "s3://attacker/overwrite.jsonl".to_string();
    cross_tenant_collision.sha256_hex = "f".repeat(64);
    cross_tenant_collision.generated_at += 1;
    let error = repo
        .store_compliance_evidence_pack(&cross_tenant_collision)
        .await
        .expect_err("cross-tenant compliance pack ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate compliance pack ID must return Conflict, got {error:?}"
    );

    assert_eq!(
        repo.list_compliance_evidence_packs("tenant-saas")
            .await
            .expect("list incumbent compliance packs failed"),
        vec![incumbent]
    );
    assert!(
        repo.list_compliance_evidence_packs("tenant-other")
            .await
            .expect("list other tenant compliance packs failed")
            .is_empty()
    );
}

#[tokio::test]
async fn test_sql_compliance_evidence_pack_create_only_contract() {
    let repo = sql_repo().await;
    assert_compliance_evidence_pack_create_only_contract(&repo).await;
}

#[tokio::test]
async fn test_file_compliance_evidence_pack_create_only_contract() {
    let repo = file_repo("test_compliance_evidence_pack_collision").await;
    assert_compliance_evidence_pack_create_only_contract(&repo).await;
}
/// A client id is answered in one read over the named realms.
#[tokio::test]
async fn test_client_lookup_across_realms_reads_only_the_named_realms() {
    let repo = sql_repo().await;
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-a".into(),
        "https://id.example.com/realms/a",
        None,
    )
    .await
    .unwrap();
    repo.create_realm(
        &"tenant-1".into(),
        &"realm-b".into(),
        "https://id.example.com/realms/b",
        None,
    )
    .await
    .unwrap();
    repo.create_client(&sample_cross_realm_client(
        "client-a",
        "realm-a",
        "shared-app",
    ))
    .await
    .unwrap();
    repo.create_client(&sample_cross_realm_client(
        "client-b",
        "realm-b",
        "shared-app",
    ))
    .await
    .unwrap();
    repo.create_client(&sample_cross_realm_client(
        "client-c",
        "realm-a",
        "other-app",
    ))
    .await
    .unwrap();

    let both = repo
        .find_clients_by_client_id(
            &[RealmId::from("realm-a"), RealmId::from("realm-b")],
            "shared-app",
        )
        .await
        .unwrap();
    assert_eq!(both.len(), 2);

    let one = repo
        .find_clients_by_client_id(&[RealmId::from("realm-a")], "shared-app")
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].realm_id, "realm-a");

    let unnamed = repo
        .find_clients_by_client_id(&[RealmId::from("realm-b")], "other-app")
        .await
        .unwrap();
    assert!(unnamed.is_empty());

    let none = repo
        .find_clients_by_client_id(&[], "shared-app")
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn test_sql_client_require_par_round_trip() {
    let repo = sql_repo().await;
    repo.create_realm(
        &TenantId::from("tenant-client-par"),
        &RealmId::from("realm-client-par"),
        "https://client-par.example.com",
        Some("Client PAR Realm"),
    )
    .await
    .unwrap();
    let mut flagged = sample_saas_client();
    flagged.id = "client-par-flagged".to_string();
    flagged.realm_id = "realm-client-par".to_string();
    flagged.client_id = "par-required-app".to_string();
    flagged.require_pushed_authorization_requests = true;
    repo.create_client(&flagged).await.unwrap();
    let loaded = repo
        .get_client_by_client_id(&RealmId::from("realm-client-par"), "par-required-app")
        .await
        .unwrap()
        .expect("flagged client must be found");
    assert!(
        loaded.require_pushed_authorization_requests,
        "the RFC 9126 PAR flag must survive SQL persistence"
    );

    let mut cleared = loaded.clone();
    cleared.require_pushed_authorization_requests = false;
    repo.update_client(&cleared).await.unwrap();
    let reloaded = repo
        .get_client_by_client_id(&RealmId::from("realm-client-par"), "par-required-app")
        .await
        .unwrap()
        .expect("updated client must be found");
    assert!(
        !reloaded.require_pushed_authorization_requests,
        "clearing the PAR flag must survive SQL persistence"
    );

    // Records written before the migration carry the schema default, so
    // the flag stays opt-in rather than locking existing clients out.
    let mut plain = sample_saas_client();
    plain.id = "client-par-plain".to_string();
    plain.realm_id = "realm-client-par".to_string();
    plain.client_id = "par-plain-app".to_string();
    assert!(
        !plain.require_pushed_authorization_requests,
        "the PAR flag defaults to false for new clients"
    );
    repo.create_client(&plain).await.unwrap();
    let found = repo
        .get_client_by_client_id(&RealmId::from("realm-client-par"), "par-plain-app")
        .await
        .unwrap()
        .expect("plain client must be found");
    assert!(
        !found.require_pushed_authorization_requests,
        "an unmarked client must stay unmarked in SQL"
    );
}

#[tokio::test]
async fn test_polling_grant_target_migration_defaults_existing_rows() {
    let url = db_url();
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    for sql in [
        include_str!("../migrations/20250101000001_initial_schema.sql"),
        include_str!("../migrations/20250618000002_device_authorization_grants.sql"),
        include_str!("../migrations/20250618000011_ciba_grants.sql"),
        include_str!("../migrations/20250618000025_device_authorization_polling.sql"),
        include_str!("../migrations/20250618000026_ciba_polling.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO realms (id, tenant_id, issuer, created_at) VALUES ('test', 'tenant', 'https://id.example.com', 1)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO device_authorization_grants (device_code_hash, user_code, client_id, realm_id, scopes, expires_at, created_at) VALUES ('device', 'user-code', 'client', 'test', '[\"read\"]', 3000, 1)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO backchannel_authentication_grants (auth_req_id_hash, client_id, realm_id, login_hint, scopes, expires_at, created_at) VALUES ('ciba', 'client', 'test', 'user@example.com', '[\"read\"]', 3000, 1)").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20261026000001_grant_targets.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let device = repo
        .get_device_authorization_grant("device")
        .await
        .unwrap()
        .unwrap();
    assert!(device.resource.is_empty() && device.audience.is_empty());
    assert_eq!(device.scopes, ["read"]);
    let ciba = repo
        .get_backchannel_authentication_grant("ciba")
        .await
        .unwrap()
        .unwrap();
    assert!(ciba.resource.is_empty() && ciba.audience.is_empty());
    assert_eq!(ciba.scopes, ["read"]);
    sqlx::raw_sql(r#"UPDATE device_authorization_grants SET audience = '"QZX"' WHERE device_code_hash = 'device'; UPDATE backchannel_authentication_grants SET resource = '"QZX"' WHERE auth_req_id_hash = 'ciba';"#)
        .execute(&pool)
        .await
        .unwrap();
    let clean = |error: qid_core::QidError| !error.message().contains("QZX");
    assert!(clean(
        repo.get_device_authorization_grant("device")
            .await
            .unwrap_err()
    ));
    assert!(clean(
        repo.get_backchannel_authentication_grant("ciba")
            .await
            .unwrap_err()
    ));
    pool.close().await;
    repo.close().await;
}
