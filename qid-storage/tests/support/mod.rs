#![allow(dead_code)]

use qid_core::models::{
    Admin, AdminApproval, AdminElevation, AuditEvent, BackchannelAuthenticationGrant,
    CiamConsentGrant, CiamVerificationChallengeRecord, Client, ClientType, Device,
    DeviceAuthorizationGrant, FedCmIdentity, IgaAccessGrantRecord, IgaAccessRequestRecord,
    IgaAccessReviewCampaignRecord, IgaAccessReviewDecisionRecord, IgaApprovalRecord,
    IgaCertificationRecord, IgaFindingRecord, IgaJitPrivilegeGrantRecord, ParRequest,
    PasswordResetToken, PolicyBundle, RelationshipTuple, ServiceAccount, TotpCredential, User,
    WebAuthnCredential, WorkloadIdentity,
};
use qid_core::tenant::{RealmId, TenantId};
use qid_storage::{FileRepository, SqlRepository, prelude::*};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

static DB_SEQ: AtomicU16 = AtomicU16::new(0);
static SCHEMA_TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();

pub fn sqlite_main_path(path: &Path) -> PathBuf {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.to_path_buf();
    };
    ["-wal", "-shm", "-journal"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .map_or_else(|| path.to_path_buf(), |name| path.with_file_name(name))
}

pub fn remove_sqlite_database_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        match std::fs::remove_file(PathBuf::from(candidate)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn clean_storage_test_databases(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let database = sqlite_main_path(&entry?.path());
        let name = database
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("test_") && name.ends_with(".db") {
            remove_sqlite_database_files(&database)?;
        }
    }
    Ok(())
}

/// Build and close one migrated schema for independent per-test database copies.
pub async fn schema_template_path() -> &'static PathBuf {
    SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let path = std::env::temp_dir()
                .join("qid_test")
                .join("schema_template.db");
            remove_sqlite_database_files(&path).expect("remove stale storage schema template");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .expect("connect storage schema template failed");
            repo.migrate()
                .await
                .expect("migrate storage schema template failed");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "schema template has a sidecar after closing the pool: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
}

pub fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    // Clean old test databases once per process
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        clean_storage_test_databases(&dir).expect("remove stale storage test database files");
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

pub async fn sql_repo() -> SqlRepository {
    let url = db_url();
    let path = Path::new(
        url.strip_prefix("sqlite:")
            .expect("test database url has sqlite prefix"),
    );
    // Migrations run once in the schema template and fresh-database coverage stays
    // in test_connect_and_migrate; copying keeps every test database isolated
    // without repeating the migration set.
    std::fs::copy(schema_template_path().await, path).expect("copy storage schema template");
    SqlRepository::connect(&url).await.expect("connect failed")
}

pub async fn file_repo(prefix: &str) -> FileRepository {
    let dir = std::env::temp_dir().join("qid_test");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("{prefix}_{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate().await.expect("file migration failed");
    repo
}

/// The owner-bound contract of a user: a record ID names one user and an
/// email names one user inside a realm, so a second user that carries
/// either is refused and the incumbent is left unchanged.
pub async fn assert_user_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + UserRepository,
{
    let realm = RealmId("realm-user-identity".to_string());
    repo.create_realm(
        &TenantId("tenant-user-identity".to_string()),
        &realm,
        "https://user-identity.example.com",
        Some("User Identity Realm"),
    )
    .await
    .expect("create user identity realm failed");
    let other_realm = RealmId("realm-user-identity-other".to_string());
    repo.create_realm(
        &TenantId("tenant-user-identity-other".to_string()),
        &other_realm,
        "https://user-identity-other.example.com",
        Some("Other User Identity Realm"),
    )
    .await
    .expect("create other user identity realm failed");

    let user = User {
        id: "user-identity-alice".to_string(),
        realm_id: realm.0.clone(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.expect("create user failed");

    // A second user that carries the email in the realm is refused.
    let duplicate_email = User {
        id: "user-identity-alice-duplicate".to_string(),
        ..user.clone()
    };
    let err = repo
        .create_user(&duplicate_email)
        .await
        .expect_err("a second user for one email in a realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second user for one email in a realm must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the incumbent user must still exist");
    assert_eq!(
        stored.email, user.email,
        "the refusal changed the incumbent"
    );
    assert_eq!(stored.display_name, user.display_name);
    assert_eq!(stored.realm_id, user.realm_id);

    // A second user that carries the record ID is refused.
    let duplicate_id = User {
        id: user.id.clone(),
        email: Some("bob@example.com".to_string()),
        ..user.clone()
    };
    let err = repo
        .create_user(&duplicate_id)
        .await
        .expect_err("a second user for one record ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second user for one record ID must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the incumbent user must still exist");
    assert_eq!(
        stored.email, user.email,
        "the refusal changed the incumbent"
    );

    // The same email in another realm names another user, so it is allowed.
    let other = User {
        id: "user-identity-other-alice".to_string(),
        realm_id: other_realm.0.clone(),
        ..user.clone()
    };
    repo.create_user(&other)
        .await
        .expect("the same email in another realm must be allowed");

    // A user ID is global, so an ID another realm holds is refused too.
    let foreign_id = User {
        id: user.id.clone(),
        realm_id: other_realm.0.clone(),
        email: Some("bob@example.com".to_string()),
        ..user.clone()
    };
    let err = repo
        .create_user(&foreign_id)
        .await
        .expect_err("a user ID another realm holds must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a user ID another realm holds must be a conflict, got: {}",
        err.message()
    );

    // NULL email values do not collide, but the primary key still does.
    for id in ["user-no-email-a", "user-no-email-b"] {
        let anonymous = User {
            id: id.to_string(),
            email: None,
            ..user.clone()
        };
        repo.create_user(&anonymous)
            .await
            .expect("NULL emails may repeat");
        let err = repo
            .create_user(&anonymous)
            .await
            .expect_err("IDs may not repeat");
        assert!(
            matches!(err, qid_core::error::QidError::Conflict { message }
            if message == format!("user record ID {id} already exists"))
        );
    }

    // The update path holds the same rule: a user of the realm may not
    // take an email another user of that realm already holds, and both
    // incumbents are left unchanged.
    let bob = User {
        id: "user-identity-bob".to_string(),
        realm_id: realm.0.clone(),
        email: Some("bob@example.com".to_string()),
        ..user.clone()
    };
    repo.create_user(&bob).await.expect("create user failed");
    let mut renamed = bob.clone();
    renamed.email = Some("alice@example.com".to_string());
    let err = repo
        .update_user(&renamed, None)
        .await
        .expect_err("an update that takes another user's email must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "an update that takes another user's email must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_user_by_id(&bob.id)
        .await
        .expect("get user by id failed")
        .expect("the incumbent user must still exist");
    assert_eq!(stored.email, bob.email, "the refusal changed the incumbent");
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the incumbent user must still exist");
    assert_eq!(
        stored.email, user.email,
        "the refusal changed the incumbent"
    );

    // A user may keep its own email.
    let mut unchanged = user.clone();
    unchanged.display_name = Some("Alice (renamed)".to_string());
    repo.update_user(&unchanged, None)
        .await
        .expect("a user keeping its own email must be allowed");
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the user must still exist");
    assert_eq!(stored.email, user.email);
    assert_eq!(stored.display_name, unchanged.display_name);

    // The owner (realm) of a user does not change on update: an input that
    // names another realm is ignored, and the stored realm is unchanged.
    let mut moved = user.clone();
    moved.realm_id = other_realm.0.clone();
    moved.display_name = Some("moved".to_string());
    repo.update_user(&moved, None)
        .await
        .expect("an update may not change the owner, but must still apply");
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the user must still exist");
    assert_eq!(stored.realm_id, user.realm_id, "update changed the owner");
}

pub async fn assert_workload_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + WorkloadRepository,
{
    let realm = RealmId("realm-workload-identity".to_string());
    repo.create_realm(
        &TenantId("tenant-workload-identity".to_string()),
        &realm,
        "https://workload-identity.example.com",
        Some("Workload Identity Realm"),
    )
    .await
    .expect("create workload identity realm failed");
    let other_realm = RealmId("realm-workload-identity-other".to_string());
    repo.create_realm(
        &TenantId("tenant-workload-identity-other".to_string()),
        &other_realm,
        "https://workload-identity-other.example.com",
        Some("Other Workload Identity Realm"),
    )
    .await
    .expect("create other workload identity realm failed");

    let identity = WorkloadIdentity {
        id: "workload-identity-api".to_string(),
        realm_id: realm.0.clone(),
        spiffe_id: "spiffe://corp.example/workload/identity-api".to_string(),
        description: Some("API workload".to_string()),
        trust_domain: "corp.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-api"}),
    };
    repo.create_workload_identity(&identity)
        .await
        .expect("create workload identity failed");

    // A second identity for one SPIFFE ID in one realm is refused.
    let duplicate_spiffe = WorkloadIdentity {
        id: "workload-identity-api-duplicate".to_string(),
        ..identity.clone()
    };
    let err = repo
        .create_workload_identity(&duplicate_spiffe)
        .await
        .expect_err("a second identity for one SPIFFE ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::BadRequest { .. }),
        "a second identity for one SPIFFE ID must be a bad request, got: {}",
        err.message()
    );
    assert!(
        err.message()
            .contains("SPIFFE identity already registered in this realm"),
        "the refused registration must name the registered SPIFFE ID, got: {}",
        err.message()
    );
    let listed = repo
        .list_workload_identities(&realm)
        .await
        .expect("list workload identities failed");
    assert_eq!(
        listed.len(),
        1,
        "the refused registration changed the realm identities"
    );
    assert_eq!(listed[0].id, identity.id);

    // An identity ID that belongs to another realm's identity is a conflict.
    let collision = WorkloadIdentity {
        id: identity.id.clone(),
        realm_id: other_realm.0.clone(),
        spiffe_id: "spiffe://other.example/workload/worker".to_string(),
        description: Some("Other workload".to_string()),
        trust_domain: "other.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-other"}),
    };
    let err = repo
        .create_workload_identity(&collision)
        .await
        .expect_err("an identity ID of another realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "an identity ID of another realm must be a conflict, got: {}",
        err.message()
    );
    assert!(
        err.message()
            .contains("workload identity ID belongs to another identity"),
        "the refused collision must name the owner of the ID, got: {}",
        err.message()
    );
    assert!(
        repo.list_workload_identities(&other_realm)
            .await
            .expect("list other realm workload identities failed")
            .is_empty(),
        "the collision created an identity in the other realm"
    );
    let listed = repo
        .list_workload_identities(&realm)
        .await
        .expect("list workload identities failed");
    assert_eq!(
        listed.len(),
        1,
        "the collision changed the incumbent identity"
    );
    assert_eq!(listed[0].realm_id, identity.realm_id);
    assert_eq!(listed[0].spiffe_id, identity.spiffe_id);

    // The same identity may be written again: ID, realm and SPIFFE ID match.
    let mut updated = identity.clone();
    updated.description = Some("API workload (updated)".to_string());
    repo.create_workload_identity(&updated)
        .await
        .expect("re-create of the same workload identity failed");
    let listed = repo
        .list_workload_identities(&realm)
        .await
        .expect("list workload identities failed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].description, updated.description);
    assert_eq!(
        repo.get_workload_identity_by_spiffe(&realm, &identity.spiffe_id)
            .await
            .expect("get workload identity by SPIFFE ID failed")
            .map(|found| found.id),
        Some(identity.id.clone()),
        "the SPIFFE ID lookup must answer the registered identity"
    );
}

pub async fn assert_ciam_consent_grant_owner_conflict<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CiamRepository,
{
    repo.create_realm(
        &"tenant-consent".into(),
        &"realm-consent".into(),
        "https://consent.example.com",
        Some("Consent realm"),
    )
    .await
    .expect("create consent realm failed");
    repo.create_realm(
        &"tenant-consent".into(),
        &"realm-consent-other".into(),
        "https://consent-other.example.com",
        Some("Other consent realm"),
    )
    .await
    .expect("create other consent realm failed");
    for (id, realm) in [
        ("user-consent", "realm-consent"),
        ("user-consent-other", "realm-consent"),
        ("user-consent-realm", "realm-consent-other"),
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
        .expect("create consent user failed");
    }

    let grant = CiamConsentGrant {
        id: "consent-owner-1".to_string(),
        realm_id: "realm-consent".to_string(),
        user_id: "user-consent".to_string(),
        client_id: "client-consent".to_string(),
        granted_claims: vec!["email".to_string()],
        terms_version: Some("2026-06".to_string()),
        granted_at_epoch_seconds: 1_800_000_000,
        revoked: false,
    };
    repo.store_ciam_consent_grant(&grant)
        .await
        .expect("store initial consent grant failed");

    let mut updated = grant.clone();
    updated.granted_claims = vec!["email".to_string(), "profile".to_string()];
    repo.store_ciam_consent_grant(&updated)
        .await
        .expect("same-owner consent update failed");
    assert_eq!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent"),
            "user-consent",
            Some("client-consent")
        )
        .await
        .expect("list same-owner consent failed"),
        vec![updated.clone()]
    );

    let mut cross_user = updated.clone();
    cross_user.user_id = "user-consent-other".to_string();
    cross_user.granted_claims = vec!["phone".to_string()];
    let error = repo
        .store_ciam_consent_grant(&cross_user)
        .await
        .expect_err("cross-user consent ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-user reuse must conflict, got {error:?}"
    );

    let mut cross_realm = updated.clone();
    cross_realm.realm_id = "realm-consent-other".to_string();
    cross_realm.user_id = "user-consent-realm".to_string();
    cross_realm.granted_claims = vec!["phone".to_string()];
    let error = repo
        .store_ciam_consent_grant(&cross_realm)
        .await
        .expect_err("cross-realm consent ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-realm reuse must conflict, got {error:?}"
    );

    let mut cross_client = updated.clone();
    cross_client.client_id = "client-other".to_string();
    cross_client.granted_claims = vec!["phone".to_string()];
    let error = repo
        .store_ciam_consent_grant(&cross_client)
        .await
        .expect_err("cross-client consent ID reuse must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "cross-client reuse must conflict, got {error:?}"
    );

    assert_eq!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent"),
            "user-consent",
            Some("client-consent")
        )
        .await
        .expect("list incumbent consent after collisions failed"),
        vec![updated.clone()]
    );
    assert!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent"),
            "user-consent-other",
            Some("client-consent")
        )
        .await
        .expect("list cross-user consent failed")
        .is_empty()
    );
    assert!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent-other"),
            "user-consent-realm",
            Some("client-consent")
        )
        .await
        .expect("list cross-realm consent failed")
        .is_empty()
    );
    assert!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent"),
            "user-consent",
            Some("client-other")
        )
        .await
        .expect("list cross-client consent failed")
        .is_empty()
    );
}

pub async fn assert_ciam_consent_grant_revoke_idempotent<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CiamRepository,
{
    repo.create_realm(
        &"tenant-consent-revoke".into(),
        &"realm-consent-revoke".into(),
        "https://consent-revoke.example.com",
        Some("Consent revoke realm"),
    )
    .await
    .expect("create consent revoke realm failed");
    repo.create_user(&User {
        id: "user-consent-revoke".to_string(),
        realm_id: "realm-consent-revoke".to_string(),
        email: Some("user-consent-revoke@example.com".to_string()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .expect("create consent revoke user failed");

    repo.revoke_ciam_consent_grant("consent-revoke-missing", 1_800_000_100)
        .await
        .expect("unknown consent revoke must succeed");
    assert!(
        repo.list_ciam_consent_grants(
            &RealmId::from("realm-consent-revoke"),
            "user-consent-revoke",
            None
        )
        .await
        .expect("list after unknown consent revoke failed")
        .is_empty(),
        "unknown consent revoke must create no grant"
    );

    let grant = CiamConsentGrant {
        id: "consent-revoke-1".to_string(),
        realm_id: "realm-consent-revoke".to_string(),
        user_id: "user-consent-revoke".to_string(),
        client_id: "client-consent-revoke".to_string(),
        granted_claims: vec!["email".to_string()],
        terms_version: Some("2026-06".to_string()),
        granted_at_epoch_seconds: 1_800_000_000,
        revoked: false,
    };
    repo.store_ciam_consent_grant(&grant)
        .await
        .expect("store consent grant failed");

    repo.revoke_ciam_consent_grant("consent-revoke-1", 1_800_000_100)
        .await
        .expect("revoke consent grant failed");
    let grants = repo
        .list_ciam_consent_grants(
            &RealmId::from("realm-consent-revoke"),
            "user-consent-revoke",
            Some("client-consent-revoke"),
        )
        .await
        .expect("list revoked consent grant failed");
    assert_eq!(grants.len(), 1, "revocation must keep the incumbent grant");
    assert!(grants[0].revoked, "revocation must mark the grant revoked");

    repo.revoke_ciam_consent_grant("consent-revoke-1", 1_800_000_200)
        .await
        .expect("repeat consent revoke must succeed");
    let grants = repo
        .list_ciam_consent_grants(
            &RealmId::from("realm-consent-revoke"),
            "user-consent-revoke",
            Some("client-consent-revoke"),
        )
        .await
        .expect("list repeat-revoked consent grant failed");
    assert_eq!(grants.len(), 1, "repeat revocation must keep the grant");
    assert!(grants[0].revoked, "incumbent must stay revoked");
}

pub async fn assert_client_id_uniqueness<R>(repo: &R)
where
    R: RealmRepository + ClientRepository,
{
    let realm = RealmId("realm-client-unique".to_string());
    repo.create_realm(
        &TenantId("tenant-client-unique".to_string()),
        &realm,
        "https://client-unique.example.com",
        Some("Client Unique Realm"),
    )
    .await
    .expect("create client unique realm failed");
    let other_realm = RealmId("realm-client-unique-other".to_string());
    repo.create_realm(
        &TenantId("tenant-client-unique-other".to_string()),
        &other_realm,
        "https://client-unique-other.example.com",
        Some("Other Client Unique Realm"),
    )
    .await
    .expect("create other client unique realm failed");

    let client = sample_cross_realm_client("client-unique-a", &realm.0, "shared-app");
    repo.create_client(&client)
        .await
        .expect("create client failed");

    // A second client in the same realm cannot carry the same client id.
    let duplicate = sample_cross_realm_client("client-unique-b", &realm.0, "shared-app");
    let err = repo
        .create_client(&duplicate)
        .await
        .expect_err("a second client with one client id must be refused");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a duplicate client id must be a conflict, got: {}",
        err.message()
    );
    let listed = repo
        .list_clients(&realm)
        .await
        .expect("list clients failed");
    assert_eq!(
        listed.len(),
        1,
        "the refused client changed the realm's clients"
    );

    // The same client id in another realm is another client.
    let elsewhere = sample_cross_realm_client("client-unique-c", &other_realm.0, "shared-app");
    repo.create_client(&elsewhere)
        .await
        .expect("the same client id in another realm must be allowed");
    let found = repo
        .find_clients_by_client_id(&[realm.clone(), other_realm.clone()], "shared-app")
        .await
        .expect("find clients by client id failed");
    assert_eq!(found.len(), 2, "one client per realm must be found");
}

pub async fn assert_client_id_ambiguity<R>(repo: &R)
where
    R: RealmRepository + ClientRepository,
{
    let realm = RealmId("realm-client-ambiguity".to_string());
    repo.create_realm(
        &TenantId("tenant-client-ambiguity".to_string()),
        &realm,
        "https://client-ambiguity.example.com",
        Some("Client Ambiguity Realm"),
    )
    .await
    .expect("create client ambiguity realm failed");
    let other_realm = RealmId("realm-client-ambiguity-other".to_string());
    repo.create_realm(
        &TenantId("tenant-client-ambiguity-other".to_string()),
        &other_realm,
        "https://client-ambiguity-other.example.com",
        Some("Other Client Ambiguity Realm"),
    )
    .await
    .expect("create other client ambiguity realm failed");

    let client = sample_cross_realm_client("client-ambiguity-a", &realm.0, "shared-app");
    repo.create_client(&client)
        .await
        .expect("create client failed");

    // The id the realm holds is no ambiguity.
    qid_storage::ensure_client_id_unambiguous(
        repo,
        &[realm.clone(), other_realm.clone()],
        "shared-app",
        &realm,
    )
    .await
    .expect("the realm's own client id must be no ambiguity");

    // The same id in another served realm is a refusal that names the
    // realm that holds it.
    let elsewhere = sample_cross_realm_client("client-ambiguity-b", &other_realm.0, "shared-app");
    repo.create_client(&elsewhere)
        .await
        .expect("create the other client failed");
    let error = qid_storage::ensure_client_id_unambiguous(
        repo,
        &[realm.clone(), other_realm.clone()],
        "shared-app",
        &other_realm,
    )
    .await
    .expect_err("an id two served realms hold must be refused");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "the refusal must be a conflict, got: {}",
        error.message()
    );
    assert!(
        error.message().contains("shared-app"),
        "the refusal must name the client id, got: {}",
        error.message()
    );
    assert!(
        error.message().contains(&realm.0),
        "the refusal must name the realm that holds the id, got: {}",
        error.message()
    );

    // A realm the deployment does not serve holds no client of a request,
    // so an id it carries is no ambiguity.
    qid_storage::ensure_client_id_unambiguous(
        repo,
        std::slice::from_ref(&other_realm),
        "shared-app",
        &realm,
    )
    .await
    .expect("an unserved realm must not make the id ambiguous");
}

pub async fn assert_workload_identity_delete_scope<R>(repo: &R)
where
    R: RealmRepository + WorkloadRepository,
{
    let realm = RealmId("realm-workload-delete".to_string());
    repo.create_realm(
        &TenantId("tenant-workload-delete".to_string()),
        &realm,
        "https://workload-delete.example.com",
        Some("Workload Delete Realm"),
    )
    .await
    .expect("create workload delete realm failed");
    let other_realm = RealmId("realm-workload-delete-other".to_string());
    repo.create_realm(
        &TenantId("tenant-workload-delete-other".to_string()),
        &other_realm,
        "https://workload-delete-other.example.com",
        Some("Other Workload Delete Realm"),
    )
    .await
    .expect("create other workload delete realm failed");

    let identity = WorkloadIdentity {
        id: "workload-delete-api".to_string(),
        realm_id: realm.0.clone(),
        spiffe_id: "spiffe://corp.example/workload/delete-api".to_string(),
        description: Some("API workload".to_string()),
        trust_domain: "corp.example".to_string(),
        authorities_json: serde_json::json!({"issuer": "ca-api"}),
    };
    repo.create_workload_identity(&identity)
        .await
        .expect("create workload identity failed");

    // Another realm may not delete this identity.
    let err = repo
        .delete_workload_identity(&other_realm, &identity.id)
        .await
        .expect_err("another realm must not delete the identity");
    assert!(
        matches!(err, qid_core::error::QidError::NotFound { .. }),
        "another realm's delete must be not found, got: {}",
        err.message()
    );
    assert_eq!(
        repo.list_workload_identities(&realm)
            .await
            .expect("list workload identities failed")
            .len(),
        1,
        "another realm's delete removed the identity"
    );

    // An unknown identity is not found in its realm.
    let err = repo
        .delete_workload_identity(&realm, "workload-delete-unknown")
        .await
        .expect_err("an unknown identity must not be deleted");
    assert!(
        matches!(err, qid_core::error::QidError::NotFound { .. }),
        "an unknown identity must be not found, got: {}",
        err.message()
    );

    // The owning realm deletes its own identity.
    repo.delete_workload_identity(&realm, &identity.id)
        .await
        .expect("the owning realm must delete its identity");
    assert!(
        repo.list_workload_identities(&realm)
            .await
            .expect("list workload identities failed")
            .is_empty(),
        "the deleted identity is still listed"
    );
    assert!(
        repo.get_workload_identity_by_spiffe(&realm, &identity.spiffe_id)
            .await
            .expect("get workload identity by spiffe failed")
            .is_none(),
        "the deleted identity is still found by its SPIFFE ID"
    );
}

pub fn sample_cross_realm_client(id: &str, realm_id: &str, client_id: &str) -> Client {
    Client {
        id: id.to_string(),
        realm_id: realm_id.to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
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
    }
}

/// A WebAuthn credential record ID belongs to one user and cannot be reused
/// to attach another user's authenticator.
pub async fn assert_webauthn_credential_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CredentialRepository,
{
    let realm = RealmId("realm-webauthn-credential-ownership".to_string());
    repo.create_realm(
        &TenantId("tenant-webauthn-credential-ownership".to_string()),
        &realm,
        "https://webauthn-credential-ownership.example.com",
        Some("WebAuthn Credential Ownership Realm"),
    )
    .await
    .expect("create WebAuthn credential realm failed");
    let user = User {
        id: "user-webauthn-credential-alice".to_string(),
        realm_id: realm.0.clone(),
        email: None,
        email_verified: false,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user)
        .await
        .expect("create WebAuthn credential user failed");
    let other_user = User {
        id: "user-webauthn-credential-bob".to_string(),
        display_name: Some("Bob".to_string()),
        ..user.clone()
    };
    repo.create_user(&other_user)
        .await
        .expect("create other WebAuthn credential user failed");

    let credential = WebAuthnCredential {
        id: "webauthn-credential-ownership".to_string(),
        user_id: user.id.clone(),
        credential_id: vec![1],
        public_key: vec![2],
        counter: 1,
        aaguid: vec![0; 16],
        device_name: Some("Alice key".to_string()),
        created_at: 1,
    };
    repo.store_webauthn_credential(&credential)
        .await
        .expect("store WebAuthn credential failed");

    let duplicate = WebAuthnCredential {
        user_id: other_user.id.clone(),
        credential_id: vec![3],
        public_key: vec![4],
        device_name: Some("Bob key".to_string()),
        ..credential.clone()
    };
    let err = repo
        .store_webauthn_credential(&duplicate)
        .await
        .expect_err("a second user cannot claim one credential record ID");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second user for one credential record ID must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_webauthn_credentials(&user.id)
        .await
        .expect("list incumbent WebAuthn credentials failed");
    assert_eq!(stored.len(), 1, "the refusal changed the incumbent list");
    assert_eq!(stored[0].user_id, credential.user_id);
    assert_eq!(stored[0].credential_id, credential.credential_id);
    assert_eq!(stored[0].public_key, credential.public_key);
    assert_eq!(stored[0].device_name, credential.device_name);
    let listed = repo
        .list_webauthn_credentials(&user.id)
        .await
        .expect("list incumbent WebAuthn credentials failed");
    assert_eq!(
        serde_json::to_value(&listed).unwrap(),
        serde_json::to_value(&stored).unwrap(),
        "list and get must return identical owner-scoped credentials"
    );
    assert!(
        repo.list_webauthn_credentials(&other_user.id)
            .await
            .expect("list duplicate user's WebAuthn credentials failed")
            .is_empty()
    );
    assert!(
        repo.get_webauthn_credentials(&other_user.id)
            .await
            .expect("list duplicate user's WebAuthn credentials failed")
            .is_empty()
    );

    repo.update_webauthn_credential_counter(&other_user.id, &credential.id, 7)
        .await
        .expect("wrong-owner counter update should be a no-op");
    let stored = repo.get_webauthn_credentials(&user.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].counter, 1,
        "wrong owner changed incumbent counter"
    );

    repo.update_webauthn_credential_counter(&user.id, &credential.id, 8)
        .await
        .expect("owner counter update failed");
    let stored = repo.get_webauthn_credentials(&user.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].counter, 8, "owner update did not persist");

    repo.update_webauthn_credential_counter(&user.id, "unknown-credential", 9)
        .await
        .expect("unknown credential update should be a no-op");
    let stored = repo.get_webauthn_credentials(&user.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].counter, 8, "unknown ID changed incumbent counter");

    let sibling = WebAuthnCredential {
        id: "alice-other-credential".to_string(),
        ..credential.clone()
    };
    let other_credential = WebAuthnCredential {
        id: "bob-credential".to_string(),
        ..duplicate
    };
    repo.store_webauthn_credential(&sibling).await.unwrap();
    repo.store_webauthn_credential(&other_credential)
        .await
        .unwrap();
    let alice_before = repo.get_webauthn_credentials(&user.id).await.unwrap();
    let bob_before = repo.get_webauthn_credentials(&other_user.id).await.unwrap();
    repo.delete_webauthn_credential(&other_user.id, &credential.id)
        .await
        .expect("wrong-owner deletion should be a no-op");
    repo.delete_webauthn_credential(&user.id, "unknown-credential")
        .await
        .expect("unknown credential deletion should be a no-op");
    assert_eq!(
        serde_json::to_value(repo.get_webauthn_credentials(&user.id).await.unwrap()).unwrap(),
        serde_json::to_value(&alice_before).unwrap(),
        "no-op deletion changed the incumbent list"
    );
    assert_eq!(
        serde_json::to_value(repo.get_webauthn_credentials(&other_user.id).await.unwrap()).unwrap(),
        serde_json::to_value(&bob_before).unwrap(),
        "no-op deletion changed the other user's list"
    );
    repo.delete_webauthn_credential(&user.id, &credential.id)
        .await
        .expect("owner deletion failed");
    let remaining = repo.get_webauthn_credentials(&user.id).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        serde_json::to_value(&remaining[0]).unwrap(),
        serde_json::to_value(&sibling).unwrap()
    );
    assert_eq!(
        serde_json::to_value(repo.get_webauthn_credentials(&other_user.id).await.unwrap()).unwrap(),
        serde_json::to_value(&bob_before).unwrap(),
        "owner deletion changed the other user's list"
    );
    repo.delete_webauthn_credential(&user.id, &credential.id)
        .await
        .expect("repeated deletion should be a no-op");
    assert_eq!(
        serde_json::to_value(repo.get_webauthn_credentials(&user.id).await.unwrap()).unwrap(),
        serde_json::to_value(&remaining).unwrap()
    );
}

/// The owner-bound contract of a service account: a record ID names one
/// account, so reusing it cannot replace or cross realm boundaries.
pub async fn assert_service_account_identity_ownership<R>(repo: &R)
where
    R: ServiceAccountRepository,
{
    let account = ServiceAccount {
        id: "service-account-ownership".to_string(),
        client_id: "client-alice".to_string(),
        realm_id: "realm-service-account-alice".to_string(),
        description: Some("Alice account".to_string()),
        created_at: 1,
    };
    repo.create_service_account(&account)
        .await
        .expect("create service account failed");

    let duplicate = ServiceAccount {
        client_id: "client-bob".to_string(),
        realm_id: "realm-service-account-bob".to_string(),
        description: Some("Bob account".to_string()),
        ..account.clone()
    };
    let err = repo
        .create_service_account(&duplicate)
        .await
        .expect_err("a second service account for one record ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second service account for one record ID must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_service_account_by_client_id(&account.realm_id, &account.client_id)
        .await
        .expect("get service account failed")
        .expect("the incumbent service account must still exist");
    assert_eq!(
        stored.id, account.id,
        "the refusal changed the incumbent ID"
    );
    assert_eq!(
        stored.realm_id, account.realm_id,
        "the refusal changed the incumbent owner"
    );
    assert_eq!(
        stored.client_id, account.client_id,
        "the refusal changed the incumbent client"
    );
    assert_eq!(
        stored.description, account.description,
        "the refusal changed the incumbent description"
    );
    assert_eq!(
        stored.created_at, account.created_at,
        "the refusal changed the incumbent creation time"
    );
    assert!(
        repo.get_service_account_by_client_id(&duplicate.realm_id, &duplicate.client_id)
            .await
            .expect("get duplicate service account failed")
            .is_none()
    );
}

/// Scoped service-account deletes refuse missing/foreign rows atomically,
/// while context-free deletes retain their idempotent ID-only behavior.
pub async fn assert_service_account_realm_delete<R>(repo: &R)
where
    R: ServiceAccountRepository,
{
    let account = ServiceAccount {
        id: "service-account-delete".to_string(),
        client_id: "client-service-account-delete".to_string(),
        realm_id: "realm-service-account-delete".to_string(),
        description: Some("Account to delete".to_string()),
        created_at: 1,
    };
    repo.create_service_account(&account)
        .await
        .expect("create service account failed");

    let foreign = repo
        .delete_service_account(Some("another-realm"), &account.id)
        .await
        .expect_err("a foreign realm must not delete the service account");
    assert!(matches!(
        foreign,
        qid_core::error::QidError::NotFound { .. }
    ));
    let missing = repo
        .delete_service_account(Some(&account.realm_id), "missing-service-account")
        .await
        .expect_err("a scoped missing account must be not found");
    assert!(matches!(
        missing,
        qid_core::error::QidError::NotFound { .. }
    ));
    let stored = repo
        .get_service_account_by_client_id(&account.realm_id, &account.client_id)
        .await
        .expect("read the incumbent service account")
        .expect("a foreign delete must leave the account unchanged");
    assert_eq!(stored.realm_id, account.realm_id);
    assert_eq!(stored.client_id, account.client_id);

    repo.delete_service_account(Some(&account.realm_id), &account.id)
        .await
        .expect("the owning realm should delete its account");
    assert!(
        repo.get_service_account_by_client_id(&account.realm_id, &account.client_id)
            .await
            .expect("read deleted service account")
            .is_none()
    );

    repo.create_service_account(&account)
        .await
        .expect("recreate service account for ID-reuse test");
    repo.delete_service_account(None, &account.id)
        .await
        .expect("unscoped delete should retain ID-only behavior");
    let replacement = ServiceAccount {
        realm_id: "replacement-realm".to_string(),
        client_id: "replacement-client".to_string(),
        ..account.clone()
    };
    repo.create_service_account(&replacement)
        .await
        .expect("create replacement using the released ID");
    let stale = repo
        .delete_service_account(Some(&account.realm_id), &account.id)
        .await
        .expect_err("a stale realm must not delete a replacement account");
    assert!(matches!(stale, qid_core::error::QidError::NotFound { .. }));
    let stored = repo
        .get_service_account_by_client_id(&replacement.realm_id, &replacement.client_id)
        .await
        .expect("read replacement service account")
        .expect("stale scoped deletion must preserve the replacement");
    assert_eq!(stored.id, replacement.id);
    assert_eq!(stored.realm_id, replacement.realm_id);
    repo.delete_service_account(None, &replacement.id)
        .await
        .expect("unscoped deletion should remove a replacement");
    repo.delete_service_account(None, &replacement.id)
        .await
        .expect("repeated unscoped missing deletion should be a no-op");
}

/// The owner-bound contract of a device: a record ID names one device, so a
/// second device that carries the same ID is refused and the incumbent is
/// left unchanged.
pub async fn assert_device_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + UserRepository + DeviceRepository,
{
    let realm = RealmId("realm-device-identity".to_string());
    repo.create_realm(
        &TenantId("tenant-device-identity".to_string()),
        &realm,
        "https://device-identity.example.com",
        Some("Device Identity Realm"),
    )
    .await
    .expect("create device identity realm failed");
    let user = qid_core::models::User {
        id: "user-device-identity".to_string(),
        realm_id: realm.0.clone(),
        email: Some("device@example.com".to_string()),
        email_verified: true,
        display_name: Some("Device User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user)
        .await
        .expect("create device user failed");

    let device = Device {
        id: "device-identity-alice".to_string(),
        user_id: user.id.clone(),
        realm_id: realm.0.clone(),
        device_name: Some("Alice device".to_string()),
        device_type: "browser".to_string(),
        posture: vec![],
        registered_at: 1,
        last_seen_at: 1,
    };
    repo.register_device(&device)
        .await
        .expect("register device failed");

    // A second device that carries the record ID is refused.
    let duplicate = Device {
        id: device.id.clone(),
        device_name: Some("duplicate".to_string()),
        ..device.clone()
    };
    let err = repo
        .register_device(&duplicate)
        .await
        .expect_err("a second device for one record ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second device for one record ID must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_device(&device.id)
        .await
        .expect("get device failed")
        .expect("the incumbent device must still exist");
    assert_eq!(
        stored.device_name, device.device_name,
        "the refusal changed the incumbent"
    );
}

/// The owner-bound contract of a FedCM identity: a record ID names one
/// identity, so a second identity that carries the same ID is refused and
/// the incumbent is left unchanged.
pub async fn assert_fedcm_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + FedCmRepository,
{
    let realm = RealmId("realm-fedcm-identity".to_string());
    repo.create_realm(
        &TenantId("tenant-fedcm-identity".to_string()),
        &realm,
        "https://fedcm-identity.example.com",
        Some("FedCM Identity Realm"),
    )
    .await
    .expect("create fedcm identity realm failed");

    let identity = FedCmIdentity {
        id: "fedcm-identity-alice".to_string(),
        realm_id: realm.0.clone(),
        account_id: "account-alice".to_string(),
        email: "alice@example.com".to_string(),
        name: Some("Alice".to_string()),
        given_name: Some("Alice".to_string()),
        picture_url: None,
        approved_clients: vec![],
    };
    repo.store_fedcm_identity(&identity)
        .await
        .expect("store fedcm identity failed");

    let duplicate = FedCmIdentity {
        id: identity.id.clone(),
        name: Some("duplicate".to_string()),
        ..identity.clone()
    };
    let err = repo
        .store_fedcm_identity(&duplicate)
        .await
        .expect_err("a second fedcm identity for one record ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a second fedcm identity for one record ID must be a conflict, got: {}",
        err.message()
    );
    let stored = repo
        .get_fedcm_identities(&realm, "account-alice")
        .await
        .expect("get fedcm identities failed");
    let incumbent = stored
        .iter()
        .find(|i| i.id == identity.id)
        .expect("incumbent must exist");
    assert_eq!(
        incumbent.name, identity.name,
        "the refusal changed the incumbent"
    );
}

/// Audit event IDs are globally unique even though each immutable event belongs
/// to one realm's append-only hash chain; collisions never change that history.
pub async fn assert_audit_event_identity_ownership<R>(repo: &R)
where
    R: AuditRepository + RealmRepository,
{
    let realm = RealmId("realm-audit-event-ownership".to_string());
    repo.create_realm(
        &TenantId("tenant-audit-event-ownership".to_string()),
        &realm,
        "https://audit-event-ownership.example.com",
        Some("Audit Event Ownership Realm"),
    )
    .await
    .expect("create audit event realm failed");
    let other_realm = RealmId("realm-audit-event-ownership-other".to_string());
    repo.create_realm(
        &TenantId("tenant-audit-event-ownership-other".to_string()),
        &other_realm,
        "https://audit-event-ownership-other.example.com",
        Some("Other Audit Event Ownership Realm"),
    )
    .await
    .expect("create other audit event realm failed");

    let incumbent = AuditEvent {
        id: "audit-event-ownership".to_string(),
        realm_id: Some(realm.0.clone()),
        actor: "incumbent-actor".to_string(),
        action: "incumbent-action".to_string(),
        target_type: "user".to_string(),
        target_id: "user-1".to_string(),
        reason: "original event".to_string(),
        metadata_json: serde_json::json!({"state": "original"}),
        created_at: 1_700_000_000,
        previous_hash: None,
        event_hash: None,
    };
    repo.append_audit_event(&incumbent)
        .await
        .expect("append incumbent audit event failed");

    // A duplicate ID in the same stream is refused and cannot replace the
    // immutable event or append a second history entry.
    let duplicate = AuditEvent {
        actor: "replacement-actor".to_string(),
        action: "replacement-action".to_string(),
        reason: "attempted replacement".to_string(),
        ..incumbent.clone()
    };
    let err = repo
        .append_audit_event(&duplicate)
        .await
        .expect_err("a duplicate audit event ID in one realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a duplicate audit event ID must be a conflict, got: {}",
        err.message()
    );

    // The database key is global, so another realm cannot claim the ID.
    let cross_owner = AuditEvent {
        realm_id: Some(other_realm.0.clone()),
        actor: "other-realm-actor".to_string(),
        ..duplicate
    };
    let err = repo
        .append_audit_event(&cross_owner)
        .await
        .expect_err("an audit event ID held by another realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-realm audit event ID must be a conflict, got: {}",
        err.message()
    );

    let events = repo
        .list_audit_events(Some(&realm), 10)
        .await
        .expect("list audit events failed");
    assert_eq!(
        events.len(),
        1,
        "a refused event changed append-only history"
    );
    assert_eq!(events[0].id, incumbent.id);
    assert_eq!(events[0].actor, incumbent.actor);
    assert_eq!(events[0].action, incumbent.action);
    assert_eq!(events[0].reason, incumbent.reason);
    assert_eq!(events[0].metadata_json, incumbent.metadata_json);
    assert!(
        repo.verify_audit_chain(Some(&realm))
            .await
            .expect("verify audit chain failed")
            .valid,
        "refused duplicate IDs must leave the audit chain valid"
    );
    assert!(
        repo.list_audit_events(Some(&other_realm), 10)
            .await
            .expect("list other realm audit events failed")
            .is_empty(),
        "a refused cross-realm ID collision created a foreign event"
    );
}

/// Admin approval IDs are global and one-shot: collision retries must not
/// replace an approval or reset its consumed state.
pub async fn assert_admin_approval_identity_ownership<R>(repo: &R)
where
    R: AdminRepository,
{
    let incumbent_approver = Admin {
        id: "admin-approval-incumbent-approver".to_string(),
        tenant_id: "tenant-admin-approval-incumbent".to_string(),
        subject: "incumbent-approver".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    let incumbent_target = Admin {
        id: "admin-approval-incumbent-target".to_string(),
        tenant_id: incumbent_approver.tenant_id.clone(),
        subject: "incumbent-target".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    repo.upsert_admin(&incumbent_approver)
        .await
        .expect("create incumbent approver failed");
    repo.upsert_admin(&incumbent_target)
        .await
        .expect("create incumbent target failed");

    let other_approver = Admin {
        id: "admin-approval-other-approver".to_string(),
        tenant_id: "tenant-admin-approval-other".to_string(),
        subject: "other-approver".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    let other_target = Admin {
        id: "admin-approval-other-target".to_string(),
        tenant_id: other_approver.tenant_id.clone(),
        subject: "other-target".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    repo.upsert_admin(&other_approver)
        .await
        .expect("create other approver failed");
    repo.upsert_admin(&other_target)
        .await
        .expect("create other target failed");

    let approval = AdminApproval {
        id: "admin-approval-ownership".to_string(),
        tenant_id: incumbent_approver.tenant_id.clone(),
        approver_admin_id: incumbent_approver.id.clone(),
        target_admin_id: incumbent_target.id.clone(),
        reason: Some("original approval".to_string()),
        approved_at: 1_700_000_001,
        expires_at: 1_700_000_100,
        consumed: false,
    };
    repo.store_admin_approval(&approval)
        .await
        .expect("store incumbent approval failed");
    assert!(
        repo.consume_admin_approval_if_unconsumed(&approval.id)
            .await
            .expect("consume incumbent approval failed"),
        "the incumbent approval should be consumable once"
    );

    // Replaying its original unconsumed form cannot reset the lifecycle.
    let duplicate = AdminApproval {
        reason: Some("attempted replacement".to_string()),
        ..approval.clone()
    };
    let err = repo
        .store_admin_approval(&duplicate)
        .await
        .expect_err("a duplicate approval ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a duplicate approval ID must be a conflict, got: {}",
        err.message()
    );

    // Approval IDs are global; another tenant cannot claim the same ID.
    let cross_owner = AdminApproval {
        tenant_id: other_approver.tenant_id.clone(),
        approver_admin_id: other_approver.id,
        target_admin_id: other_target.id,
        consumed: false,
        ..duplicate
    };
    let err = repo
        .store_admin_approval(&cross_owner)
        .await
        .expect_err("an approval ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant approval ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .get_admin_approval(&approval.id)
        .await
        .expect("get incumbent approval failed")
        .expect("incumbent approval must remain stored");
    assert_eq!(stored.tenant_id, approval.tenant_id);
    assert_eq!(stored.approver_admin_id, approval.approver_admin_id);
    assert_eq!(stored.target_admin_id, approval.target_admin_id);
    assert_eq!(stored.reason, approval.reason);
    assert!(stored.consumed, "the duplicate store reset consumed state");
    assert!(
        !repo
            .consume_admin_approval_if_unconsumed(&approval.id)
            .await
            .expect("second consumption attempt failed"),
        "a duplicate store made the approval reusable"
    );
}

/// An admin-elevation ID names one identity-bound context and must never
/// replace or move the incumbent to another tenant.
pub async fn assert_admin_elevation_identity_ownership<R>(repo: &R)
where
    R: AdminRepository,
{
    let admin = Admin {
        id: "admin-elevation-owner".to_string(),
        tenant_id: "tenant-admin-elevation".to_string(),
        subject: "owner".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    repo.upsert_admin(&admin)
        .await
        .expect("create admin elevation owner failed");
    let other_admin = Admin {
        id: "admin-elevation-other-owner".to_string(),
        tenant_id: "tenant-admin-elevation-other".to_string(),
        subject: "other-owner".to_string(),
        roles: vec!["admin".to_string()],
        created_at: 1_700_000_000,
    };
    repo.upsert_admin(&other_admin)
        .await
        .expect("create other admin elevation owner failed");

    let elevation = AdminElevation {
        id: "admin-elevation-identity".to_string(),
        tenant_id: admin.tenant_id.clone(),
        admin_id: admin.id.clone(),
        acr: Some("urn:example:loa:2".to_string()),
        amr: vec!["pwd".to_string(), "otp".to_string()],
        elevation_expires_at: 1_700_000_100,
        created_at: 1_700_000_001,
    };
    repo.store_admin_elevation(&elevation)
        .await
        .expect("store incumbent admin elevation failed");

    let duplicate = AdminElevation {
        acr: Some("urn:example:loa:1".to_string()),
        amr: vec!["pwd".to_string()],
        elevation_expires_at: 1_700_000_200,
        ..elevation.clone()
    };
    let err = repo
        .store_admin_elevation(&duplicate)
        .await
        .expect_err("a duplicate admin elevation ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a duplicate admin elevation ID must be a conflict, got: {}",
        err.message()
    );

    let cross_owner = AdminElevation {
        tenant_id: other_admin.tenant_id.clone(),
        admin_id: other_admin.id,
        acr: Some("urn:example:loa:3".to_string()),
        ..duplicate
    };
    let err = repo
        .store_admin_elevation(&cross_owner)
        .await
        .expect_err("an elevation ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant admin elevation ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .get_admin_elevation(&elevation.id)
        .await
        .expect("get incumbent admin elevation failed")
        .expect("incumbent admin elevation must remain stored");
    assert_eq!(stored.tenant_id, elevation.tenant_id);
    assert_eq!(stored.admin_id, elevation.admin_id);
    assert_eq!(stored.acr, elevation.acr);
    assert_eq!(stored.amr, elevation.amr);
    assert_eq!(stored.elevation_expires_at, elevation.elevation_expires_at);
    assert_eq!(stored.created_at, elevation.created_at);
}

/// A challenge ID is immutable so a duplicate cannot reset its single-use state.
pub async fn assert_ciam_verification_challenge_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CiamRepository,
{
    let realm = RealmId("realm-ciam-verification-owner".to_string());
    repo.create_realm(
        &TenantId("tenant-ciam-verification-owner".to_string()),
        &realm,
        "https://ciam-verification-owner.example.com",
        Some("CIAM Verification Owner"),
    )
    .await
    .expect("create CIAM verification owner realm failed");
    let other_realm = RealmId("realm-ciam-verification-other".to_string());
    repo.create_realm(
        &TenantId("tenant-ciam-verification-other".to_string()),
        &other_realm,
        "https://ciam-verification-other.example.com",
        Some("Other CIAM Verification Realm"),
    )
    .await
    .expect("create other CIAM verification realm failed");

    let user = User {
        id: "user-ciam-verification-owner".to_string(),
        realm_id: realm.0.clone(),
        email: Some("owner@example.com".to_string()),
        email_verified: false,
        display_name: Some("Owner".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user)
        .await
        .expect("create CIAM verification owner user failed");
    let other_user = User {
        id: "user-ciam-verification-other".to_string(),
        realm_id: other_realm.0.clone(),
        email: Some("other@example.com".to_string()),
        email_verified: false,
        display_name: Some("Other".to_string()),
        ..user.clone()
    };
    repo.create_user(&other_user)
        .await
        .expect("create other CIAM verification user failed");

    let challenge = CiamVerificationChallengeRecord {
        id: "ciam-verification-identity".to_string(),
        realm_id: realm.0.clone(),
        user_id: user.id.clone(),
        channel: "email".to_string(),
        address: "owner@example.com".to_string(),
        purpose: "verify_email".to_string(),
        code_hash: "incumbent-code-hash".to_string(),
        attempt_count: 0,
        expires_at_epoch_seconds: 1_700_000_100,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_ciam_verification_challenge(&challenge)
        .await
        .expect("store incumbent CIAM verification challenge failed");
    for (attempt_realm, id) in [(&realm, "unknown-challenge"), (&other_realm, &challenge.id)] {
        let err = repo
            .attempt_ciam_verification_challenge(
                attempt_realm,
                id,
                &challenge.code_hash,
                false,
                1_700_000_040,
                5,
            )
            .await
            .expect_err("unknown or foreign-realm challenge consumption must fail");
        assert!(
            matches!(err, qid_core::error::QidError::NotFound { .. }),
            "unknown or foreign-realm consumption must be NotFound, got: {}",
            err.message()
        );
        assert_eq!(
            repo.get_ciam_verification_challenge(&realm, &challenge.id)
                .await
                .expect("get challenge after rejected consumption failed"),
            Some(challenge.clone())
        );
    }
    let err = repo
        .attempt_ciam_verification_challenge(
            &realm,
            &challenge.id,
            &challenge.code_hash,
            false,
            1_700_000_101,
            5,
        )
        .await
        .expect_err("an expired challenge must not be consumed");
    assert!(matches!(err, qid_core::error::QidError::Conflict { .. }));
    assert_eq!(
        repo.get_ciam_verification_challenge(&realm, &challenge.id)
            .await
            .expect("get challenge after expired consumption failed"),
        Some(challenge.clone()),
        "expired consumption must leave the challenge unchanged"
    );
    repo.attempt_ciam_verification_challenge(
        &realm,
        &challenge.id,
        &challenge.code_hash,
        true,
        1_700_000_100,
        5,
    )
    .await
    .expect("a challenge is valid at the inclusive expiry second");
    for (attempt_realm, is_owner) in [(&realm, true), (&other_realm, false)] {
        let err = repo
            .attempt_ciam_verification_challenge(
                attempt_realm,
                &challenge.id,
                &challenge.code_hash,
                true,
                1_700_000_100,
                5,
            )
            .await
            .expect_err("consumed challenge must not be consumed again");
        assert!(
            if is_owner {
                matches!(err, qid_core::error::QidError::Conflict { .. })
            } else {
                matches!(err, qid_core::error::QidError::NotFound { .. })
            },
            "repeat must be Conflict for owner and NotFound for foreign realm, got: {}",
            err.message()
        );
    }

    let bounded = CiamVerificationChallengeRecord {
        id: "ciam-verification-bounded".to_string(),
        realm_id: realm.0.clone(),
        user_id: user.id.clone(),
        channel: "email".to_string(),
        address: "owner@example.com".to_string(),
        purpose: "verify_email".to_string(),
        code_hash: "bounded-code-hash".to_string(),
        attempt_count: 0,
        expires_at_epoch_seconds: 1_700_000_100,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_ciam_verification_challenge(&bounded)
        .await
        .expect("store bounded CIAM challenge failed");
    let err = repo
        .attempt_ciam_verification_challenge(
            &realm,
            &bounded.id,
            "stale-code-hash",
            false,
            1_700_000_010,
            2,
        )
        .await
        .expect_err("an attempt against a stale challenge hash must fail");
    assert!(matches!(err, qid_core::error::QidError::Conflict { .. }));
    for attempted_at in [1_700_000_010, 1_700_000_020] {
        repo.attempt_ciam_verification_challenge(
            &realm,
            &bounded.id,
            &bounded.code_hash,
            false,
            attempted_at,
            2,
        )
        .await
        .expect("wrong codes should be counted until the configured limit");
    }
    let exhausted = repo
        .get_ciam_verification_challenge(&realm, &bounded.id)
        .await
        .expect("read exhausted CIAM challenge failed")
        .expect("bounded CIAM challenge missing");
    assert_eq!(exhausted.attempt_count, 2);
    assert_eq!(exhausted.consumed_at_epoch_seconds, None);
    let err = repo
        .attempt_ciam_verification_challenge(
            &realm,
            &bounded.id,
            &bounded.code_hash,
            false,
            1_700_000_030,
            2,
        )
        .await
        .expect_err("an exhausted CIAM challenge must refuse further attempts");
    assert!(matches!(err, qid_core::error::QidError::Conflict { .. }));
    assert_eq!(
        repo.get_ciam_verification_challenge(&realm, &bounded.id)
            .await
            .expect("re-read exhausted CIAM challenge failed"),
        Some(exhausted),
        "an exhausted attempt must not mutate the challenge"
    );

    let concurrent = CiamVerificationChallengeRecord {
        id: "ciam-verification-concurrent".to_string(),
        code_hash: "concurrent-code-hash".to_string(),
        attempt_count: 0,
        consumed_at_epoch_seconds: None,
        ..bounded
    };
    repo.store_ciam_verification_challenge(&concurrent)
        .await
        .expect("store concurrent CIAM challenge failed");
    let (a, b, c, d, e) = tokio::join!(
        repo.attempt_ciam_verification_challenge(
            &realm,
            &concurrent.id,
            &concurrent.code_hash,
            false,
            1_700_000_010,
            3
        ),
        repo.attempt_ciam_verification_challenge(
            &realm,
            &concurrent.id,
            &concurrent.code_hash,
            false,
            1_700_000_010,
            3
        ),
        repo.attempt_ciam_verification_challenge(
            &realm,
            &concurrent.id,
            &concurrent.code_hash,
            false,
            1_700_000_010,
            3
        ),
        repo.attempt_ciam_verification_challenge(
            &realm,
            &concurrent.id,
            &concurrent.code_hash,
            false,
            1_700_000_010,
            3
        ),
        repo.attempt_ciam_verification_challenge(
            &realm,
            &concurrent.id,
            &concurrent.code_hash,
            false,
            1_700_000_010,
            3
        ),
    );
    assert_eq!(
        [&a, &b, &c, &d, &e]
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        3,
        "the cross-backend attempt limit must be atomic under concurrency"
    );
    for result in [&a, &b, &c, &d, &e] {
        if let Err(error) = result {
            assert!(
                matches!(error, qid_core::error::QidError::Conflict { .. }),
                "exhausted concurrent attempts must conflict, got: {}",
                error.message()
            );
        }
    }
    assert_eq!(
        repo.get_ciam_verification_challenge(&realm, &concurrent.id)
            .await
            .expect("read concurrent CIAM challenge failed")
            .expect("concurrent CIAM challenge missing")
            .attempt_count,
        3
    );

    let same_realm_duplicate = CiamVerificationChallengeRecord {
        code_hash: "replacement-code-hash".to_string(),
        consumed_at_epoch_seconds: None,
        ..challenge.clone()
    };
    let err = repo
        .store_ciam_verification_challenge(&same_realm_duplicate)
        .await
        .expect_err("a duplicate challenge ID in one realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-realm duplicate challenge ID must be a conflict, got: {}",
        err.message()
    );

    let cross_realm_duplicate = CiamVerificationChallengeRecord {
        realm_id: other_realm.0.clone(),
        user_id: other_user.id,
        address: "other@example.com".to_string(),
        code_hash: "foreign-code-hash".to_string(),
        consumed_at_epoch_seconds: None,
        ..challenge.clone()
    };
    let err = repo
        .store_ciam_verification_challenge(&cross_realm_duplicate)
        .await
        .expect_err("a challenge ID held by another realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-realm duplicate challenge ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .get_ciam_verification_challenge(&realm, &challenge.id)
        .await
        .expect("get incumbent CIAM verification challenge failed")
        .expect("incumbent CIAM verification challenge must remain stored");
    assert_eq!(
        stored,
        CiamVerificationChallengeRecord {
            attempt_count: 1,
            consumed_at_epoch_seconds: Some(1_700_000_100),
            ..challenge
        }
    );
    assert!(
        repo.get_ciam_verification_challenge(&other_realm, &same_realm_duplicate.id)
            .await
            .expect("get foreign-realm challenge failed")
            .is_none()
    );
}

/// A password-reset token ID is immutable so retries cannot clear consumption.
pub async fn assert_password_reset_token_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CiamRepository,
{
    let realm = RealmId("realm-password-reset-owner".to_string());
    repo.create_realm(
        &TenantId("tenant-password-reset-owner".to_string()),
        &realm,
        "https://password-reset-owner.example.com",
        Some("Password Reset Owner"),
    )
    .await
    .expect("create password reset owner realm failed");
    let other_realm = RealmId("realm-password-reset-other".to_string());
    repo.create_realm(
        &TenantId("tenant-password-reset-other".to_string()),
        &other_realm,
        "https://password-reset-other.example.com",
        Some("Other Password Reset Realm"),
    )
    .await
    .expect("create other password reset realm failed");

    let user = User {
        id: "user-password-reset-owner".to_string(),
        realm_id: realm.0.clone(),
        email: Some("owner@example.com".to_string()),
        email_verified: true,
        display_name: Some("Owner".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user)
        .await
        .expect("create password reset owner user failed");
    let other_user = User {
        id: "user-password-reset-other".to_string(),
        realm_id: other_realm.0.clone(),
        email: Some("other@example.com".to_string()),
        email_verified: true,
        display_name: Some("Other".to_string()),
        ..user.clone()
    };
    repo.create_user(&other_user)
        .await
        .expect("create other password reset user failed");

    let token = PasswordResetToken {
        id: "password-reset-identity".to_string(),
        realm_id: realm.0.clone(),
        user_id: user.id.clone(),
        token_hash: "incumbent-token-hash".to_string(),
        device_id: Some("device-owner".to_string()),
        risk_json: serde_json::json!({"score": 4}),
        expires_at_epoch_seconds: 1_700_000_100,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_password_reset_token(&token)
        .await
        .expect("store incumbent password reset token failed");
    let err = repo
        .consume_password_reset_token("unknown-password-reset", 1_700_000_040)
        .await
        .expect_err("unknown password reset token consumption must fail");
    assert!(
        matches!(err, qid_core::error::QidError::NotFound { .. }),
        "unknown consumption must be NotFound, got: {}",
        err.message()
    );
    assert_eq!(
        repo.get_password_reset_token(&token.id)
            .await
            .expect("get token after rejected consumption failed"),
        Some(token.clone())
    );
    repo.consume_password_reset_token(&token.id, 1_700_000_050)
        .await
        .expect("consume incumbent password reset token failed");
    let err = repo
        .consume_password_reset_token(&token.id, 1_700_000_060)
        .await
        .expect_err("consumed password reset token must not be consumed again");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "repeat consumption must be Conflict, got: {}",
        err.message()
    );
    assert_eq!(
        repo.get_password_reset_token(&token.id)
            .await
            .expect("get token after repeat consumption failed")
            .expect("incumbent password reset token must remain stored")
            .consumed_at_epoch_seconds,
        Some(1_700_000_050)
    );

    let same_realm_duplicate = PasswordResetToken {
        token_hash: "replacement-token-hash".to_string(),
        consumed_at_epoch_seconds: None,
        ..token.clone()
    };
    let err = repo
        .store_password_reset_token(&same_realm_duplicate)
        .await
        .expect_err("a duplicate token ID in one realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-realm duplicate token ID must be a conflict, got: {}",
        err.message()
    );

    let cross_realm_duplicate = PasswordResetToken {
        realm_id: other_realm.0,
        user_id: other_user.id,
        token_hash: "foreign-token-hash".to_string(),
        consumed_at_epoch_seconds: None,
        ..token.clone()
    };
    let err = repo
        .store_password_reset_token(&cross_realm_duplicate)
        .await
        .expect_err("a token ID held by another realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-realm duplicate token ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .get_password_reset_token(&token.id)
        .await
        .expect("get incumbent password reset token failed")
        .expect("incumbent password reset token must remain stored");
    assert_eq!(
        stored,
        PasswordResetToken {
            consumed_at_epoch_seconds: Some(1_700_000_050),
            ..token
        }
    );
}

/// A review-decision ID is immutable so a retry cannot rewrite an audited decision.
pub async fn assert_iga_access_review_decision_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let decision = IgaAccessReviewDecisionRecord {
        id: "iga-review-decision-identity".to_string(),
        tenant_id: "tenant-iga-review".to_string(),
        campaign_id: "campaign-iga-review".to_string(),
        subject: "user-reviewed".to_string(),
        reviewer: "admin-reviewer".to_string(),
        decision: "revoke".to_string(),
        reason: Some("Access is no longer required".to_string()),
        decided_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_iga_access_review_decision(&decision)
        .await
        .expect("store incumbent IGA review decision failed");

    let same_tenant_duplicate = IgaAccessReviewDecisionRecord {
        subject: "different-user".to_string(),
        decision: "certify".to_string(),
        reason: Some("Replacement decision".to_string()),
        decided_at_epoch_seconds: 1_700_000_100,
        ..decision.clone()
    };
    let err = repo
        .store_iga_access_review_decision(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate review-decision ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant review-decision ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaAccessReviewDecisionRecord {
        tenant_id: "tenant-iga-review-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_access_review_decision(&cross_tenant_duplicate)
        .await
        .expect_err("a review-decision ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant review-decision ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .list_iga_access_review_decisions(&decision.tenant_id, &decision.campaign_id)
        .await
        .expect("list incumbent IGA review decisions failed");
    assert_eq!(stored, vec![decision]);
    assert!(
        repo.list_iga_access_review_decisions("tenant-iga-review-other", "campaign-iga-review")
            .await
            .expect("list other-tenant IGA review decisions failed")
            .is_empty()
    );
}

/// A certification ID is immutable so retries cannot rewrite evidence or decisions.
pub async fn assert_iga_certification_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let certification = IgaCertificationRecord {
        id: "iga-certification-identity".to_string(),
        tenant_id: "tenant-iga-certification".to_string(),
        certification_type: "manager".to_string(),
        campaign_id: Some("campaign-iga-certification".to_string()),
        subject: "user-certified".to_string(),
        entitlement: "crm:admin".to_string(),
        certifier: "manager-certifier".to_string(),
        decision: "certify".to_string(),
        reason: Some("Access remains required".to_string()),
        evidence_json: serde_json::json!({"source": "original"}),
        decided_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_iga_certification(&certification)
        .await
        .expect("store incumbent IGA certification failed");

    let same_tenant_duplicate = IgaCertificationRecord {
        decision: "revoke".to_string(),
        reason: Some("Replacement certification".to_string()),
        evidence_json: serde_json::json!({"source": "replacement"}),
        decided_at_epoch_seconds: 1_700_000_100,
        ..certification.clone()
    };
    let err = repo
        .store_iga_certification(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate certification ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant certification ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaCertificationRecord {
        tenant_id: "tenant-iga-certification-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_certification(&cross_tenant_duplicate)
        .await
        .expect_err("a certification ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant certification ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .list_iga_certifications(&certification.tenant_id, Some("manager"))
        .await
        .expect("list incumbent IGA certifications failed");
    assert_eq!(stored, vec![certification]);
    assert!(
        repo.list_iga_certifications("tenant-iga-certification-other", Some("manager"))
            .await
            .expect("list other-tenant IGA certifications failed")
            .is_empty()
    );
}

/// Duplicate stores cannot reset the monotonic resolved state or replace finding evidence.
pub async fn assert_iga_finding_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let finding = IgaFindingRecord {
        id: "iga-finding-identity".to_string(),
        tenant_id: "tenant-iga-finding".to_string(),
        finding_type: "dormant_account".to_string(),
        subject: "user-flagged".to_string(),
        severity: "high".to_string(),
        evidence_json: serde_json::json!({"source": "original"}),
        detected_at_epoch_seconds: 1_700_000_000,
        resolved: false,
    };
    repo.store_iga_finding(&finding)
        .await
        .expect("store incumbent IGA finding failed");
    repo.resolve_iga_finding("tenant-iga-finding-other", &finding.id)
        .await
        .expect("wrong-tenant resolve of IGA finding failed");
    let stored = repo
        .list_iga_findings(&finding.tenant_id, Some("dormant_account"))
        .await
        .expect("list IGA findings after wrong-tenant resolve failed");
    assert_eq!(
        stored,
        vec![finding.clone()],
        "a wrong-tenant resolve must leave the incumbent unchanged"
    );
    repo.resolve_iga_finding(&finding.tenant_id, "no-such-finding")
        .await
        .expect("unknown-ID resolve of IGA finding failed");
    let stored = repo
        .list_iga_findings(&finding.tenant_id, Some("dormant_account"))
        .await
        .expect("list IGA findings after unknown-ID resolve failed");
    assert_eq!(
        stored,
        vec![finding.clone()],
        "an unknown-ID resolve must leave the incumbent unchanged"
    );
    repo.resolve_iga_finding(&finding.tenant_id, &finding.id)
        .await
        .expect("resolve incumbent IGA finding failed");
    repo.resolve_iga_finding("tenant-iga-finding-other", &finding.id)
        .await
        .expect("wrong-tenant resolve after resolution failed");
    let stored = repo
        .list_iga_findings(&finding.tenant_id, Some("dormant_account"))
        .await
        .expect("list IGA findings after correct resolve failed");
    let mut resolved = finding.clone();
    resolved.resolved = true;
    assert_eq!(
        stored,
        vec![resolved],
        "the owning tenant resolves the finding exactly once"
    );
    repo.resolve_iga_finding(&finding.tenant_id, &finding.id)
        .await
        .expect("repeat resolve of IGA finding failed");

    let same_tenant_duplicate = IgaFindingRecord {
        subject: "different-user".to_string(),
        evidence_json: serde_json::json!({"source": "replacement"}),
        detected_at_epoch_seconds: 1_700_000_100,
        resolved: false,
        ..finding.clone()
    };
    let err = repo
        .store_iga_finding(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate finding ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant finding ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaFindingRecord {
        tenant_id: "tenant-iga-finding-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_finding(&cross_tenant_duplicate)
        .await
        .expect_err("a finding ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant finding ID must be a conflict, got: {}",
        err.message()
    );

    let stored = repo
        .list_iga_findings(&finding.tenant_id, Some("dormant_account"))
        .await
        .expect("list incumbent IGA findings failed");
    let mut incumbent = finding;
    incumbent.resolved = true;
    assert_eq!(stored, vec![incumbent]);
    assert!(
        repo.list_iga_findings("tenant-iga-finding-other", Some("dormant_account"))
            .await
            .expect("list other-tenant IGA findings failed")
            .is_empty()
    );
}

/// Duplicate access-request stores cannot erase lifecycle or approval state.
pub async fn assert_iga_access_request_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let request = IgaAccessRequestRecord {
        id: "iga-access-request-identity".to_string(),
        tenant_id: "tenant-iga-access-request".to_string(),
        subject: "user-requesting".to_string(),
        entitlement: "crm:admin".to_string(),
        reason: Some("Need elevated access".to_string()),
        status: "pending".to_string(),
        approval_steps_json: serde_json::json!([{"approver": "manager", "status": "pending"}]),
        violations_json: serde_json::json!([{"policy": "separation-of-duties"}]),
        package_entitlement_ids_json: serde_json::json!(["entitlement-package-entry"]),
        expires_at_epoch_seconds: Some(1_700_086_400),
        created_at_epoch_seconds: 1_700_000_000,
    };
    repo.store_iga_access_request(&request)
        .await
        .expect("store incumbent IGA access request failed");
    repo.update_iga_access_request_status(&request.tenant_id, &request.id, "approved")
        .await
        .expect("advance incumbent IGA access request status failed");

    let same_tenant_duplicate = IgaAccessRequestRecord {
        subject: "replacement-user".to_string(),
        status: "pending".to_string(),
        approval_steps_json: serde_json::json!([]),
        violations_json: serde_json::json!([]),
        package_entitlement_ids_json: serde_json::json!([]),
        ..request.clone()
    };
    let err = repo
        .store_iga_access_request(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate access-request ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant access-request ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaAccessRequestRecord {
        tenant_id: "tenant-iga-access-request-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_access_request(&cross_tenant_duplicate)
        .await
        .expect_err("an access-request ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant access-request ID must be a conflict, got: {}",
        err.message()
    );

    let mut incumbent = request;
    incumbent.status = "approved".to_string();
    assert_eq!(
        repo.get_iga_access_request(&incumbent.tenant_id, &incumbent.id)
            .await
            .expect("get incumbent IGA access request failed"),
        Some(incumbent)
    );
    assert!(
        repo.get_iga_access_request(
            "tenant-iga-access-request-other",
            "iga-access-request-identity"
        )
        .await
        .expect("get other-tenant IGA access request failed")
        .is_none()
    );
}

/// Duplicate IGA approvals cannot replace immutable decision evidence.
pub async fn assert_iga_approval_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let approval = IgaApprovalRecord {
        id: "iga-approval-identity".to_string(),
        tenant_id: "tenant-iga-approval".to_string(),
        request_id: "request-iga-approval".to_string(),
        approver: "manager".to_string(),
        decision: "approved".to_string(),
        approved_at_epoch_seconds: 1_700_000_000,
        expires_at_epoch_seconds: Some(1_700_086_400),
        reason: Some("Approved for the requested work".to_string()),
    };
    repo.store_iga_approval(&approval)
        .await
        .expect("store incumbent IGA approval failed");

    let same_tenant_duplicate = IgaApprovalRecord {
        decision: "rejected".to_string(),
        approver: "replacement-approver".to_string(),
        reason: Some("Replacement evidence".to_string()),
        ..approval.clone()
    };
    let err = repo
        .store_iga_approval(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate approval ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant approval ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaApprovalRecord {
        tenant_id: "tenant-iga-approval-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_approval(&cross_tenant_duplicate)
        .await
        .expect_err("an approval ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant approval ID must be a conflict, got: {}",
        err.message()
    );

    assert_eq!(
        repo.list_iga_approvals(&approval.tenant_id, &approval.request_id)
            .await
            .expect("list incumbent IGA approvals failed"),
        vec![approval]
    );
    assert!(
        repo.list_iga_approvals("tenant-iga-approval-other", "request-iga-approval")
            .await
            .expect("list other-tenant IGA approvals failed")
            .is_empty()
    );
}

/// Duplicate stores cannot undo a grant's revoked state.
pub async fn assert_iga_access_grant_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let grant = IgaAccessGrantRecord {
        id: "iga-access-grant-identity".to_string(),
        tenant_id: "tenant-iga-access-grant".to_string(),
        request_id: "request-iga-access-grant".to_string(),
        subject: "user-iga-access-grant".to_string(),
        entitlement: "crm:admin".to_string(),
        granted_at_epoch_seconds: 1_700_000_000,
        expires_at_epoch_seconds: Some(1_700_086_400),
        approval_ids: vec!["approval-iga-access-grant".to_string()],
        revoked: false,
    };
    repo.store_iga_access_grant(&grant)
        .await
        .expect("store incumbent IGA access grant failed");
    repo.revoke_iga_access_grant(&grant.tenant_id, &grant.id)
        .await
        .expect("revoke incumbent IGA access grant failed");

    let same_tenant_duplicate = IgaAccessGrantRecord {
        revoked: false,
        entitlement: "replacement-entitlement".to_string(),
        ..grant.clone()
    };
    let err = repo
        .store_iga_access_grant(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate access-grant ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant access-grant ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaAccessGrantRecord {
        tenant_id: "tenant-iga-access-grant-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_access_grant(&cross_tenant_duplicate)
        .await
        .expect_err("an access-grant ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant access-grant ID must be a conflict, got: {}",
        err.message()
    );

    let mut incumbent = grant;
    incumbent.revoked = true;
    assert_eq!(
        repo.list_iga_access_grants(&incumbent.tenant_id, Some(&incumbent.subject))
            .await
            .expect("list incumbent IGA access grant failed"),
        vec![incumbent]
    );
    assert!(
        repo.list_iga_access_grants("tenant-iga-access-grant-other", None)
            .await
            .expect("list other-tenant IGA access grants failed")
            .is_empty()
    );
}

/// Duplicate stores cannot undo a JIT privilege grant's revoked state.
pub async fn assert_iga_jit_privilege_grant_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let grant = IgaJitPrivilegeGrantRecord {
        id: "iga-jit-grant-identity".to_string(),
        tenant_id: "tenant-iga-jit-grant".to_string(),
        subject: "user-iga-jit-grant".to_string(),
        entitlement: "crm:admin".to_string(),
        requested_by: "user-iga-jit-grant".to_string(),
        approved_by: Some("manager-iga-jit-grant".to_string()),
        reason: "Emergency access".to_string(),
        issued_at_epoch_seconds: 1_700_000_000,
        expires_at_epoch_seconds: 1_700_000_900,
        revoked: false,
        constraints_json: serde_json::json!({"ticket": "INC-jit"}),
    };
    repo.store_iga_jit_privilege_grant(&grant)
        .await
        .expect("store incumbent IGA JIT grant failed");
    repo.revoke_iga_jit_privilege_grant(&grant.tenant_id, &grant.id)
        .await
        .expect("revoke incumbent IGA JIT grant failed");

    let same_tenant_duplicate = IgaJitPrivilegeGrantRecord {
        revoked: false,
        entitlement: "replacement-entitlement".to_string(),
        ..grant.clone()
    };
    let err = repo
        .store_iga_jit_privilege_grant(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate JIT grant ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant JIT grant ID must be a conflict, got: {}",
        err.message()
    );

    let cross_tenant_duplicate = IgaJitPrivilegeGrantRecord {
        tenant_id: "tenant-iga-jit-grant-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_jit_privilege_grant(&cross_tenant_duplicate)
        .await
        .expect_err("a JIT grant ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant JIT grant ID must be a conflict, got: {}",
        err.message()
    );

    let mut incumbent = grant;
    incumbent.revoked = true;
    assert_eq!(
        repo.list_iga_jit_privilege_grants(&incumbent.tenant_id, Some(&incumbent.subject))
            .await
            .expect("list incumbent IGA JIT grant failed"),
        vec![incumbent]
    );
    assert!(
        repo.list_iga_jit_privilege_grants("tenant-iga-jit-grant-other", None)
            .await
            .expect("list other-tenant IGA JIT grants failed")
            .is_empty()
    );
}

/// Duplicate campaign IDs cannot reopen a closed campaign in either tenant.
pub async fn assert_iga_access_review_campaign_identity_ownership<R>(repo: &R)
where
    R: IgaRepository,
{
    let campaign = IgaAccessReviewCampaignRecord {
        id: "iga-campaign-identity".to_string(),
        tenant_id: "tenant-iga-campaign".to_string(),
        reviewer: "reviewer-iga-campaign".to_string(),
        subjects_json: serde_json::json!(["user-iga-campaign"]),
        status: "open".to_string(),
        created_at_epoch_seconds: 1_700_000_000,
        due_at_epoch_seconds: Some(1_700_086_400),
    };
    repo.store_iga_access_review_campaign(&campaign)
        .await
        .expect("store incumbent IGA campaign failed");
    assert!(
        repo.close_iga_access_review_campaign(&campaign.tenant_id, &campaign.id)
            .await
            .expect("close incumbent IGA campaign failed")
    );
    let same_tenant_duplicate = IgaAccessReviewCampaignRecord {
        status: "open".to_string(),
        ..campaign.clone()
    };
    let err = repo
        .store_iga_access_review_campaign(&same_tenant_duplicate)
        .await
        .expect_err("a duplicate campaign ID in one tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a same-tenant campaign ID must be a conflict, got: {}",
        err.message()
    );
    let cross_tenant_duplicate = IgaAccessReviewCampaignRecord {
        tenant_id: "tenant-iga-campaign-other".to_string(),
        ..same_tenant_duplicate
    };
    let err = repo
        .store_iga_access_review_campaign(&cross_tenant_duplicate)
        .await
        .expect_err("a campaign ID held by another tenant must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "a cross-tenant campaign ID must be a conflict, got: {}",
        err.message()
    );
    let mut incumbent = campaign;
    incumbent.status = "closed".to_string();
    assert_eq!(
        repo.get_iga_access_review_campaign(&incumbent.tenant_id, &incumbent.id)
            .await
            .expect("get incumbent IGA campaign failed"),
        Some(incumbent.clone())
    );
    assert_eq!(
        repo.list_iga_access_review_campaigns(&incumbent.tenant_id)
            .await
            .expect("list incumbent IGA campaigns failed"),
        vec![incumbent]
    );
    assert!(
        repo.get_iga_access_review_campaign("tenant-iga-campaign-other", "iga-campaign-identity")
            .await
            .expect("get other-tenant IGA campaign failed")
            .is_none()
    );
    assert!(
        repo.list_iga_access_review_campaigns("tenant-iga-campaign-other")
            .await
            .expect("list other-tenant IGA campaigns failed")
            .is_empty()
    );
}

/// Realm IDs and issuers are globally unique and refusals preserve ownership.
pub async fn assert_realm_identity_ownership<R>(repo: &R)
where
    R: RealmRepository,
{
    let owner = TenantId("tenant-realm-owner".to_string());
    let realm = RealmId("realm-owner".to_string());
    let issuer = "https://realm-owner.example.com";
    repo.create_realm(&owner, &realm, issuer, Some("Owner realm"))
        .await
        .expect("create incumbent realm failed");

    let other_tenant = TenantId("tenant-realm-other".to_string());
    let duplicate_id = repo
        .create_realm(
            &other_tenant,
            &realm,
            "https://realm-attacker.example.com",
            Some("Other tenant realm"),
        )
        .await
        .expect_err("a realm ID held by another tenant must fail");
    assert!(
        matches!(duplicate_id, qid_core::error::QidError::Conflict { .. }),
        "duplicate realm ID must be a conflict, got: {}",
        duplicate_id.message()
    );
    assert_eq!(
        repo.get_realm_issuer(&realm)
            .await
            .expect("get incumbent issuer failed")
            .as_deref(),
        Some(issuer),
        "duplicate realm ID changed the incumbent issuer"
    );
    assert_eq!(
        repo.get_realm_tenant(&realm)
            .await
            .expect("get incumbent tenant failed")
            .as_deref(),
        Some(owner.as_str()),
        "duplicate realm ID changed the incumbent tenant"
    );

    let duplicate_issuer_realm = RealmId("realm-duplicate-issuer".to_string());
    let duplicate_issuer = repo
        .create_realm(
            &other_tenant,
            &duplicate_issuer_realm,
            issuer,
            Some("Duplicate issuer realm"),
        )
        .await
        .expect_err("a realm issuer already held by another ID must fail");
    assert!(
        matches!(duplicate_issuer, qid_core::error::QidError::Conflict { .. }),
        "duplicate realm issuer must be a conflict, got: {}",
        duplicate_issuer.message()
    );
    assert!(
        repo.get_realm_issuer(&duplicate_issuer_realm)
            .await
            .expect("get rejected realm issuer failed")
            .is_none(),
        "duplicate issuer created another realm"
    );
    assert!(
        repo.get_realm_tenant(&duplicate_issuer_realm)
            .await
            .expect("get rejected realm tenant failed")
            .is_none(),
        "duplicate issuer created another tenant binding"
    );

    let unrelated = RealmId("realm-unrelated".to_string());
    repo.create_realm(
        &other_tenant,
        &unrelated,
        "https://realm-unrelated.example.com",
        Some("Unrelated realm"),
    )
    .await
    .expect("a distinct realm identity must be allowed");
    assert_eq!(
        repo.get_realm_tenant(&unrelated)
            .await
            .expect("get unrelated realm tenant failed")
            .as_deref(),
        Some(other_tenant.as_str())
    );
}

/// The owner-bound contract of a policy bundle: a record ID names one bundle
/// globally and a name names one bundle in a realm, so a create that carries
/// either taken key is refused with `Conflict` and the incumbent is unchanged.
pub async fn assert_policy_bundle_identity_ownership<R>(repo: &R)
where
    R: RealmRepository + PolicyRepository,
{
    let realm = RealmId("realm-policy-bundle".to_string());
    repo.create_realm(
        &TenantId("tenant-policy-bundle".to_string()),
        &realm,
        "https://policy-bundle.example.com",
        Some("Policy Bundle Realm"),
    )
    .await
    .expect("create policy bundle realm failed");
    let other_realm = RealmId("realm-policy-bundle-other".to_string());
    repo.create_realm(
        &TenantId("tenant-policy-bundle-other".to_string()),
        &other_realm,
        "https://policy-bundle-other.example.com",
        Some("Other Policy Bundle Realm"),
    )
    .await
    .expect("create other policy bundle realm failed");

    let bundle = PolicyBundle {
        id: "policy-bundle-a".to_string(),
        realm_id: realm.0.clone(),
        name: "allow".to_string(),
        source_hash: "hash-a".to_string(),
        compiled_json: serde_json::json!({"rules": []}),
        version: 1,
        active: true,
    };
    repo.create_policy_bundle(&bundle)
        .await
        .expect("create policy bundle failed");

    let replay = repo
        .create_policy_bundle(&bundle)
        .await
        .expect_err("even an identical create replay must be refused");
    assert!(
        matches!(replay, qid_core::error::QidError::Conflict { .. }),
        "an identical create replay must be a conflict, got: {}",
        replay.message()
    );
    assert_eq!(
        serde_json::to_value(repo.list_policy_bundles(&realm).await.unwrap()).unwrap(),
        serde_json::json!([bundle]),
        "an identical replay changed the incumbent"
    );

    // Refuse a taken name, a same-owner ID and a foreign-owner ID.
    for duplicate in [
        PolicyBundle {
            id: "policy-bundle-b".to_string(),
            ..bundle.clone()
        },
        PolicyBundle {
            name: "other".to_string(),
            ..bundle.clone()
        },
        PolicyBundle {
            realm_id: other_realm.0.clone(),
            name: "other".to_string(),
            ..bundle.clone()
        },
    ] {
        let changed = PolicyBundle {
            source_hash: "changed".to_string(),
            compiled_json: serde_json::json!({"rules": ["changed"]}),
            version: 2,
            active: false,
            ..duplicate
        };
        let err = repo
            .create_policy_bundle(&changed)
            .await
            .expect_err("taken key must fail");
        assert!(
            matches!(err, qid_core::error::QidError::Conflict { .. }),
            "{}",
            err.message()
        );
        let listed = repo.list_policy_bundles(&realm).await.unwrap();
        assert_eq!(
            serde_json::to_value(listed).unwrap(),
            serde_json::json!([bundle])
        );
        assert!(
            repo.list_policy_bundles(&other_realm)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // The same name in another realm names another bundle, so it is allowed.
    let elsewhere = PolicyBundle {
        id: "policy-bundle-elsewhere".to_string(),
        realm_id: other_realm.0.clone(),
        ..bundle.clone()
    };
    repo.create_policy_bundle(&elsewhere)
        .await
        .expect("the same bundle name in another realm must be allowed");
    let listed_elsewhere = repo
        .list_policy_bundles(&other_realm)
        .await
        .expect("list other-realm bundles failed");
    assert_eq!(listed_elsewhere.len(), 1);
    assert_eq!(
        serde_json::to_value(listed_elsewhere).unwrap(),
        serde_json::json!([elsewhere]),
        "the allowed cross-realm create must persist the complete bundle"
    );

    // A distinct name in the same realm is another bundle, so it is allowed.
    let distinct = PolicyBundle {
        id: "policy-bundle-distinct".to_string(),
        name: "deny".to_string(),
        source_hash: "hash-deny".to_string(),
        ..bundle.clone()
    };
    repo.create_policy_bundle(&distinct)
        .await
        .expect("a distinct bundle name in the same realm must be allowed");
    let listed = repo
        .list_policy_bundles(&realm)
        .await
        .expect("list policy bundles failed");
    assert_eq!(
        listed.len(),
        2,
        "both distinct realm bundles must be listed"
    );
    for expected in [&bundle, &distinct] {
        assert!(
            listed.iter().any(|stored| {
                serde_json::to_value(stored).unwrap() == serde_json::to_value(expected).unwrap()
            }),
            "the allowed same-realm create must persist the full bundle {}",
            expected.id
        );
    }
}

pub async fn assert_client_delete_realm_scope<R>(repo: &R)
where
    R: RealmRepository + ClientRepository,
{
    let realm = RealmId::from("realm-client-delete");
    repo.create_realm(
        &TenantId::from("tenant-client-delete"),
        &realm,
        "https://client-delete.example.com",
        Some("Client Delete Realm"),
    )
    .await
    .expect("create client delete realm failed");
    let other_realm = RealmId::from("realm-client-delete-other");
    repo.create_realm(
        &TenantId::from("tenant-client-delete-other"),
        &other_realm,
        "https://client-delete-other.example.com",
        Some("Other Client Delete Realm"),
    )
    .await
    .expect("create other client delete realm failed");

    let client = sample_cross_realm_client("client-delete-a", realm.as_str(), "delete-app");
    repo.create_client(&client)
        .await
        .expect("create client for delete contract failed");

    repo.delete_client(&other_realm, &client.id)
        .await
        .expect("foreign-realm client delete must be a no-op");
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "delete-app")
                .await
                .expect("get client after foreign delete failed"),
        )
        .expect("serialize client after foreign delete failed"),
        serde_json::to_value(Some(client.clone())).expect("serialize expected client failed"),
        "a foreign-realm delete must leave the incumbent unchanged"
    );

    repo.delete_client(&realm, "missing-client-delete-id")
        .await
        .expect("missing client delete must be a no-op");
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "delete-app")
                .await
                .expect("get client after missing delete failed"),
        )
        .expect("serialize client after missing delete failed"),
        serde_json::to_value(Some(client.clone())).expect("serialize expected client failed"),
        "a missing-ID delete must leave the incumbent unchanged"
    );

    repo.delete_client(&realm, &client.id)
        .await
        .expect("same-realm client delete failed");
    assert!(
        repo.get_client_by_client_id(&realm, "delete-app")
            .await
            .expect("get client after authorized delete failed")
            .is_none(),
        "a same-realm delete must remove the client"
    );
}

/// The stable update identity of a client: an existing record ID accepts only
/// the same `(realm_id, client_id)` binding, and a mismatched binding is a
/// conflict that changes no field.
pub async fn assert_client_update_identity<R>(repo: &R)
where
    R: RealmRepository + ClientRepository,
{
    let realm = RealmId("realm-client-update".to_string());
    repo.create_realm(
        &TenantId("tenant-client-update".to_string()),
        &realm,
        "https://client-update.example.com",
        Some("Client Update Realm"),
    )
    .await
    .expect("create client update realm failed");
    let other_realm = RealmId("realm-client-update-other".to_string());
    repo.create_realm(
        &TenantId("tenant-client-update-other".to_string()),
        &other_realm,
        "https://client-update-other.example.com",
        Some("Other Client Update Realm"),
    )
    .await
    .expect("create other client update realm failed");

    let client = sample_cross_realm_client("client-update-a", &realm.0, "update-app");
    repo.create_client(&client)
        .await
        .expect("create client failed");

    // A same-identity metadata update succeeds.
    let mut updated = client.clone();
    updated.client_name = Some("Updated App".to_string());
    repo.update_client(&updated)
        .await
        .expect("a same-identity metadata update must succeed");
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "update-app")
                .await
                .expect("get updated client failed")
        )
        .expect("serialize updated client failed"),
        serde_json::to_value(Some(updated.clone())).expect("serialize expected failed"),
        "the metadata update must persist"
    );

    // An identical retry succeeds.
    repo.update_client(&updated)
        .await
        .expect("an identical update must succeed");
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "update-app")
                .await
                .expect("get retried client failed")
        )
        .expect("serialize retried client failed"),
        serde_json::to_value(Some(updated.clone())).expect("serialize expected failed"),
        "the identical update must leave the client unchanged"
    );

    // The other realm is seeded but holds no client, so only the identity
    // check can refuse the move below.
    assert!(
        repo.get_client_by_client_id(&other_realm, "update-app")
            .await
            .expect("get other-realm client failed")
            .is_none(),
        "the other realm must hold no client before the move"
    );

    // Moving the record ID to another realm is refused without changing it.
    let mut moved = updated.clone();
    moved.realm_id = other_realm.0.clone();
    moved.client_name = Some("Moved App".to_string());
    let err = repo
        .update_client(&moved)
        .await
        .expect_err("moving a client to another realm must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "moving a client to another realm must be a conflict, got: {}",
        err.message()
    );
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "update-app")
                .await
                .expect("get incumbent client failed")
        )
        .expect("serialize incumbent client failed"),
        serde_json::to_value(Some(updated.clone())).expect("serialize expected failed"),
        "the refused move changed the incumbent"
    );
    assert!(
        repo.get_client_by_client_id(&other_realm, "update-app")
            .await
            .expect("get other-realm client failed")
            .is_none(),
        "the refused move created a client in the other realm"
    );

    // Renaming the client ID to an otherwise unused ID is refused likewise.
    // The unused ID guarantees no unique violation can mask the check.
    let mut renamed = updated.clone();
    renamed.client_id = "update-app-unused".to_string();
    renamed.client_name = Some("Renamed App".to_string());
    let err = repo
        .update_client(&renamed)
        .await
        .expect_err("renaming a client ID must fail");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "renaming a client ID must be a conflict, got: {}",
        err.message()
    );
    assert_eq!(
        serde_json::to_value(
            repo.get_client_by_client_id(&realm, "update-app")
                .await
                .expect("get incumbent client failed")
        )
        .expect("serialize incumbent client failed"),
        serde_json::to_value(Some(updated.clone())).expect("serialize expected failed"),
        "the refused rename changed the incumbent"
    );
    assert!(
        repo.get_client_by_client_id(&realm, "update-app-unused")
            .await
            .expect("get renamed client failed")
            .is_none(),
        "the refused rename created a client under the new ID"
    );
}

pub async fn assert_rebac_tuple_identity_conflict<R>(repo: &R)
where
    R: RebacRepository,
{
    let tuple = RelationshipTuple {
        namespace: "rebac-contract".into(),
        object_id: "document-1".into(),
        relation: "viewer".into(),
        subject_namespace: "user".into(),
        subject_id: "user-1".into(),
        subject_relation: String::new(),
        created_at_epoch_seconds: 1,
    };
    repo.create_relationship_tuple(&tuple)
        .await
        .expect("create initial relationship tuple");

    let mut duplicate = tuple.clone();
    duplicate.created_at_epoch_seconds = 2;
    let error = repo
        .create_relationship_tuple(&duplicate)
        .await
        .expect_err("duplicate tuple identity must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate tuple identity returned {error:?}"
    );

    let stored = repo
        .list_relationship_tuples("rebac-contract", "document-1", Some("viewer"))
        .await
        .expect("list relationship tuples");
    assert_eq!(stored, vec![tuple], "duplicate changed the incumbent tuple");
}

pub async fn assert_par_request_identity_conflict<R>(repo: &R)
where
    R: TokenRepository,
{
    let initial = ParRequest {
        request_uri: "urn:par:identity-contract".into(),
        client_id: "client-par-contract".into(),
        realm_id: "realm-par-contract".into(),
        params_json: serde_json::json!({"scope": "read"}),
        expires_at: 3000,
        used: false,
        created_at: 1,
    };
    repo.store_par_request(&initial)
        .await
        .expect("store initial PAR request");
    repo.mark_par_request_used(&initial.request_uri)
        .await
        .expect("consume initial PAR request");

    let duplicate = ParRequest {
        request_uri: initial.request_uri.clone(),
        client_id: "other-client".into(),
        realm_id: "other-realm".into(),
        params_json: serde_json::json!({"scope": "admin"}),
        expires_at: 4000,
        used: false,
        created_at: 2,
    };
    let error = repo
        .store_par_request(&duplicate)
        .await
        .expect_err("duplicate request URI must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate PAR request URI returned {error:?}"
    );

    let stored = repo
        .get_par_request(&initial.request_uri)
        .await
        .expect("get incumbent PAR request")
        .expect("incumbent PAR request missing");
    assert_eq!(stored.request_uri, initial.request_uri);
    assert_eq!(stored.client_id, initial.client_id);
    assert_eq!(stored.realm_id, initial.realm_id);
    assert_eq!(stored.params_json, initial.params_json);
    assert_eq!(stored.expires_at, initial.expires_at);
    assert_eq!(stored.created_at, initial.created_at);
    assert!(stored.used, "duplicate reset the consumed PAR request");
}

/// The create-only contract of a device authorization grant: the device code
/// hash names one grant and the user code names one grant globally, so a
/// second grant that carries either is refused with `Conflict` and the
/// incumbent keeps its owner, payload and lifecycle state.
pub async fn assert_device_authorization_grant_create_only<R>(repo: &R)
where
    R: RealmRepository + UserRepository + TokenRepository,
{
    let realm = RealmId("realm-device-contract".to_string());
    repo.create_realm(
        &TenantId("tenant-device-contract".to_string()),
        &realm,
        "https://device-contract.example.com",
        Some("Device Contract Realm"),
    )
    .await
    .expect("create device contract realm failed");
    let approver = User {
        id: "user-device-contract".to_string(),
        realm_id: realm.0.clone(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&approver)
        .await
        .expect("create device contract user failed");

    let incumbent = DeviceAuthorizationGrant {
        resource: vec!["https://api.example.com/device".into()],
        audience: vec!["api://device".into()],
        device_code_hash: "device-code-contract".into(),
        user_code: "DEVICE-CONTRACT".into(),
        client_id: "client-device-contract".into(),
        realm_id: "realm-device-contract".into(),
        scopes: vec!["read".to_string()],
        user_id: None,
        expires_at: 3000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 1,
    };
    repo.store_device_authorization_grant(&incumbent)
        .await
        .expect("store initial device grant");
    repo.record_device_authorization_poll(&incumbent.device_code_hash, 1100, 10)
        .await
        .expect("poll initial device grant");
    repo.approve_device_authorization_grant(&incumbent.user_code, "user-device-contract", 1200)
        .await
        .expect("approve initial device grant");
    repo.consume_device_authorization_grant(&incumbent.device_code_hash)
        .await
        .expect("consume initial device grant");

    // A second grant for the same device code hash is refused, even with a
    // changed owner and payload and reset lifecycle fields.
    let duplicate_hash = DeviceAuthorizationGrant {
        resource: Vec::new(),
        audience: Vec::new(),
        device_code_hash: incumbent.device_code_hash.clone(),
        user_code: "DEVICE-OTHER".into(),
        client_id: "other-client".into(),
        realm_id: "other-realm".into(),
        scopes: vec!["admin".to_string()],
        user_id: None,
        expires_at: 4000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 2,
    };
    let error = repo
        .store_device_authorization_grant(&duplicate_hash)
        .await
        .expect_err("duplicate device code hash must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate device code hash returned {error:?}"
    );
    let stored = repo
        .get_device_authorization_grant(&incumbent.device_code_hash)
        .await
        .expect("get incumbent device grant")
        .expect("incumbent device grant missing");
    assert_eq!(stored.realm_id, incumbent.realm_id);
    assert_eq!(stored.client_id, incumbent.client_id);
    assert_eq!(stored.user_code, incumbent.user_code);
    assert_eq!(stored.scopes, incumbent.scopes);
    assert_eq!(stored.resource, incumbent.resource);
    assert_eq!(stored.audience, incumbent.audience);
    assert_eq!(stored.user_id.as_deref(), Some("user-device-contract"));
    assert_eq!(stored.approved_at, Some(1200));
    assert!(stored.consumed, "duplicate reset the consumed device grant");
    assert_eq!(stored.last_poll_at, Some(1100));
    assert_eq!(stored.poll_interval_seconds, 10);

    // A second grant that carries the incumbent user code under a distinct
    // hash is refused, and the new hash stays absent.
    let duplicate_code = DeviceAuthorizationGrant {
        resource: Vec::new(),
        audience: Vec::new(),
        device_code_hash: "device-code-contract-other".into(),
        user_code: incumbent.user_code.clone(),
        client_id: "other-client".into(),
        realm_id: "other-realm".into(),
        scopes: vec!["admin".to_string()],
        user_id: None,
        expires_at: 4000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 2,
    };
    let error = repo
        .store_device_authorization_grant(&duplicate_code)
        .await
        .expect_err("duplicate user code must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate user code returned {error:?}"
    );
    assert!(
        repo.get_device_authorization_grant(&duplicate_code.device_code_hash)
            .await
            .expect("get duplicate user-code hash")
            .is_none(),
        "the refused user-code grant must stay absent"
    );
    let stored = repo
        .get_device_authorization_grant(&incumbent.device_code_hash)
        .await
        .expect("get incumbent device grant")
        .expect("incumbent device grant missing");
    assert_eq!(stored.realm_id, incumbent.realm_id);
    assert_eq!(stored.client_id, incumbent.client_id);
    assert_eq!(stored.user_code, incumbent.user_code);
    assert_eq!(stored.user_id.as_deref(), Some("user-device-contract"));
    assert_eq!(stored.approved_at, Some(1200));
    assert!(stored.consumed, "duplicate reset the consumed device grant");
    assert_eq!(stored.last_poll_at, Some(1100));
}

/// The create-only contract of a backchannel authentication grant: the
/// `auth_req_id_hash` names one grant, so a second grant with the same hash
/// is refused with `Conflict` and the incumbent keeps its owner, payload,
/// approval, consumed and poll state.
pub async fn assert_backchannel_authentication_grant_create_only<R>(repo: &R)
where
    R: RealmRepository + UserRepository + TokenRepository,
{
    let realm = RealmId("realm-backchannel-contract".to_string());
    repo.create_realm(
        &TenantId("tenant-backchannel-contract".to_string()),
        &realm,
        "https://backchannel-contract.example.com",
        Some("Backchannel Contract Realm"),
    )
    .await
    .expect("create backchannel contract realm failed");
    let approver = User {
        id: "user-backchannel-contract".to_string(),
        realm_id: realm.0.clone(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&approver)
        .await
        .expect("create backchannel contract user failed");

    let incumbent = BackchannelAuthenticationGrant {
        resource: vec!["https://api.example.com/ciba".into()],
        audience: vec!["api://ciba".into()],
        auth_req_id_hash: "auth-req-contract".into(),
        client_id: "client-backchannel-contract".into(),
        realm_id: "realm-backchannel-contract".into(),
        login_hint: "user@example.com".into(),
        binding_message: Some("bind-one".into()),
        scopes: vec!["openid".to_string()],
        user_id: None,
        expires_at: 3000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 1,
    };
    repo.store_backchannel_authentication_grant(&incumbent)
        .await
        .expect("store initial backchannel grant");
    repo.record_backchannel_authentication_poll(&incumbent.auth_req_id_hash, 1100, 10)
        .await
        .expect("poll initial backchannel grant");
    repo.approve_backchannel_authentication_grant(
        &incumbent.auth_req_id_hash,
        "user-backchannel-contract",
        1200,
    )
    .await
    .expect("approve initial backchannel grant");
    repo.consume_backchannel_authentication_grant(&incumbent.auth_req_id_hash)
        .await
        .expect("consume initial backchannel grant");

    // A second grant for the same hash is refused, even with a changed owner
    // and payload and reset lifecycle fields.
    let duplicate = BackchannelAuthenticationGrant {
        resource: Vec::new(),
        audience: Vec::new(),
        auth_req_id_hash: incumbent.auth_req_id_hash.clone(),
        client_id: "other-client".into(),
        realm_id: "other-realm".into(),
        login_hint: "other@example.com".into(),
        binding_message: Some("other-bind".into()),
        scopes: vec!["admin".to_string()],
        user_id: None,
        expires_at: 4000,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: 2,
    };
    let error = repo
        .store_backchannel_authentication_grant(&duplicate)
        .await
        .expect_err("duplicate auth request ID must conflict");
    assert!(
        matches!(error, qid_core::error::QidError::Conflict { .. }),
        "duplicate auth request ID returned {error:?}"
    );
    let stored = repo
        .get_backchannel_authentication_grant(&incumbent.auth_req_id_hash)
        .await
        .expect("get incumbent backchannel grant")
        .expect("incumbent backchannel grant missing");
    assert_eq!(stored.realm_id, incumbent.realm_id);
    assert_eq!(stored.client_id, incumbent.client_id);
    assert_eq!(stored.login_hint, incumbent.login_hint);
    assert_eq!(stored.binding_message, incumbent.binding_message);
    assert_eq!(stored.scopes, incumbent.scopes);
    assert_eq!(stored.resource, incumbent.resource);
    assert_eq!(stored.audience, incumbent.audience);
    assert_eq!(stored.user_id.as_deref(), Some("user-backchannel-contract"));
    assert_eq!(stored.approved_at, Some(1200));
    assert!(
        stored.consumed,
        "duplicate reset the consumed backchannel grant"
    );
    assert_eq!(stored.last_poll_at, Some(1100));
    assert_eq!(stored.poll_interval_seconds, 10);
    assert_eq!(stored.expires_at, incumbent.expires_at);
    assert_eq!(stored.created_at, incumbent.created_at);
}

pub async fn assert_totp_step_owner_bound<R>(repo: &R)
where
    R: RealmRepository + UserRepository + CredentialRepository,
{
    let realm = RealmId("realm-totp-owner".to_string());
    repo.create_realm(
        &TenantId("tenant-totp-owner".to_string()),
        &realm,
        "https://totp-owner.example.com",
        None,
    )
    .await
    .expect("create TOTP owner realm failed");
    repo.create_user(&User {
        id: "user-totp-owner".to_string(),
        realm_id: realm.0,
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .expect("create TOTP owner user failed");
    repo.create_user(&User {
        id: "user-totp-other".to_string(),
        realm_id: "realm-totp-owner".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .expect("create second TOTP user failed");
    let credential = TotpCredential {
        id: "totp-owner-credential".to_string(),
        user_id: "user-totp-owner".to_string(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        enabled: true,
        last_used_step: None,
        created_at: 1,
    };
    repo.store_totp_credential(&credential)
        .await
        .expect("store TOTP owner credential failed");
    let replacement = TotpCredential {
        secret: "MFRGGZDFMZTWQ2LK".to_string(),
        created_at: 2,
        ..credential.clone()
    };
    repo.store_totp_credential(&replacement)
        .await
        .expect("same-owner TOTP replacement failed");
    let foreign_replacement = TotpCredential {
        user_id: "user-totp-other".to_string(),
        secret: "GEZDGNBVGY3TQOJQ".to_string(),
        algorithm: "SHA256".to_string(),
        digits: 8,
        period: 60,
        enabled: false,
        last_used_step: Some(99),
        created_at: 3,
        ..replacement.clone()
    };
    assert!(matches!(
        repo.store_totp_credential(&foreign_replacement).await,
        Err(qid_core::error::QidError::Conflict { .. })
    ));
    let stored = repo
        .get_totp_credential(&credential.user_id)
        .await
        .expect("get TOTP owner credential failed")
        .expect("TOTP owner credential missing after collision");
    assert_eq!(stored.id, replacement.id);
    assert_eq!(stored.user_id, replacement.user_id);
    assert_eq!(stored.secret, replacement.secret);
    assert_eq!(stored.algorithm, replacement.algorithm);
    assert_eq!(stored.digits, replacement.digits);
    assert_eq!(stored.period, replacement.period);
    assert_eq!(stored.enabled, replacement.enabled);
    assert_eq!(stored.last_used_step, replacement.last_used_step);
    assert_eq!(stored.created_at, replacement.created_at);

    let wrong_owner = TotpCredential {
        user_id: "user-totp-other".to_string(),
        ..credential.clone()
    };
    assert!(
        !repo
            .consume_totp_step(&wrong_owner, 100)
            .await
            .expect("wrong-owner TOTP step claim failed")
    );
    assert_eq!(
        repo.get_totp_credential(&credential.user_id)
            .await
            .expect("get TOTP owner credential failed")
            .expect("TOTP owner credential missing")
            .last_used_step,
        None,
        "a wrong-owner claim must not consume the step"
    );
    assert!(
        repo.consume_totp_step(&credential, 100)
            .await
            .expect("correct-owner TOTP step claim failed")
    );
    assert!(
        !repo
            .consume_totp_step(&credential, 100)
            .await
            .expect("replayed TOTP step claim failed")
    );
    let missing = TotpCredential {
        id: "totp-owner-missing".to_string(),
        ..credential.clone()
    };
    assert!(
        !repo
            .consume_totp_step(&missing, 101)
            .await
            .expect("unknown TOTP step claim failed")
    );
    assert!(
        repo.consume_totp_step(&credential, 101)
            .await
            .expect("later TOTP step claim failed")
    );
}
