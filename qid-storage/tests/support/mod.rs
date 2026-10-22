#![allow(dead_code)]

use qid_core::models::{CiamConsentGrant, Client, ClientType, User, WorkloadIdentity};
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
        .update_user(&renamed)
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
    repo.update_user(&unchanged)
        .await
        .expect("a user keeping its own email must be allowed");
    let stored = repo
        .get_user_by_id(&user.id)
        .await
        .expect("get user by id failed")
        .expect("the user must still exist");
    assert_eq!(stored.email, user.email);
    assert_eq!(stored.display_name, unchanged.display_name);
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
    }
}
