//! Server-backed push storage evidence. CI supplies a disposable database; local
//! runs skip unless QID_TEST_POSTGRES_URL is set. Never use a production database.
//! Verification booleans stand in for signatures already checked by qid-mfa.
use qid_core::{QidResult, models::*, util::now_seconds};
use qid_storage::{SqlRepository, prelude::*};
use sqlx::{ConnectOptions, PgPool, Postgres, Transaction, postgres::PgConnectOptions};
use std::{future::Future, time::Duration};

fn registration(realm: &str, user: &str) -> PushRegistrationChallenge {
    let now = now_seconds();
    PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: ulid::Ulid::new().to_string(),
            realm_id: realm.into(),
            user_id: user.into(),
            destination: "disposable-test-destination".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::OKP {
                crv: "Ed25519".into(),
                x: "public-test-key".into(),
            },
            created_at: now,
            revoked_at: None,
        },
        nonce_verifier: "a".repeat(64),
        expires_at: now + 3600,
        max_attempts: 2,
        attempt_count: 0,
    }
}

fn login(a: &PushAuthenticator) -> PushLoginChallenge {
    let now = now_seconds();
    PushLoginChallenge {
        id: ulid::Ulid::new().to_string(),
        realm_id: a.realm_id.clone(),
        user_id: a.user_id.clone(),
        authenticator_id: a.id.clone(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: "b".repeat(64),
        browser_binding_verifier: "c".repeat(64),
        resend_admitted_at: Vec::new(),
        created_at: now,
        expires_at: now + 600,
        max_attempts: 2,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    }
}

async fn enroll(repo: &SqlRepository, realm: &str, user: &str) -> PushAuthenticator {
    let c = registration(realm, user);
    assert!(
        repo.try_issue_push_registration(&c, 100, 86400)
            .await
            .unwrap()
    );
    assert!(
        repo.attempt_push_registration(&c, true, now_seconds())
            .await
            .unwrap()
    );
    repo.get_push_authenticator(&realm.into(), user, &c.authenticator.id)
        .await
        .unwrap()
        .unwrap()
}

async fn issue(repo: &SqlRepository, a: &PushAuthenticator) -> PushLoginChallenge {
    let c = login(a);
    assert!(repo.try_issue_push_login(&c, 100, 86400).await.unwrap());
    c
}

async fn row_lock<'a>(pool: &'a PgPool, a: &PushAuthenticator) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM push_authenticators WHERE id = $1 FOR UPDATE")
        .bind(&a.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx
}

// The control connection holds the relevant advisory/row lock until BOTH
// independent repository sessions are waiting inside PostgreSQL. No scheduler
// timing assumptions, shared SQLite connection, or process-local mutex race.
async fn contend(
    pool: &PgPool,
    app: &str,
    lock: Transaction<'_, Postgres>,
    left: impl Future<Output = QidResult<bool>>,
    right: impl Future<Output = QidResult<bool>>,
) -> (bool, bool) {
    let release = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock'",
                ).bind(app).fetch_one(pool).await.unwrap();
                if waiting == 2 { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("both repository sessions must contend on a database lock");
        lock.commit().await.unwrap();
    };
    let (a, b, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(left, right, release)
    })
    .await
    .expect("push database race must complete without deadlock");
    (a.unwrap(), b.unwrap())
}

async fn quota_lock<'a>(
    pool: &'a PgPool,
    realm: &str,
    user: &str,
    purpose: &str,
) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(serde_json::json!([realm, user, purpose]).to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

fn repository_url(options: &PgConnectOptions, app: &str, isolation: &str) -> String {
    // PgConnectOptions::to_url_lossy omits application_name and custom options.
    let mut url = options.to_url_lossy();
    let startup_options = format!(
        "-c default_transaction_isolation={}",
        isolation.replace(' ', r"\ ")
    );
    url.query_pairs_mut()
        .append_pair("application_name", app)
        .append_pair("options", &startup_options);
    url.to_string()
}

#[test]
fn postgres_repository_url_retains_application_name_and_isolation() {
    let options: PgConnectOptions = "postgres://qid_test:qid_test@localhost/qid_test"
        .parse()
        .unwrap();
    let url = repository_url(&options, "qid-push-test", "repeatable read");
    let parsed: PgConnectOptions = url.parse().unwrap();

    assert_eq!(parsed.get_application_name(), Some("qid-push-test"));
    assert_eq!(
        parsed.get_options(),
        Some(r"-c default_transaction_isolation=repeatable\ read")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_push_quota_and_row_lock_invariants() {
    let url = match std::env::var("QID_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL push evidence: QID_TEST_POSTGRES_URL is unset");
            return;
        }
        Err(_) => panic!("QID_TEST_POSTGRES_URL must be valid Unicode"),
    };
    assert!(url.starts_with("postgres://") || url.starts_with("postgresql://"));
    let app = format!("qid-push-{}", ulid::Ulid::new());
    let options: PgConnectOptions = url.parse().expect("valid PostgreSQL test URL");
    let pool = PgPool::connect_with(options.clone()).await.unwrap();
    // Deliberately hostile session default: admission must explicitly use READ
    // COMMITTED so a waiter sees the winner's insert after the advisory lock.
    let quota_url = repository_url(&options, &app, "repeatable read");
    let probe = PgPool::connect(quota_url.as_str()).await.unwrap();
    let isolation: String = sqlx::query_scalar("SHOW default_transaction_isolation")
        .fetch_one(&probe)
        .await
        .unwrap();
    assert_eq!(isolation, "repeatable read");
    probe.close().await;
    let first = SqlRepository::connect(quota_url.as_str()).await.unwrap();
    first.migrate().await.unwrap();
    let second = SqlRepository::connect(quota_url.as_str()).await.unwrap();
    let realm = format!("realm-{}", ulid::Ulid::new());
    let user = format!("user-{}", ulid::Ulid::new());
    first
        .create_realm(
            &ulid::Ulid::new().to_string().into(),
            &realm.clone().into(),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
    first
        .create_user(&User {
            id: user.clone(),
            realm_id: realm.clone(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();

    sqlx::query("INSERT INTO credentials_password (user_id, hash, algorithm) VALUES ($1, $2, $3)")
        .bind(&user)
        .bind("disposable-original-hash")
        .bind("argon2id")
        .execute(&pool)
        .await
        .unwrap();
    let rehashed = PasswordCredential {
        user_id: user.clone(),
        hash: "disposable-replacement-hash".into(),
        algorithm: "argon2id".into(),
    };
    first
        .update_password_credential_in_realm(&rehashed, &realm)
        .await
        .unwrap();
    let stored_hash: String =
        sqlx::query_scalar("SELECT hash FROM credentials_password WHERE user_id = $1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_hash, rehashed.hash);

    let a = registration(&realm, &user);
    let b = registration(&realm, &user);
    let lock = quota_lock(&pool, &realm, &user, "registration").await;
    let result = contend(
        &pool,
        &app,
        lock,
        first.try_issue_push_registration(&a, 1, 86400),
        second.try_issue_push_registration(&b, 1, 86400),
    )
    .await;
    assert_ne!(
        result.0, result.1,
        "exactly one registration fits the quota"
    );
    let winner = if result.0 { &a } else { &b };
    assert!(
        first
            .attempt_push_registration(winner, true, now_seconds())
            .await
            .unwrap()
    );
    let auth = first
        .get_push_authenticator(&realm.clone().into(), &user, &winner.authenticator.id)
        .await
        .unwrap()
        .unwrap();
    let a = login(&auth);
    let b = login(&auth);
    let lock = quota_lock(&pool, &realm, &user, "password_login").await;
    let result = contend(
        &pool,
        &app,
        lock,
        first.try_issue_push_login(&a, 1, 86400),
        second.try_issue_push_login(&b, 1, 86400),
    )
    .await;
    assert_ne!(result.0, result.1, "exactly one login fits the quota");
    // Resends and initial sends share the same advisory lock and event quota,
    // even with a hostile REPEATABLE READ default on these pooled sessions.
    let c = if result.0 { &a } else { &b };
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let next = login(&auth);
    let nonce = qid_core::util::sha256_hex(b"resend nonce");
    let lock = quota_lock(&pool, &realm, &user, "password_login").await;
    let (resent, issued) = contend(
        &pool,
        &app,
        lock,
        async {
            first
                .try_resend_push_login(c, &c.browser_binding_verifier, &nonce, 2, 86400, 1)
                .await
                .map(|challenge| challenge.is_some())
        },
        second.try_issue_push_login(&next, 2, 86400),
    )
    .await;
    assert_ne!(
        resent, issued,
        "one last send admission, shared across send types"
    );
    let stored = first
        .get_push_login(&realm.clone().into(), &user, &c.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.resend_admitted_at.len(), usize::from(resent));
    if resent {
        assert_eq!(stored.nonce_verifier, nonce);
        assert!(
            !second
                .attempt_push_login(c, Some(PushDecision::Approve), now_seconds())
                .await
                .unwrap()
        );
    }
    first.close().await;
    second.close().await;

    // Row mutation races use READ COMMITTED, including if the supplied test DB
    // has a different default. Each repository owns an independent pool.
    let row_url = repository_url(&options, &app, "read committed");
    let first = SqlRepository::connect(row_url.as_str()).await.unwrap();
    let second = SqlRepository::connect(row_url.as_str()).await.unwrap();
    let c = issue(&first, &auth).await;
    let lock = row_lock(&pool, &auth).await;
    let (approved, denied) = contend(
        &pool,
        &app,
        lock,
        first.attempt_push_login(&c, Some(PushDecision::Approve), now_seconds()),
        second.attempt_push_login(&c, Some(PushDecision::Deny), now_seconds()),
    )
    .await;
    assert_ne!(approved, denied);
    let stored = first
        .get_push_login(&realm.clone().into(), &user, &c.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.attempt_count, 1);
    assert_eq!(
        stored.decision,
        Some(if approved {
            PushDecision::Approve
        } else {
            PushDecision::Deny
        })
    );
    assert!(
        !second
            .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
            .await
            .unwrap()
    );

    // Concurrent invalid signatures cannot lose an attempt update or exceed the cap.
    let mut c = login(&auth);
    c.max_attempts = 1;
    assert!(first.try_issue_push_login(&c, 100, 86400).await.unwrap());
    let lock = row_lock(&pool, &auth).await;
    let result = contend(
        &pool,
        &app,
        lock,
        first.attempt_push_login(&c, None, now_seconds()),
        second.attempt_push_login(&c, None, now_seconds()),
    )
    .await;
    assert_ne!(result.0, result.1);
    assert_eq!(
        first
            .get_push_login(&realm.clone().into(), &user, &c.id)
            .await
            .unwrap()
            .unwrap()
            .attempt_count,
        1
    );
    assert!(
        !first
            .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
            .await
            .unwrap()
    );

    let c = issue(&first, &auth).await;
    assert!(
        first
            .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
            .await
            .unwrap()
    );
    let lock = row_lock(&pool, &auth).await;
    let result = contend(
        &pool,
        &app,
        lock,
        first.redeem_push_login(&c, &c.browser_binding_verifier, now_seconds()),
        second.redeem_push_login(&c, &c.browser_binding_verifier, now_seconds()),
    )
    .await;
    assert_ne!(
        result.0, result.1,
        "an approved challenge is redeemed exactly once"
    );
    assert!(
        first
            .get_push_login(&realm.clone().into(), &user, &c.id)
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_some()
    );
    assert!(
        !first
            .redeem_push_login(&c, &c.browser_binding_verifier, now_seconds())
            .await
            .unwrap()
    );

    // Either operation may get the authenticator row lock first. A decision or
    // redemption before revocation is valid, but none may succeed afterwards.
    for redeem in [false, true] {
        let auth = enroll(&first, &realm, &user).await;
        let c = issue(&first, &auth).await;
        if redeem {
            assert!(
                first
                    .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
                    .await
                    .unwrap()
            );
        }
        let lock = row_lock(&pool, &auth).await;
        let operation = async {
            if redeem {
                first
                    .redeem_push_login(&c, &c.browser_binding_verifier, now_seconds())
                    .await
            } else {
                first
                    .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
                    .await
            }
        };
        let (used, revoked) = contend(
            &pool,
            &app,
            lock,
            operation,
            second.revoke_push_authenticator(&realm.clone().into(), &user, &auth.id, now_seconds()),
        )
        .await;
        assert!(revoked);
        let stored = first
            .get_push_login(&realm.clone().into(), &user, &c.id)
            .await
            .unwrap()
            .unwrap();
        if redeem {
            assert_eq!(stored.consumed_at.is_some(), used);
        } else {
            assert_eq!(stored.decision.is_some(), used);
        }
        assert!(
            first
                .get_push_authenticator(&realm.clone().into(), &user, &auth.id)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            !first
                .attempt_push_login(&c, Some(PushDecision::Approve), now_seconds())
                .await
                .unwrap()
        );
        assert!(
            !second
                .redeem_push_login(&c, &c.browser_binding_verifier, now_seconds())
                .await
                .unwrap()
        );
        assert!(
            first
                .try_issue_push_login(&login(&auth), 100, 86400)
                .await
                .is_err()
        );
    }
    first.close().await;
    second.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_realm_deletion_is_tenant_bound_across_locked_id_reuse() {
    let url = match std::env::var("QID_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL realm deletion: QID_TEST_POSTGRES_URL is unset");
            return;
        }
        Err(_) => panic!("QID_TEST_POSTGRES_URL must be valid Unicode"),
    };
    let options: PgConnectOptions = url.parse().expect("valid PostgreSQL test URL");
    let pool = PgPool::connect_with(options.clone()).await.unwrap();
    let app = format!("qid-realm-delete-{}", ulid::Ulid::new());
    let repo = SqlRepository::connect(&repository_url(&options, &app, "read committed"))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    let realm = format!("realm-delete-{}", ulid::Ulid::new());
    let id = realm.clone().into();
    let tenant_a = "tenant-a".into();
    let tenant_b = "tenant-b".into();
    let issuer = format!("https://{realm}.example");
    repo.create_realm(&tenant_a, &id, &issuer, None)
        .await
        .unwrap();
    let user = User {
        id: format!("user-{}", ulid::Ulid::new()),
        realm_id: realm.clone(),
        email: None,
        email_verified: false,
        display_name: Some("Replacement B".into()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.unwrap();

    // Hold the old row while a stale A deletion enters its UPDATE. It must
    // block before touching any children, then recheck the vanished owner row.
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM realms WHERE id = $1 FOR UPDATE")
        .bind(&realm)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let stale = repo.delete_realm(&id, &tenant_a);
    let replace = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock' AND query LIKE 'UPDATE realms%'",
                ).bind(&app).fetch_one(&pool).await.unwrap();
                if waiting == 1 { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("realm deletion must lock its tenant-qualified parent first");
        assert!(repo.get_user_by_id(&user.id).await.unwrap().is_some());
        // Controlled parent deletion while holding its lock makes the waiter
        // exercise PostgreSQL's READ COMMITTED row recheck (not just a pre-read).
        sqlx::query("DELETE FROM realms WHERE id = $1")
            .bind(&realm)
            .execute(&mut *lock)
            .await
            .unwrap();
        lock.commit().await.unwrap();
        repo.create_realm(&tenant_b, &id, &issuer, None)
            .await
            .unwrap();
        repo.create_user(&user).await.unwrap();
    };
    let (deleted, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(stale, replace)
    })
    .await
    .expect("stale deletion and recreation must finish");
    deleted.unwrap();

    let account = ServiceAccount {
        id: format!("service-{}", ulid::Ulid::new()),
        client_id: "replacement-client".into(),
        realm_id: realm.clone(),
        description: Some("B non-FK live data".into()),
        created_at: now_seconds(),
    };
    // Fixture SQL keeps unrelated service-account CRUD placeholder portability
    // outside this realm-deletion slice; root/user setup uses Repository APIs.
    sqlx::query("INSERT INTO service_accounts (id, client_id, realm_id, description, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&account.id).bind(&account.client_id).bind(&account.realm_id)
        .bind(&account.description).bind(account.created_at as i32)
        .execute(&pool).await.unwrap();
    // Also cover a request whose authorization preceded a fully committed B.
    repo.delete_realm(&id, &tenant_a).await.unwrap();
    assert_eq!(
        repo.get_realm_tenant(&id).await.unwrap().as_deref(),
        Some("tenant-b")
    );
    assert_eq!(repo.get_realm_issuer(&id).await.unwrap(), Some(issuer));
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id(&user.id).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&user).unwrap()
    );
    let stored: (String, String, String, Option<String>, i32) = sqlx::query_as(
        "SELECT id, client_id, realm_id, description, created_at FROM service_accounts WHERE id = $1",
    ).bind(&account.id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        stored,
        (
            account.id.clone(),
            account.client_id.clone(),
            realm.clone(),
            account.description.clone(),
            account.created_at as i32
        )
    );
    repo.delete_realm(&id, &tenant_b).await.unwrap();
    assert!(repo.get_realm_tenant(&id).await.unwrap().is_none());
    assert!(repo.get_user_by_id(&user.id).await.unwrap().is_none());
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM service_accounts WHERE id = $1")
        .bind(&account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    repo.delete_realm(&id, &tenant_b).await.unwrap();
    repo.close().await;
    pool.close().await;
}

#[tokio::test]
async fn postgres_realm_creation_clears_legacy_non_fk_orphans() {
    let url = match std::env::var("QID_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL realm reuse: QID_TEST_POSTGRES_URL is unset");
            return;
        }
        Err(_) => panic!("QID_TEST_POSTGRES_URL must be valid Unicode"),
    };
    let options: PgConnectOptions = url.parse().expect("valid PostgreSQL test URL");
    let pool = PgPool::connect_with(options.clone()).await.unwrap();
    let repo = SqlRepository::connect(&repository_url(
        &options,
        "qid-realm-reuse",
        "read committed",
    ))
    .await
    .unwrap();
    repo.migrate().await.unwrap();
    let realm = format!("realm-reuse-{}", ulid::Ulid::new());
    let peer = format!("{realm}-peer");
    let id = realm.clone().into();
    let issuer = format!("https://{realm}.example");
    let peer_issuer = format!("https://{peer}.example");
    for (scope, issuer) in [(&realm, &issuer), (&peer, &peer_issuer)] {
        repo.create_realm(&"tenant-a".into(), &scope.clone().into(), issuer, None)
            .await
            .unwrap();
        // Non-FK legacy data/history only. Keep unrelated CRUD placeholder
        // portability outside this slice; parent creation uses Repository APIs.
        for statement in include_str!("fixtures/realm_seed.sql").lines().filter(|s| {
            [
                "service_accounts",
                "ciam_brands",
                "audit_events",
                "audit_retention_configs",
                "siem_delivery_queue",
                "marketplace_connectors",
                "relationship_tuples",
            ]
            .iter()
            .any(|table| s.starts_with(&format!("INSERT INTO {table} (")))
        }) {
            sqlx::raw_sql(&statement.replace("'realm", &format!("'{scope}")))
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    let counts_sql = format!(
        "{} ORDER BY resource",
        include_str!("fixtures/realm_counts.sql").replace('?', "$1")
    );
    let before: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
        .bind(&peer)
        .fetch_all(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM realms WHERE id = $1")
        .bind(&realm)
        .execute(&pool)
        .await
        .unwrap();
    let orphans: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
        .bind(&realm)
        .fetch_all(&pool)
        .await
        .unwrap();
    for table in ["service_accounts", "ciam_brands"] {
        assert_eq!(orphans.iter().find(|(t, _)| t == table).unwrap().1, 1);
    }
    // Unknown deletion is still unauthorized; issuer/ID conflicts must not
    // clean either the orphaned target or the incumbent peer.
    repo.delete_realm(&id, &"tenant-a".into()).await.unwrap();
    for (candidate, candidate_issuer) in [(&id, &peer_issuer), (&peer.clone().into(), &issuer)] {
        assert!(matches!(
            repo.create_realm(&"tenant-b".into(), candidate, candidate_issuer, None)
                .await,
            Err(qid_core::QidError::Conflict { .. })
        ));
        let remaining: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
            .bind(&realm)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, orphans);
        let remaining: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
            .bind(&peer)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, before);
    }
    repo.create_realm(&"tenant-b".into(), &id, &issuer, None)
        .await
        .unwrap();
    assert_eq!(
        repo.get_realm_tenant(&id).await.unwrap().as_deref(),
        Some("tenant-b")
    );
    let remaining: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
        .bind(&realm)
        .fetch_all(&pool)
        .await
        .unwrap();
    for (table, count) in remaining {
        assert_eq!(count, i64::from(table == "realms"), "{table}");
    }
    let remaining: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
        .bind(&peer)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, before);
    for scope in [&realm, &peer] {
        for statement in [
            "SELECT COUNT(*) FROM audit_events WHERE realm_id = $1",
            "SELECT COUNT(*) FROM audit_retention_configs WHERE realm_id = $1",
            "SELECT COUNT(*) FROM siem_delivery_queue WHERE realm_id = $1",
            "SELECT COUNT(*) FROM marketplace_connectors WHERE id = $1 || '-record'",
            "SELECT COUNT(*) FROM relationship_tuples WHERE namespace = $1",
        ] {
            let count: i64 = sqlx::query_scalar(statement)
                .bind(scope)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, 1, "{statement}");
        }
    }
    repo.delete_realm(&id, &"tenant-b".into()).await.unwrap();
    repo.delete_realm(&peer.clone().into(), &"tenant-a".into())
        .await
        .unwrap();
    for scope in [&realm, &peer] {
        for statement in [
            "DELETE FROM audit_events WHERE realm_id = $1",
            "DELETE FROM audit_retention_configs WHERE realm_id = $1",
            "DELETE FROM siem_delivery_queue WHERE realm_id = $1",
            "DELETE FROM marketplace_connectors WHERE id = $1 || '-record'",
            "DELETE FROM relationship_tuples WHERE namespace = $1",
        ] {
            sqlx::query(statement)
                .bind(scope)
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    repo.close().await;
    pool.close().await;
}
