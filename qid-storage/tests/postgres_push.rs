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
    let tenant = ulid::Ulid::new().to_string();
    sqlx::query("INSERT INTO realms (id, tenant_id, issuer) VALUES ($1, $2, $3)")
        .bind(&realm)
        .bind(&tenant)
        .bind("https://id.example.com")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, realm_id, email_verified) VALUES ($1, $2, 0)")
        .bind(&user)
        .bind(&realm)
        .execute(&pool)
        .await
        .unwrap();

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
