use qid_core::{QidError, models::*, tenant::RealmId};
use qid_storage::{FileRepository, SqlRepository, prelude::*};
use tokio::sync::Barrier;

fn credential(user: &str, hash: &str) -> PasswordCredential {
    PasswordCredential {
        user_id: user.into(),
        hash: hash.into(),
        algorithm: "argon2id".into(),
    }
}

async fn seed(repo: &impl Repository) {
    repo.create_realm(
        &"tenant".into(),
        &"realm".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    for id in ["owner", "other"] {
        repo.create_user(&User {
            id: id.into(),
            realm_id: "realm".into(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
        repo.store_password_credential(&credential(id, "previous"))
            .await
            .unwrap();
    }
    repo.store_password_reset_token(&PasswordResetToken {
        id: "reset".into(),
        realm_id: "realm".into(),
        user_id: "owner".into(),
        token_hash: "presented-digest".into(),
        device_id: Some("device".into()),
        risk_json: serde_json::json!({}),
        expires_at_epoch_seconds: 200,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 100,
    })
    .await
    .unwrap();
}

async fn assert_state(repo: &impl Repository, hash: &str, consumed_at: Option<u64>) {
    let actual = repo
        .get_password_credential("owner")
        .await
        .unwrap()
        .unwrap();
    let expected = credential("owner", hash);
    assert_eq!(actual.hash, expected.hash);
    assert_eq!(actual.algorithm, expected.algorithm);
    let token = repo
        .get_password_reset_token("reset")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token.consumed_at_epoch_seconds, consumed_at);
    assert_eq!(token.token_hash, "presented-digest");
    assert_eq!(token.user_id, "owner");
    assert_eq!(
        repo.get_password_credential("other")
            .await
            .unwrap()
            .unwrap()
            .hash,
        "previous"
    );
}

async fn reset_regressions(repo: &impl Repository) {
    seed(repo).await;
    let realm: RealmId = "realm".into();
    // Every rejection leaves both owners' credentials and the unused token intact.
    for (id, realm, hash, device, user, now, expected) in [
        (
            "reset",
            "realm",
            "wrong",
            Some("device"),
            "owner",
            150,
            "token_mismatch",
        ),
        (
            "reset",
            "realm",
            "presented-digest",
            Some("wrong"),
            "owner",
            150,
            "device_mismatch",
        ),
        (
            "reset",
            "realm",
            "presented-digest",
            None,
            "owner",
            150,
            "device_mismatch",
        ),
        (
            "reset",
            "realm",
            "presented-digest",
            Some("device"),
            "owner",
            201,
            "expired",
        ),
        (
            "reset",
            "realm",
            "presented-digest",
            Some("device"),
            "other",
            150,
            "owner_mismatch",
        ),
        (
            "reset",
            "other",
            "presented-digest",
            Some("device"),
            "owner",
            150,
            "owner_mismatch",
        ),
    ] {
        let err = repo
            .replace_password_with_reset_token(
                id,
                &realm.into(),
                hash,
                device,
                &credential(user, "rejected"),
                now,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, QidError::BadRequest { message } if message == expected));
        assert_state(repo, "previous", None).await;
    }
    assert!(matches!(
        repo.replace_password_with_reset_token(
            "missing",
            &realm,
            "presented-digest",
            Some("device"),
            &credential("owner", "rejected"),
            150
        )
        .await,
        Err(QidError::NotFound { .. })
    ));
    assert_state(repo, "previous", None).await;

    // Both callers have read the same unused token before either may mutate.
    // Distinct credentials identify the winner, independent of task scheduling.
    let barrier = Barrier::new(2);
    let attempt = |hash| {
        let barrier = &barrier;
        let realm = &realm;
        async move {
            assert!(
                repo.get_password_reset_token("reset")
                    .await
                    .unwrap()
                    .unwrap()
                    .consumed_at_epoch_seconds
                    .is_none()
            );
            barrier.wait().await;
            repo.replace_password_with_reset_token(
                "reset",
                realm,
                "presented-digest",
                Some("device"),
                &credential("owner", hash),
                200,
            )
            .await
        }
    };
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(attempt("first"), attempt("second"))
    })
    .await
    .expect("concurrent reset deadlocked");
    let winner = match (first, second) {
        (Ok(()), Err(QidError::Conflict { .. })) => "first",
        (Err(QidError::Conflict { .. }), Ok(())) => "second",
        results => panic!("expected exactly one winner, got {results:?}"),
    };
    assert_state(repo, winner, Some(200)).await;
    assert!(matches!(
        repo.replace_password_with_reset_token(
            "reset",
            &realm,
            "presented-digest",
            Some("device"),
            &credential("owner", "replay"),
            200
        )
        .await,
        Err(QidError::Conflict { .. })
    ));
    assert_state(repo, winner, Some(200)).await;

    // An unbound token requires an absent device.
    let mut unbound = repo
        .get_password_reset_token("reset")
        .await
        .unwrap()
        .unwrap();
    unbound.id = "unbound".into();
    unbound.device_id = None;
    unbound.consumed_at_epoch_seconds = None;
    repo.store_password_reset_token(&unbound).await.unwrap();
    assert!(
        matches!(repo.replace_password_with_reset_token("unbound", &realm, "presented-digest", Some("device"), &credential("owner", "unbound"), 150).await,
        Err(QidError::BadRequest { message }) if message == "device_mismatch")
    );
    repo.replace_password_with_reset_token(
        "unbound",
        &realm,
        "presented-digest",
        None,
        &credential("owner", "unbound"),
        150,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.get_password_credential("owner")
            .await
            .unwrap()
            .unwrap()
            .hash,
        "unbound"
    );
    assert_eq!(
        repo.get_password_reset_token("unbound")
            .await
            .unwrap()
            .unwrap()
            .consumed_at_epoch_seconds,
        Some(150)
    );
}

#[tokio::test]
async fn file_password_reset_is_atomic_and_owner_bound() {
    let dir = std::env::temp_dir().join(format!("qid-reset-{}", ulid::Ulid::new()));
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    reset_regressions(&repo).await;
    drop(repo);
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert_eq!(
        repo.get_password_credential("owner")
            .await
            .unwrap()
            .unwrap()
            .hash,
        "unbound"
    );
    assert_eq!(
        repo.get_password_reset_token("reset")
            .await
            .unwrap()
            .unwrap()
            .consumed_at_epoch_seconds,
        Some(200)
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_password_reset_is_atomic_and_owner_bound() {
    let path = std::env::temp_dir().join(format!("qid-reset-{}.db", ulid::Ulid::new()));
    let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    reset_regressions(&repo).await;
    repo.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sql_password_reset_credential_failure_rolls_back_both_writes() {
    let path = std::env::temp_dir().join(format!("qid-reset-rollback-{}.db", ulid::Ulid::new()));
    let url = format!("sqlite:{}", path.display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::raw_sql("CREATE TRIGGER block_reset AFTER UPDATE ON credentials_password BEGIN SELECT RAISE(ABORT, 'test failure'); END;")
        .execute(&pool).await.unwrap();
    assert!(
        repo.replace_password_with_reset_token(
            "reset",
            &"realm".into(),
            "presented-digest",
            Some("device"),
            &credential("owner", "failed"),
            150
        )
        .await
        .is_err()
    );
    assert_state(&repo, "previous", None).await;
    sqlx::raw_sql("DROP TRIGGER block_reset")
        .execute(&pool)
        .await
        .unwrap();
    repo.replace_password_with_reset_token(
        "reset",
        &"realm".into(),
        "presented-digest",
        Some("device"),
        &credential("owner", "retry"),
        150,
    )
    .await
    .unwrap();
    assert_state(&repo, "retry", Some(150)).await;
    repo.close().await;
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}

fn issuance_token(id: &str, realm: &str, user: &str, now: u64) -> PasswordResetToken {
    PasswordResetToken {
        id: id.into(),
        realm_id: realm.into(),
        user_id: user.into(),
        token_hash: "digest".into(),
        device_id: None,
        risk_json: serde_json::json!({}),
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now + 50,
        consumed_at_epoch_seconds: None,
    }
}

async fn issuance_boundaries(repo: &impl Repository) {
    seed(repo).await;
    repo.create_realm(
        &"tenant".into(),
        &"elsewhere".into(),
        "https://elsewhere.example.com",
        None,
    )
    .await
    .unwrap();
    // Consumed, expired and failed-delivery records retain their accounting.
    repo.consume_password_reset_token("reset", 105)
        .await
        .unwrap();
    let mut token = issuance_token("boundary", "realm", "owner", 299);
    assert!(
        !repo
            .try_issue_password_reset_token(&token, 1, 200)
            .await
            .unwrap()
    );
    assert!(
        repo.get_password_reset_token("boundary")
            .await
            .unwrap()
            .is_none()
    );
    token.created_at_epoch_seconds = 300;
    token.expires_at_epoch_seconds = 350;
    assert!(
        repo.try_issue_password_reset_token(&token, 1, 200)
            .await
            .unwrap()
    );
    // Duplicate IDs are errors even when the account has spent its budget.
    assert!(
        repo.try_issue_password_reset_token(&token, 1, 200)
            .await
            .is_err()
    );
    let mut collision = token.clone();
    collision.user_id = "other".into();
    assert!(
        repo.try_issue_password_reset_token(&collision, 1, 200)
            .await
            .is_err()
    );
    assert_eq!(
        repo.get_password_reset_token("boundary")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        "owner"
    );
    // Realm and user are both accounting keys.
    for (id, realm, user) in [
        ("other-user", "realm", "other"),
        ("other-realm", "elsewhere", "owner"),
    ] {
        assert!(
            repo.try_issue_password_reset_token(&issuance_token(id, realm, user, 300), 1, 200)
                .await
                .unwrap()
        );
    }
    // An older task cannot ignore newer records already inserted by another task.
    assert!(
        !repo
            .try_issue_password_reset_token(
                &issuance_token("delayed", "realm", "owner", 298),
                2,
                200
            )
            .await
            .unwrap()
    );
    for (max, window) in [(0, 200), (1, 0), (1, 86401)] {
        assert!(
            repo.try_issue_password_reset_token(
                &issuance_token("invalid", "realm", "owner", 500),
                max,
                window
            )
            .await
            .is_err()
        );
    }
    let mut overflow = issuance_token("overflow", "realm", "owner", i64::MAX as u64);
    assert!(
        repo.try_issue_password_reset_token(&overflow, 1, 1)
            .await
            .is_err()
    );
    overflow = issuance_token("overflow", "realm", "owner", 500);
    overflow.consumed_at_epoch_seconds = Some(u64::MAX);
    assert!(
        repo.try_issue_password_reset_token(&overflow, 1, 1)
            .await
            .is_err()
    );
    // u32::MAX is a valid budget, and a one-second window counts the current second.
    let token = issuance_token("wide-budget", "realm", "owner", 500);
    assert!(
        repo.try_issue_password_reset_token(&token, u32::MAX, 1)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .try_issue_password_reset_token(
                &issuance_token("same-second", "realm", "owner", 500),
                1,
                1
            )
            .await
            .unwrap()
    );
    assert!(
        repo.try_issue_password_reset_token(
            &issuance_token("next-second", "realm", "owner", 501),
            1,
            1
        )
        .await
        .unwrap()
    );
}

async fn issuance_concurrency<R: Repository + 'static>(repo: std::sync::Arc<R>) {
    repo.create_user(&User {
        id: "parallel".into(),
        realm_id: "realm".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let barrier = std::sync::Arc::new(Barrier::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8 {
        let repo = repo.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            let token = issuance_token(&format!("parallel-{index}"), "realm", "parallel", 600);
            barrier.wait().await;
            let issued = repo
                .try_issue_password_reset_token(&token, 3, 3600)
                .await
                .unwrap();
            assert_eq!(
                repo.get_password_reset_token(&token.id)
                    .await
                    .unwrap()
                    .is_some(),
                issued
            );
            issued
        });
    }
    let mut issued = 0;
    while let Some(result) = tasks.join_next().await {
        issued += usize::from(result.unwrap());
    }
    assert_eq!(issued, 3);
}

#[tokio::test]
async fn file_password_reset_issuance_budget_boundaries_and_concurrency() {
    let dir = std::env::temp_dir().join(format!("qid-reset-budget-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let repo = std::sync::Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    issuance_boundaries(repo.as_ref()).await;
    issuance_concurrency(repo.clone()).await;
    drop(repo);
    // Budget history survives restart, including consumed rows.
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert!(
        !repo
            .try_issue_password_reset_token(
                &issuance_token("after-restart", "realm", "parallel", 600),
                3,
                3600
            )
            .await
            .unwrap()
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_password_reset_issuance_budget_boundaries_and_concurrency() {
    let path = std::env::temp_dir().join(format!("qid-reset-budget-{}.db", ulid::Ulid::new()));
    let repo = std::sync::Arc::new(
        SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    issuance_boundaries(repo.as_ref()).await;
    issuance_concurrency(repo.clone()).await;
    std::sync::Arc::try_unwrap(repo).unwrap().close().await;
    std::fs::remove_file(path).unwrap();
}
