//! One confirmation contract, exercised against both supported stores.
use qid_core::{
    models::{CiamVerificationChallengeRecord, User},
    tenant::RealmId,
};
use qid_storage::{FileFlushMode, FileRepository, SqlRepository, prelude::*};
use std::{sync::Arc, time::Duration};

async fn seed(repo: &impl Repository) -> CiamVerificationChallengeRecord {
    repo.create_realm(
        &"tenant".into(),
        &"test".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "owner".into(),
        realm_id: "test".into(),
        email: Some("owner@example.com".into()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    CiamVerificationChallengeRecord {
        id: "challenge".into(),
        realm_id: "test".into(),
        user_id: "owner".into(),
        channel: "email".into(),
        address: "owner@example.com".into(),
        purpose: "email_verification".into(),
        code_hash: "trusted-bound-hash".into(),
        attempt_count: 0,
        expires_at_epoch_seconds: 200,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 100,
    }
}

async fn row(repo: &impl Repository, id: &str) -> CiamVerificationChallengeRecord {
    repo.get_ciam_verification_challenge(&"test".into(), id)
        .await
        .unwrap()
        .unwrap()
}

async fn confirm(
    repo: &impl Repository,
    realm: &str,
    id: &str,
    owner: &str,
    hash: &str,
    now: u64,
    attempts: u32,
) -> bool {
    repo.confirm_ciam_email_verification(&RealmId::from(realm), id, owner, hash, now, attempts)
        .await
        .unwrap()
}

async fn contract(repo: &impl Repository) {
    let challenge = seed(repo).await;
    repo.store_ciam_verification_challenge(&challenge)
        .await
        .unwrap();
    for (realm, id, owner, now, attempts) in [
        ("test", "unknown", "owner", 150, 5),
        ("foreign", "challenge", "owner", 150, 5),
        ("test", "challenge", "foreign", 150, 5),
        ("test", "challenge", "owner", 201, 5), // after inclusive expiry
        ("test", "challenge", "owner", 150, 0),
    ] {
        assert!(!confirm(repo, realm, id, owner, &challenge.code_hash, now, attempts).await);
        assert_eq!(row(repo, &challenge.id).await, challenge);
    }
    let mut boundary = challenge.clone();
    boundary.id = "expiry-boundary".into();
    repo.store_ciam_verification_challenge(&boundary)
        .await
        .unwrap();
    assert!(
        confirm(
            repo,
            "test",
            &boundary.id,
            "owner",
            &boundary.code_hash,
            200,
            5
        )
        .await
    );
    assert_eq!(
        row(repo, &boundary.id).await.consumed_at_epoch_seconds,
        Some(200)
    );
    assert!(!confirm(repo, "test", &challenge.id, "owner", "wrong", 150, 2).await);
    assert!(!confirm(repo, "test", &challenge.id, "owner", "wrong", 151, 2).await);
    assert!(
        !confirm(
            repo,
            "test",
            &challenge.id,
            "owner",
            &challenge.code_hash,
            152,
            2
        )
        .await
    );
    let exhausted = row(repo, &challenge.id).await;
    assert_eq!(exhausted.attempt_count, 2);
    assert!(exhausted.consumed_at_epoch_seconds.is_none());

    let mut stale = challenge.clone();
    stale.id = "stale".into();
    repo.store_ciam_verification_challenge(&stale)
        .await
        .unwrap();
    let mut user = repo.get_user_by_id("owner").await.unwrap().unwrap();
    user.email_verified = false;
    user.email = Some("OWNER@example.com".into()); // exact, not case-folded equality
    repo.update_user(&user).await.unwrap();
    assert!(!confirm(repo, "test", &stale.id, "owner", &stale.code_hash, 150, 5).await);
    assert_eq!(row(repo, &stale.id).await, stale);
    assert!(
        !repo
            .get_user_by_id("owner")
            .await
            .unwrap()
            .unwrap()
            .email_verified
    );
    user.email = None;
    repo.update_user(&user).await.unwrap();
    assert!(!confirm(repo, "test", &stale.id, "owner", &stale.code_hash, 150, 5).await);
    user.email = Some(stale.address.clone());
    repo.update_user(&user).await.unwrap();
    // Competing valid requests: exactly one consumes and verifies.
    let (a, b) = tokio::join!(
        confirm(repo, "test", &stale.id, "owner", &stale.code_hash, 150, 5),
        confirm(repo, "test", &stale.id, "owner", &stale.code_hash, 150, 5),
    );
    assert_ne!(a, b);
    assert_eq!(row(repo, &stale.id).await.attempt_count, 1);
    assert_eq!(
        row(repo, &stale.id).await.consumed_at_epoch_seconds,
        Some(150)
    );
    assert!(
        repo.get_user_by_id("owner")
            .await
            .unwrap()
            .unwrap()
            .email_verified
    );
    assert!(!confirm(repo, "test", &stale.id, "owner", &stale.code_hash, 151, 5).await);

    let mut last = challenge.clone();
    last.id = "last-attempt".into();
    repo.store_ciam_verification_challenge(&last).await.unwrap();
    // Wrong and correct requests share one remaining attempt, never overrun it.
    let (wrong, correct) = tokio::join!(
        confirm(repo, "test", &last.id, "owner", "wrong", 150, 1),
        confirm(repo, "test", &last.id, "owner", &last.code_hash, 150, 1),
    );
    assert!(!wrong);
    let final_row = row(repo, &last.id).await;
    assert_eq!(final_row.attempt_count, 1);
    assert_eq!(final_row.consumed_at_epoch_seconds.is_some(), correct);

    let mut race = challenge;
    race.id = "contact-race".into();
    repo.store_ciam_verification_challenge(&race).await.unwrap();
    user.email_verified = false;
    repo.update_user(&user).await.unwrap();
    user.email = Some("replacement@example.com".into());
    let (verified, updated) = tokio::join!(
        confirm(repo, "test", &race.id, "owner", &race.code_hash, 150, 5),
        repo.update_user(&user),
    );
    updated.unwrap();
    let final_user = repo.get_user_by_id("owner").await.unwrap().unwrap();
    assert_eq!(final_user.email, user.email);
    assert!(!final_user.email_verified);
    let final_row = row(repo, &race.id).await;
    assert_eq!(final_row.consumed_at_epoch_seconds.is_some(), verified);
    assert_eq!(final_row.attempt_count, u32::from(verified));
}

#[tokio::test]
async fn file_email_verification_contract_and_durability() {
    let dir = std::env::temp_dir().join(format!("qid-email-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    contract(&repo).await;
    let before = row(&repo, "stale").await;
    drop(repo);
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert_eq!(row(&repo, "stale").await, before);
    assert!(!confirm(&repo, "test", "stale", "owner", &before.code_hash, 151, 5).await);
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_email_verification_contract_and_durability() {
    let dir = std::env::temp_dir().join(format!("qid-email-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    contract(&repo).await;
    let before = row(&repo, "stale").await;
    repo.close().await;
    let repo = SqlRepository::connect(&url).await.unwrap();
    assert_eq!(row(&repo, "stale").await, before);
    assert!(!confirm(&repo, "test", "stale", "owner", &before.code_hash, 151, 5).await);
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn file_email_verification_is_durable_even_with_interval_flush_and_rolls_back_failure() {
    let dir = std::env::temp_dir().join(format!("qid-email-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let path = dir.join("store.json");
        let repo = Arc::new(
            FileRepository::new_with_flush_mode(
                path.to_str().unwrap(),
                FileFlushMode::Interval(Duration::from_secs(3600)),
            )
            .await
            .unwrap(),
        );
        let challenge = seed(repo.as_ref()).await;
        repo.store_ciam_verification_challenge(&challenge)
            .await
            .unwrap();
        // The published file must already include issuance despite interval mode.
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            disk["ciam_verification_challenges"]["challenge"]["attempt_count"],
            0
        );
        // Force a bounded persistence failure without platform-specific permissions.
        let tmp = path.with_extension("tmp");
        std::fs::create_dir(&tmp).unwrap();
        assert!(
            repo.confirm_ciam_email_verification(
                &"test".into(),
                &challenge.id,
                "owner",
                &challenge.code_hash,
                150,
                5
            )
            .await
            .is_err()
        );
        assert_eq!(row(repo.as_ref(), &challenge.id).await, challenge);
        assert!(
            !repo
                .get_user_by_id("owner")
                .await
                .unwrap()
                .unwrap()
                .email_verified
        );
        let mut failed = challenge.clone();
        failed.id = "failed-issuance".into();
        assert!(
            repo.store_ciam_verification_challenge(&failed)
                .await
                .is_err()
        );
        assert!(
            repo.get_ciam_verification_challenge(&"test".into(), &failed.id)
                .await
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir(&tmp).unwrap();
        assert!(
            confirm(
                repo.as_ref(),
                "test",
                &challenge.id,
                "owner",
                &challenge.code_hash,
                150,
                5
            )
            .await
        );
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            disk["ciam_verification_challenges"]["challenge"]["consumed_at_epoch_seconds"],
            150
        );
        assert_eq!(disk["users"]["owner"]["email_verified"], true);
    });
    // Dropping the runtime cancels the interval task and releases its file lock
    // before cleanup, including on Windows.
    drop(runtime);
    std::fs::remove_dir_all(dir).unwrap();
}
