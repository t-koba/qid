//! The same durable magic-link contract against file and SQL stores.
use qid_core::{
    QidError,
    models::{CiamVerificationChallengeRecord, User},
};
use qid_storage::{FileFlushMode, FileRepository, SqlRepository, prelude::*};
use std::time::Duration;

fn proof(binding: &str, token: &str) -> String {
    format!("ml2:{}:{}", binding.repeat(64), token.repeat(64))
}

async fn seed(repo: &impl Repository) -> CiamVerificationChallengeRecord {
    for realm in ["test", "other"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    for id in ["owner", "secondary"] {
        repo.create_user(&User {
            id: id.into(),
            realm_id: "test".into(),
            email: Some(format!("{id}@example.com")),
            email_verified: true,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    CiamVerificationChallengeRecord {
        id: "challenge".into(),
        realm_id: "test".into(),
        user_id: "owner".into(),
        channel: "email".into(),
        address: "owner@example.com".into(),
        purpose: "email_magic_link".into(),
        code_hash: proof("a", "b"),
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

async fn redeem(
    repo: &impl Repository,
    c: &CiamVerificationChallengeRecord,
    hash: &str,
    now: u64,
    cap: u32,
) -> Option<User> {
    repo.redeem_email_magic_link_challenge(&c.realm_id.clone().into(), &c.id, hash, now, cap)
        .await
        .unwrap()
}

async fn contract(repo: &impl Repository) {
    let base = seed(repo).await;
    // Admission refuses a stale destination or an unverified current owner.
    for kind in ["stale-address", "foreign-realm"] {
        let mut invalid = base.clone();
        invalid.id = format!("invalid-{kind}");
        if kind == "stale-address" {
            invalid.address = "old@example.com".into();
        } else {
            invalid.realm_id = "other".into();
        }
        assert!(
            !repo
                .try_issue_email_magic_link_challenge(&invalid, 1, 10)
                .await
                .unwrap()
        );
        assert!(
            repo.get_ciam_verification_challenge(&invalid.realm_id.clone().into(), &invalid.id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut unverified = repo.get_user_by_id("owner").await.unwrap().unwrap();
    unverified.email_verified = false;
    repo.update_user(&unverified).await.unwrap();
    let mut ineligible = base.clone();
    ineligible.id = "unverified-owner".into();
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&ineligible, 1, 10)
            .await
            .unwrap()
    );
    assert!(
        repo.get_ciam_verification_challenge(&ineligible.realm_id.clone().into(), &ineligible.id)
            .await
            .unwrap()
            .is_none()
    );
    unverified.email_verified = true;
    repo.update_user(&unverified).await.unwrap();
    // Unrelated purposes, owners and realms do not spend this account's budget.
    for kind in ["purpose", "user", "realm"] {
        let mut c = base.clone();
        c.id = format!("unrelated-{kind}");
        match kind {
            "purpose" => c.purpose = "email_verification".into(),
            "user" => c.user_id = "secondary".into(),
            _ => c.realm_id = "other".into(),
        }
        repo.store_ciam_verification_challenge(&c).await.unwrap();
    }
    let mut earliest = base.clone();
    earliest.id = "saturating-window".into();
    earliest.created_at_epoch_seconds = 1;
    earliest.expires_at_epoch_seconds = 2;
    assert!(
        repo.try_issue_email_magic_link_challenge(&earliest, 1, 86400)
            .await
            .unwrap()
    );
    let mut old = base.clone();
    old.id = "old-consumed".into();
    old.expires_at_epoch_seconds = 101;
    assert!(
        repo.try_issue_email_magic_link_challenge(&old, 1, 10)
            .await
            .unwrap()
    );
    assert!(redeem(repo, &old, &old.code_hash, 101, 2).await.is_some());
    let mut next = base.clone();
    next.id = "not-delivered".into();
    next.created_at_epoch_seconds = 109;
    // Window [100,109]: the consumed, expired record still counts at equality.
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&next, 1, 10)
            .await
            .unwrap()
    );
    assert!(
        repo.get_ciam_verification_challenge(&"test".into(), &next.id)
            .await
            .unwrap()
            .is_none()
    );
    // Window [101,110]: the old creation is now outside, exactly one second later.
    next.created_at_epoch_seconds = 110;
    next.expires_at_epoch_seconds = 111;
    assert!(
        repo.try_issue_email_magic_link_challenge(&next, 1, 10)
            .await
            .unwrap()
    );
    let mut suppressed = next.clone();
    suppressed.id = "suppressed".into();
    suppressed.created_at_epoch_seconds = 119;
    suppressed.expires_at_epoch_seconds = 120;
    // A failed delivery is deliberately not deleted, nor discounted after expiry.
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&suppressed, 1, 10)
            .await
            .unwrap()
    );
    let mut duplicate = suppressed.clone();
    duplicate.id = next.id.clone();
    duplicate.code_hash = proof("d", "e");
    assert!(matches!(
        repo.try_issue_email_magic_link_challenge(&duplicate, 1, 10)
            .await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(row(repo, &next.id).await, next);
    duplicate.user_id = "secondary".into(); // global identity is immutable across owners too
    assert!(matches!(
        repo.try_issue_email_magic_link_challenge(&duplicate, 1, 10)
            .await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(row(repo, &next.id).await, next);

    let mut future = base.clone();
    future.id = "newer-record".into();
    future.created_at_epoch_seconds = 1000;
    future.expires_at_epoch_seconds = 1100;
    assert!(
        repo.try_issue_email_magic_link_challenge(&future, 1, 10)
            .await
            .unwrap()
    );
    let mut backward = future.clone();
    backward.id = "clock-backward".into();
    backward.created_at_epoch_seconds = 900;
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&backward, 1, 10)
            .await
            .unwrap()
    );

    // Issuance serializes independent requests sharing the last budget slot.
    let mut a = base.clone();
    a.id = "concurrent-a".into();
    a.created_at_epoch_seconds = 2000;
    a.expires_at_epoch_seconds = 2100;
    let mut b = a.clone();
    b.id = "concurrent-b".into();
    let (issued_a, issued_b) = tokio::join!(
        repo.try_issue_email_magic_link_challenge(&a, 1, 10),
        repo.try_issue_email_magic_link_challenge(&b, 1, 10),
    );
    assert_ne!(issued_a.unwrap(), issued_b.unwrap());
    assert_ne!(
        repo.get_ciam_verification_challenge(&"test".into(), &a.id)
            .await
            .unwrap()
            .is_some(),
        repo.get_ciam_verification_challenge(&"test".into(), &b.id)
            .await
            .unwrap()
            .is_some()
    );

    // Invalid admission inputs fail closed without inserting anything.
    for kind in [
        "channel",
        "purpose",
        "attempts",
        "consumed",
        "timestamp",
        "empty-hash",
        "legacy-hash",
    ] {
        let mut invalid = base.clone();
        invalid.id = format!("invalid-{kind}");
        match kind {
            "channel" => invalid.channel = "phone".into(),
            "purpose" => invalid.purpose = "email_verification".into(),
            "attempts" => invalid.attempt_count = 1,
            "consumed" => invalid.consumed_at_epoch_seconds = Some(101),
            "timestamp" => invalid.expires_at_epoch_seconds = u64::MAX,
            "legacy-hash" => invalid.code_hash = "legacy-digest".into(),
            _ => invalid.code_hash.clear(),
        }
        assert!(matches!(
            repo.try_issue_email_magic_link_challenge(&invalid, 1, 10)
                .await,
            Err(QidError::BadRequest { .. })
        ));
        assert!(
            repo.get_ciam_verification_challenge(&"test".into(), &invalid.id)
                .await
                .unwrap()
                .is_none()
        );
    }
    for (cap, window) in [(0, 10), (1, 0), (1, 86401)] {
        assert!(
            repo.try_issue_email_magic_link_challenge(&base, cap, window)
                .await
                .is_err()
        );
    }
    // A one-second window excludes the previous second; the largest window is supported.
    let mut short = base.clone();
    short.id = "short-window".into();
    short.created_at_epoch_seconds = 2001;
    short.expires_at_epoch_seconds = 2100;
    assert!(
        repo.try_issue_email_magic_link_challenge(&short, 1, 1)
            .await
            .unwrap()
    );
    let mut long = short.clone();
    long.id = "long-window".into();
    long.created_at_epoch_seconds = 90000;
    long.expires_at_epoch_seconds = 90001;
    assert!(
        repo.try_issue_email_magic_link_challenge(&long, 1, 86400)
            .await
            .unwrap()
    );

    // The budget key is purpose, not channel. Even an old phone record of this
    // purpose counts; raising the cap admits exactly the next remaining slot.
    let mut phone = base.clone();
    phone.id = "legacy-phone".into();
    phone.channel = "phone".into();
    phone.created_at_epoch_seconds = 94999;
    phone.expires_at_epoch_seconds = 96000;
    repo.store_ciam_verification_challenge(&phone)
        .await
        .unwrap();
    let mut later = phone.clone();
    later.id = "larger-budget".into();
    later.channel = "email".into();
    later.created_at_epoch_seconds = 95000;
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&later, 1, 10)
            .await
            .unwrap()
    );
    assert!(
        repo.try_issue_email_magic_link_challenge(&later, 2, 10)
            .await
            .unwrap()
    );
    later.id = "larger-budget-spent".into();
    assert!(
        !repo
            .try_issue_email_magic_link_challenge(&later, 2, 10)
            .await
            .unwrap()
    );

    // Redemption rejects foreign/inactive records without spending attempts.
    repo.store_ciam_verification_challenge(&base).await.unwrap();
    for (realm, id, now, cap) in [
        ("other", "challenge", 150, 3),
        ("test", "missing", 150, 3),
        ("test", "challenge", 99, 3),
        ("test", "challenge", 201, 3),
        ("test", "challenge", 150, 0),
        ("test", "challenge", u64::MAX, 3),
    ] {
        assert!(
            repo.redeem_email_magic_link_challenge(&realm.into(), id, &base.code_hash, now, cap)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(row(repo, &base.id).await, base);
    }
    for kind in ["channel", "purpose", "foreign-owner"] {
        let mut wrong = base.clone();
        wrong.id = format!("wrong-{kind}");
        match kind {
            "channel" => wrong.channel = "phone".into(),
            "purpose" => wrong.purpose = "email_verification".into(),
            _ => wrong.user_id = "secondary".into(),
        }
        repo.store_ciam_verification_challenge(&wrong)
            .await
            .unwrap();
        assert!(
            redeem(repo, &wrong, &wrong.code_hash, 150, 3)
                .await
                .is_none()
        );
        assert_eq!(row(repo, &wrong.id).await, wrong);
    }
    // A stored challenge whose realm differs from its user's realm is unusable.
    assert!(
        repo.redeem_email_magic_link_challenge(
            &"other".into(),
            "unrelated-realm",
            &base.code_hash,
            150,
            3
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        repo.get_ciam_verification_challenge(&"other".into(), "unrelated-realm")
            .await
            .unwrap()
            .unwrap()
            .attempt_count,
        0
    );
    let mut owner = repo.get_user_by_id("owner").await.unwrap().unwrap();
    for email in [
        Some("OWNER@example.com".into()),
        None,
        Some(base.address.clone()),
    ] {
        owner.email = email;
        owner.email_verified = owner.email.as_deref() != Some(base.address.as_str());
        repo.update_user(&owner).await.unwrap();
        assert!(redeem(repo, &base, &base.code_hash, 150, 3).await.is_none());
        assert_eq!(row(repo, &base.id).await, base);
    }
    owner.email_verified = true;
    repo.update_user(&owner).await.unwrap();
    // Wrong/missing/malformed binding proofs never spend attempts, even beyond the cap.
    for _ in 0..4 {
        for candidate in [
            proof("c", "b"),
            String::new(),
            "ml2:bad:bad".into(),
            "legacy-combined-digest".into(),
            format!("{}:extra", base.code_hash),
        ] {
            assert!(redeem(repo, &base, &candidate, 150, 2).await.is_none());
            assert_eq!(row(repo, &base.id).await, base);
        }
    }
    // The same valid challenge still works from its original browser.
    let mut browser = base.clone();
    browser.id = "browser-binding".into();
    repo.store_ciam_verification_challenge(&browser)
        .await
        .unwrap();
    for _ in 0..4 {
        assert!(
            redeem(repo, &browser, &proof("c", "b"), 150, 2)
                .await
                .is_none()
        );
    }
    assert!(
        redeem(repo, &browser, &browser.code_hash, 150, 2)
            .await
            .is_some()
    );
    assert_eq!(row(repo, &browser.id).await.attempt_count, 1);
    assert_eq!(
        row(repo, &browser.id).await.consumed_at_epoch_seconds,
        Some(150)
    );
    // Correct binding with a wrong token exhausts exactly the durable ceiling.
    for index in 0..2 {
        assert!(
            redeem(repo, &base, &proof("a", "c"), 150, 2)
                .await
                .is_none()
        );
        assert_eq!(row(repo, &base.id).await.attempt_count, index + 1);
    }
    assert!(redeem(repo, &base, &base.code_hash, 150, 2).await.is_none());
    assert_eq!(row(repo, &base.id).await.attempt_count, 2);
    assert!(
        row(repo, &base.id)
            .await
            .consumed_at_epoch_seconds
            .is_none()
    );

    for stored in ["legacy-combined-digest", "ml2:bad:bad"] {
        let mut legacy = base.clone();
        legacy.id = format!("invalid-proof-{stored}");
        legacy.code_hash = stored.into();
        repo.store_ciam_verification_challenge(&legacy)
            .await
            .unwrap();
        assert!(redeem(repo, &legacy, stored, 150, 2).await.is_none());
        assert_eq!(row(repo, &legacy.id).await, legacy);
    }

    // Correct final permitted attempt, at inclusive expiry, returns the bound User.
    let mut success = base.clone();
    success.id = "success".into();
    repo.store_ciam_verification_challenge(&success)
        .await
        .unwrap();
    assert!(
        redeem(repo, &success, &proof("a", "c"), 150, 2)
            .await
            .is_none()
    );
    assert_eq!(
        serde_json::to_value(
            redeem(repo, &success, &success.code_hash, 200, 2)
                .await
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&owner).unwrap()
    );
    let committed = row(repo, &success.id).await;
    assert_eq!(committed.attempt_count, 2);
    assert_eq!(committed.consumed_at_epoch_seconds, Some(200));
    assert!(
        redeem(repo, &success, &success.code_hash, 200, 2)
            .await
            .is_none()
    );
    assert_eq!(row(repo, &success.id).await, committed);
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id("owner").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(owner).unwrap()
    );

    let mut race = base.clone();
    race.id = "race".into();
    repo.store_ciam_verification_challenge(&race).await.unwrap();
    let (a, b) = tokio::join!(
        redeem(repo, &race, &race.code_hash, 100, 1),
        redeem(repo, &race, &race.code_hash, 100, 1),
    );
    assert_ne!(a.is_some(), b.is_some());
    assert_eq!(row(repo, &race.id).await.attempt_count, 1);
    assert_eq!(
        row(repo, &race.id).await.consumed_at_epoch_seconds,
        Some(100)
    );
    // An unauthorized browser racing redemption cannot steal the final attempt.
    race.id = "wrong-binding-race".into();
    repo.store_ciam_verification_challenge(&race).await.unwrap();
    let wrong_binding = proof("c", "b");
    let (bad, good) = tokio::join!(
        redeem(repo, &race, &wrong_binding, 150, 1),
        redeem(repo, &race, &race.code_hash, 150, 1),
    );
    assert!(bad.is_none());
    assert!(good.is_some());
    assert_eq!(row(repo, &race.id).await.attempt_count, 1);
    assert_eq!(
        row(repo, &race.id).await.consumed_at_epoch_seconds,
        Some(150)
    );

    race.id = "last-attempt-race".into();
    repo.store_ciam_verification_challenge(&race).await.unwrap();
    let wrong_token = proof("a", "c");
    let (bad, good) = tokio::join!(
        redeem(repo, &race, &wrong_token, 150, 1),
        redeem(repo, &race, &race.code_hash, 150, 1),
    );
    assert!(bad.is_none());
    let final_row = row(repo, &race.id).await;
    assert_eq!(final_row.attempt_count, 1);
    assert_eq!(
        final_row.consumed_at_epoch_seconds.is_some(),
        good.is_some()
    );
}

#[tokio::test]
async fn file_email_magic_link_contract_and_reopen() {
    let dir = std::env::temp_dir().join(format!("qid-magic-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    contract(&repo).await;
    let before = row(&repo, "success").await;
    drop(repo);
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert_eq!(row(&repo, "success").await, before);
    assert!(
        redeem(&repo, &before, &before.code_hash, 200, 5)
            .await
            .is_none()
    );
    assert_eq!(row(&repo, "not-delivered").await.attempt_count, 0);
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_email_magic_link_contract_and_reopen() {
    let dir = std::env::temp_dir().join(format!("qid-magic-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    contract(&repo).await;
    let before = row(&repo, "success").await;
    repo.close().await;
    let repo = SqlRepository::connect(&url).await.unwrap();
    assert_eq!(row(&repo, "success").await, before);
    assert!(
        redeem(&repo, &before, &before.code_hash, 200, 5)
            .await
            .is_none()
    );
    assert_eq!(row(&repo, "not-delivered").await.attempt_count, 0);
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn file_magic_link_interval_mode_persists_and_rolls_back_errors() {
    let dir = std::env::temp_dir().join(format!("qid-magic-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let path = dir.join("store.json");
        let repo = FileRepository::new_with_flush_mode(
            path.to_str().unwrap(),
            FileFlushMode::Interval(Duration::from_secs(3600)),
        )
        .await
        .unwrap();
        let c = seed(&repo).await;
        let tmp = path.with_extension("tmp");
        std::fs::create_dir(&tmp).unwrap();
        assert!(
            repo.try_issue_email_magic_link_challenge(&c, 1, 10)
                .await
                .is_err()
        );
        assert!(
            repo.get_ciam_verification_challenge(&"test".into(), &c.id)
                .await
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir(&tmp).unwrap();
        assert!(
            repo.try_issue_email_magic_link_challenge(&c, 1, 10)
                .await
                .unwrap()
        );
        let issued = std::fs::read(&path).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        for hash in [&proof("a", "c"), &c.code_hash] {
            assert!(
                repo.redeem_email_magic_link_challenge(&"test".into(), &c.id, hash, 150, 3)
                    .await
                    .is_err()
            );
            assert_eq!(row(&repo, &c.id).await, c);
            assert_eq!(std::fs::read(&path).unwrap(), issued);
        }
        std::fs::remove_dir(&tmp).unwrap();
        assert!(redeem(&repo, &c, &proof("a", "c"), 150, 3).await.is_none());
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            disk["ciam_verification_challenges"]["challenge"]["attempt_count"],
            1
        );
        assert!(redeem(&repo, &c, &c.code_hash, 150, 3).await.is_some());
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            disk["ciam_verification_challenges"]["challenge"]["consumed_at_epoch_seconds"],
            150
        );
    });
    drop(runtime); // cancels interval task and releases the file lock on Windows
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_magic_link_storage_errors_roll_back_admission_and_redemption() {
    let dir = std::env::temp_dir().join(format!("qid-magic-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    let c = seed(&repo).await;
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_issuance BEFORE INSERT ON ciam_verification_challenges BEGIN SELECT RAISE(ABORT, 'injected storage error'); END")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        repo.try_issue_email_magic_link_challenge(&c, 1, 10).await,
        Err(QidError::Storage { .. })
    ));
    assert!(
        repo.get_ciam_verification_challenge(&"test".into(), &c.id)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("DROP TRIGGER fail_issuance")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        repo.try_issue_email_magic_link_challenge(&c, 1, 10)
            .await
            .unwrap()
    );
    // Failure of consumption must roll back the earlier attempt increment too.
    sqlx::query("CREATE TRIGGER fail_consumption BEFORE UPDATE OF consumed_at_epoch_seconds ON ciam_verification_challenges BEGIN SELECT RAISE(ABORT, 'injected storage error'); END")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        repo.redeem_email_magic_link_challenge(&"test".into(), &c.id, &c.code_hash, 150, 2)
            .await,
        Err(QidError::Storage { .. })
    ));
    assert_eq!(row(&repo, &c.id).await, c);
    sqlx::query("DROP TRIGGER fail_consumption")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_attempt BEFORE UPDATE OF attempt_count ON ciam_verification_challenges BEGIN SELECT RAISE(ABORT, 'injected storage error'); END")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        repo.redeem_email_magic_link_challenge(&"test".into(), &c.id, &proof("a", "c"), 150, 2)
            .await,
        Err(QidError::Storage { .. })
    ));
    assert_eq!(row(&repo, &c.id).await, c);
    sqlx::query("DROP TRIGGER fail_attempt")
        .execute(&pool)
        .await
        .unwrap();
    assert!(redeem(&repo, &c, &c.code_hash, 150, 2).await.is_some());
    pool.close().await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
