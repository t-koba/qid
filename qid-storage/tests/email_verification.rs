//! One confirmation contract, exercised against both supported stores.
use qid_core::{
    QidError,
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

fn issuance(
    realm: &str,
    user: &str,
    address: &str,
    id: &str,
    created_at: u64,
) -> CiamVerificationChallengeRecord {
    CiamVerificationChallengeRecord {
        id: id.into(),
        realm_id: realm.into(),
        user_id: user.into(),
        channel: "email".into(),
        address: address.into(),
        purpose: "email_verification".into(),
        code_hash: "plain-verification-hash".into(),
        attempt_count: 0,
        expires_at_epoch_seconds: created_at + 100,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: created_at,
    }
}

fn ml2_proof() -> String {
    format!("ml2:{}:{}", "a".repeat(64), "b".repeat(64))
}

async fn issue(
    repo: &impl Repository,
    challenge: &CiamVerificationChallengeRecord,
    cap: u32,
    window: u64,
) -> bool {
    repo.try_issue_email_challenge(challenge, cap, window)
        .await
        .unwrap()
}

async fn missing(repo: &impl Repository, id: &str) -> bool {
    repo.get_ciam_verification_challenge(&"test".into(), id)
        .await
        .unwrap()
        .is_none()
}

/// The same rolling per-(realm,user,purpose) admission as email magic-link:
/// only the same realm/user's current stored email while still unverified is
/// admitted, failed deliveries and newer records still spend the budget, and a
/// magic-link proof is never admissible as email verification (or vice versa).
async fn issuance_contract(repo: &impl Repository) {
    seed(repo).await;
    // Admission refuses a stale destination, a foreign realm, and an owner
    // whose stored email is already verified.
    let stale = issuance("test", "owner", "old@example.com", "stale-address", 100);
    assert!(!issue(repo, &stale, 1, 10).await);
    assert!(missing(repo, &stale.id).await);
    let foreign = issuance("other", "owner", "owner@example.com", "foreign-realm", 100);
    assert!(!issue(repo, &foreign, 1, 10).await);
    let mut verified = repo.get_user_by_id("owner").await.unwrap().unwrap();
    verified.email_verified = true;
    repo.update_user(&verified).await.unwrap();
    let ineligible = issuance("test", "owner", "owner@example.com", "verified-owner", 100);
    assert!(!issue(repo, &ineligible, 1, 10).await);
    assert!(missing(repo, &ineligible.id).await);
    verified.email_verified = false;
    repo.update_user(&verified).await.unwrap();
    // Stored records of another purpose, owner or realm do not spend this
    // account's email-verification budget.
    repo.create_realm(
        &"tenant".into(),
        &"other".into(),
        "https://id.example.com/other",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "secondary".into(),
        realm_id: "test".into(),
        email: Some("secondary@example.com".into()),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    for (kind, realm, user, purpose) in [
        ("purpose", "test", "owner", "email_magic_link"),
        ("user", "test", "secondary", "email_verification"),
        ("realm", "other", "owner", "email_verification"),
    ] {
        let mut unrelated = issuance(
            realm,
            user,
            "owner@example.com",
            &format!("unrelated-{kind}"),
            100,
        );
        unrelated.purpose = purpose.into();
        if user == "secondary" {
            unrelated.address = "secondary@example.com".into();
        }
        repo.store_ciam_verification_challenge(&unrelated)
            .await
            .unwrap();
    }
    // Independent owners are eligible through admission, not just raw storage.
    let secondary = issuance(
        "test",
        "secondary",
        "secondary@example.com",
        "secondary-issued",
        100,
    );
    assert!(issue(repo, &secondary, 2, 10).await);
    assert!(
        !issue(
            repo,
            &issuance(
                "test",
                "secondary",
                "secondary@example.com",
                "secondary-full",
                100
            ),
            2,
            10
        )
        .await
    );
    let mut other = repo.get_user_by_id("secondary").await.unwrap().unwrap();
    other.id = "other-owner".into();
    other.realm_id = "other".into();
    repo.create_user(&other).await.unwrap();
    let other_challenge = issuance(
        "other",
        "other-owner",
        "secondary@example.com",
        "other-issued",
        100,
    );
    assert!(issue(repo, &other_challenge, 1, 10).await);
    assert_eq!(
        repo.get_ciam_verification_challenge(&"other".into(), &other_challenge.id)
            .await
            .unwrap(),
        Some(other_challenge)
    );
    let mut earliest = issuance("test", "owner", "owner@example.com", "saturating-window", 1);
    earliest.expires_at_epoch_seconds = 2;
    assert!(issue(repo, &earliest, 1, 86400).await);
    let old = issuance("test", "owner", "owner@example.com", "old-consumed", 100);
    let mut old = old;
    old.expires_at_epoch_seconds = 101;
    assert!(issue(repo, &old, 1, 10).await);
    assert!(confirm(repo, "test", &old.id, "owner", &old.code_hash, 101, 5).await);
    assert_eq!(
        row(repo, &old.id).await.consumed_at_epoch_seconds,
        Some(101)
    );
    verified.email_verified = false;
    verified.email = Some("replacement@example.com".into());
    repo.update_user(&verified).await.unwrap();
    let changed_address = issuance(
        "test",
        "owner",
        "replacement@example.com",
        "changed-address",
        109,
    );
    assert!(!issue(repo, &changed_address, 1, 10).await);
    verified.email = Some("owner@example.com".into());
    repo.update_user(&verified).await.unwrap();
    // Window [100,109]: the old record still counts at equality.
    let next = issuance("test", "owner", "owner@example.com", "not-delivered", 109);
    assert!(!issue(repo, &next, 1, 10).await);
    assert!(missing(repo, &next.id).await);
    // Window [101,110]: the old creation is now outside, exactly one second later.
    let mut next = next;
    next.id = "admitted-after-window".into();
    next.created_at_epoch_seconds = 110;
    next.expires_at_epoch_seconds = 210;
    assert!(issue(repo, &next, 1, 10).await);
    // A failed delivery is deliberately not deleted, nor discounted after expiry.
    let mut suppressed = issuance("test", "owner", "owner@example.com", "suppressed", 119);
    suppressed.expires_at_epoch_seconds = 219;
    assert!(!issue(repo, &suppressed, 1, 10).await);
    assert!(missing(repo, &suppressed.id).await);
    let mut duplicate = suppressed.clone();
    duplicate.id = next.id.clone();
    assert!(matches!(
        repo.try_issue_email_challenge(&duplicate, 1, 10).await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(row(repo, &next.id).await, next);

    let future = issuance("test", "owner", "owner@example.com", "newer-record", 1000);
    assert!(issue(repo, &future, 1, 10).await);
    let backward = issuance("test", "owner", "owner@example.com", "clock-backward", 900);
    assert!(!issue(repo, &backward, 1, 10).await);
    assert!(missing(repo, &backward.id).await);

    // Issuance serializes independent requests sharing the last budget slot.
    let a = issuance("test", "owner", "owner@example.com", "concurrent-a", 2000);
    let mut b = a.clone();
    b.id = "concurrent-b".into();
    let (issued_a, issued_b) = tokio::join!(
        repo.try_issue_email_challenge(&a, 1, 10),
        repo.try_issue_email_challenge(&b, 1, 10),
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

    // Invalid admission inputs fail closed without inserting anything: the
    // wrong channel, either cross-kind proof confusion, attempts, consumption
    // and unrepresentable expiry all refuse before any budget accounting.
    for kind in [
        "channel",
        "magic-link-purpose",
        "verification-proof",
        "other-purpose",
        "attempts",
        "consumed",
        "timestamp",
        "empty-hash",
    ] {
        let mut invalid = issuance(
            "test",
            "owner",
            "owner@example.com",
            &format!("invalid-{kind}"),
            3000,
        );
        invalid.expires_at_epoch_seconds = 3100;
        match kind {
            "channel" => invalid.channel = "phone".into(),
            "magic-link-purpose" => invalid.purpose = "email_magic_link".into(),
            "verification-proof" => invalid.code_hash = ml2_proof(),
            "other-purpose" => invalid.purpose = "verify_email".into(),
            "attempts" => invalid.attempt_count = 1,
            "consumed" => invalid.consumed_at_epoch_seconds = Some(3001),
            "timestamp" => invalid.expires_at_epoch_seconds = u64::MAX,
            _ => invalid.code_hash.clear(),
        }
        assert!(
            matches!(
                repo.try_issue_email_challenge(&invalid, 1, 10).await,
                Err(QidError::BadRequest { .. })
            ),
            "{kind} must fail closed"
        );
        assert!(missing(repo, &invalid.id).await);
    }
    for (cap, window) in [(0, 10), (1, 0), (1, 86401)] {
        let budget = issuance("test", "owner", "owner@example.com", "invalid-budget", 3000);
        assert!(
            repo.try_issue_email_challenge(&budget, cap, window)
                .await
                .is_err()
        );
    }
    // A one-second window excludes the previous second; the largest window is supported.
    let short = issuance("test", "owner", "owner@example.com", "short-window", 3001);
    assert!(issue(repo, &short, 1, 1).await);
    let long = issuance("test", "owner", "owner@example.com", "long-window", 90000);
    assert!(issue(repo, &long, 1, 86400).await);

    // The budget key is purpose, not channel. Even an old phone record of this
    // purpose counts; raising the cap admits exactly the next remaining slot.
    let mut legacy = issuance("test", "owner", "owner@example.com", "legacy-phone", 94999);
    legacy.channel = "phone".into();
    legacy.expires_at_epoch_seconds = 96000;
    repo.store_ciam_verification_challenge(&legacy)
        .await
        .unwrap();
    let later = issuance("test", "owner", "owner@example.com", "larger-budget", 95000);
    assert!(!issue(repo, &later, 1, 10).await);
    assert!(issue(repo, &later, 2, 10).await);
    let mut spent = later.clone();
    spent.id = "larger-budget-spent".into();
    assert!(!issue(repo, &spent, 2, 10).await);
    assert!(missing(repo, &spent.id).await);
}

#[tokio::test]
async fn file_email_verification_issuance_budget() {
    let dir = std::env::temp_dir().join(format!("qid-email-issuance-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    issuance_contract(&repo).await;
    let before = row(&repo, "larger-budget").await;
    drop(repo);
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(row(&repo, &before.id).await, before);
    assert!(
        !issue(
            &repo,
            &issuance("test", "owner", "owner@example.com", "after-reopen", 95000),
            2,
            10
        )
        .await
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_email_verification_issuance_budget() {
    let dir = std::env::temp_dir().join(format!("qid-email-issuance-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    issuance_contract(&repo).await;
    let before = row(&repo, "larger-budget").await;
    repo.close().await;
    let repo = SqlRepository::connect(&url).await.unwrap();
    assert_eq!(row(&repo, &before.id).await, before);
    assert!(
        !issue(
            &repo,
            &issuance("test", "owner", "owner@example.com", "after-reopen", 95000),
            2,
            10
        )
        .await
    );
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
