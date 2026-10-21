//! The realm's password policy is the policy the product enforces: the
//! lockout limits are the realm's own, and the Argon2id cost is the
//! deployment's calibration.

use anyhow::Context;
use qid_core::{
    config::{Argon2idCostConfig, PasswordConfig},
    error::QidError,
    models::{PasswordCredential, User},
    tenant::RealmId,
    throttle::FailureBudget,
};
use qid_crypto::{
    ARGON2ID_ALGORITHM, Argon2idParams, PBKDF2_SHA256_ALGORITHM, encode_pbkdf2_sha256_hash,
    hash_password_with_params,
};
use qid_session::auth::{Authenticator, PasswordPolicy};
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;

fn policy(max_failed_attempts: u32, argon2id: Argon2idCostConfig) -> PasswordPolicy {
    policy_with_realm_budget(max_failed_attempts, 100, argon2id)
}

fn policy_with_realm_budget(
    max_failed_attempts: u32,
    max_failed_attempts_per_realm: u32,
    argon2id: Argon2idCostConfig,
) -> PasswordPolicy {
    let config = PasswordConfig {
        max_failed_attempts,
        max_failed_attempts_per_realm,
        argon2id,
        ..PasswordConfig::default()
    };
    PasswordPolicy::from_config(&config)
}

async fn repository_with_user(
    password_hash: String,
    algorithm: &str,
) -> anyhow::Result<Arc<FileRepository>> {
    // The two tests of this file run in parallel, so the store path must
    // differ per test rather than per second.
    let path = std::env::temp_dir().join(format!(
        "qid-session-password-policy-{}-{}.json",
        algorithm,
        ulid::Ulid::new()
    ));
    let repo = Arc::new(
        FileRepository::new(path.to_str().context("test path is not UTF-8")?)
            .await
            .context("file repository creation failed")?,
    );
    repo.migrate()
        .await
        .context("file repository migration failed")?;
    repo.create_realm(
        &"tenant-1".into(),
        &"corp".into(),
        "https://login.example.com",
        Some("Test realm"),
    )
    .await
    .context("realm creation failed")?;
    repo.create_user(&User {
        id: "user-1".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .context("user creation failed")?;
    repo.store_password_credential(&PasswordCredential {
        user_id: "user-1".to_string(),
        hash: password_hash,
        algorithm: algorithm.to_string(),
    })
    .await
    .context("password credential creation failed")?;
    Ok(repo)
}

#[tokio::test]
async fn the_realm_lockout_limit_locks_the_account() -> anyhow::Result<()> {
    // The realm states two failed attempts, so the second failure locks
    // the account - the built-in five does not apply.
    let repo = repository_with_user(
        encode_pbkdf2_sha256_hash("correct-password-123!", b"0123456789abcdef", 100_000)
            .context("legacy hash")?,
        PBKDF2_SHA256_ALGORITHM,
    )
    .await?;
    let authenticator = Authenticator::new(
        repo.clone(),
        policy(2, Argon2idCostConfig::default()),
        Arc::new(FailureBudget::new()),
    );

    for _ in 0..2 {
        let err = authenticator
            .authenticate_password(
                &RealmId::from("corp"),
                "alice@example.com",
                "wrong-password",
            )
            .await
            .err()
            .context("a wrong password is refused")?;
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "the refusal is an unauthorized error: {err:?}"
        );
    }

    let stored = repo
        .get_user_by_id("user-1")
        .await
        .context("user lookup failed")?
        .context("the user is missing")?;
    assert!(
        stored.locked_until.is_some(),
        "the second failure locks the account"
    );

    let err = authenticator
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "correct-password-123!",
        )
        .await
        .err()
        .context("a locked account refuses the correct password")?;
    assert!(
        matches!(&err, QidError::TooManyRequests { message } if message == "account is temporarily locked"),
        "the locked account is refused: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_realm_argon2id_cost_reaches_a_credential_that_already_exists() -> anyhow::Result<()> {
    // The credential was hashed at a cheaper cost than the realm states,
    // so the next successful login rehashes it with the realm's cost.
    let repo = repository_with_user(
        hash_password_with_params("correct-password-123!", &Argon2idParams::new(8, 1, 1))
            .context("password hashing failed")?,
        ARGON2ID_ALGORITHM,
    )
    .await?;
    let authenticator = Authenticator::new(
        repo.clone(),
        policy(
            5,
            Argon2idCostConfig {
                memory_kib: 8192,
                time_cost: 4,
                parallelism: 1,
            },
        ),
        Arc::new(FailureBudget::new()),
    );

    authenticator
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "correct-password-123!",
        )
        .await
        .context("password authentication failed")?;

    let stored = repo
        .get_password_credential("user-1")
        .await
        .context("password credential lookup failed")?
        .context("the password credential is missing")?;
    assert!(
        stored.hash.contains("m=8192"),
        "the realm's memory cost reaches the credential: {}",
        stored.hash
    );
    assert!(
        stored.hash.contains("t=4"),
        "the realm's time cost reaches the credential: {}",
        stored.hash
    );
    Ok(())
}

#[tokio::test]
async fn the_realm_argon2id_cost_applies_when_the_product_creates_a_credential()
-> anyhow::Result<()> {
    // An imported PBKDF2 credential is rehashed when the product creates
    // the Argon2id credential, and the realm's own cost applies.
    let repo = repository_with_user(
        encode_pbkdf2_sha256_hash("correct-password-123!", b"0123456789abcdef", 100_000)
            .context("legacy hash")?,
        PBKDF2_SHA256_ALGORITHM,
    )
    .await?;
    let authenticator = Authenticator::new(
        repo.clone(),
        policy(
            5,
            Argon2idCostConfig {
                memory_kib: 8192,
                time_cost: 4,
                parallelism: 1,
            },
        ),
        Arc::new(FailureBudget::new()),
    );

    authenticator
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "correct-password-123!",
        )
        .await
        .context("password authentication failed")?;

    let stored = repo
        .get_password_credential("user-1")
        .await
        .context("password credential lookup failed")?
        .context("the password credential is missing")?;
    assert_eq!(stored.algorithm, ARGON2ID_ALGORITHM);
    assert!(
        stored.hash.contains("m=8192"),
        "the realm's memory cost applies: {}",
        stored.hash
    );
    assert!(
        stored.hash.contains("t=4"),
        "the realm's time cost applies: {}",
        stored.hash
    );
    Ok(())
}

#[tokio::test]
async fn a_spent_realm_budget_refuses_the_password_paths() -> anyhow::Result<()> {
    // The realm accepts one failed login per window. The account lockout
    // stays at five, so what refuses the second login is the budget of
    // the realm and not the lockout of the account.
    let repo = repository_with_user(
        hash_password_with_params("correct-password-123!", &Argon2idParams::new(8, 1, 1))
            .context("password hashing failed")?,
        ARGON2ID_ALGORITHM,
    )
    .await?;
    let budget = Arc::new(FailureBudget::new());
    let policy = policy_with_realm_budget(5, 1, Argon2idCostConfig::default());
    // Both password login paths share the budget of the realm.
    let session_path = Authenticator::new(repo.clone(), policy, budget.clone());
    let oidc_path = Authenticator::new(repo.clone(), policy, budget.clone());

    let err = session_path
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "wrong-password",
        )
        .await
        .err()
        .context("a wrong password is refused")?;
    assert!(matches!(err, QidError::Unauthorized { .. }));

    // The other path spends the same budget, so it refuses the correct
    // password before it verifies a credential.
    let err = oidc_path
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "correct-password-123!",
        )
        .await
        .err()
        .context("a spent realm budget refuses the login")?;
    assert!(matches!(err, QidError::AttemptBudgetSpent { .. }));
    Ok(())
}
