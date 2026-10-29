mod support;

use qid_core::{
    error::QidError,
    models::{PasswordCredential, User},
};
use qid_storage::prelude::*;

fn credential(hash: &str, algorithm: &str) -> PasswordCredential {
    PasswordCredential {
        user_id: "shared".into(),
        hash: hash.into(),
        algorithm: algorithm.into(),
    }
}

async fn assert_credential(repo: &impl UserRepository, expected: &PasswordCredential) {
    let stored = repo
        .get_password_credential(&expected.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.user_id, expected.user_id);
    assert_eq!(stored.hash, expected.hash);
    assert_eq!(stored.algorithm, expected.algorithm);
}

async fn assert_refused(repo: &impl UserRepository, cred: &PasswordCredential, realm: &str) {
    assert!(matches!(
        repo.update_password_credential_in_realm(cred, realm).await,
        Err(QidError::NotFound { .. })
    ));
}

async fn assert_scope(repo: &impl Repository) {
    for realm in ["a", "b"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://{realm}.example.com"),
            None,
        )
        .await
        .unwrap();
    }
    let rehashed = credential("rehashed", "argon2id");
    // Missing user: the update must not create a credential.
    assert_refused(repo, &rehashed, "a").await;
    assert!(
        repo.get_password_credential("shared")
            .await
            .unwrap()
            .is_none()
    );
    let mut user = User {
        id: "shared".into(),
        realm_id: "a".into(),
        email: Some("alice@example.com".into()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.unwrap();
    // A matching owner without a credential still cannot insert via rehash.
    assert_refused(repo, &rehashed, "a").await;
    assert!(
        repo.get_password_credential("shared")
            .await
            .unwrap()
            .is_none()
    );
    let imported = credential("imported", "pbkdf2-sha256");
    repo.store_password_credential(&imported).await.unwrap();
    assert_refused(repo, &rehashed, "b").await;
    assert_credential(repo, &imported).await;
    repo.update_password_credential_in_realm(&rehashed, "a")
        .await
        .unwrap();
    assert_credential(repo, &rehashed).await;
    // An identical same-owner update also succeeds.
    repo.update_password_credential_in_realm(&rehashed, "a")
        .await
        .unwrap();
    assert_credential(repo, &rehashed).await;

    // Simulate a rehash computed in A, then delete and reuse the selected ID in B.
    let stale_rehash = credential("stale A rehash", "argon2id");
    repo.delete_user("shared", Some("a")).await.unwrap();
    assert_refused(repo, &stale_rehash, "a").await;
    assert!(
        repo.get_password_credential("shared")
            .await
            .unwrap()
            .is_none()
    );
    user.realm_id = "b".into();
    repo.create_user(&user).await.unwrap();
    assert_refused(repo, &stale_rehash, "a").await;
    assert!(
        repo.get_password_credential("shared")
            .await
            .unwrap()
            .is_none()
    );
    let replacement = credential("replacement B password", "replacement algorithm");
    repo.store_password_credential(&replacement).await.unwrap();
    assert_refused(repo, &stale_rehash, "a").await;
    assert_credential(repo, &replacement).await;
    assert_eq!(
        repo.get_user_by_id("shared")
            .await
            .unwrap()
            .unwrap()
            .realm_id,
        "b"
    );
    // The unscoped setup API remains an upsert for an existing credential.
    let setup = credential("setup replacement", "setup algorithm");
    repo.store_password_credential(&setup).await.unwrap();
    assert_credential(repo, &setup).await;
}

#[tokio::test]
async fn credential_rehash_scope_file() {
    let repo = support::file_repo("password-credential-scope").await;
    assert_scope(&repo).await;
}

#[tokio::test]
async fn credential_rehash_scope_sqlite() {
    let repo = support::sql_repo().await;
    assert_scope(&repo).await;
    repo.close().await;
}
