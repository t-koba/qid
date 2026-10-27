mod support;

use qid_core::{error::QidError, models::User};
use qid_storage::prelude::*;

fn user(id: &str, realm: &str) -> User {
    User {
        id: id.into(),
        realm_id: realm.into(),
        email: Some(format!("{realm}@example.com")),
        email_verified: true,
        display_name: Some(format!("{realm} name")),
        failed_login_attempts: 7,
        locked_until: Some(12345),
        org: Some(format!("{realm} org")),
    }
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
    let original = user("shared", "a");
    assert!(matches!(
        repo.update_user(&original, Some("a")).await,
        Err(QidError::NotFound { .. })
    ));
    assert!(repo.get_user_by_id("shared").await.unwrap().is_none());
    repo.create_user(&original).await.unwrap();
    let mut changed = original.clone();
    changed.display_name = Some("updated".into());
    changed.email_verified = false;
    changed.failed_login_attempts = 2;
    changed.locked_until = None;
    changed.org = Some("old org".into());
    repo.update_user(&changed, Some("a")).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id("shared").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&changed).unwrap()
    );
    let mut neighbor = user("neighbor", "a");
    neighbor.email = Some("neighbor@example.com".into());
    repo.create_user(&neighbor).await.unwrap();
    let mut conflict = changed.clone();
    conflict.email = neighbor.email.clone();
    assert!(matches!(
        repo.update_user(&conflict, Some("a")).await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id("shared").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&changed).unwrap()
    );
    assert!(matches!(
        repo.update_user(&changed, Some("b")).await,
        Err(QidError::NotFound { .. })
    ));
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id("shared").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&changed).unwrap()
    );
    // Simulate the admin pre-read, then delete and reuse the caller-supplied ID.
    let stale = repo.get_user_by_id("shared").await.unwrap().unwrap();
    repo.delete_user("shared", Some("a")).await.unwrap();
    let replacement = user("shared", "b");
    repo.create_user(&replacement).await.unwrap();
    assert!(matches!(
        repo.update_user(&stale, Some("a")).await,
        Err(QidError::NotFound { .. })
    ));
    assert_eq!(
        serde_json::to_value(repo.get_user_by_id("shared").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&replacement).unwrap()
    );
}

#[tokio::test]
async fn scoped_update_contract_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_scope(&sql).await;
    let file = support::file_repo("user-update-scope").await;
    assert_scope(&file).await;
}

#[tokio::test]
async fn unscoped_missing_update_retains_backend_semantics() {
    let file = support::file_repo("user-update-upsert").await;
    let missing = user("missing", "a");
    file.update_user(&missing, None).await.unwrap();
    assert_eq!(
        serde_json::to_value(file.get_user_by_id("missing").await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&missing).unwrap()
    );
    let sql = support::sql_repo().await;
    sql.update_user(&missing, None).await.unwrap();
    assert!(sql.get_user_by_id("missing").await.unwrap().is_none());
}
