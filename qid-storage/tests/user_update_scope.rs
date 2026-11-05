mod support;

use qid_core::{error::QidError, models::User};
use qid_storage::{FileRepository, prelude::*};

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

#[tokio::test]
async fn legacy_file_email_ambiguity_fails_closed_without_changes() {
    let dir = std::env::temp_dir().join(format!("qid-user-email-legacy-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let first = user("first", "a");
    let mut peer = user("peer", "b");
    peer.email.clone_from(&first.email);
    let mut unique = user("unique", "a");
    unique.email = Some("unique@example.com".into());
    for record in [&first, &peer, &unique] {
        repo.create_user(record).await.unwrap();
    }
    assert_eq!(
        repo.get_user_by_email(&"a".into(), "a@example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    drop(repo);
    // Simulate legacy data that predates realm/email uniqueness on writes.
    let mut fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let second = user("second", "a");
    fixture["users"][&second.id] = serde_json::to_value(&second).unwrap();
    let before = serde_json::to_vec_pretty(&fixture).unwrap();
    std::fs::write(&path, &before).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert!(matches!(
        repo.get_user_by_email(&"a".into(), "a@example.com").await,
        Err(QidError::Conflict { .. })
    ));
    for record in [&unique, &peer] {
        assert_eq!(
            serde_json::to_value(
                repo.get_user_by_email(
                    &record.realm_id.clone().into(),
                    record.email.as_ref().unwrap()
                )
                .await
                .unwrap()
                .unwrap()
            )
            .unwrap(),
            serde_json::to_value(record).unwrap()
        );
    }
    for (realm, email) in [("a", "missing@example.com"), ("missing", "a@example.com")] {
        assert!(
            repo.get_user_by_email(&realm.into(), email)
                .await
                .unwrap()
                .is_none()
        );
    }
    for record in [&first, &second, &peer, &unique] {
        assert_eq!(
            serde_json::to_value(repo.get_user_by_id(&record.id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(record).unwrap()
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(repo);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}
