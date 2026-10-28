mod support;

use qid_core::models::{Session, User};
use qid_storage::prelude::*;

async fn assert_session_scope(repo: &impl Repository) {
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
    repo.create_user(&User {
        id: "user-b".into(),
        realm_id: "b".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let mut expected = Session {
        id: "session-b".into(),
        realm_id: "b".into(),
        user_id: "user-b".into(),
        auth_time: 100,
        acr: Some("password".into()),
        amr: vec!["pwd".into()],
        idle_expires_at: 200,
        absolute_expires_at: 500,
        revoked: false,
        created_at: 100,
        cnf: None,
    };
    repo.create_session(&expected).await.unwrap();
    for scope in [Some("a"), Some("b"), None] {
        assert!(
            !repo
                .update_session_idle_expiry("missing", 300, scope)
                .await
                .unwrap()
        );
        assert!(!repo.revoke_session("missing", scope).await.unwrap());
    }
    assert!(
        !repo
            .update_session_idle_expiry(&expected.id, 300, Some("a"))
            .await
            .unwrap()
    );
    assert_row(repo, &expected).await;
    assert!(!repo.revoke_session(&expected.id, Some("a")).await.unwrap());
    assert_row(repo, &expected).await;

    assert!(
        repo.update_session_idle_expiry(&expected.id, 300, Some("b"))
            .await
            .unwrap()
    );
    expected.idle_expires_at = 300;
    assert_row(repo, &expected).await;
    assert!(
        repo.update_session_idle_expiry(&expected.id, 400, None)
            .await
            .unwrap()
    );
    expected.idle_expires_at = 400;
    assert_row(repo, &expected).await;
    assert!(repo.revoke_session(&expected.id, Some("b")).await.unwrap());
    expected.revoked = true;
    assert_row(repo, &expected).await;
    assert!(!repo.revoke_session(&expected.id, Some("b")).await.unwrap());
    assert_row(repo, &expected).await;

    // None is not an implicit realm: it can revoke a live realm-B row too.
    expected.id = "session-b-unscoped".into();
    expected.revoked = false;
    repo.create_session(&expected).await.unwrap();
    assert!(repo.revoke_session(&expected.id, None).await.unwrap());
    expected.revoked = true;
    assert_row(repo, &expected).await;
}

async fn assert_row(repo: &impl Repository, expected: &Session) {
    assert_eq!(
        serde_json::to_value(repo.get_session(&expected.id).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn scoped_session_writes_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_session_scope(&sql).await;
    sql.close().await;
    let file = support::file_repo("session-scope").await;
    assert_session_scope(&file).await;
}
