mod support;

use qid_core::{
    error::QidError,
    models::{TokenFamily, User},
};
use qid_storage::prelude::*;

async fn assert_scope(repo: &impl Repository, sql: bool) {
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
    let mut expected = TokenFamily {
        id: "family-b".into(),
        user_id: "user-b".into(),
        client_id: "client-b".into(),
        realm_id: "b".into(),
        current_refresh_hash: "hash".into(),
        scopes: vec!["read".into()],
        auth_time: Some(100),
        acr: Some("password".into()),
        amr: vec!["pwd".into()],
        audience: vec!["api".into()],
        resource: vec!["https://api.example.com".into()],
        authorization_details: Some(serde_json::json!([{"type": "example"}])),
        sender_constraint: Some(serde_json::json!({"jkt": "thumbprint"})),
        issued_at: 100,
        refresh_expires_at: Some(200),
        session_id: Some("session-b".into()),
        revoked: false,
    };
    repo.create_token_family(&expected).await.unwrap();
    // A valid but wrong realm cannot change any field of the incumbent.
    assert_miss(repo.revoke_token_family(&expected.id, "a").await, sql);
    assert_row(repo, &expected).await;
    for realm in ["a", "b"] {
        assert_miss(repo.revoke_token_family("missing", realm).await, sql);
        assert_row(repo, &expected).await;
    }
    repo.revoke_token_family(&expected.id, "b").await.unwrap();
    expected.revoked = true;
    assert_row(repo, &expected).await;
    // Repeated owner revocation is successful and never changes other fields.
    repo.revoke_token_family(&expected.id, "b").await.unwrap();
    assert_row(repo, &expected).await;
    assert_miss(repo.revoke_token_family(&expected.id, "a").await, sql);
    assert_row(repo, &expected).await;
}

fn assert_miss(result: Result<(), QidError>, sql: bool) {
    if sql {
        assert!(
            matches!(result, Err(QidError::NotFound { .. })),
            "{result:?}"
        );
    } else {
        result.unwrap(); // Preserve File's existing missing-record no-op.
    }
}

async fn assert_row(repo: &impl Repository, expected: &TokenFamily) {
    assert_eq!(
        serde_json::to_value(repo.get_token_family(&expected.id).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn token_family_revocation_is_realm_bound_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_scope(&sql, true).await;
    sql.close().await;
    let file = support::file_repo("token-family-scope").await;
    assert_scope(&file, false).await;
}
