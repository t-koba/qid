mod support;

use qid_core::models::{AccessToken, TokenFormat, User};
use qid_storage::prelude::*;

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
    let mut expected = AccessToken {
        jti: "token-b".into(),
        family_id: None,
        user_id: "user-b".into(),
        client_id: "client-b".into(),
        realm_id: "b".into(),
        scopes: vec!["read".into()],
        audience: vec!["api".into()],
        resource: vec!["https://api.example.com".into()],
        authorization_details: Some(serde_json::json!([{"type": "example"}])),
        cnf: Some(serde_json::json!({"jkt": "thumbprint"})),
        auth_time: Some(100),
        acr: Some("password".into()),
        amr: vec!["pwd".into()],
        nonce: Some("nonce".into()),
        sender_constraint: Some(serde_json::json!({"jkt": "thumbprint"})),
        token_format: TokenFormat::Jwt,
        expires_at: 200,
        revoked: false,
        issued_at: 100,
    };
    repo.create_access_token(&expected).await.unwrap();
    // Compare the complete stored token, not just the revocation flag.
    assert_row(repo, &expected).await;
    repo.revoke_access_token(&expected.jti, "a").await.unwrap();
    assert_row(repo, &expected).await;
    for realm in ["a", "b"] {
        repo.revoke_access_token("missing", realm).await.unwrap();
        assert!(repo.get_access_token("missing").await.unwrap().is_none());
        assert_row(repo, &expected).await;
    }
    for _ in 0..2 {
        repo.revoke_access_token(&expected.jti, "b").await.unwrap();
        expected.revoked = true;
        assert_row(repo, &expected).await;
        repo.revoke_access_token(&expected.jti, "a").await.unwrap();
        assert_row(repo, &expected).await;
    }
}

async fn assert_row(repo: &impl Repository, expected: &AccessToken) {
    assert_eq!(
        serde_json::to_value(repo.get_access_token(&expected.jti).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn access_token_revocation_is_realm_bound_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_scope(&sql).await;
    sql.close().await;
    let file = support::file_repo("access-token-scope").await;
    assert_scope(&file).await;
}
