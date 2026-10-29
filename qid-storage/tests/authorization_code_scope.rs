mod support;

use qid_core::{
    error::QidError,
    models::{AuthorizationCode, User},
};
use qid_storage::prelude::*;

fn auth_code(hash: &str, realm: &str, client: &str, user: &str, now: u64) -> AuthorizationCode {
    AuthorizationCode {
        code_hash: hash.into(),
        client_id: client.into(),
        user_id: user.into(),
        realm_id: realm.into(),
        redirect_uri: "https://app.example.com/callback".into(),
        state: Some("state".into()),
        nonce: Some("nonce".into()),
        auth_time: Some(100),
        acr: Some("urn:qid:acr:password".into()),
        amr: vec!["pwd".into()],
        code_challenge: Some("challenge".into()),
        code_challenge_method: Some("S256".into()),
        scopes: vec!["openid".into()],
        resource: vec!["https://api.example.com".into()],
        authorization_details: Some(serde_json::json!([{"type": "example"}])),
        expires_at: now + 3600,
        used: false,
        created_at: now,
        session_id: Some("session-b".into()),
    }
}

async fn assert_row(repo: &impl Repository, expected: &AuthorizationCode) {
    assert_eq!(
        serde_json::to_value(
            repo.get_authorization_code(&expected.code_hash)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

async fn assert_scope(repo: &impl Repository, sql: bool) {
    repo.create_realm(&"tenant".into(), &"b".into(), "https://b.example.com", None)
        .await
        .unwrap();
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
    let now = qid_core::util::now_seconds();
    // A missing identity is NotFound and never creates a row.
    assert!(matches!(
        repo.mark_authorization_code_used(&auth_code("missing", "b", "client-b", "user-b", now))
            .await,
        Err(QidError::NotFound { .. })
    ));
    assert!(
        repo.get_authorization_code("missing")
            .await
            .unwrap()
            .is_none()
    );
    let mut expected = auth_code("code-b", "b", "client-b", "user-b", now);
    repo.create_authorization_code(&expected).await.unwrap();
    // Compare the complete stored code, not just the consumed flag.
    assert_row(repo, &expected).await;
    // A stale owner after the grant's pre-read cannot consume: realm, client
    // and user replacements are all NotFound and leave the row unchanged.
    for (realm, client, user) in [
        ("a", "client-b", "user-b"),
        ("b", "other-client", "user-b"),
        ("b", "client-b", "other-user"),
    ] {
        let foreign = AuthorizationCode {
            realm_id: realm.into(),
            client_id: client.into(),
            user_id: user.into(),
            ..expected.clone()
        };
        assert!(
            matches!(
                repo.mark_authorization_code_used(&foreign).await,
                Err(QidError::NotFound { .. })
            ),
            "wrong owner must be NotFound"
        );
        assert_row(repo, &expected).await;
    }
    // The validated owner consumes exactly once.
    repo.mark_authorization_code_used(&expected).await.unwrap();
    expected.used = true;
    assert_row(repo, &expected).await;
    // Sequential reuse keeps the backends' existing difference: File answers
    // Conflict while SQL answers BadRequest from reuse validation.
    let reuse = repo.mark_authorization_code_used(&expected).await;
    if sql {
        assert!(
            matches!(reuse, Err(QidError::BadRequest { .. })),
            "SQL sequential reuse must stay BadRequest, got {reuse:?}"
        );
    } else {
        assert!(
            matches!(reuse, Err(QidError::Conflict { .. })),
            "File sequential reuse must stay Conflict, got {reuse:?}"
        );
    }
    assert_row(repo, &expected).await;
    // Concurrent single-use: one winner consumes and no interleaving can
    // consume twice. SQL returns Conflict when both pre-reads see unused;
    // if serialized before the second pre-read, its sequential BadRequest is
    // preserved. File serializes both cases as Conflict under its write lock.
    let race = auth_code("code-race", "b", "client-b", "user-b", now);
    repo.create_authorization_code(&race).await.unwrap();
    let (first, second) = tokio::join!(
        repo.mark_authorization_code_used(&race),
        repo.mark_authorization_code_used(&race)
    );
    assert!(
        first.is_ok() || second.is_ok(),
        "at least one concurrent consume must succeed"
    );
    assert!(
        first.is_err() || second.is_err(),
        "at least one concurrent consume must be rejected"
    );
    for result in [first, second] {
        if let Err(error) = result {
            let expected = if sql {
                matches!(
                    error,
                    QidError::Conflict { .. } | QidError::BadRequest { .. }
                )
            } else {
                matches!(error, QidError::Conflict { .. })
            };
            assert!(expected, "unexpected concurrent loser error: {error:?}");
        }
    }
    let mut raced = race.clone();
    raced.used = true;
    assert_row(repo, &raced).await;
}

#[tokio::test]
async fn authorization_code_consumption_is_owner_bound_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_scope(&sql, true).await;
    sql.close().await;
    let file = support::file_repo("authorization-code-scope").await;
    assert_scope(&file, false).await;
}
