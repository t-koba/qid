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
    assert_rotation_misses(repo, &expected).await;
    // Same-owner reuse and CAS misses remain conflicts, not missing families.
    for (old, new) in [("hash", "hash"), ("stale", "new")] {
        assert!(matches!(
            repo.update_token_family_refresh_hash(&expected.id, "b", old, new, 300)
                .await,
            Err(QidError::Conflict { .. })
        ));
        assert_row(repo, &expected).await;
    }
    repo.update_token_family_refresh_hash(&expected.id, "b", "hash", "rotated", 300)
        .await
        .unwrap();
    expected.current_refresh_hash = "rotated".into();
    expected.refresh_expires_at = Some(300);
    assert_row(repo, &expected).await;
    // A valid but wrong realm cannot change any field of the incumbent.
    assert_miss(repo.revoke_token_family(&expected.id, "a").await, sql);
    assert_row(repo, &expected).await;
    for realm in ["a", "b"] {
        assert_miss(repo.revoke_token_family("missing", realm).await, sql);
        assert_row(repo, &expected).await;
    }
    repo.revoke_token_family(&expected.id, "b").await.unwrap();
    expected.revoked = true;
    assert_rotation_misses(repo, &expected).await;
    assert!(matches!(
        repo.update_token_family_refresh_hash(&expected.id, "b", "rotated", "next", 400)
            .await,
        Err(QidError::Conflict { .. })
    ));
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
async fn token_family_revocation_and_rotation_are_realm_bound_file_and_sql() {
    let sql = support::sql_repo().await;
    assert_scope(&sql, true).await;
    sql.close().await;
    let file = support::file_repo("token-family-scope").await;
    assert_scope(&file, false).await;
}

// Classify ownership before reuse, even for equal hashes, stale hashes or revoked rows.
async fn assert_rotation_misses(repo: &impl Repository, expected: &TokenFamily) {
    for (id, realm) in [(&*expected.id, "a"), ("missing", "a"), ("missing", "b")] {
        for (old, new) in [
            (&*expected.current_refresh_hash, "next"),
            (
                &*expected.current_refresh_hash,
                &*expected.current_refresh_hash,
            ),
            ("stale", "next"),
            ("stale", "stale"),
        ] {
            let result = repo
                .update_token_family_refresh_hash(id, realm, old, new, 999)
                .await;
            assert!(
                matches!(result, Err(QidError::NotFound { .. })),
                "{result:?}"
            );
            // Includes revoked, deadline, session, authorization and identity fields.
            assert_row(repo, expected).await;
        }
    }
}
