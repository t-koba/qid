use super::iga_tests::test_support::IsolatedDb;
use super::*;

async fn setup() -> IsolatedDb {
    // Schema comes from the per-process migrated template; the realm seed is
    // still applied per test on the isolated copy, preserving seed behavior.
    let db = IsolatedDb::setup().await;
    let seed = include_str!("../../tests/fixtures/realm_seed.sql");
    for sql in [
        seed.to_string(),
        seed.replace("'realm", "'realm-peer")
            .replace("https://realm.", "https://realm-peer."),
    ] {
        sqlx::raw_sql(&sql).execute(&db.repo().pool).await.unwrap();
    }
    sqlx::query("UPDATE audit_retention_configs SET stream_id = 'realm:' || realm_id")
        .execute(&db.repo().pool)
        .await
        .unwrap();
    db
}

async fn counts(repo: &SqlRepository, realm: &str) -> Vec<(String, i64)> {
    sqlx::query_as(include_str!("../../tests/fixtures/realm_counts.sql"))
        .bind(realm)
        .fetch_all(&repo.pool)
        .await
        .unwrap()
}

async fn assert_history(repo: &SqlRepository) {
    for statement in [
        "SELECT COUNT(*) FROM audit_events",
        "SELECT COUNT(*) FROM audit_retention_configs",
        "SELECT COUNT(*) FROM siem_delivery_queue",
        "SELECT COUNT(*) FROM marketplace_connectors",
        "SELECT COUNT(*) FROM relationship_tuples",
    ] {
        let (count,): (i64,) = sqlx::query_as(statement)
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "{statement}");
    }
    let event = repo
        .list_audit_events(Some(&"realm".into()), 10)
        .await
        .unwrap();
    assert_eq!(event.len(), 1);
    assert_eq!(event[0].actor, "realm-user");
    assert!(
        repo.get_audit_retention_config(Some(&"realm".into()))
            .await
            .unwrap()
            .unwrap()
            .legal_hold
    );
}

async fn assert_deleted(repo: &SqlRepository, recreated: bool) {
    for (resource, count) in counts(repo, "realm").await {
        assert_eq!(
            count,
            i64::from(recreated && resource == "realms"),
            "{resource}"
        );
    }
}

#[tokio::test]
async fn realm_deletion_sql_rolls_back_then_removes_all_live_state_without_revival() {
    let db = setup().await;
    let repo = db.repo();
    let repo_clone = repo.clone();
    let target_before = counts(repo, "realm").await;
    // Every live inventory category is seeded, including existing FK cascades.
    assert!(target_before.iter().all(|(_, count)| *count == 1));
    let peer_before = counts(repo, "realm-peer").await;
    assert_history(repo).await;

    // Inject a late deterministic failure after earlier explicit cleanup has
    // run. Every statement and the root/cascade state must roll back together.
    sqlx::raw_sql("CREATE TRIGGER fail_realm_cleanup BEFORE DELETE ON ssf_streams WHEN OLD.realm_id = 'realm' BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;")
        .execute(&repo.pool).await.unwrap();
    assert!(
        repo.delete_realm(&"realm".into(), &"tenant".into())
            .await
            .is_err()
    );
    assert_eq!(counts(repo, "realm").await, target_before);
    assert_eq!(counts(repo, "realm-peer").await, peer_before);
    assert_history(repo).await;
    sqlx::query("DROP TRIGGER fail_realm_cleanup")
        .execute(&repo.pool)
        .await
        .unwrap();

    // Cross-realm direct bindings still depend on a removed session/family or
    // user. Unlinked non-user subjects, on the other hand, are independent.
    let mut family = repo
        .get_token_family("realm-peer-record")
        .await
        .unwrap()
        .unwrap();
    family.id = "linked-family".into();
    family.session_id = Some("realm-record".into());
    repo.create_token_family(&family).await.unwrap();
    let mut code = repo
        .get_authorization_code("realm-peer-record")
        .await
        .unwrap()
        .unwrap();
    code.code_hash = "linked-code".into();
    code.session_id = Some("realm-record".into());
    repo.create_authorization_code(&code).await.unwrap();
    let base = repo
        .get_access_token("realm-peer-record")
        .await
        .unwrap()
        .unwrap();
    for (jti, user, family, realm) in [
        ("service", "service", None, "realm-peer"),
        ("workload", "workload", None, "realm-peer"),
        (
            "linked-token",
            "service",
            Some("linked-family"),
            "realm-peer",
        ),
        ("user-token", "realm-user", None, "realm-peer"),
        ("realm-service-token", "service", None, "realm"),
    ] {
        let mut token = base.clone();
        token.jti = jti.into();
        token.user_id = user.into();
        token.family_id = family.map(String::from);
        token.realm_id = realm.into();
        repo.create_access_token(&token).await.unwrap();
    }
    for _ in 0..2 {
        repo.delete_realm(&"realm".into(), &"tenant".into())
            .await
            .unwrap();
        assert_deleted(repo, false).await;
        assert_history(repo).await;
    }
    assert!(
        repo.get_authorization_code("linked-code")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_token_family("linked-family")
            .await
            .unwrap()
            .is_none()
    );
    for jti in ["linked-token", "user-token", "realm-service-token"] {
        assert!(repo.get_access_token(jti).await.unwrap().is_none(), "{jti}");
    }
    for jti in ["service", "workload"] {
        assert!(repo.get_access_token(jti).await.unwrap().is_some(), "{jti}");
    }
    let mut peer_expected = peer_before;
    peer_expected
        .iter_mut()
        .find(|(resource, _)| resource == "access_tokens")
        .unwrap()
        .1 += 2;
    assert_eq!(counts(repo, "realm-peer").await, peer_expected);
    repo.create_realm(
        &"new-tenant".into(),
        &"realm".into(),
        "https://new.example.com",
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.get_realm_tenant(&"realm".into())
            .await
            .unwrap()
            .as_deref(),
        Some("new-tenant")
    );
    assert_eq!(
        repo.get_realm_issuer(&"realm".into())
            .await
            .unwrap()
            .as_deref(),
        Some("https://new.example.com")
    );
    assert_deleted(repo, true).await;
    assert_eq!(counts(repo, "realm-peer").await, peer_expected);
    assert_history(repo).await;
    drop(repo_clone);
    db.cleanup().await;
}

#[tokio::test]
async fn realm_creation_sql_clears_orphans_only_after_claiming_absent_id() {
    let db = setup().await;
    let repo = db.repo();
    let peer_before = counts(repo, "realm-peer").await;
    // Emulate legacy parent-only deletion: cascades happen, non-FK live state
    // remains. With no tenant-bound parent, deletion cannot authorize cleanup.
    sqlx::query("DELETE FROM realms WHERE id = 'realm'")
        .execute(&repo.pool)
        .await
        .unwrap();
    let orphaned = counts(repo, "realm").await;
    assert_eq!(orphaned.iter().find(|(t, _)| t == "users").unwrap().1, 0);
    for resource in [
        "service_accounts",
        "ciam_brands",
        "custom_domains",
        "app_catalog_entries",
        "scim_devices",
        "scim_event_subscriptions",
        "ssf_streams",
        "ssf_set_replay",
    ] {
        assert_eq!(
            orphaned.iter().find(|(t, _)| t == resource).unwrap().1,
            1,
            "{resource}"
        );
    }
    repo.delete_realm(&"realm".into(), &"tenant".into())
        .await
        .unwrap();
    assert_eq!(counts(repo, "realm").await, orphaned);
    assert_eq!(counts(repo, "realm-peer").await, peer_before);
    assert_history(repo).await;
    assert!(
        repo.get_service_account_by_client_id("realm", "realm-client")
            .await
            .unwrap()
            .is_some()
    );
    for (id, issuer) in [
        ("realm-peer", "https://unused.example.com"),
        ("realm", "https://realm-peer.example.com"),
    ] {
        assert!(matches!(
            repo.create_realm(&"tenant-b".into(), &id.into(), issuer, None)
                .await,
            Err(QidError::Conflict { .. })
        ));
        assert_eq!(counts(repo, "realm").await, orphaned);
        assert_eq!(counts(repo, "realm-peer").await, peer_before);
    }
    // A late cleanup failure must roll back both earlier deletes and the insert.
    sqlx::raw_sql("CREATE TRIGGER fail_realm_reuse BEFORE DELETE ON ssf_streams WHEN OLD.realm_id = 'realm' BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;")
        .execute(&repo.pool).await.unwrap();
    assert!(
        repo.create_realm(
            &"tenant-b".into(),
            &"realm".into(),
            "https://new.example.com",
            None
        )
        .await
        .is_err()
    );
    assert_eq!(counts(repo, "realm").await, orphaned);
    assert_history(repo).await;
    sqlx::query("DROP TRIGGER fail_realm_reuse")
        .execute(&repo.pool)
        .await
        .unwrap();
    repo.create_realm(
        &"tenant-b".into(),
        &"realm".into(),
        "https://new.example.com",
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.get_realm_tenant(&"realm".into())
            .await
            .unwrap()
            .as_deref(),
        Some("tenant-b")
    );
    assert!(
        repo.get_service_account_by_client_id("realm", "realm-client")
            .await
            .unwrap()
            .is_none()
    );
    assert_deleted(repo, true).await;
    assert_eq!(counts(repo, "realm-peer").await, peer_before);
    assert_history(repo).await;
    db.cleanup().await;
}

#[tokio::test]
async fn realm_deletion_sql_rechecks_tenant_after_id_reuse() {
    let db = setup().await;
    let repo = db.repo();
    repo.delete_realm(&"realm".into(), &"tenant".into())
        .await
        .unwrap();
    // Recreate the full live inventory under B at the same global realm ID.
    let seed =
        include_str!("../../tests/fixtures/realm_seed.sql").replace("'tenant'", "'tenant-b'");
    // History survived A's deletion; avoid reinserting independent history.
    for statement in seed.lines().filter(|s| s.starts_with("INSERT INTO")) {
        if [
            "audit_events",
            "audit_retention_configs",
            "siem_delivery_queue",
            "marketplace_connectors",
            "relationship_tuples",
        ]
        .iter()
        .any(|table| statement.contains(&format!("INSERT INTO {table} ")))
        {
            continue;
        }
        sqlx::raw_sql(statement).execute(&repo.pool).await.unwrap();
    }
    let before = counts(repo, "realm").await;
    assert!(before.iter().all(|(_, count)| *count == 1));
    let peer_before = counts(repo, "realm-peer").await;
    // A delete trigger makes even a tentative child deletion fail the test.
    sqlx::raw_sql("CREATE TRIGGER no_foreign_cleanup BEFORE DELETE ON hr_receipts BEGIN SELECT RAISE(ABORT, 'foreign cleanup'); END;")
        .execute(&repo.pool).await.unwrap();
    repo.delete_realm(&"realm".into(), &"tenant".into())
        .await
        .unwrap();
    assert_eq!(
        repo.get_realm_tenant(&"realm".into())
            .await
            .unwrap()
            .as_deref(),
        Some("tenant-b")
    );
    assert_eq!(
        repo.get_realm_issuer(&"realm".into())
            .await
            .unwrap()
            .as_deref(),
        Some("https://realm.example.com")
    );
    assert_eq!(counts(repo, "realm").await, before);
    assert_eq!(counts(repo, "realm-peer").await, peer_before);
    assert_history(repo).await;
    sqlx::query("DROP TRIGGER no_foreign_cleanup")
        .execute(&repo.pool)
        .await
        .unwrap();
    repo.delete_realm(&"realm".into(), &"tenant-b".into())
        .await
        .unwrap();
    assert_deleted(repo, false).await;
    assert_history(repo).await;
    db.cleanup().await;
}
