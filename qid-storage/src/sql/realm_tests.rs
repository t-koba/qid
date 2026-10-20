use super::*;

struct TempDbDir(Option<std::path::PathBuf>);

impl TempDbDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("qid-realm-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        Self(Some(path))
    }

    fn path(&self) -> &std::path::Path {
        self.0
            .as_deref()
            .expect("temporary database directory exists")
    }

    fn remove(mut self) {
        std::fs::remove_dir_all(self.0.take().unwrap()).unwrap();
    }
}

impl Drop for TempDbDir {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

struct SqlRealmTestDb {
    temp_dir: TempDbDir,
    repo: SqlRepository,
}

impl SqlRealmTestDb {
    async fn setup() -> Self {
        let temp_dir = TempDbDir::new();
        let path = temp_dir.path().join("realm.db");
        let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap();
        repo.migrate().await.unwrap();
        let seed = include_str!("../../tests/fixtures/realm_seed.sql");
        for sql in [
            seed.to_string(),
            seed.replace("'realm", "'realm-peer")
                .replace("https://realm.", "https://realm-peer."),
        ] {
            sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                .execute(&repo.pool)
                .await
                .unwrap();
        }
        Self { temp_dir, repo }
    }

    fn repo(&self) -> &SqlRepository {
        &self.repo
    }

    async fn cleanup(self) {
        self.repo.close().await;
        self.temp_dir.remove();
    }
}

async fn setup() -> SqlRealmTestDb {
    SqlRealmTestDb::setup().await
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
    assert!(repo.delete_realm(&"realm".into()).await.is_err());
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
        repo.delete_realm(&"realm".into()).await.unwrap();
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
    db.cleanup().await;
    drop(repo_clone);
}

#[tokio::test]
async fn realm_deletion_sql_cleans_non_fk_orphans_without_parent() {
    let db = setup().await;
    let repo = db.repo();
    let peer_before = counts(repo, "realm-peer").await;
    // Emulate legacy parent-only deletion: cascades happen, non-FK live state
    // remains. No existence check may skip this cleanup on a repeated delete.
    sqlx::query("DELETE FROM realms WHERE id = 'realm'")
        .execute(&repo.pool)
        .await
        .unwrap();
    let orphaned = counts(repo, "realm").await;
    assert_eq!(orphaned.iter().find(|(t, _)| t == "users").unwrap().1, 0);
    for resource in [
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
    repo.delete_realm(&"realm".into()).await.unwrap();
    assert_deleted(repo, false).await;
    assert_eq!(counts(repo, "realm-peer").await, peer_before);
    assert_history(repo).await;
    db.cleanup().await;
}
