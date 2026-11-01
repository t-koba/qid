use sqlx::SqlitePool;
use std::{borrow::Cow, path::PathBuf};

const CONNECTOR_TENANT_FK_VERSION: i64 = 20261101000003;

fn migrator_before_connector_tenant_fk() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(
        migrator
            .iter()
            .filter(|migration| migration.version < CONNECTOR_TENANT_FK_VERSION)
            .cloned()
            .collect(),
    );
    migrator
}

async fn legacy_database() -> (PathBuf, SqlitePool) {
    let dir = std::env::temp_dir().join(format!("qid-app-catalog-migration-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create AppCatalog migration fixture directory");
    let database = dir.join("legacy.db");
    std::fs::File::create(&database).expect("create AppCatalog migration fixture database");
    let url = format!("sqlite:{}", database.display());
    let pool = SqlitePool::connect(&url)
        .await
        .expect("connect AppCatalog migration fixture");
    migrator_before_connector_tenant_fk()
        .run(&pool)
        .await
        .expect("apply migrations before AppCatalog connector tenant FK");
    (dir, pool)
}

async fn insert_connector(pool: &SqlitePool, id: &str, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO marketplace_connectors (id, tenant_id, provider, connector_type, config_json, enabled) VALUES (?, ?, 'test', 'oidc', '{}', 1)",
    )
    .bind(id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert migration fixture connector");
}

async fn insert_entry(pool: &SqlitePool, id: &str, tenant_id: &str, connector_id: &str) {
    sqlx::query(
        "INSERT INTO app_catalog_entries (id, tenant_id, realm_id, display_name, category, scim_enabled, marketplace_connector_id) VALUES (?, ?, 'realm-test', 'Test', 'Other', 0, ?)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(connector_id)
    .execute(pool)
    .await
    .expect("insert migration fixture app catalog entry");
}

async fn invalid_legacy_reference_fails_closed(connector_id: &str, connector_owner: Option<&str>) {
    let (dir, pool) = legacy_database().await;
    if let Some(owner) = connector_owner {
        insert_connector(&pool, connector_id, owner).await;
    }
    insert_entry(&pool, "legacy", "tenant-a", connector_id).await;
    let before: (String, String, Option<String>) = sqlx::query_as(
        "SELECT id, tenant_id, marketplace_connector_id FROM app_catalog_entries WHERE id = 'legacy'",
    )
    .fetch_one(&pool)
    .await
    .expect("read legacy AppCatalog entry before migration");

    let error = sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect_err("invalid legacy connector binding must stop migration");
    assert!(
        error
            .to_string()
            .contains("app_catalog_connector_tenant_preflight"),
        "migration should identify the failed preflight check, got {error}"
    );
    let after: (String, String, Option<String>) = sqlx::query_as(
        "SELECT id, tenant_id, marketplace_connector_id FROM app_catalog_entries WHERE id = 'legacy'",
    )
    .fetch_one(&pool)
    .await
    .expect("read legacy AppCatalog entry after failed migration");
    assert_eq!(after, before, "failed migration changed the legacy entry");
    let parent_index: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_marketplace_connectors_tenant_id_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("check parent index rollback");
    assert_eq!(parent_index, 0, "failed migration retained its new index");
    let replacement_table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'app_catalog_entries_new'",
    )
    .fetch_one(&pool)
    .await
    .expect("check rebuilt table rollback");
    assert_eq!(
        replacement_table, 0,
        "failed migration retained its new table"
    );
    let applied: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = ? AND success = 1",
    )
    .bind(CONNECTOR_TENANT_FK_VERSION)
    .fetch_one(&pool)
    .await
    .expect("check migration ledger after preflight failure");
    assert_eq!(applied, 0, "failed migration advanced the ledger");

    insert_connector(&pool, "repaired-a", "tenant-a").await;
    sqlx::query(
        "UPDATE app_catalog_entries SET marketplace_connector_id = 'repaired-a' WHERE id = 'legacy'",
    )
    .execute(&pool)
    .await
    .expect("explicitly repair legacy connector reference");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("retry migration after explicit repair");
    let repaired: (String, String, Option<String>) = sqlx::query_as(
        "SELECT id, tenant_id, marketplace_connector_id FROM app_catalog_entries WHERE id = 'legacy'",
    )
    .fetch_one(&pool)
    .await
    .expect("read repaired AppCatalog entry");
    assert_eq!(
        repaired,
        (
            "legacy".to_string(),
            "tenant-a".to_string(),
            Some("repaired-a".to_string())
        )
    );
    pool.close().await;
    std::fs::remove_dir_all(dir).expect("remove AppCatalog migration fixture directory");
}

#[tokio::test]
async fn connector_tenant_migration_preserves_valid_rows_and_blocks_rebinding() {
    let (dir, pool) = legacy_database().await;
    insert_connector(&pool, "c1", "tenant-a").await;
    insert_entry(&pool, "existing", "tenant-a", "c1").await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate valid AppCatalog connector reference");
    let preserved: (String, String, Option<String>) = sqlx::query_as(
        "SELECT id, tenant_id, marketplace_connector_id FROM app_catalog_entries WHERE id = 'existing'",
    )
    .fetch_one(&pool)
    .await
    .expect("read preserved AppCatalog entry");
    assert_eq!(
        preserved,
        (
            "existing".to_string(),
            "tenant-a".to_string(),
            Some("c1".to_string())
        )
    );

    let mut stale_writer = pool.acquire().await.expect("acquire stale writer");
    let mut replacement_writer = pool.acquire().await.expect("acquire replacement writer");
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *stale_writer)
        .await
        .expect("read SQLite foreign-key setting");
    assert_eq!(
        foreign_keys, 1,
        "SQLite foreign-key enforcement must be enabled"
    );
    sqlx::query(
        "INSERT INTO marketplace_connectors (id, tenant_id, provider, connector_type, config_json, enabled) VALUES ('race-id', 'tenant-a', 'test', 'oidc', '{}', 1)",
    )
    .execute(&mut *replacement_writer)
    .await
    .expect("create connector before stale-read interleaving");
    let observed_owner: String =
        sqlx::query_scalar("SELECT tenant_id FROM marketplace_connectors WHERE id = 'race-id'")
            .fetch_one(&mut *stale_writer)
            .await
            .expect("perform stale tenant-A connector lookup");
    assert_eq!(observed_owner, "tenant-a");
    sqlx::query(
        "DELETE FROM marketplace_connectors WHERE id = 'race-id' AND tenant_id = 'tenant-a'",
    )
    .execute(&mut *replacement_writer)
    .await
    .expect("delete connector after stale tenant-A lookup");
    sqlx::query(
        "INSERT INTO marketplace_connectors (id, tenant_id, provider, connector_type, config_json, enabled) VALUES ('race-id', 'tenant-b', 'test', 'oidc', '{}', 1)",
    )
    .execute(&mut *replacement_writer)
    .await
    .expect("reuse deleted connector ID under tenant B");
    let error = sqlx::query(
        "INSERT INTO app_catalog_entries (id, tenant_id, realm_id, display_name, category, scim_enabled, marketplace_connector_id) VALUES ('raced', 'tenant-a', 'realm-test', 'Raced', 'Other', 0, 'race-id')",
    )
    .execute(&mut *stale_writer)
    .await
    .expect_err("stale tenant-A insert must not bind the tenant-B connector");
    assert!(
        error.to_string().contains("FOREIGN KEY constraint failed"),
        "stale write should fail at the database FK, got {error}"
    );
    let raced_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM app_catalog_entries WHERE id = 'raced'")
            .fetch_one(&pool)
            .await
            .expect("check stale insert did not persist");
    assert_eq!(raced_rows, 0);
    let delete_error = sqlx::query(
        "DELETE FROM marketplace_connectors WHERE id = 'c1' AND tenant_id = 'tenant-a'",
    )
    .execute(&mut *replacement_writer)
    .await
    .expect_err("referenced connector deletion must be restricted");
    assert!(
        delete_error
            .to_string()
            .contains("FOREIGN KEY constraint failed"),
        "referenced delete should fail at the database FK, got {delete_error}"
    );
    drop(stale_writer);
    drop(replacement_writer);
    pool.close().await;
    std::fs::remove_dir_all(dir).expect("remove AppCatalog migration fixture directory");

    invalid_legacy_reference_fails_closed("shared", Some("tenant-b")).await;
    invalid_legacy_reference_fails_closed("missing", None).await;
}
