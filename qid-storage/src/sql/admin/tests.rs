use super::EXPIRED_LOW;
use std::borrow::Cow;

const INDEX_VERSION: i64 = 20261115000002;

async fn plan(pool: &sqlx::SqlitePool, query: &str, args: &[i64]) -> Vec<String> {
    let sql = format!("EXPLAIN QUERY PLAN {query}");
    let mut explain = sqlx::query_as::<_, (i64, i64, i64, String)>(&sql);
    for arg in args {
        explain = explain.bind(*arg);
    }
    let rows = explain
        .fetch_all(pool)
        .await
        .expect("SQLite fixture operation succeeds");
    rows.into_iter().map(|row| row.3).collect()
}

#[tokio::test]
async fn additive_expiry_index_preserves_rows_and_serves_bounded_cleanup() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("SQLite fixture operation succeeds");
    let mut legacy = sqlx::migrate!("./migrations");
    legacy.migrations = Cow::Owned(
        legacy
            .iter()
            .filter(|migration| migration.version < INDEX_VERSION)
            .cloned()
            .collect(),
    );
    legacy
        .run(&pool)
        .await
        .expect("SQLite fixture operation succeeds");
    sqlx::query("INSERT INTO admins (id, tenant_id, subject, created_at) VALUES ('admin', 'tenant', 'subject', 1)")
        .execute(&pool).await.expect("SQLite fixture operation succeeds");
    sqlx::query("INSERT INTO admin_elevations (id, tenant_id, admin_id, elevation_expires_at, created_at) VALUES ('legacy', 'tenant', 'admin', -1, 1)")
        .execute(&pool).await.expect("SQLite fixture operation succeeds");
    for (query, args) in [(EXPIRED_LOW, &[100, 1][..])] {
        let details = plan(&pool, query, args).await;
        assert!(
            details
                .iter()
                .any(|detail| detail == "SCAN admin_elevations")
        );
    }

    crate::sql::MIGRATOR
        .run(&pool)
        .await
        .expect("SQLite fixture operation succeeds");
    crate::sql::MIGRATOR
        .run(&pool)
        .await
        .expect("SQLite fixture operation succeeds");
    let expiry: i64 =
        sqlx::query_scalar("SELECT elevation_expires_at FROM admin_elevations WHERE id = 'legacy'")
            .fetch_one(&pool)
            .await
            .expect("SQLite fixture operation succeeds");
    assert_eq!(expiry, -1, "index migration must not rewrite existing data");
    for (query, args, ranges) in [(EXPIRED_LOW, &[100, 1][..], 1)] {
        let details = plan(&pool, query, args).await;
        assert_eq!(
            details
                .iter()
                .filter(|detail| detail.contains("USING INDEX idx_admin_elevations_expiry"))
                .count(),
            ranges,
            "{details:?}"
        );
        assert!(
            !details.iter().any(|detail| detail.starts_with("SCAN")),
            "{details:?}"
        );
    }
    pool.close().await;
}
