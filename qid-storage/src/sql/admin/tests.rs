use super::{EXPIRED_HIGH, EXPIRED_LOW};
use std::borrow::Cow;

const INDEX_VERSION: i64 = 20261115000002;

async fn plan(pool: &sqlx::SqlitePool, query: &str, cutoff: i64) -> Vec<String> {
    let rows: Vec<(i64, i64, i64, String)> = sqlx::query_as(&format!("EXPLAIN QUERY PLAN {query}"))
        .bind(cutoff)
        .bind("incoming")
        .fetch_all(pool)
        .await
        .expect("SQLite fixture operation succeeds");
    rows.into_iter().map(|row| row.3).collect()
}

#[tokio::test]
async fn additive_expiry_index_preserves_rows_and_serves_both_cleanup_ranges() {
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
    for (query, cutoff) in [(EXPIRED_LOW, 100), (EXPIRED_HIGH, -100)] {
        let details = plan(&pool, query, cutoff).await;
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
    for (query, cutoff, ranges) in [(EXPIRED_LOW, 100, 1), (EXPIRED_HIGH, -100, 2)] {
        let details = plan(&pool, query, cutoff).await;
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
