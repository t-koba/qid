//! Deterministic cleanup/issuance interleaving on a disposable PostgreSQL database.
//! Local runs skip unless QID_TEST_POSTGRES_URL is set; never use production data.
use qid_storage::{AdminRepository, SqlRepository};
use sqlx::{ConnectOptions, Connection, Executor, PgConnection, postgres::PgConnectOptions};
use std::time::Duration;

#[tokio::test]
async fn postgres_cleanup_preserves_fresh_elevation_reusing_a_stale_id() {
    let url = match std::env::var("QID_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL elevation cleanup: QID_TEST_POSTGRES_URL is unset");
            return;
        }
        Err(_) => panic!("QID_TEST_POSTGRES_URL must be valid Unicode"),
    };
    let options: PgConnectOptions = url.parse().expect("valid PostgreSQL test URL");
    let mut issuer = PgConnection::connect_with(&options).await.unwrap();
    // Isolate the global cleanup from other PostgreSQL tests and remove all
    // fixture state at the end, including migration bookkeeping.
    let schema = format!("elevation_{}", ulid::Ulid::new().to_string().to_lowercase());
    issuer
        .execute(format!("CREATE SCHEMA {schema}").as_str())
        .await
        .unwrap();
    issuer
        .execute(format!("SET search_path TO {schema}").as_str())
        .await
        .unwrap();
    let mut repo_url = options.to_url_lossy();
    repo_url
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let repo = SqlRepository::connect(repo_url.as_str()).await.unwrap();
    repo.migrate().await.unwrap();
    issuer.execute("INSERT INTO admins (id, tenant_id, subject, created_at) VALUES ('admin', 'tenant', 'subject', 1)").await.unwrap();
    issuer.execute("INSERT INTO admin_elevations (id, tenant_id, admin_id, elevation_expires_at, created_at) VALUES ('reused', 'tenant', 'admin', 100, 1)").await.unwrap();

    let mut replacement = issuer.begin().await.unwrap();
    // SHARE permits the old cleanup's SELECT, but blocks its ID-only DELETE.
    // It also blocks the fixed atomic DELETE before it can remove any row.
    sqlx::query("LOCK TABLE admin_elevations IN SHARE MODE")
        .execute(&mut *replacement)
        .await
        .unwrap();
    let stale_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM admin_elevations WHERE elevation_expires_at >= 0 AND elevation_expires_at <= 100 ORDER BY elevation_expires_at LIMIT 1",
    ).fetch_all(&mut *replacement).await.unwrap();
    assert_eq!(stale_ids, ["reused"]);

    let cleanup = repo.cleanup_expired_admin_elevations(100, 1);
    let replace = async {
        // Observe an actual waiting DELETE, not elapsed time. With the old
        // implementation this proves its earlier expiry scan already finished.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation = 'admin_elevations'::regclass AND mode = 'RowExclusiveLock' AND NOT granted)",
                ).fetch_one(&mut *replacement).await.unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("cleanup must reach its DELETE");
        // Model the winning cleanup and a new issuance using the same ID.
        // SQL keeps both writes inside the lock-holding fixture transaction.
        let deleted = sqlx::query("DELETE FROM admin_elevations WHERE id = $1")
            .bind(&stale_ids[0])
            .execute(&mut *replacement)
            .await
            .unwrap();
        assert_eq!(deleted.rows_affected(), 1);
        sqlx::query("INSERT INTO admin_elevations (id, tenant_id, admin_id, elevation_expires_at, created_at) VALUES ($1, 'tenant', 'admin', 101, 100)")
            .bind(&stale_ids[0]).execute(&mut *replacement).await.unwrap();
        replacement.commit().await.unwrap();
    };
    let (deleted, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(cleanup, replace)
    })
    .await
    .expect("cleanup and ID reuse must complete without deadlock");
    assert_eq!(deleted.unwrap(), 0, "fresh issuance must not be reclaimed");
    let fresh: (i64, i64) = sqlx::query_as(
        "SELECT elevation_expires_at, created_at FROM admin_elevations WHERE id = 'reused'",
    )
    .fetch_one(&mut issuer)
    .await
    .unwrap();
    assert_eq!(fresh, (101, 100));
    // The same row becomes eligible exactly at the inclusive expiry cutoff.
    assert_eq!(
        repo.cleanup_expired_admin_elevations(101, 1).await.unwrap(),
        1
    );
    repo.close().await;
    issuer
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await
        .unwrap();
    issuer.close().await.unwrap();
}
