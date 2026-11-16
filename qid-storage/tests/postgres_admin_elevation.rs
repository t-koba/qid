#![cfg(test)]

//! Deterministic cleanup/issuance interleaving on a disposable PostgreSQL database.
//! Local runs skip unless QID_TEST_POSTGRES_URL is set; never use production data.
use qid_storage::{AdminRepository, SqlRepository};
use sqlx::{
    AnyPool, ConnectOptions, Connection, Executor, PgConnection, postgres::PgConnectOptions,
};
use std::{future::Future, time::Duration};

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

    // The repository pool is private; exercise the old algorithm through a
    // test-only pool with the same driver and isolated database configuration.
    let legacy_pool = AnyPool::connect(repo_url.as_str()).await.unwrap();
    let deleted = refresh_during_cleanup(&mut issuer, async {
        legacy_cleanup(&legacy_pool, 100, 1).await
    })
    .await;
    assert_eq!(
        deleted, 1,
        "the interleaving must defeat the legacy cleanup"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_elevations WHERE id = 'reused'")
            .fetch_one(&mut issuer)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "legacy cleanup must delete the fresh row");
    legacy_pool.close().await;

    issuer.execute("INSERT INTO admin_elevations (id, tenant_id, admin_id, elevation_expires_at, created_at) VALUES ('reused', 'tenant', 'admin', 100, 1)").await.unwrap();
    let deleted = refresh_during_cleanup(&mut issuer, async {
        repo.cleanup_expired_admin_elevations(100, 1).await.unwrap()
    })
    .await;
    assert_eq!(deleted, 0, "fresh issuance must not be reclaimed");
    let fresh: (i32, i32) = sqlx::query_as(
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

// Retain the pre-fix SELECT-then-DELETE-by-ID algorithm as a negative control.
// Its SELECT must run in the same transaction as its DELETE, as production did.
async fn legacy_cleanup(pool: &AnyPool, now: u64, limit: u32) -> u64 {
    let mut tx = pool
        .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .unwrap();
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM admin_elevations WHERE elevation_expires_at >= 0 AND elevation_expires_at <= $1 ORDER BY elevation_expires_at LIMIT $2",
    )
    .bind(now as i64)
    .bind(i64::from(limit))
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert_eq!(ids, ["reused"]);
    let mut deleted = 0;
    for id in ids {
        deleted += sqlx::query("DELETE FROM admin_elevations WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
    }
    tx.commit().await.unwrap();
    deleted
}

async fn refresh_during_cleanup(
    issuer: &mut PgConnection,
    cleanup: impl Future<Output = u64>,
) -> u64 {
    let mut replacement = issuer.begin().await.unwrap();
    // A row lock (not a table SHARE lock) lets both DELETE statements acquire
    // their READ COMMITTED snapshot and find the stale tuple before blocking.
    // A BEFORE ROW trigger would already hold this tuple lock, preventing the
    // concurrent UPDATE we need to exercise EvalPlanQual's predicate recheck.
    let stale: (i32, i32) = sqlx::query_as(
        "SELECT elevation_expires_at, created_at FROM admin_elevations WHERE id = 'reused' FOR UPDATE",
    )
    .fetch_one(&mut *replacement)
    .await
    .unwrap();
    assert_eq!(stale, (100, 1));

    let replace = async {
        // Explicit lock handshake: a DELETE must hold its table lock and wait
        // on our row-locking transaction. No elapsed-time assumption or retry
        // of the race itself is involved. Query pg_locks, not cached statistics.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks waiting \
                     JOIN pg_locks held ON held.transactionid = waiting.transactionid \
                     WHERE waiting.locktype = 'transactionid' AND NOT waiting.granted \
                     AND held.locktype = 'transactionid' AND held.granted \
                     AND held.mode = 'ExclusiveLock' AND held.pid = pg_backend_pid() \
                     AND EXISTS (SELECT 1 FROM pg_locks target \
                         WHERE target.pid = waiting.pid AND target.granted \
                         AND target.relation = 'admin_elevations'::regclass \
                         AND target.mode = 'RowExclusiveLock'))",
                )
                .fetch_one(&mut *replacement)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup must reach its DELETE and wait on the stale row");
        // UPDATE preserves the tuple chain so the waiting DELETE follows it
        // after commit. EPQ must recheck the fresh tuple against the DELETE's
        // predicate: expiry-bounded cleanup skips it; ID-only cleanup deletes it.
        let updated = sqlx::query(
            "UPDATE admin_elevations SET elevation_expires_at = 101, created_at = 100 WHERE id = 'reused'",
        )
        .execute(&mut *replacement)
        .await
        .unwrap();
        assert_eq!(updated.rows_affected(), 1);
        replacement.commit().await.unwrap();
    };
    let (deleted, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(cleanup, replace)
    })
    .await
    .expect("cleanup and row refresh must complete without deadlock");
    deleted
}
