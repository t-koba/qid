//! Test-only shared SQLite fixture for the SQL unit tests.
//!
//! Each test used to create a fresh database and run all migrations. With 65
//! migrations that repeats the same work per test, while
//! `qid-storage/tests/support` already showed that copying a migrated schema
//! template keeps every test database isolated. This helper brings that
//! pattern to the in-crate SQL tests: one migrated schema template per test
//! process, copied to a distinct per-test database file.
//!
//! Fresh-migration coverage stays where it is: `test_connect_and_migrate` and
//! the migration-plan tests in `qid-storage/tests/sql_repository.rs` keep
//! running migrations on an empty database and never use this template.
//! Seed and transaction behavior is unchanged: callers apply their seed SQL
//! after the copy, on the per-test database only.

use super::super::SqlRepository;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();
static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        // Integration tests sweep test_*.db in qid_test, so all unit-test
        // files must live one level below it. Never sweep another process's
        // directory. A reused PID may leave stale files, cleared once before
        // this process opens any databases (not on every template attempt).
        let root = std::env::temp_dir()
            .join("qid_test")
            .join(format!("sql_unit_{}", std::process::id()));
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "clear stale unit-test directory {}: {error}",
                root.display()
            ),
        }
        std::fs::create_dir_all(&root).expect("create storage unit-test dir failed");
        root
    })
}

fn remove_sqlite_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        match std::fs::remove_file(PathBuf::from(candidate)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Migrated schema template for this test process, built once.
async fn schema_template() -> PathBuf {
    TEMPLATE
        .get_or_init(|| async {
            let path = test_root().join("schema.db");
            remove_sqlite_files(&path).expect("clear unit-test schema template failed");
            let url = format!("sqlite:{}", path.display());
            let repo = SqlRepository::connect(&url)
                .await
                .expect("connect storage unit-test template failed");
            repo.migrate()
                .await
                .expect("migrate storage unit-test template failed");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "unit-test schema template has a sidecar after closing the pool: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
        .clone()
}

/// One isolated database copied from the process template.
///
/// Cleanup must close the pool before removing files, otherwise Windows holds
/// the file handle and removal fails. Call [`IsolatedDb::cleanup`] at the end
/// of the test; the `Drop` impl only best-effort removes files for panic
/// paths where the pool could not be closed.
pub(in crate::sql) struct IsolatedDb {
    path: PathBuf,
    url: String,
    repo: Option<SqlRepository>,
}

impl IsolatedDb {
    pub(in crate::sql) async fn setup() -> Self {
        let template = schema_template().await;
        let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = test_root().join(format!("test_{n}.db"));
        std::fs::copy(&template, &path).expect("copy storage unit-test template");
        let url = format!("sqlite:{}", path.display());
        let repo = SqlRepository::connect(&url)
            .await
            .expect("connect storage unit-test database failed");
        Self {
            path,
            url,
            repo: Some(repo),
        }
    }

    pub(in crate::sql) fn repo(&self) -> &SqlRepository {
        self.repo
            .as_ref()
            .expect("unit-test database repository exists")
    }

    pub(in crate::sql) fn url(&self) -> &str {
        &self.url
    }

    pub(in crate::sql) async fn cleanup(mut self) {
        if let Some(repo) = self.repo.take() {
            repo.close().await;
        }
        remove_sqlite_files(&self.path).unwrap_or_else(|error| {
            panic!("remove unit-test database {}: {error}", self.path.display())
        });
    }
}

impl Drop for IsolatedDb {
    fn drop(&mut self) {
        // Panic cleanup cannot await pool closure. Drop our repository first
        // and try only this database; Windows may retain open handles until
        // the runtime exits. PID reuse cleanup handles any leftovers.
        drop(self.repo.take());
        let _ = remove_sqlite_files(&self.path);
    }
}
