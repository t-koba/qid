//! Shared test-only SQLite schema copies. Fresh-migration coverage belongs to qid-storage.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use qid_storage::SqlRepository;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// One static fixture per namespace/test binary. Each repository has an independent database.
///
/// Initialization clears stale numbered databases and their sidecars, then migrates and closes
/// a schema template once. Files persist until the next run; a process-held lock prevents a
/// concurrent run with the same namespace from sweeping live databases (it fails closed).
/// Callers own repository lifetimes, including closing pools before explicit file cleanup.
pub struct SqliteTestFixture {
    namespace: &'static str,
    template: tokio::sync::OnceCell<(PathBuf, File)>,
    sequence: AtomicU64,
}

impl SqliteTestFixture {
    pub const fn new(namespace: &'static str) -> Self {
        Self {
            namespace,
            template: tokio::sync::OnceCell::const_new(),
            sequence: AtomicU64::new(0),
        }
    }

    /// Copy the closed, sidecar-free template and connect without rerunning migrations.
    pub async fn repository(&self) -> SqlRepository {
        let (template, _lock) = self
            .template
            .get_or_init(|| async {
                assert!(
                    !self.namespace.is_empty()
                        && self.namespace.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "SQLite fixture namespace must contain only ASCII letters, digits or underscores"
                );
                let dir = std::env::temp_dir().join(format!("qid_test_{}", self.namespace));
                fs::create_dir_all(&dir).expect("create SQLite fixture directory");
                assert!(
                    fs::symlink_metadata(&dir).unwrap().file_type().is_dir(),
                    "SQLite fixture directory must not be a symlink"
                );
                let lock_path = dir.join("fixture.lock");
                if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
                    assert!(metadata.file_type().is_file(), "fixture lock must be a regular file");
                }
                let lock = File::options()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(lock_path)
                    .expect("open SQLite fixture lock");
                lock.try_lock().expect("SQLite fixture namespace is already in use");
                clean_test_databases(&dir).expect("remove stale SQLite test databases");
                let path = dir.join("schema_template.db");
                remove_database_files(&path).expect("remove stale SQLite schema template");
                let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                    .await
                    .expect("connect SQLite schema template");
                repo.migrate().await.expect("migrate SQLite schema template");
                repo.close().await;
                for suffix in ["-wal", "-shm", "-journal"] {
                    assert!(
                        !sidecar(&path, suffix).try_exists().unwrap(),
                        "SQLite schema template has a sidecar after closing: {suffix}"
                    );
                }
                (path, lock)
            })
            .await;
        let n = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("SQLite test database sequence exhausted");
        let path = template.with_file_name(format!("test_{n}.db"));
        fs::copy(template, &path).expect("copy SQLite schema template");
        SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .expect("connect isolated SQLite test database")
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn remove_database_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        match fs::remove_file(sidecar(path, suffix)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn clean_test_databases(dir: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let main = ["-wal", "-shm", "-journal"]
            .iter()
            .find_map(|suffix| name.strip_suffix(suffix))
            .unwrap_or(name);
        if let Some(number) = main
            .strip_prefix("test_")
            .and_then(|s| s.strip_suffix(".db"))
            && !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
        {
            remove_database_files(&path.with_file_name(main))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn schema_copies_are_independent_under_concurrent_initialization() {
        use qid_storage::prelude::*;

        let fixture = SqliteTestFixture::new("fixture_isolation");
        let (first, second) = tokio::join!(fixture.repository(), fixture.repository());
        first
            .create_realm(
                &"tenant".into(),
                &"realm".into(),
                "https://example.com",
                None,
            )
            .await
            .unwrap();
        assert_eq!(first.list_realms().await.unwrap().len(), 1);
        assert!(second.list_realms().await.unwrap().is_empty());
        let third = fixture.repository().await;
        assert!(third.list_realms().await.unwrap().is_empty());
        first.close().await;
        second.close().await;
        third.close().await;
        let (template, _) = fixture.template.get().unwrap();
        let dir = template.parent().unwrap().to_path_buf();
        clean_test_databases(&dir).unwrap();
        remove_database_files(template).unwrap();
        drop(fixture);
        fs::remove_file(dir.join("fixture.lock")).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn sqlite_database_cleanup_removes_stale_sidecars_without_matching_template() {
        let dir = std::env::temp_dir().join(format!("qid_fixture_cleanup_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let test_database = dir.join("test_123.db");
        let orphan_database = dir.join("test_456.db");
        let template = dir.join("schema_template.db");
        let unrelated = dir.join("test_other.db");
        for path in [&test_database, &template, &unrelated] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                fs::write(sidecar(path, suffix), b"stale database artifact").unwrap();
            }
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            fs::write(sidecar(&orphan_database, suffix), b"orphan sidecar").unwrap();
        }
        clean_test_databases(&dir).unwrap();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            assert!(!sidecar(&test_database, suffix).exists());
            assert!(!sidecar(&orphan_database, suffix).exists());
            assert!(sidecar(&template, suffix).exists());
            assert!(sidecar(&unrelated, suffix).exists());
        }
        remove_database_files(&template).unwrap();
        remove_database_files(&unrelated).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
