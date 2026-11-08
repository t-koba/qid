//! Shared test-only SQLite schema copies. Fresh-migration coverage belongs to qid-storage.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use qid_storage::SqlRepository;
use std::{
    fs::{self, File},
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};
/// One migrated schema per test process, kept only as bytes in memory.
pub struct SqliteTestFixture {
    namespace: &'static str,
    template: tokio::sync::OnceCell<Vec<u8>>,
}
impl SqliteTestFixture {
    pub const fn new(namespace: &'static str) -> Self {
        Self {
            namespace,
            template: tokio::sync::OnceCell::const_new(),
        }
    }
    async fn template_bytes(&self) -> &[u8] {
        self.template.get_or_init(|| async {
            assert!(!self.namespace.is_empty() && self.namespace.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "SQLite fixture namespace must contain only ASCII letters, digits or underscores");
            let base = std::env::temp_dir().join(format!("qid_test_{}", self.namespace));
            fs::create_dir_all(&base).expect("create SQLite fixture directory");
            assert!(fs::symlink_metadata(&base).expect("stat SQLite fixture directory").file_type().is_dir(), "SQLite fixture directory must not be a symlink");
            let init_path = base.join("init.lock");
            if let Ok(metadata) = fs::symlink_metadata(&init_path) {
                assert!(metadata.file_type().is_file(), "fixture init lock must be a regular file");
            }
            let init_lock = File::options().write(true).create(true).truncate(false).open(&init_path).expect("open SQLite fixture init lock");
            init_lock.lock().expect("acquire SQLite fixture init lock");
            let sweep = sweep_stale_runs(&base);
            if let Err(error) = sweep {
                let _ = init_lock.unlock();
                panic!("sweep stale SQLite fixtures: {error}");
            }
            init_lock.unlock().expect("release SQLite fixture init lock");
            drop(init_lock);
            let template_dir = tempfile::TempDir::new().expect("create SQLite schema template directory");
            let template_path = template_dir.path().join("schema_template.db");
            let repo = SqlRepository::connect(&format!("sqlite:{}", template_path.display())).await.expect("connect SQLite schema template");
            repo.migrate().await.expect("migrate SQLite schema template");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                assert!(!sidecar(&template_path, suffix).try_exists().unwrap(), "SQLite schema template has a sidecar after closing: {suffix}");
            }
            let bytes = fs::read(&template_path).expect("read SQLite schema template");
            assert!(!bytes.is_empty(), "SQLite schema template image must not be empty");
            template_dir.close().expect("remove SQLite schema template directory");
            bytes
        }).await.as_slice()
    }
    /// Copy the in-memory schema image into a unique per-test directory.
    pub async fn repository(&self) -> TestDatabase {
        let bytes: Vec<u8> = self.template_bytes().await.to_vec();
        let dir = tempfile::TempDir::new().expect("create isolated SQLite test directory");
        let path = dir.path().join("test.db");
        fs::write(&path, &bytes).expect("write isolated SQLite test database");
        let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .expect("connect isolated SQLite test database");
        TestDatabase { repo, dir }
    }
}
/// One isolated test database in its own temporary directory.
pub struct TestDatabase {
    repo: SqlRepository,
    dir: tempfile::TempDir,
}
impl TestDatabase {
    pub fn repo(&self) -> &SqlRepository {
        &self.repo
    }
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
    /// Close the shared pool, then remove this test database directory.
    pub async fn close(self) {
        self.repo.close().await;
        self.dir
            .close()
            .expect("remove isolated SQLite test directory");
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
            Err(error) if error.kind() == ErrorKind::NotFound => {}
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
fn is_valid_run_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("run_") else {
        return false;
    };
    let Some((pid, sequence)) = rest.split_once('_') else {
        return false;
    };
    !pid.is_empty()
        && !sequence.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && sequence.bytes().all(|b| b.is_ascii_digit())
}
fn is_stale_run(run_dir: &Path) -> std::io::Result<bool> {
    let lock_path = run_dir.join("fixture.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("run lock is not a regular file: {}", lock_path.display()),
                ));
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    }
    let lock = match File::options().write(true).open(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    match lock.try_lock() {
        Ok(()) => {
            let _ = lock.unlock();
            Ok(true)
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}
fn sweep_legacy_files(base: &Path) -> std::io::Result<()> {
    let legacy_lock = base.join("fixture.lock");
    match fs::symlink_metadata(&legacy_lock) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "legacy fixture lock is not a regular file: {}",
                    legacy_lock.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Create and retain the stable pathname even when an older run left no lock.
    // Hold the lock until every legacy database and sidecar has been removed.
    let lock = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&legacy_lock)?;
    match lock.try_lock() {
        Ok(()) => {
            clean_test_databases(base)?;
            remove_database_files(&base.join("schema_template.db"))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(()),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

fn sweep_stale_runs(base: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(base)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == "init.lock" {
            continue;
        }
        if !is_valid_run_name(name) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("run path is a symlink: {}", path.display()),
            ));
        }
        if !metadata.file_type().is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("run path is not a directory: {}", path.display()),
            ));
        }
        if is_stale_run(&path)? {
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    sweep_legacy_files(base)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn template_bytes_are_shared_and_copies_are_isolated() {
        use qid_storage::prelude::*;
        let fixture = SqliteTestFixture::new("fixture_isolation");
        let (first, second) = tokio::join!(fixture.repository(), fixture.repository());
        assert!(!fixture.template.get().unwrap().is_empty());
        let first_dir = first.dir().to_path_buf();
        let second_dir = second.dir().to_path_buf();
        assert_ne!(first_dir, second_dir);
        first
            .repo()
            .create_realm(
                &"tenant".into(),
                &"realm".into(),
                "https://example.com",
                None,
            )
            .await
            .unwrap();
        assert_eq!(first.repo().list_realms().await.unwrap().len(), 1);
        assert!(second.repo().list_realms().await.unwrap().is_empty());
        let third = fixture.repository().await;
        assert!(third.repo().list_realms().await.unwrap().is_empty());
        assert_ne!(third.dir(), first.dir());
        assert_ne!(third.dir(), second.dir());
        first.close().await;
        assert!(!first_dir.exists(), "closed test directory must be removed");
        second.close().await;
        assert!(
            !second_dir.exists(),
            "closed test directory must be removed"
        );
        let third_dir = third.dir().to_path_buf();
        third.close().await;
        assert!(!third_dir.exists(), "closed test directory must be removed");
    }
    #[tokio::test]
    async fn concurrent_fixtures_with_same_namespace_stay_isolated() {
        use qid_storage::prelude::*;
        let first_fixture = SqliteTestFixture::new("fixture_concurrent");
        let second_fixture = SqliteTestFixture::new("fixture_concurrent");
        let (first, second) = tokio::join!(first_fixture.repository(), second_fixture.repository());
        assert_ne!(first.dir(), second.dir());
        assert!(!first_fixture.template.get().unwrap().is_empty());
        assert!(!second_fixture.template.get().unwrap().is_empty());
        first
            .repo()
            .create_realm(
                &"tenant".into(),
                &"realm".into(),
                "https://example.com",
                None,
            )
            .await
            .unwrap();
        assert_eq!(first.repo().list_realms().await.unwrap().len(), 1);
        assert!(second.repo().list_realms().await.unwrap().is_empty());
        let first_dir = first.dir().to_path_buf();
        let second_dir = second.dir().to_path_buf();
        first.close().await;
        second.close().await;
        assert!(!first_dir.exists());
        assert!(!second_dir.exists());
    }
    #[tokio::test]
    async fn close_removes_database_and_sidecars_after_pool_close() {
        use qid_storage::prelude::*;
        let fixture = SqliteTestFixture::new("fixture_close_cleanup");
        let db = fixture.repository().await;
        let dir = db.dir().to_path_buf();
        let db_path = dir.join("test.db");
        assert!(db_path.exists(), "fresh test database file must exist");
        db.repo()
            .create_realm(
                &"tenant".into(),
                &"realm".into(),
                "https://example.com",
                None,
            )
            .await
            .unwrap();
        for suffix in ["-wal", "-shm", "-journal"] {
            fs::write(sidecar(&db_path, suffix), b"sidecar").unwrap();
        }
        assert!(sidecar(&db_path, "-wal").exists());
        db.close().await;
        assert!(!dir.exists(), "close must remove the per-test directory");
        assert!(
            !db_path.exists(),
            "close must remove the test database file"
        );
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(
                !sidecar(&db_path, suffix).exists(),
                "close must remove sidecar {suffix}"
            );
        }
    }
    #[test]
    fn sqlite_database_cleanup_removes_stale_sidecars_without_matching_template() {
        let dir = std::env::temp_dir().join(format!("qid_fixture_cleanup_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
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
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    fn stale_run_sweep_removes_released_run_but_preserves_active() {
        let base = std::env::temp_dir().join(format!("qid_fixture_sweep_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("init.lock"), b"init").unwrap();
        let active_run = base.join("run_1_0");
        fs::create_dir_all(&active_run).unwrap();
        let active_lock_path = active_run.join("fixture.lock");
        let active_lock = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&active_lock_path)
            .unwrap();
        active_lock.try_lock().unwrap();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            fs::write(
                sidecar(&active_run.join("schema_template.db"), suffix),
                b"active",
            )
            .unwrap();
            fs::write(sidecar(&active_run.join("test_0.db"), suffix), b"active").unwrap();
        }
        let stale_run = base.join("run_2_0");
        fs::create_dir_all(&stale_run).unwrap();
        {
            let released = File::options()
                .write(true)
                .create(true)
                .truncate(false)
                .open(stale_run.join("fixture.lock"))
                .unwrap();
            released.try_lock().unwrap();
            released.unlock().unwrap();
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            fs::write(
                sidecar(&stale_run.join("schema_template.db"), suffix),
                b"stale",
            )
            .unwrap();
            fs::write(sidecar(&stale_run.join("test_0.db"), suffix), b"stale").unwrap();
        }
        let incomplete_run = base.join("run_3_0");
        fs::create_dir_all(&incomplete_run).unwrap();
        fs::write(incomplete_run.join("partial.tmp"), b"incomplete").unwrap();
        sweep_stale_runs(&base).unwrap();
        assert!(active_run.exists());
        for suffix in ["", "-wal", "-shm", "-journal"] {
            assert!(sidecar(&active_run.join("schema_template.db"), suffix).exists());
            assert!(sidecar(&active_run.join("test_0.db"), suffix).exists());
        }
        assert!(!stale_run.exists());
        assert!(!incomplete_run.exists());
        assert!(base.join("init.lock").exists());
        active_lock.unlock().unwrap();
        drop(active_lock);
        fs::remove_dir_all(&base).unwrap();
    }
    #[test]
    fn legacy_cleanup_preserves_files_when_holder_is_active() {
        let base =
            std::env::temp_dir().join(format!("qid_fixture_legacy_active_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let legacy_lock_path = base.join("fixture.lock");
        let holder = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&legacy_lock_path)
            .unwrap();
        holder.try_lock().unwrap();
        let template = base.join("schema_template.db");
        let numbered = base.join("test_7.db");
        for path in [&template, &numbered] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                fs::write(sidecar(path, suffix), b"active legacy").unwrap();
            }
        }
        sweep_legacy_files(&base).unwrap();
        assert!(
            legacy_lock_path.exists(),
            "active legacy lock path must be retained"
        );
        for path in [&template, &numbered] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                assert!(
                    sidecar(path, suffix).exists(),
                    "active holder files must be preserved: {}",
                    sidecar(path, suffix).display()
                );
            }
        }
        holder.unlock().unwrap();
        drop(holder);
        fs::remove_dir_all(&base).unwrap();
    }
    #[test]
    fn legacy_cleanup_removes_leftovers_without_unlinking_lock() {
        let base =
            std::env::temp_dir().join(format!("qid_fixture_legacy_idle_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let legacy_lock_path = base.join("fixture.lock");
        let template = base.join("schema_template.db");
        let numbered = base.join("test_9.db");
        for path in [&template, &numbered] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                fs::write(sidecar(path, suffix), b"stale legacy").unwrap();
            }
        }
        sweep_legacy_files(&base).unwrap();
        assert!(
            legacy_lock_path.exists(),
            "cleanup must create and retain the stable legacy lock path"
        );
        sweep_legacy_files(&base).unwrap();
        assert!(
            legacy_lock_path.exists(),
            "repeated cleanup must retain the lock path"
        );
        for path in [&template, &numbered] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                assert!(
                    !sidecar(path, suffix).exists(),
                    "stale legacy file must be removed: {}",
                    sidecar(path, suffix).display()
                );
            }
        }
        fs::remove_file(&legacy_lock_path).unwrap();
        fs::remove_dir(&base).unwrap();
    }
}
