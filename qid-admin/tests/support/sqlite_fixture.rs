//! Shared test-only SQLite schema copies. Fresh-migration coverage belongs to qid-storage.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use qid_storage::SqlRepository;
use std::{
    fs::{self, File},
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
};
/// One migrated schema per test process, kept only as bytes in memory.
static PROCESS_TEMPLATE: tokio::sync::OnceCell<Arc<Vec<u8>>> = tokio::sync::OnceCell::const_new();
pub struct SqliteTestFixture {
    namespace: &'static str,
    pub(super) template: tokio::sync::OnceCell<Arc<Vec<u8>>>,
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
            Arc::clone(
                PROCESS_TEMPLATE
                    .get_or_init(|| async {
                        let template_dir = tempfile::TempDir::new()
                            .expect("create SQLite schema template directory");
                        let template_path = template_dir.path().join("schema_template.db");
                        let repo = SqlRepository::connect(&format!(
                            "sqlite:{}",
                            template_path.display()
                        ))
                        .await
                        .expect("connect SQLite schema template");
                        repo.migrate().await.expect("migrate SQLite schema template");
                        repo.close().await;
                        for suffix in ["-wal", "-shm", "-journal"] {
                            assert!(
                                !sidecar(&template_path, suffix).try_exists().unwrap(),
                                "SQLite schema template has a sidecar after closing: {suffix}"
                            );
                        }
                        let bytes = fs::read(&template_path)
                            .expect("read SQLite schema template");
                        assert!(
                            !bytes.is_empty(),
                            "SQLite schema template image must not be empty"
                        );
                        template_dir
                            .close()
                            .expect("remove SQLite schema template directory");
                        Arc::new(bytes)
                    })
                    .await,
            )
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
pub(super) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}
pub(super) fn remove_database_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        match fs::remove_file(sidecar(path, suffix)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub(super) fn clean_test_databases(dir: &Path) -> std::io::Result<()> {
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
pub(super) fn sweep_legacy_files(base: &Path) -> std::io::Result<()> {
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

pub(super) fn sweep_stale_runs(base: &Path) -> std::io::Result<()> {
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
