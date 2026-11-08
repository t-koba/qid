//! Shared test-only SQLite schema copies. Fresh-migration coverage belongs to qid-storage.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use qid_storage::SqlRepository;
use std::{
    fs::{self, File},
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// One static fixture per namespace/test binary. Each process gets an independent run directory.
///
/// Initialization holds `<base>/init.lock` only while sweeping stale `run_<pid>_<seq>`
/// directories and creating a new unique run directory. The new run's `fixture.lock` is held
/// for the fixture lifetime, so a concurrent process never fails merely because another
/// process is active: it uses its own run directory instead. Stale runs (lock free or missing)
/// are removed with all sidecars; active runs are skipped. Incomplete run directories without
/// a lock file are treated as stale. Callers own repository lifetimes, including closing pools
/// before explicit file cleanup.
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
                let base = std::env::temp_dir().join(format!("qid_test_{}", self.namespace));
                fs::create_dir_all(&base).expect("create SQLite fixture directory");
                assert!(
                    fs::symlink_metadata(&base)
                        .expect("stat SQLite fixture directory")
                        .file_type()
                        .is_dir(),
                    "SQLite fixture directory must not be a symlink"
                );
                let init_path = base.join("init.lock");
                if let Ok(metadata) = fs::symlink_metadata(&init_path) {
                    assert!(
                        metadata.file_type().is_file(),
                        "fixture init lock must be a regular file"
                    );
                }
                let init_lock = File::options()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&init_path)
                    .expect("open SQLite fixture init lock");
                init_lock
                    .lock()
                    .expect("acquire SQLite fixture init lock");
                let run_dir = match (|| -> std::io::Result<PathBuf> {
                    sweep_stale_runs(&base)?;
                    create_unique_run_dir(&base)
                })() {
                    Ok(dir) => dir,
                    Err(error) => {
                        let _ = init_lock.unlock();
                        panic!("prepare SQLite fixture run directory: {error}");
                    }
                };
                let run_lock_path = run_dir.join("fixture.lock");
                // Fresh run directories are empty, so a pre-existing lock file is unexpected.
                if let Ok(metadata) = fs::symlink_metadata(&run_lock_path) {
                    let _ = init_lock.unlock();
                    assert!(
                        metadata.file_type().is_file(),
                        "fixture run lock must be a regular file"
                    );
                    panic!("fresh SQLite fixture run already has a lock file");
                }
                let run_lock = File::options()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&run_lock_path)
                    .expect("open SQLite fixture run lock");
                match run_lock.try_lock() {
                    Ok(()) => {}
                    Err(std::fs::TryLockError::WouldBlock) => {
                        let _ = init_lock.unlock();
                        panic!("fresh SQLite fixture run lock is already held");
                    }
                    Err(std::fs::TryLockError::Error(error)) => {
                        let _ = init_lock.unlock();
                        panic!("lock fresh SQLite fixture run: {error}");
                    }
                }
                init_lock
                    .unlock()
                    .expect("release SQLite fixture init lock");
                drop(init_lock);
                let template_path = run_dir.join("schema_template.db");
                remove_database_files(&template_path)
                    .expect("remove stale SQLite schema template");
                let repo = SqlRepository::connect(&format!("sqlite:{}", template_path.display()))
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
                (template_path, run_lock)
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
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "legacy fixture lock is not a regular file: {}",
                        legacy_lock.display()
                    ),
                ));
            }
            let lock = File::options().write(true).open(&legacy_lock)?;
            match lock.try_lock() {
                Ok(()) => {
                    let _ = lock.unlock();
                    drop(lock);
                    clean_test_databases(base)?;
                    remove_database_files(&base.join("schema_template.db"))?;
                    match fs::remove_file(&legacy_lock) {
                        Ok(()) => {}
                        Err(error) if error.kind() == ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    Ok(())
                }
                Err(std::fs::TryLockError::WouldBlock) => Ok(()),
                Err(std::fs::TryLockError::Error(error)) => Err(error),
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            // No legacy holder; any base-level template or numbered database is a leftover.
            clean_test_databases(base)?;
            remove_database_files(&base.join("schema_template.db"))?;
            Ok(())
        }
        Err(error) => Err(error),
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

fn create_unique_run_dir(base: &Path) -> std::io::Result<PathBuf> {
    let pid = std::process::id();
    for sequence in 0..10_000 {
        let dir = base.join(format!("run_{pid}_{sequence}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(Error::new(
        ErrorKind::AlreadyExists,
        "could not create a unique SQLite fixture run directory",
    ))
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
        let run_dir = template.parent().unwrap().to_path_buf();
        let base = run_dir.parent().unwrap().to_path_buf();
        drop(fixture);
        fs::remove_dir_all(&run_dir).unwrap();
        fs::remove_file(base.join("init.lock")).unwrap();
        fs::remove_dir(&base).unwrap();
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

    #[tokio::test]
    async fn concurrent_fixtures_with_same_namespace_use_distinct_runs() {
        use qid_storage::prelude::*;

        let first_fixture = SqliteTestFixture::new("fixture_concurrent");
        let second_fixture = SqliteTestFixture::new("fixture_concurrent");
        let (first, second) = tokio::join!(first_fixture.repository(), second_fixture.repository());
        let (first_template, _) = first_fixture.template.get().unwrap();
        let (second_template, _) = second_fixture.template.get().unwrap();
        assert_ne!(first_template, second_template);
        let first_run = first_template.parent().unwrap().to_path_buf();
        let second_run = second_template.parent().unwrap().to_path_buf();
        assert_ne!(first_run, second_run);
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
        first.close().await;
        second.close().await;
        let base = first_run.parent().unwrap().to_path_buf();
        assert_eq!(base, second_run.parent().unwrap().to_path_buf());
        drop(first_fixture);
        drop(second_fixture);
        fs::remove_dir_all(&first_run).unwrap();
        fs::remove_dir_all(&second_run).unwrap();
        fs::remove_file(base.join("init.lock")).unwrap();
        fs::remove_dir(&base).unwrap();
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
}
