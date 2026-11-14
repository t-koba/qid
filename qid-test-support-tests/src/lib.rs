#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
#[path = "../../qid-admin/tests/support/sqlite_fixture.rs"]
mod sqlite_fixture;

#[cfg(test)]
mod tests {
    use super::sqlite_fixture::*;
    use std::fs::{self, File};
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
        let other_fixture = SqliteTestFixture::new("fixture_concurrent_other");
        let (first, second, other) = tokio::join!(
            first_fixture.repository(),
            second_fixture.repository(),
            other_fixture.repository()
        );
        assert!(std::sync::Arc::ptr_eq(
            first_fixture.template.get().unwrap(),
            second_fixture.template.get().unwrap()
        ));
        assert!(std::sync::Arc::ptr_eq(
            first_fixture.template.get().unwrap(),
            other_fixture.template.get().unwrap()
        ));
        assert_ne!(first.dir(), second.dir());
        assert_ne!(first.dir(), other.dir());
        assert_ne!(second.dir(), other.dir());
        assert!(!first_fixture.template.get().unwrap().is_empty());
        assert!(!second_fixture.template.get().unwrap().is_empty());
        assert!(!other_fixture.template.get().unwrap().is_empty());
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
        assert!(other.repo().list_realms().await.unwrap().is_empty());
        let first_dir = first.dir().to_path_buf();
        let second_dir = second.dir().to_path_buf();
        let other_dir = other.dir().to_path_buf();
        first.close().await;
        second.close().await;
        other.close().await;
        assert!(!first_dir.exists());
        assert!(!second_dir.exists());
        assert!(!other_dir.exists());
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
