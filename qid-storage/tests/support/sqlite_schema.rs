use qid_storage::SqlRepository;
use std::path::{Path, PathBuf};

static SCHEMA_TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();

pub fn remove_sqlite_database_files(path: &Path) -> std::io::Result<()> {
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

/// Build and close one migrated schema for independent per-test database copies.
pub async fn schema_template_path() -> &'static PathBuf {
    SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let path = std::env::temp_dir()
                .join("qid_test")
                .join("schema_template.db");
            std::fs::create_dir_all(path.parent().expect("schema template has a parent"))
                .expect("create storage schema template directory");
            remove_sqlite_database_files(&path).expect("remove stale storage schema template");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .expect("connect storage schema template failed");
            repo.migrate()
                .await
                .expect("migrate storage schema template failed");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "schema template has a sidecar after closing the pool: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
}

pub async fn copy_schema_template(destination: &Path) {
    std::fs::copy(schema_template_path().await, destination).expect("copy storage schema template");
}
