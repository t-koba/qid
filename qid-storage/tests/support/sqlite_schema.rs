use qid_storage::SqlRepository;
use std::path::{Path, PathBuf};

static SCHEMA_TEMPLATE: tokio::sync::OnceCell<Vec<u8>> = tokio::sync::OnceCell::const_new();

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

/// Build one migrated schema in an owned temporary directory, then cache only its bytes.
async fn schema_template_bytes() -> &'static [u8] {
    SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let directory = tempfile::tempdir().expect("create storage schema template directory");
            let path = directory.path().join("schema_template.db");
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
            let bytes = std::fs::read(&path).expect("read storage schema template");
            remove_sqlite_database_files(&path).expect("remove storage schema template files");
            directory
                .close()
                .expect("remove storage schema template directory");
            bytes
        })
        .await
}

pub async fn copy_schema_template(destination: &Path) {
    std::fs::write(destination, schema_template_bytes().await)
        .expect("copy storage schema template");
}
