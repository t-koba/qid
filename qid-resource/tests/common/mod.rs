use qid_storage::SqlRepository;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

static DB_SEQ: AtomicU16 = AtomicU16::new(0);
static SCHEMA_TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();

fn db_url(namespace: &str) -> String {
    let dir = std::env::temp_dir().join(namespace);
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
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

async fn schema_template_path(namespace: &str) -> PathBuf {
    let path = std::env::temp_dir()
        .join(namespace)
        .join("schema_template.db");
    SCHEMA_TEMPLATE
        .get_or_init(|| async move {
            remove_sqlite_files(&path).expect("clear SQLite schema template");
            let url = format!("sqlite:{}", path.display());
            let repo = SqlRepository::connect(&url)
                .await
                .expect("connect SQLite schema template");
            repo.migrate()
                .await
                .expect("migrate SQLite schema template");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "schema template still has an open SQLite sidecar: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
        .clone()
}

/// Each setup copies an isolated database; fresh-migration coverage stays in qid-storage.
pub async fn sql_repo(namespace: &str) -> SqlRepository {
    let url = db_url(namespace);
    let path = url.strip_prefix("sqlite:").expect("SQLite test URL");
    std::fs::copy(schema_template_path(namespace).await, path)
        .expect("copy SQLite schema template");
    SqlRepository::connect(&url)
        .await
        .expect("connect test repository")
}
