use qid_storage::SqlRepository;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();
static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("qid_worker_test_{}", std::process::id()));
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "clear stale worker-test directory {}: {error}",
                root.display()
            ),
        }
        std::fs::create_dir_all(&root).expect("create worker-test directory");
        root
    })
}

async fn schema_template() -> PathBuf {
    TEMPLATE
        .get_or_init(|| async {
            let path = test_root().join("schema.db");
            let url = format!("sqlite:{}", path.display());
            let repo = SqlRepository::connect(&url)
                .await
                .expect("connect schema template");
            repo.migrate().await.expect("migrate schema template");
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "schema template sidecar remains: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
        .clone()
}

pub(crate) async fn test_db_path() -> PathBuf {
    let template = schema_template().await;
    let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = test_root().join(format!("test_{n}.db"));
    std::fs::copy(template, &path).expect("copy worker-test database template");
    path
}
