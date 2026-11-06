use qid_storage::SqlRepository;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::task::Poll;

static TEMPLATE: tokio::sync::OnceCell<Vec<u8>> = tokio::sync::OnceCell::const_new();

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qid_worker_test_{}_{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        std::fs::create_dir(&path).expect("create worker-test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap_or_else(|error| {
            panic!("remove worker-test directory {}: {error}", self.0.display())
        });
    }
}

async fn schema_template() -> &'static [u8] {
    TEMPLATE
        .get_or_init(|| async {
            let dir = TestDir::new();
            let path = dir.0.join("schema.db");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .expect("connect schema template");
            let migrated = repo.migrate().await;
            repo.close().await;
            migrated.expect("migrate schema template");
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                assert!(
                    !PathBuf::from(sidecar).exists(),
                    "schema template sidecar remains: {suffix}"
                );
            }
            // Only the closed, checkpointed database survives in process memory.
            // The guard removes the template directory before publishing it.
            std::fs::read(path).expect("read worker-test schema template")
        })
        .await
}

/// Own the database and any config/CSV files for the entire test. Even a test
/// assertion panic is resumed only after dropping its future, closing all pool
/// connections, and removing the directory (including SQLite sidecars).
pub(crate) async fn with_repo<T>(test: impl AsyncFnOnce(SqlRepository, PathBuf) -> T) -> T {
    let template = schema_template().await;
    let dir = TestDir::new();
    let path = dir.0.join("test.db");
    std::fs::write(&path, template).expect("write worker-test database template");
    let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
        .await
        .expect("connect worker-test database");
    let result = {
        let mut future = std::pin::pin!(test(repo.clone(), dir.0.clone()));
        poll_fn(
            |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
                Err(panic) => Poll::Ready(Err(panic)),
            },
        )
        .await
    };
    repo.close().await;
    drop(dir);
    result.unwrap_or_else(|panic| resume_unwind(panic))
}

#[tokio::test]
async fn database_scopes_are_isolated_and_remove_only_their_closed_files() {
    use qid_storage::RealmRepository;

    let (first, second) = with_repo(async |repo, first| {
        let first_db = first.join("test.db");
        assert!(first_db.exists());
        repo.create_realm(
            &"default".into(),
            &"isolated".into(),
            "https://id.example",
            None,
        )
        .await
        .unwrap();
        let second = with_repo(async |other, second| {
            assert_ne!(first_db, second.join("test.db"));
            assert!(
                other
                    .get_realm_issuer(&"isolated".into())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(first_db.exists(), "another scope must not remove a live DB");
            assert!(second.join("test.db").exists());
            // Retain a pool handle so the outer assertion can prove close was
            // awaited, rather than relying on unlink semantics (which vary by OS).
            (second, other)
        })
        .await;
        assert!(!second.0.exists());
        assert!(second.1.get_realm_issuer(&"isolated".into()).await.is_err());
        assert!(
            repo.get_realm_issuer(&"isolated".into())
                .await
                .unwrap()
                .is_some()
        );
        (first, second.0)
    })
    .await;
    assert!(!first.exists());
    assert!(!second.exists());
}

#[tokio::test]
async fn database_scope_closes_and_cleans_up_before_resuming_a_test_panic() {
    use qid_storage::RealmRepository;

    let (send, receive) = tokio::sync::oneshot::channel();
    let test = tokio::spawn(async move {
        with_repo(async move |repo, dir| {
            send.send((dir, repo)).unwrap();
            // Exercise an assertion after the test future has yielded as well.
            tokio::task::yield_now().await;
            panic!("injected test failure");
        })
        .await;
    });
    let (dir, repo) = receive.await.unwrap();
    assert!(test.await.unwrap_err().is_panic());
    assert!(!dir.exists());
    assert!(repo.get_realm_issuer(&"isolated".into()).await.is_err());
}
