use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use tokio::sync::oneshot;

// Consumed once, before snapshot/write. No global failpoint or scheduling
// sleeps: each test controls exactly one flush failure.
#[derive(Debug)]
pub(super) struct FlushHook {
    entered: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

impl FlushHook {
    pub(super) async fn run(self) -> QidResult<()> {
        self.entered.send(()).unwrap();
        self.resume.await.unwrap();
        Err(QidError::Internal {
            message: "injected persistence failure".to_string(),
        })
    }
}

fn fail_next_flush(repo: &FileRepository) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, reached) = oneshot::channel();
    let (resume, paused) = oneshot::channel();
    *repo.flush_hook.lock().unwrap() = Some(FlushHook {
        entered,
        resume: paused,
    });
    (reached, resume)
}

// Separate from the flush failure so an unrelated save can complete before the
// rotation reaches persistence, even if rotation mutates before owning save_lock.
#[derive(Debug)]
pub(super) struct RotationHook {
    entered: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

impl RotationHook {
    pub(super) async fn run(self) {
        self.entered.send(()).unwrap();
        self.resume.await.unwrap();
    }
}

fn pause_next_rotation(repo: &FileRepository) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, reached) = oneshot::channel();
    let (resume, paused) = oneshot::channel();
    *repo.rotation_hook.lock().unwrap() = Some(RotationHook {
        entered,
        resume: paused,
    });
    (reached, resume)
}

// Poll exactly once to reach a hook or queue behind a held lock.
// Unlike spawning/yielding, this does not depend on task scheduling.
async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn complete<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("persistence operation deadlocked")
}

struct TestFile(PathBuf);

impl TestFile {
    async fn new() -> (Self, FileRepository) {
        let dir = std::env::temp_dir().join(format!("qid_rotation_{}", ulid::Ulid::new()));
        let file = Self(dir.join("store.json"));
        let repo = FileRepository::new(file.0.to_str().unwrap()).await.unwrap();
        (file, repo)
    }

    async fn reopen(&self) -> FileRepository {
        FileRepository::new(self.0.to_str().unwrap()).await.unwrap()
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn family(id: &str, hash: &str, deadline: Option<u64>) -> TokenFamily {
    TokenFamily {
        id: id.to_string(),
        user_id: "user".to_string(),
        client_id: "client".to_string(),
        realm_id: "test".to_string(),
        current_refresh_hash: hash.to_string(),
        scopes: Vec::new(),
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        audience: Vec::new(),
        resource: Vec::new(),
        authorization_details: None,
        sender_constraint: None,
        issued_at: 100,
        refresh_expires_at: deadline,
        session_id: None,
        revoked: false,
    }
}

async fn assert_family(repo: &FileRepository, id: &str, hash: &str, deadline: Option<u64>) {
    let family = repo.get_token_family(id).await.unwrap().unwrap();
    assert_eq!(family.current_refresh_hash, hash);
    assert_eq!(family.refresh_expires_at, deadline);
}

#[tokio::test]
async fn file_ciam_progressive_profile_legacy_keys_rekey_on_open() {
    let (file, empty_repo) = TestFile::new().await;
    drop(empty_repo);
    let mut store = Store::default();
    for (key, realm, user) in [
        ("team_blue:person", "team_blue", "person"),
        ("team:blue_person", "team", "blue_person"),
    ] {
        store.ciam_profiles.insert(
            key.to_string(),
            CiamProgressiveProfile {
                id: "legacy-collision-id".to_string(),
                realm_id: realm.to_string(),
                user_id: user.to_string(),
                profile_json: serde_json::json!({"owner": user}),
                passwordless_migrated_at: None,
                created_at: 100,
                updated_at: 100,
            },
        );
    }
    tokio::fs::write(&file.0, serde_json::to_vec(&store).unwrap())
        .await
        .unwrap();

    let repo = FileRepository::new(file.0.to_str().unwrap()).await.unwrap();
    let mut first = repo
        .get_ciam_progressive_profile(&"team_blue".into(), "person")
        .await
        .unwrap()
        .unwrap();
    let second = repo
        .get_ciam_progressive_profile(&"team".into(), "blue_person")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.id, "legacy-collision-id");
    assert_eq!(second.id, "legacy-collision-id");
    first.profile_json = serde_json::json!({"owner": "updated"});
    first.updated_at = 200;
    repo.store_ciam_progressive_profile(&first).await.unwrap();
    assert_eq!(
        repo.get_ciam_progressive_profile(&"team".into(), "blue_person")
            .await
            .unwrap(),
        Some(second.clone())
    );

    let persisted: Store =
        serde_json::from_slice(&tokio::fs::read(&file.0).await.unwrap()).unwrap();
    assert!(persisted.ciam_profiles.contains_key("9:team_blueperson"));
    assert!(persisted.ciam_profiles.contains_key("4:teamblue_person"));
    repo.delete_ciam_progressive_profile(&"team_blue".into(), "person")
        .await
        .unwrap();
    assert!(
        repo.get_ciam_progressive_profile(&"team_blue".into(), "person")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_ciam_progressive_profile(&"team".into(), "blue_person")
            .await
            .unwrap(),
        Some(second)
    );
}

#[tokio::test]
async fn failed_rotation_cannot_leak_into_another_save() {
    let (file, repo) = TestFile::new().await;
    repo.create_token_family(&family("rotating", "old", Some(200)))
        .await
        .unwrap();
    repo.create_token_family(&family("unrelated", "other", None))
        .await
        .unwrap();
    repo.create_token_family(&family("saved-first", "first", None))
        .await
        .unwrap();
    {
        let guard = repo.save_lock.lock().await;
        let (mutated, resume_rotation) = pause_next_rotation(&repo);
        // Tokio's mutex is FIFO: queue an unrelated writer's save first, then
        // poll rotation. Correct rotation waits before mutating; the old order
        // would already mutate and enter the rotation hook while guard is held.
        let first_save = repo.revoke_token_family("saved-first");
        tokio::pin!(first_save);
        assert_pending(first_save.as_mut()).await;
        let rotation = repo.update_token_family_refresh_hash("rotating", "old", "tentative", 300);
        tokio::pin!(rotation);
        assert_pending(rotation.as_mut()).await;
        drop(guard);
        complete(first_save).await.unwrap();
        assert_pending(rotation.as_mut()).await;
        mutated.await.unwrap();

        // Inspect the file, not live state: with mutation before save_lock the
        // unrelated save above would have persisted the tentative refresh fields.
        let persisted: Store =
            serde_json::from_slice(&tokio::fs::read(&file.0).await.unwrap()).unwrap();
        let saved_family = &persisted.token_families["rotating"];
        assert_eq!(saved_family.current_refresh_hash, "old");
        assert_eq!(saved_family.refresh_expires_at, Some(200));
        assert!(persisted.token_families["saved-first"].revoked);

        // Arm failure only after the unrelated save has completed, so it cannot
        // consume the one-shot intended for rotation's persistence attempt.
        let (reached, resume) = fail_next_flush(&repo);
        resume_rotation.send(()).unwrap();
        assert_pending(rotation.as_mut()).await;
        reached.await.unwrap();
        assert!(repo.save_lock.try_lock().is_err());
        // Reads are not isolated from tentative state; only persistence is.
        assert_family(&repo, "rotating", "tentative", Some(300)).await;

        let unrelated = repo.revoke_token_family("unrelated");
        let revocation = repo.revoke_token_family("rotating");
        tokio::pin!(unrelated, revocation);
        assert_pending(unrelated.as_mut()).await;
        assert_pending(revocation.as_mut()).await;
        assert!(
            repo.get_token_family("unrelated")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert!(
            repo.get_token_family("rotating")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );

        // Force rollback itself to yield: ownership must extend past the failed
        // flush until it can reacquire store and restore just the two fields.
        let reader = repo.store.read().await;
        resume.send(()).unwrap();
        assert_pending(rotation.as_mut()).await;
        assert!(repo.save_lock.try_lock().is_err());
        drop(reader);
        let error = complete(rotation).await.unwrap_err();
        assert!(error.to_string().contains("injected persistence failure"));
        // Rollback happens before waiting saves can acquire the lock.
        assert_family(&repo, "rotating", "old", Some(200)).await;
        complete(unrelated).await.unwrap();
        complete(revocation).await.unwrap();
    }
    assert_family(&repo, "rotating", "old", Some(200)).await;
    for id in ["saved-first", "unrelated"] {
        assert!(repo.get_token_family(id).await.unwrap().unwrap().revoked);
    }
    assert!(
        repo.get_token_family("rotating")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    drop(repo);
    let reopened = file.reopen().await;
    assert_family(&reopened, "rotating", "old", Some(200)).await;
    assert!(
        reopened
            .get_token_family("saved-first")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        reopened
            .get_token_family("rotating")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        reopened
            .get_token_family("unrelated")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn same_id_replacement_waits_for_rotation_rollback() {
    let (file, repo) = TestFile::new().await;
    repo.create_token_family(&family("same", "old", None))
        .await
        .unwrap();
    let mut replacement = family("same", "replacement", Some(900));
    replacement.user_id = "replacement-user".to_string();
    {
        let (reached, resume) = fail_next_flush(&repo);
        let rotation = repo.update_token_family_refresh_hash("same", "old", "tentative", 300);
        tokio::pin!(rotation);
        assert_pending(rotation.as_mut()).await;
        reached.await.unwrap();
        let create = repo.create_token_family(&replacement);
        tokio::pin!(create);
        assert_pending(create.as_mut()).await;
        assert_family(&repo, "same", "tentative", Some(300)).await;
        resume.send(()).unwrap();
        assert!(complete(rotation).await.is_err());
        assert_family(&repo, "same", "old", None).await;
        complete(create).await.unwrap();
    }
    assert_family(&repo, "same", "replacement", Some(900)).await;
    // Rotation must validate against the replacement, not stale pre-lock state.
    assert!(
        repo.update_token_family_refresh_hash("same", "old", "stale", 400)
            .await
            .is_err()
    );
    drop(repo);
    let reopened = file.reopen().await;
    assert_family(&reopened, "same", "replacement", Some(900)).await;
    assert_eq!(
        reopened
            .get_token_family("same")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        "replacement-user"
    );
}

#[tokio::test]
async fn interval_rotation_marks_dirty_and_survives_flush_failure() {
    let (file, mut repo) = TestFile::new().await;
    repo.create_token_family(&family("interval", "old", None))
        .await
        .unwrap();
    // Exercise Interval save behavior with manually driven flushes, without
    // spawning a perpetual background flusher that would retain the process lock.
    repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
    let (reached, resume) = fail_next_flush(&repo);
    {
        // Neither interval create nor rotation should wait for save_lock.
        let _guard = repo.save_lock.lock().await;
        complete(repo.create_token_family(&family("interval", "replacement", Some(200))))
            .await
            .unwrap();
        complete(repo.update_token_family_refresh_hash("interval", "replacement", "new", 300))
            .await
            .unwrap();
    }
    assert!(repo.dirty.load(Ordering::Acquire));
    assert_family(&repo, "interval", "new", Some(300)).await;
    {
        let flush = repo.flush();
        tokio::pin!(flush);
        assert_pending(flush.as_mut()).await;
        reached.await.unwrap();
        resume.send(()).unwrap();
        assert!(complete(flush).await.is_err());
    }
    assert!(repo.dirty.load(Ordering::Acquire));
    assert_family(&repo, "interval", "new", Some(300)).await;
    complete(repo.flush()).await.unwrap();
    assert!(!repo.dirty.load(Ordering::Acquire));
    drop(repo);
    let reopened = file.reopen().await;
    assert_family(&reopened, "interval", "new", Some(300)).await;
}
