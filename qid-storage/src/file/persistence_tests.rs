use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use tokio::sync::oneshot;

// Consumed once at the configured persistence stage. No global failpoint or
// scheduling sleeps: each test controls exactly one pause and optional failure.
#[derive(Debug)]
pub(super) struct FlushHook {
    fail: bool,
    after_rename: bool,
    entered: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

impl FlushHook {
    pub(super) async fn run(self) -> QidResult<()> {
        self.entered.send(()).unwrap();
        self.resume.await.unwrap();
        if self.fail {
            Err(QidError::Internal {
                message: "injected persistence failure".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

pub(super) fn fail_next_flush(
    repo: &FileRepository,
) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, reached) = oneshot::channel();
    let (resume, paused) = oneshot::channel();
    *repo.flush_hook.lock().unwrap() = Some(FlushHook {
        fail: true,
        after_rename: false,
        entered,
        resume: paused,
    });
    (reached, resume)
}

pub(super) fn pause_after_rename(
    repo: &FileRepository,
) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, reached) = oneshot::channel();
    let (resume, paused) = oneshot::channel();
    *repo.write_hook.lock().unwrap() = Some(FlushHook {
        fail: false,
        after_rename: true,
        entered,
        resume: paused,
    });
    (reached, resume)
}

impl FileRepository {
    pub(super) async fn run_write_hook(&self, after_rename: bool) -> QidResult<()> {
        let hook = self.write_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            if hook.after_rename == after_rename {
                hook.run().await?;
            } else {
                *self.write_hook.lock().unwrap() = Some(hook);
            }
        }
        Ok(())
    }
}

pub(super) fn pause_next_write(
    repo: &FileRepository,
    fail: bool,
) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, reached) = oneshot::channel();
    let (resume, paused) = oneshot::channel();
    *repo.write_hook.lock().unwrap() = Some(FlushHook {
        fail,
        after_rename: false,
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
pub(super) async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

pub(super) async fn complete<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("persistence operation deadlocked")
}

pub(super) struct TestFile(pub(super) PathBuf);

impl TestFile {
    pub(super) async fn new() -> (Self, FileRepository) {
        let dir = std::env::temp_dir().join(format!("qid_rotation_{}", ulid::Ulid::new()));
        let file = Self(dir.join("store.json"));
        let repo = FileRepository::new(file.0.to_str().unwrap()).await.unwrap();
        (file, repo)
    }

    pub(super) async fn reopen(&self) -> FileRepository {
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
        let first_save = repo.revoke_token_family("saved-first", "test");
        tokio::pin!(first_save);
        assert_pending(first_save.as_mut()).await;
        let rotation =
            repo.update_token_family_refresh_hash("rotating", "test", "old", "tentative", 300);
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

        let unrelated = repo.revoke_token_family("unrelated", "test");
        let revocation = repo.revoke_token_family("rotating", "test");
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
        let rotation =
            repo.update_token_family_refresh_hash("same", "test", "old", "tentative", 300);
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
        repo.update_token_family_refresh_hash("same", "test", "old", "stale", 400)
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
        complete(repo.update_token_family_refresh_hash(
            "interval",
            "test",
            "replacement",
            "new",
            300,
        ))
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

fn reset_credential(hash: &str) -> PasswordCredential {
    PasswordCredential {
        user_id: "user".into(),
        hash: hash.into(),
        algorithm: "argon2id".into(),
    }
}

async fn seed_reset(repo: &FileRepository) {
    repo.store_password_credential(&reset_credential("previous"))
        .await
        .unwrap();
    repo.store_password_reset_token(&PasswordResetToken {
        id: "reset".into(),
        realm_id: "test".into(),
        user_id: "user".into(),
        token_hash: "digest".into(),
        device_id: None,
        risk_json: serde_json::json!({}),
        expires_at_epoch_seconds: 200,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 100,
    })
    .await
    .unwrap();
}

async fn assert_reset(repo: &FileRepository, hash: &str, consumed_at: Option<u64>) {
    assert_eq!(
        repo.get_password_credential("user")
            .await
            .unwrap()
            .unwrap()
            .hash,
        hash
    );
    assert_eq!(
        repo.get_password_reset_token("reset")
            .await
            .unwrap()
            .unwrap()
            .consumed_at_epoch_seconds,
        consumed_at
    );
}

#[tokio::test]
async fn immediate_password_reset_waits_for_save_lock_and_rolls_back_flush_failure() {
    let (file, repo) = TestFile::new().await;
    seed_reset(&repo).await;
    {
        let guard = repo.save_lock.lock().await;
        let realm = "test".into();
        let credential = reset_credential("failed");
        let reset = repo.replace_password_with_reset_token(
            "reset",
            &realm,
            "digest",
            None,
            &credential,
            150,
        );
        tokio::pin!(reset);
        assert_pending(reset.as_mut()).await;
        // Mutation must not happen until save_lock is acquired.
        assert_reset(&repo, "previous", None).await;
        let (reached, resume) = fail_next_flush(&repo);
        drop(guard);
        assert_pending(reset.as_mut()).await;
        reached.await.unwrap();
        // No reader or writer can observe tentative fields before rollback.
        assert!(repo.store.try_read().is_err());
        assert!(repo.save_lock.try_lock().is_err());
        resume.send(()).unwrap();
        assert!(complete(reset).await.is_err());
    }
    assert_reset(&repo, "previous", None).await;
    drop(repo);
    let repo = file.reopen().await;
    assert_reset(&repo, "previous", None).await;
    repo.replace_password_with_reset_token(
        "reset",
        &"test".into(),
        "digest",
        None,
        &reset_credential("retry"),
        150,
    )
    .await
    .unwrap();
    assert_reset(&repo, "retry", Some(150)).await;
}

#[tokio::test]
async fn interval_password_reset_marks_both_changes_dirty_and_retries_flush() {
    let (file, mut repo) = TestFile::new().await;
    seed_reset(&repo).await;
    repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
    {
        let _guard = repo.save_lock.lock().await;
        complete(repo.replace_password_with_reset_token(
            "reset",
            &"test".into(),
            "digest",
            None,
            &reset_credential("new"),
            150,
        ))
        .await
        .unwrap();
    }
    assert!(repo.dirty.load(Ordering::Acquire));
    assert_reset(&repo, "new", Some(150)).await;
    let (reached, resume) = fail_next_flush(&repo);
    {
        let flush = repo.flush();
        tokio::pin!(flush);
        assert_pending(flush.as_mut()).await;
        reached.await.unwrap();
        resume.send(()).unwrap();
        assert!(complete(flush).await.is_err());
    }
    assert!(repo.dirty.load(Ordering::Acquire));
    assert_reset(&repo, "new", Some(150)).await;
    repo.flush().await.unwrap();
    assert!(!repo.dirty.load(Ordering::Acquire));
    drop(repo);
    let repo = file.reopen().await;
    assert_reset(&repo, "new", Some(150)).await;
}

#[tokio::test]
async fn cancelled_immediate_password_reset_finishes_persistence_or_rollback() {
    for fail in [false, true] {
        let (file, repo) = TestFile::new().await;
        seed_reset(&repo).await;
        let (entered, reached) = oneshot::channel();
        let (resume, paused) = oneshot::channel();
        *repo.write_hook.lock().unwrap() = Some(FlushHook {
            fail,
            after_rename: false,
            entered,
            resume: paused,
        });
        let realm = "test".into();
        let credential = reset_credential("new");
        let mut reset = Box::pin(repo.replace_password_with_reset_token(
            "reset",
            &realm,
            "digest",
            None,
            &credential,
            150,
        ));
        assert_pending(reset.as_mut()).await;
        complete(reached).await.unwrap();
        // The temp file has been written, but the live store is still isolated
        // and the atomic rename has not happened. Cancel only the caller.
        let tentative: Store =
            serde_json::from_slice(&tokio::fs::read(file.0.with_extension("tmp")).await.unwrap())
                .unwrap();
        assert_eq!(tentative.credentials_password["user"].hash, "new");
        assert_eq!(
            tentative.password_reset_tokens["reset"].consumed_at_epoch_seconds,
            Some(150)
        );
        drop(reset);
        assert!(repo.store.try_read().is_err());
        assert!(repo.save_lock.try_lock().is_err());
        resume.send(()).unwrap();
        // Acquiring save_lock waits for the independent task's commit/rollback.
        drop(complete(repo.save_lock.lock()).await);
        let (hash, consumed_at) = if fail {
            ("previous", None)
        } else {
            ("new", Some(150))
        };
        assert_reset(&repo, hash, consumed_at).await;
        drop(repo);
        let repo = file.reopen().await;
        assert_reset(&repo, hash, consumed_at).await;
        if fail {
            // Failure after cancellation must leave the token available to retry.
            repo.replace_password_with_reset_token(
                "reset",
                &realm,
                "digest",
                None,
                &credential,
                150,
            )
            .await
            .unwrap();
        }
        // A committed reset, including a successful retry, is still one-use.
        assert!(
            repo.replace_password_with_reset_token(
                "reset",
                &realm,
                "digest",
                None,
                &reset_credential("replay"),
                151,
            )
            .await
            .is_err()
        );
        assert_reset(&repo, "new", Some(150)).await;
        drop(repo);
        let reopened = file.reopen().await;
        assert_reset(&reopened, "new", Some(150)).await;
    }
}

#[tokio::test]
async fn cancelled_magic_link_operations_finish_persistence_or_rollback() {
    for fail in [false, true] {
        for operation in ["issue", "bad-candidate", "redeem"] {
            let (file, mut repo) = TestFile::new().await;
            repo.create_user(&User {
                id: "user".into(),
                realm_id: "test".into(),
                email: Some("user@example.com".into()),
                email_verified: true,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
            // These operations must bypass interval flushing as well.
            repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
            let challenge = CiamVerificationChallengeRecord {
                id: "magic".into(),
                realm_id: "test".into(),
                user_id: "user".into(),
                channel: "email".into(),
                address: "user@example.com".into(),
                purpose: "email_magic_link".into(),
                code_hash: format!("ml2:{}:{}", "a".repeat(64), "b".repeat(64)),
                attempt_count: 0,
                expires_at_epoch_seconds: 200,
                consumed_at_epoch_seconds: None,
                created_at_epoch_seconds: 100,
            };
            if operation != "issue" {
                repo.try_issue_email_challenge(&challenge, 1, 10)
                    .await
                    .unwrap();
            }
            let before = tokio::fs::read(&file.0).await.unwrap();
            let (reached, resume) = pause_next_write(&repo, fail);
            let mut request = Box::pin(async {
                if operation == "issue" {
                    repo.try_issue_email_challenge(&challenge, 1, 10)
                        .await
                        .map(|_| ())
                } else {
                    let candidate = if operation == "redeem" {
                        challenge.code_hash.clone()
                    } else {
                        format!("ml2:{}:{}", "a".repeat(64), "c".repeat(64))
                    };
                    repo.redeem_email_magic_link_challenge(
                        &"test".into(),
                        "magic",
                        &candidate,
                        150,
                        2,
                    )
                    .await
                    .map(|_| ())
                }
            });
            assert_pending(request.as_mut()).await;
            complete(reached).await.unwrap();
            // Cancellation happens after temp-file write but before rename.
            drop(request);
            assert!(repo.store.try_read().is_err());
            assert!(repo.save_lock.try_lock().is_err());
            resume.send(()).unwrap();
            drop(complete(repo.save_lock.lock()).await);
            let expected = if operation == "issue" && fail {
                None
            } else {
                let mut c = challenge.clone();
                if operation != "issue" && !fail {
                    c.attempt_count = 1;
                    if operation == "redeem" {
                        c.consumed_at_epoch_seconds = Some(150);
                    }
                }
                Some(c)
            };
            assert_eq!(
                repo.get_ciam_verification_challenge(&"test".into(), "magic")
                    .await
                    .unwrap(),
                expected
            );
            let after = tokio::fs::read(&file.0).await.unwrap();
            if fail {
                assert_eq!(after, before);
            }
            let disk: Store = serde_json::from_slice(&after).unwrap();
            assert_eq!(
                disk.ciam_verification_challenges.get("magic"),
                expected.as_ref()
            );
            drop(repo);
            let reopened = file.reopen().await;
            assert_eq!(
                reopened
                    .get_ciam_verification_challenge(&"test".into(), "magic")
                    .await
                    .unwrap(),
                expected
            );
        }
    }
}

fn retention_config(realm_id: Option<&str>, days: u64) -> AuditRetentionConfig {
    AuditRetentionConfig {
        realm_id: realm_id.map(str::to_owned),
        retention_days: days,
        legal_hold: days == 90,
        updated_by: "legacy-admin".into(),
        reason: "preserve legacy values".into(),
        updated_at: 123,
    }
}

#[tokio::test]
async fn file_audit_retention_legacy_keys_rekey_on_open() {
    // Legacy stores can contain either the global or sentinel-named realm row,
    // not both. Its realm_id, rather than its ambiguous key, determines identity.
    for sentinel_realm in [None, Some("__global__")] {
        let (file, empty_repo) = TestFile::new().await;
        drop(empty_repo);
        let mut store = Store::default();
        let configs = [
            ("__global__", retention_config(sentinel_realm, 90)),
            ("global", retention_config(Some("global"), 30)),
            ("realm-a", retention_config(Some("realm-a"), 60)),
        ];
        store.audit_retention_configs = configs
            .iter()
            .map(|(key, config)| (key.to_string(), config.clone()))
            .collect();
        tokio::fs::write(&file.0, serde_json::to_vec(&store).unwrap())
            .await
            .unwrap();

        let repo = file.reopen().await;
        for (_, expected) in &configs {
            let realm = expected.realm_id.as_deref().map(RealmId::from);
            assert_eq!(
                repo.get_audit_retention_config(realm.as_ref())
                    .await
                    .unwrap(),
                Some(expected.clone())
            );
        }
        let persisted = tokio::fs::read(&file.0).await.unwrap();
        let migrated: Store = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(migrated.audit_retention_configs.len(), configs.len());
        for (_, config) in &configs {
            let key = crate::domain::audit_retention_stream_id(config.realm_id.as_deref());
            assert_eq!(migrated.audit_retention_configs.get(&key), Some(config));
        }
        drop(repo);
        let reopened = file.reopen().await;
        assert_eq!(
            tokio::fs::read(&file.0).await.unwrap(),
            persisted,
            "reopening migrated keys must be a no-op"
        );
        drop(reopened);
    }
}

#[tokio::test]
async fn file_audit_retention_duplicate_streams_fail_without_rewriting() {
    let (file, empty_repo) = TestFile::new().await;
    drop(empty_repo);
    let mut store = Store::default();
    store
        .audit_retention_configs
        .insert("__global__".into(), retention_config(None, 90));
    store
        .audit_retention_configs
        .insert("global".into(), retention_config(None, 30));
    let original = serde_json::to_vec(&store).unwrap();
    tokio::fs::write(&file.0, &original).await.unwrap();
    let error = FileRepository::new(file.0.to_str().unwrap())
        .await
        .unwrap_err();
    assert!(
        error
            .message()
            .contains("duplicate audit retention streams")
    );
    assert_eq!(tokio::fs::read(&file.0).await.unwrap(), original);
    assert_eq!(store.audit_retention_configs.len(), 2);
    assert!(store.rekey_audit_retention_configs().is_err());
    assert_eq!(
        serde_json::to_vec(&store).unwrap(),
        original,
        "failed rekey must also leave in-memory records intact"
    );
}
