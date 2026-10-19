use super::persistence_tests::{
    TestFile, assert_pending, complete, fail_next_flush, pause_next_write,
};
use super::*;
use crate::iga_grants::tests::{fixture, rejects_invalid_sets};

#[tokio::test]
async fn grant_batch_repairs_partial_revoked_set_and_survives_reopen() {
    let (file, repo) = TestFile::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    let mut incumbent = candidates[0].clone();
    incumbent.id = "historical-revoked".into();
    incumbent.revoked = true;
    incumbent.granted_at_epoch_seconds = 101;
    incumbent.expires_at_epoch_seconds = Some(102); // expired, too
    incumbent.approval_ids = vec!["historical-approval".into()];
    repo.store_iga_access_grant(&incumbent).await.unwrap();
    let bytes = serde_json::to_vec(&incumbent).unwrap();
    assert_eq!(
        repo.ensure_iga_access_grants(&candidates).await.unwrap(),
        vec![candidates[1].clone()]
    );
    assert!(
        repo.ensure_iga_access_grants(&candidates)
            .await
            .unwrap()
            .is_empty()
    );
    let stored = repo.list_iga_access_grants("tenant", None).await.unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        serde_json::to_vec(stored.iter().find(|g| g.id == incumbent.id).unwrap()).unwrap(),
        bytes
    );
    drop(repo);
    let repo = file.reopen().await;
    assert_eq!(
        repo.list_iga_access_grants("tenant", None).await.unwrap(),
        stored
    );
    assert!(
        repo.ensure_iga_access_grants(&candidates)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn grant_batch_rejects_invalid_sets_without_effects() {
    let (_file, repo) = TestFile::new().await;
    rejects_invalid_sets(&repo).await;
}

#[tokio::test]
async fn grant_batch_waits_for_save_lock_before_mutating() {
    let (_file, repo) = TestFile::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    let guard = repo.save_lock.lock().await;
    let mut batch = Box::pin(repo.ensure_iga_access_grants(&candidates));
    assert_pending(batch.as_mut()).await;
    assert!(repo.store.read().await.iga_access_grants.is_empty());
    drop(guard);
    assert_eq!(complete(batch).await.unwrap(), candidates);
}

#[tokio::test]
async fn grant_batch_immediate_failure_returns_error_and_restores_prior_store() {
    let (file, repo) = TestFile::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    repo.store_iga_access_grant(&candidates[0]).await.unwrap();
    let before = serde_json::to_value(&*repo.store.read().await).unwrap();
    let disk_before = tokio::fs::read(&file.0).await.unwrap();
    let (reached, resume) = fail_next_flush(&repo);
    let mut batch = Box::pin(repo.ensure_iga_access_grants(&candidates));
    assert_pending(batch.as_mut()).await;
    complete(reached).await.unwrap();
    resume.send(()).unwrap();
    assert!(complete(batch).await.is_err());
    assert_eq!(
        serde_json::to_value(&*repo.store.read().await).unwrap(),
        before
    );
    assert_eq!(tokio::fs::read(&file.0).await.unwrap(), disk_before);
    assert_eq!(
        repo.ensure_iga_access_grants(&candidates).await.unwrap(),
        vec![candidates[1].clone()]
    );
}

#[tokio::test]
async fn grant_batch_cancelled_immediate_write_finishes_persist_or_exact_rollback() {
    for fail in [false, true] {
        let (file, repo) = TestFile::new().await;
        let (request, candidates) = fixture();
        repo.store_iga_access_request(&request).await.unwrap();
        let before = serde_json::to_value(&*repo.store.read().await).unwrap();
        let disk_before = tokio::fs::read(&file.0).await.unwrap();
        let (reached, resume) = pause_next_write(&repo, fail);
        let mut batch = Box::pin(repo.ensure_iga_access_grants(&candidates));
        assert_pending(batch.as_mut()).await;
        complete(reached).await.unwrap();
        drop(batch);
        assert!(repo.store.try_read().is_err());
        assert!(repo.save_lock.try_lock().is_err());
        resume.send(()).unwrap();
        drop(complete(repo.save_lock.lock()).await);
        if fail {
            assert_eq!(
                serde_json::to_value(&*repo.store.read().await).unwrap(),
                before
            );
            assert_eq!(tokio::fs::read(&file.0).await.unwrap(), disk_before);
        } else {
            assert_eq!(repo.store.read().await.iga_access_grants.len(), 2);
        }
        let expected = serde_json::to_value(&*repo.store.read().await).unwrap();
        drop(repo);
        let repo = file.reopen().await;
        assert_eq!(
            serde_json::to_value(&*repo.store.read().await).unwrap(),
            expected
        );
        if fail {
            assert_eq!(
                repo.ensure_iga_access_grants(&candidates).await.unwrap(),
                candidates
            );
        }
    }
}

#[tokio::test]
async fn grant_batch_interval_updates_memory_once_without_waiting_for_save() {
    let (file, mut repo) = TestFile::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
    {
        let _guard = repo.save_lock.lock().await;
        assert_eq!(
            complete(repo.ensure_iga_access_grants(&candidates))
                .await
                .unwrap(),
            candidates
        );
        assert!(repo.dirty.load(Ordering::Acquire));
        assert_eq!(repo.store.read().await.iga_access_grants.len(), 2);
    }
    // Force the interval flush explicitly, without a timing-dependent sleep.
    repo.flush_store().await.unwrap();
    drop(repo);
    let repo = file.reopen().await;
    assert_eq!(
        repo.list_iga_access_grants("tenant", None)
            .await
            .unwrap()
            .len(),
        2
    );
}
