use super::super::persistence_tests::{TestFile, assert_pending, complete, pause_next_write};
use super::*;
use crate::{HrSummary, HrUserChange};

fn batch() -> HrBatch {
    HrBatch {
        realm_id: "corp".into(),
        provider_id: "hr".into(),
        receipt: HrReceipt {
            sequence: 1,
            digest: "body-digest".into(),
            summary: HrSummary {
                created: 1,
                ..Default::default()
            },
        },
        changes: Some(vec![HrUserChange {
            expected: None,
            user: ScimUser {
                id: "created".into(),
                realm_id: "corp".into(),
                external_id: Some("external".into()),
                user_name: "created".into(),
                name_json: serde_json::json!({}),
                emails_json: serde_json::json!([]),
                enterprise_json: serde_json::json!({}),
                directory_provider_id: None,
                deprovisioned_at: None,
                active: true,
            },
        }]),
    }
}

#[tokio::test]
async fn failed_hr_persistence_never_publishes_candidate_and_identical_retry_works() {
    let (file, repo) = TestFile::new().await;
    repo.migrate().await.unwrap();
    let before = tokio::fs::read(&file.0).await.unwrap();
    let (reached, resume) = pause_next_write(&repo, true);
    let request = batch();
    let task = tokio::spawn({
        let repo = repo.clone();
        let request = request.clone();
        async move { repo.apply_hr_batch(&request).await }
    });
    complete(reached).await.unwrap();
    let mut reader = Box::pin(repo.get_scim_user("created"));
    assert_pending(reader.as_mut()).await;
    resume.send(()).unwrap();
    assert!(complete(task).await.unwrap().is_err());
    assert!(complete(reader).await.unwrap().is_none());
    assert!(repo.get_hr_receipt("corp", "hr").await.unwrap().is_none());
    assert_eq!(tokio::fs::read(&file.0).await.unwrap(), before);
    repo.apply_hr_batch(&request).await.unwrap();
    let after = tokio::fs::read(&file.0).await.unwrap();
    // A replay performs no store write (the failing write hook remains unused).
    let _unused = pause_next_write(&repo, true);
    assert!(repo.apply_hr_batch(&request).await.unwrap().replayed);
    assert_eq!(tokio::fs::read(&file.0).await.unwrap(), after);
    drop(repo);
    let reopened = file.reopen().await;
    assert!(reopened.get_scim_user("created").await.unwrap().is_some());
    assert_eq!(
        reopened
            .get_hr_receipt("corp", "hr")
            .await
            .unwrap()
            .unwrap(),
        request.receipt
    );
}

#[tokio::test]
async fn cancelled_hr_commit_finishes_and_interval_mode_still_persists_receipt() {
    let (file, mut repo) = TestFile::new().await;
    repo.migrate().await.unwrap();
    repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
    let (reached, resume) = pause_next_write(&repo, false);
    let request = batch();
    let task = tokio::spawn({
        let repo = repo.clone();
        let request = request.clone();
        async move { repo.apply_hr_batch(&request).await }
    });
    complete(reached).await.unwrap();
    task.abort();
    let _ = task.await;
    resume.send(()).unwrap();
    assert!(
        complete(repo.apply_hr_batch(&request))
            .await
            .unwrap()
            .replayed
    );
    drop(repo);
    let reopened = file.reopen().await;
    assert_eq!(
        reopened
            .get_hr_receipt("corp", "hr")
            .await
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert!(reopened.get_scim_user("created").await.unwrap().is_some());
}
