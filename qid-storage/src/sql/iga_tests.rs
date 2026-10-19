use super::*;
use crate::iga_grants::tests::{fixture, rejects_invalid_sets};

struct Database(std::path::PathBuf);
impl Database {
    async fn new() -> (Self, SqlRepository, String) {
        let dir = std::env::temp_dir().join(format!("qid-grants-{}", ulid::Ulid::new()));
        std::fs::create_dir(&dir).unwrap();
        let url = format!("sqlite:{}", dir.join("grants.db").display());
        let repo = SqlRepository::connect(&url).await.unwrap();
        repo.migrate().await.unwrap();
        (Self(dir), repo, url)
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn grant_batch_rolls_back_second_insert_then_retries_and_replays() {
    let (_db, repo, _) = Database::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_second_grant BEFORE INSERT ON iga_access_grants WHEN NEW.entitlement = 'member-b' BEGIN SELECT RAISE(ABORT, 'injected second member failure'); END")
        .execute(&repo.pool).await.unwrap();
    let error = repo
        .ensure_iga_access_grants(&candidates)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("injected second member failure"),
        "{error}"
    );
    assert!(
        repo.list_iga_access_grants("tenant", None)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("DROP TRIGGER fail_second_grant")
        .execute(&repo.pool)
        .await
        .unwrap();
    assert_eq!(
        repo.ensure_iga_access_grants(&candidates).await.unwrap(),
        candidates
    );
    let mut replay = candidates.clone();
    for grant in &mut replay {
        grant.id.push_str("-retry");
    }
    assert!(
        repo.ensure_iga_access_grants(&replay)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.list_iga_access_grants("tenant", None)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn grant_batch_rejects_invalid_sets_without_effects() {
    let (_db, repo, _) = Database::new().await;
    rejects_invalid_sets(&repo).await;
}

#[tokio::test]
async fn grant_batch_serializes_independent_sqlite_repositories() {
    let (_db, repo, url) = Database::new().await;
    let second = SqlRepository::connect(&url).await.unwrap();
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    let mut replay = candidates.clone();
    for grant in &mut replay {
        grant.id.push_str("-concurrent");
    }
    let (a, b) = tokio::join!(
        repo.ensure_iga_access_grants(&candidates),
        second.ensure_iga_access_grants(&replay)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!((a.len() == 2 && b.is_empty()) || (a.is_empty() && b.len() == 2));
    assert_eq!(
        repo.list_iga_access_grants("tenant", None)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn grant_batch_preserves_revoked_incumbent_and_rejects_malformed_evidence() {
    let (_db, repo, _) = Database::new().await;
    let (request, candidates) = fixture();
    repo.store_iga_access_request(&request).await.unwrap();
    let mut incumbent = candidates[0].clone();
    incumbent.id = "revoked-old-id".into();
    incumbent.revoked = true;
    incumbent.expires_at_epoch_seconds = Some(201);
    incumbent.approval_ids = vec!["old-approval".into()];
    repo.store_iga_access_grant(&incumbent).await.unwrap();
    sqlx::query("UPDATE iga_access_grants SET approval_ids_json = 'not-json' WHERE id = ?")
        .bind(&incumbent.id)
        .execute(&repo.pool)
        .await
        .unwrap();
    assert!(repo.ensure_iga_access_grants(&candidates).await.is_err());
    assert_eq!(
        repo.list_iga_access_grants("tenant", None)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::query("UPDATE iga_access_grants SET approval_ids_json = ? WHERE id = ?")
        .bind(serde_json::to_string(&incumbent.approval_ids).unwrap())
        .bind(&incumbent.id)
        .execute(&repo.pool)
        .await
        .unwrap();
    assert_eq!(
        repo.ensure_iga_access_grants(&candidates).await.unwrap(),
        vec![candidates[1].clone()]
    );
    let stored = repo.list_iga_access_grants("tenant", None).await.unwrap();
    assert_eq!(
        stored.iter().find(|grant| grant.id == incumbent.id),
        Some(&incumbent)
    );
}
