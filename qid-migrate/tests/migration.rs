use qid_storage::SqlRepository;
use tempfile::NamedTempFile;

fn sqlite_url() -> (String, NamedTempFile) {
    let file = NamedTempFile::new().unwrap();
    let url = format!("sqlite:{}", file.path().display());
    (url, file)
}

async fn fresh_repo() -> (SqlRepository, NamedTempFile) {
    let (url, file) = sqlite_url();
    let repo = SqlRepository::connect(&url).await.unwrap();
    (repo, file)
}

#[tokio::test]
async fn migration_plan_is_not_empty() {
    let (repo, _file) = fresh_repo().await;
    let plan = repo.migration_plan().await.unwrap();
    assert!(
        !plan.pending.is_empty(),
        "expected at least one pending migration"
    );
    assert!(plan.target_version.is_some(), "expected a target version");
}

#[tokio::test]
async fn migrations_apply_and_reduce_pending_count() {
    let (repo, _file) = fresh_repo().await;
    let plan_before = repo.migration_plan().await.unwrap();

    repo.migrate().await.unwrap();

    let plan_after = repo.migration_plan().await.unwrap();
    let before = plan_before.pending.len();
    let after = plan_after.pending.len();
    assert!(
        after < before,
        "expected fewer pending migrations after apply: before={before} after={after}"
    );
    assert!(
        plan_after.current_version >= plan_before.current_version,
        "current version should not regress"
    );
}

#[tokio::test]
async fn migration_is_idempotent() {
    let (repo, _file) = fresh_repo().await;

    repo.migrate().await.unwrap();
    repo.migrate().await.unwrap();

    let plan = repo.migration_plan().await.unwrap();
    assert!(
        plan.divergent.is_empty(),
        "no divergent migrations after idempotent apply"
    );
    assert!(
        plan.unknown_applied.is_empty(),
        "no unknown applied migrations"
    );
}

#[tokio::test]
async fn migration_rollback_not_supported() {
    // qid-migrate does not expose a rollback API.
    // sqlx supports revert but the crate does not expose it.
    let (repo, _file) = fresh_repo().await;
    repo.migrate().await.unwrap();
    let plan = repo.migration_plan().await.unwrap();
    assert!(plan.pending.is_empty() || plan.ready);
}
