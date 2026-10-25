use self::test_support::IsolatedDb;
use super::*;

#[path = "test_support.rs"]
pub(in crate::sql) mod test_support;
use crate::iga_grants::tests::{fixture, rejects_invalid_sets};

#[tokio::test]
async fn grant_batch_rolls_back_second_insert_then_retries_and_replays() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
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
    db.cleanup().await;
}

#[tokio::test]
async fn grant_batch_rejects_invalid_sets_without_effects() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
    rejects_invalid_sets(repo).await;
    db.cleanup().await;
}

#[tokio::test]
async fn grant_batch_serializes_independent_sqlite_repositories() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
    let url = db.url().to_string();
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
    second.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn grant_batch_preserves_revoked_incumbent_and_rejects_malformed_evidence() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
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
    db.cleanup().await;
}

#[tokio::test]
async fn sql_iga_entitlement_store_upserts_tenant_scoped_row() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
    let initial = IgaEntitlementRecord {
        id: "ent-1".into(),
        tenant_id: "tenant-a".into(),
        display_name: "Payroll read".into(),
        owner: "owner-1".into(),
        risk_level: "low".into(),
        conflicting_entitlements: vec!["other".into()],
        max_duration_seconds: Some(3600),
        active: true,
    };
    repo.store_iga_entitlement(&initial).await.unwrap();
    let other_tenant = IgaEntitlementRecord {
        id: "ent-1".into(),
        tenant_id: "tenant-b".into(),
        display_name: "Other tenant".into(),
        owner: "other-owner".into(),
        risk_level: "low".into(),
        conflicting_entitlements: vec![],
        max_duration_seconds: None,
        active: true,
    };
    repo.store_iga_entitlement(&other_tenant).await.unwrap();
    let updated = IgaEntitlementRecord {
        id: "ent-1".into(),
        tenant_id: "tenant-a".into(),
        display_name: "Payroll read v2".into(),
        owner: "owner-2".into(),
        risk_level: "high".into(),
        conflicting_entitlements: vec!["x".into(), "y".into()],
        max_duration_seconds: Some(7200),
        active: false,
    };
    repo.store_iga_entitlement(&updated).await.unwrap();
    assert_eq!(
        repo.list_iga_entitlements("tenant-a").await.unwrap(),
        vec![updated]
    );
    assert_eq!(
        repo.list_iga_entitlements("tenant-b").await.unwrap(),
        vec![other_tenant]
    );
    db.cleanup().await;
}

#[tokio::test]
async fn sql_iga_access_package_store_upserts_tenant_scoped_row() {
    let db = IsolatedDb::setup().await;
    let repo = db.repo();
    let initial = IgaAccessPackageRecord {
        id: "pkg-1".into(),
        tenant_id: "tenant-a".into(),
        display_name: "Base package".into(),
        owner: "owner-1".into(),
        entitlement_ids: vec!["ent-1".into()],
        approval_policy_json: serde_json::json!({"steps": [{"approver": "manager"}]}),
        max_duration_seconds: Some(7200),
        active: true,
    };
    repo.store_iga_access_package(&initial).await.unwrap();
    let other_tenant = IgaAccessPackageRecord {
        id: "pkg-1".into(),
        tenant_id: "tenant-b".into(),
        display_name: "Other tenant".into(),
        owner: "other-owner".into(),
        entitlement_ids: vec!["ent-9".into()],
        approval_policy_json: serde_json::json!({"steps": [{"approver": "other"}]}),
        max_duration_seconds: None,
        active: true,
    };
    repo.store_iga_access_package(&other_tenant).await.unwrap();
    let updated = IgaAccessPackageRecord {
        id: "pkg-1".into(),
        tenant_id: "tenant-a".into(),
        display_name: "Base package v2".into(),
        owner: "owner-2".into(),
        entitlement_ids: vec!["ent-1".into(), "ent-2".into()],
        approval_policy_json: serde_json::json!({"steps": [{"approver": "owner"}]}),
        max_duration_seconds: None,
        active: false,
    };
    repo.store_iga_access_package(&updated).await.unwrap();
    assert_eq!(
        repo.list_iga_access_packages("tenant-a").await.unwrap(),
        vec![updated]
    );
    assert_eq!(
        repo.list_iga_access_packages("tenant-b").await.unwrap(),
        vec![other_tenant]
    );
    db.cleanup().await;
}
