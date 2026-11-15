#![cfg(test)]

//! Expiry reclamation is a create-only storage contract, independent of wall time.
use qid_core::{
    QidError,
    models::{Admin, AdminElevation},
};
use qid_storage::{AdminRepository, FileRepository, SqlRepository};

fn elevation(id: &str, created_at: u64, expiry: u64) -> AdminElevation {
    AdminElevation {
        id: id.into(),
        tenant_id: "tenant".into(),
        admin_id: "admin".into(),
        source_session_id: Some("session".into()),
        acr: Some("phr".into()),
        amr: vec!["webauthn".into()],
        elevation_expires_at: expiry,
        created_at,
    }
}

async fn assert_records(repo: &impl AdminRepository, records: &[AdminElevation], cutoff: u64) {
    for expected in records {
        let actual = repo
            .get_admin_elevation(&expected.id)
            .await
            .expect("read elevation");
        if expected.elevation_expires_at <= cutoff {
            assert!(actual.is_none(), "expired row {} at {cutoff}", expected.id);
        } else {
            assert_eq!(
                serde_json::to_value(actual.expect("active elevation retained"))
                    .expect("serialize actual"),
                serde_json::to_value(expected).expect("serialize expected"),
                "active row {} at {cutoff}",
                expected.id
            );
        }
    }
}

async fn retention_contract(repo: &impl AdminRepository) -> Vec<AdminElevation> {
    for (id, tenant) in [("admin", "tenant"), ("other-admin", "other-tenant")] {
        repo.upsert_admin(&Admin {
            id: id.into(),
            tenant_id: tenant.into(),
            subject: id.into(),
            roles: vec!["admin".into()],
            created_at: 1,
        })
        .await
        .expect("seed admin");
    }
    let high = 1_u64 << 63;
    let mut records = Vec::new();
    for expiry in [
        99,
        100,
        101,
        high - 1,
        high,
        high + 199,
        high + 200,
        u64::MAX,
    ] {
        let mut record = elevation(&format!("expiry-{expiry}"), 1, expiry);
        // Cleanup spans tenants, but must not change any active row's binding.
        if expiry % 2 == 0 {
            record.tenant_id = "other-tenant".into();
            record.admin_id = "other-admin".into();
        }
        repo.store_admin_elevation(&record)
            .await
            .expect("seed elevation");
        records.push(record);
    }

    // An expired incumbent is still a create-only conflict, even across owners.
    let mut duplicate = records[0].clone();
    duplicate.created_at = 99;
    duplicate.elevation_expires_at = u64::MAX;
    duplicate.tenant_id = "other-tenant".into();
    duplicate.admin_id = "other-admin".into();
    assert!(matches!(
        repo.store_admin_elevation(&duplicate).await,
        Err(QidError::Conflict { .. })
    ));
    assert_records(repo, &records, 98).await;

    for cutoff in [
        98,
        99,
        100,
        101,
        high - 1,
        high,
        high + 199,
        high + 200,
        u64::MAX - 1,
    ] {
        let incoming = elevation(&format!("write-{cutoff}"), cutoff, cutoff + 1);
        repo.store_admin_elevation(&incoming)
            .await
            .expect("store next elevation");
        records.push(incoming);
        assert_records(repo, &records, cutoff).await;
    }
    records
}

#[tokio::test]
async fn file_writes_reclaim_expired_elevations_durably() {
    let dir = tempfile::tempdir().expect("isolated directory");
    let path = dir.path().join("store.json");
    let repo = FileRepository::new(path.to_str().expect("UTF-8 path"))
        .await
        .expect("open file repository");
    repo.migrate().await.expect("migrate repository");
    let records = retention_contract(&repo).await;
    drop(repo);
    let reopened = FileRepository::new(path.to_str().expect("UTF-8 path"))
        .await
        .expect("open file repository");
    assert_records(&reopened, &records, u64::MAX - 1).await;
}

#[tokio::test]
async fn sqlite_writes_reclaim_expired_elevations_durably_in_unsigned_order() {
    let dir = tempfile::tempdir().expect("isolated directory");
    let url = format!("sqlite:{}", dir.path().join("store.db").display());
    let repo = SqlRepository::connect(&url)
        .await
        .expect("connect SQLite repository");
    repo.migrate().await.expect("migrate repository");
    let records = retention_contract(&repo).await;
    repo.close().await;
    let reopened = SqlRepository::connect(&url)
        .await
        .expect("connect SQLite repository");
    assert_records(&reopened, &records, u64::MAX - 1).await;
    reopened.close().await;
}
