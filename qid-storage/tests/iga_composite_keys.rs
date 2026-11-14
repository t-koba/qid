#![cfg(test)]

use qid_core::{
    error::QidError,
    models::{IgaAccessPackageRecord, IgaEntitlementRecord},
};
use qid_storage::{FileRepository, IgaRepository, SqlRepository};
use std::path::PathBuf;

struct TestFile(PathBuf);

impl TestFile {
    fn new() -> Self {
        Self(
            std::env::temp_dir()
                .join(format!("qid_iga_keys_{}", ulid::Ulid::new()))
                .join("store.json"),
        )
    }

    async fn open(&self) -> FileRepository {
        FileRepository::new(self.0.to_str().unwrap()).await.unwrap()
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn entitlement(tenant_id: &str, id: &str) -> IgaEntitlementRecord {
    IgaEntitlementRecord {
        tenant_id: tenant_id.into(),
        id: id.into(),
        display_name: "Entitlement".into(),
        owner: "owner".into(),
        risk_level: "low".into(),
        conflicting_entitlements: vec![],
        max_duration_seconds: Some(60),
        active: true,
    }
}

fn package(tenant_id: &str, id: &str) -> IgaAccessPackageRecord {
    IgaAccessPackageRecord {
        tenant_id: tenant_id.into(),
        id: id.into(),
        display_name: "Package".into(),
        owner: "owner".into(),
        entitlement_ids: vec!["entitlement".into()],
        approval_policy_json: serde_json::json!({}),
        max_duration_seconds: Some(60),
        active: true,
    }
}

async fn assert_pairs(repo: &impl IgaRepository, first_name: Option<&str>) {
    for (tenant, id) in [("tenant:a", "pkg"), ("tenant", "a:pkg")] {
        let mut expected_entitlement = entitlement(tenant, id);
        let mut expected_package = package(tenant, id);
        if let Some(name) = first_name.filter(|_| tenant == "tenant:a") {
            expected_entitlement.display_name = name.into();
            expected_package.display_name = name.into();
        }
        assert_eq!(
            repo.list_iga_entitlements(tenant).await.unwrap(),
            vec![expected_entitlement]
        );
        assert_eq!(
            repo.list_iga_access_packages(tenant).await.unwrap(),
            vec![expected_package]
        );
    }
}

async fn seed_pairs(repo: &impl IgaRepository) {
    for (tenant, id) in [("tenant:a", "pkg"), ("tenant", "a:pkg")] {
        repo.store_iga_entitlement(&entitlement(tenant, id))
            .await
            .unwrap();
        repo.store_iga_access_package(&package(tenant, id))
            .await
            .unwrap();
    }
}

async fn assert_update_and_delete(repo: &impl IgaRepository) {
    // Both writes survive even though their old delimiter-joined keys coincide.
    assert_pairs(repo, None).await;
    let mut first_entitlement = entitlement("tenant:a", "pkg");
    let mut first_package = package("tenant:a", "pkg");
    first_entitlement.display_name = "Updated".into();
    first_package.display_name = "Updated".into();
    repo.store_iga_entitlement(&first_entitlement)
        .await
        .unwrap();
    repo.store_iga_access_package(&first_package).await.unwrap();
    assert_pairs(repo, Some("Updated")).await;

    repo.delete_iga_entitlement("tenant:a", "pkg")
        .await
        .unwrap();
    repo.delete_iga_access_package("tenant:a", "pkg")
        .await
        .unwrap();
    assert!(
        repo.list_iga_entitlements("tenant:a")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.list_iga_access_packages("tenant:a")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.list_iga_entitlements("tenant").await.unwrap(),
        vec![entitlement("tenant", "a:pkg")]
    );
    assert_eq!(
        repo.list_iga_access_packages("tenant").await.unwrap(),
        vec![package("tenant", "a:pkg")]
    );
}

#[tokio::test]
async fn iga_composite_keys_sqlite() {
    let file = TestFile::new();
    std::fs::create_dir_all(file.0.parent().unwrap()).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", file.0.display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    seed_pairs(&repo).await;
    assert_update_and_delete(&repo).await;
    repo.close().await;
}

#[tokio::test]
async fn iga_composite_keys_file() {
    let file = TestFile::new();
    let repo = file.open().await;
    seed_pairs(&repo).await;
    drop(repo);
    let repo = file.open().await;
    assert_update_and_delete(&repo).await;
    drop(repo);
    let repo = file.open().await;
    assert!(
        repo.list_iga_entitlements("tenant:a")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.list_iga_access_packages("tenant:a")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.list_iga_entitlements("tenant").await.unwrap(),
        vec![entitlement("tenant", "a:pkg")]
    );
    assert_eq!(
        repo.list_iga_access_packages("tenant").await.unwrap(),
        vec![package("tenant", "a:pkg")]
    );
}

async fn legacy_store(file: &TestFile) -> serde_json::Value {
    let repo = file.open().await;
    repo.store_iga_entitlement(&entitlement("tenant:a", "pkg"))
        .await
        .unwrap();
    repo.store_iga_access_package(&package("tenant:a", "pkg"))
        .await
        .unwrap();
    drop(repo);
    let mut store: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file.0).unwrap()).unwrap();
    for map in ["iga_entitlements", "iga_access_packages"] {
        let records = store[map].as_object_mut().unwrap();
        let record = records.remove("8:tenant:apkg").unwrap();
        records.insert("tenant:a:pkg".into(), record);
    }
    store
}

#[tokio::test]
async fn iga_legacy_keys_rekey_on_open() {
    let file = TestFile::new();
    let store = legacy_store(&file).await;
    std::fs::write(&file.0, serde_json::to_vec(&store).unwrap()).unwrap();
    let repo = file.open().await;
    // Opening alone must persist the rebuilt keys, before any repository write.
    let migrated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file.0).unwrap()).unwrap();
    for map in ["iga_entitlements", "iga_access_packages"] {
        assert_eq!(migrated[map]["8:tenant:apkg"], store[map]["tenant:a:pkg"]);
        assert!(migrated[map].get("tenant:a:pkg").is_none());
    }
    // The legacy record can be updated and deleted without touching a new,
    // formerly aliasing owner. Reopening the migrated store is idempotent.
    drop(repo);
    let bytes = std::fs::read(&file.0).unwrap();
    let repo = file.open().await;
    assert_eq!(std::fs::read(&file.0).unwrap(), bytes);
    seed_pairs(&repo).await;
    assert_update_and_delete(&repo).await;
}

#[tokio::test]
async fn iga_duplicate_bindings_refuse_open_without_mutation() {
    for map in ["iga_entitlements", "iga_access_packages"] {
        let file = TestFile::new();
        let mut store = legacy_store(&file).await;
        // A mixed legacy/new map must not select either conflicting record.
        let mut duplicate = store[map]["tenant:a:pkg"].clone();
        duplicate["display_name"] = "Conflicting record".into();
        store[map]["8:tenant:apkg"] = duplicate;
        let bytes = serde_json::to_vec(&store).unwrap();
        std::fs::write(&file.0, &bytes).unwrap();
        let error = FileRepository::new(file.0.to_str().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, QidError::Internal { ref message } if message.contains("duplicate IGA")),
            "{error:?}"
        );
        assert_eq!(std::fs::read(&file.0).unwrap(), bytes);
    }
}
