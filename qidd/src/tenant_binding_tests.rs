use super::*;
use crate::tests::minimal_config;

async fn close_repository(repo: AnyRepository) {
    if let AnyRepository::Sql(repo) = repo {
        repo.close().await;
    }
}

#[tokio::test]
async fn tenant_binding_seeds_declared_and_default_tenants() {
    for sql in [false, true] {
        for configured in [Some("tenant-corp"), None] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("store.json");
            let url = if sql {
                format!(
                    "sqlite://{}?mode=rwc",
                    dir.path().join("store.db").display()
                )
            } else {
                path.to_str().unwrap().to_owned()
            };
            let repo = AnyRepository::connect(&url).await.unwrap();
            let mut config = minimal_config();
            config.realms[0].tenant_id = configured.map(str::to_owned);
            let config_path = dir.path().join("qid.yaml");
            let realm = RealmId::from("corp");
            let expected = configured.unwrap_or("default");
            for _ in 0..2 {
                seed_configured_realms_and_clients(&repo, &config, &config_path)
                    .await
                    .unwrap();
                assert_eq!(
                    repo.get_realm_tenant(&realm).await.unwrap().as_deref(),
                    Some(expected)
                );
            }
            // An omitted optional tenant must not move an existing realm to default.
            config.realms[0].tenant_id = None;
            seed_configured_realms_and_clients(&repo, &config, &config_path)
                .await
                .unwrap();
            assert_eq!(
                repo.get_realm_tenant(&realm).await.unwrap().as_deref(),
                Some(expected)
            );
            assert_eq!(
                repo.get_realm_issuer(&realm).await.unwrap().as_deref(),
                Some(config.realms[0].issuer.as_str())
            );
            close_repository(repo).await;
        }
    }
}

#[tokio::test]
async fn tenant_binding_rejects_mismatch_and_missing_binding_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    let config_path = dir.path().join("qid.yaml");
    let url = path.to_str().unwrap();
    let repo = AnyRepository::connect(url).await.unwrap();
    let mut config = minimal_config();
    config.realms[0].tenant_id = Some("tenant-corp".into());
    seed_configured_realms_and_clients(&repo, &config, &config_path)
        .await
        .unwrap();
    // A client not yet stored must not be written when the tenant conflicts.
    let mut first = config.realms[0].clone();
    first.id = "pending-realm".into();
    first.issuer = "https://id.example.com/realms/pending".into();
    first.tenant_id = Some("tenant-first".into());
    first.clients = vec![
        serde_json::from_value(json!({
            "client_id": "pending-client",
            "client_type": "public",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"]
        }))
        .unwrap(),
    ];
    config.realms[0].tenant_id = Some("foreign-tenant".into());
    config.realms.insert(0, first);
    let before = std::fs::read(&path).unwrap();
    let error = seed_configured_realms_and_clients(&repo, &config, &config_path)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("tenant mismatch"), "{error:#}");
    // Byte equality includes all audit and membership collections, not just realms.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        repo.get_client_by_client_id(&RealmId::from("pending-realm"), "pending-client")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_realm_tenant(&RealmId::from("pending-realm"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_realm_tenant(&RealmId::from("corp"))
            .await
            .unwrap()
            .as_deref(),
        Some("tenant-corp")
    );
    config.realms.remove(0);
    drop(repo);

    // Model an existing realm whose persisted binding is missing, without a write API.
    let mut stored: serde_json::Value = serde_json::from_slice(&before).unwrap();
    stored["realm_tenants"]
        .as_object_mut()
        .unwrap()
        .remove("corp");
    std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    let repo = AnyRepository::connect(url).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    for configured in [Some("tenant-corp"), None] {
        config.realms[0].tenant_id = configured.map(str::to_owned);
        let error = seed_configured_realms_and_clients(&repo, &config, &config_path)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no tenant binding"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(
            repo.get_realm_tenant(&RealmId::from("corp"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_client_by_client_id(&RealmId::from("corp"), "pending-client")
                .await
                .unwrap()
                .is_none()
        );
    }
    drop(repo);
}

#[tokio::test]
async fn tenant_binding_multi_realm_sample_preserves_distinct_owners() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../config/usecases/12-composition/multi-realm-ciam-and-workforce.yaml");
    let config = QidConfig::from_files([&config_path]).unwrap();
    assert_eq!(config.realms.len(), 2);
    for sql in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let url = if sql {
            format!(
                "sqlite://{}?mode=rwc",
                dir.path().join("store.db").display()
            )
        } else {
            dir.path().join("store.json").to_str().unwrap().to_owned()
        };
        let repo = AnyRepository::connect(&url).await.unwrap();
        for _ in 0..2 {
            seed_configured_realms_and_clients(&repo, &config, &config_path)
                .await
                .unwrap();
        }
        for (id, tenant) in [
            ("workforce", "tenant-workforce"),
            ("customers", "tenant-customers"),
        ] {
            let realm = RealmId::from(id);
            let declared = config.realms.iter().find(|realm| realm.id == id).unwrap();
            assert_eq!(declared.tenant_id.as_deref(), Some(tenant));
            assert_eq!(
                repo.get_realm_tenant(&realm).await.unwrap().as_deref(),
                Some(tenant)
            );
            assert_eq!(
                repo.get_realm_issuer(&realm).await.unwrap().as_deref(),
                Some(declared.issuer.as_str())
            );
            for client in &declared.clients {
                let stored = repo
                    .get_client_by_client_id(&realm, &client.client_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(client_matches_static_config(
                    &stored,
                    &static_client_to_model(id, client)
                ));
            }
            assert_eq!(
                repo.list_policy_bundles(&realm).await.unwrap().len(),
                declared.policy.bundles.len()
            );
        }
        close_repository(repo).await;
    }
}
