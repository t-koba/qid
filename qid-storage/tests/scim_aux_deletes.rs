//! Cross-backend contract for realm-bound SCIM auxiliary deletes.
//!
//! Device and EventSubscription deletion carries an optional expected realm.
//! `None` is unrestricted administration; a supplied realm must match the
//! incumbent or no row is removed. Missing and mismatched rows report `false`.

use qid_storage::{AnyRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, ScimRepository};

fn device(id: &str, realm: &str) -> ScimDeviceRecord {
    ScimDeviceRecord {
        id: id.into(),
        realm_id: realm.into(),
        display_name: Some("phone".into()),
        manufacturer: Some("Acme".into()),
        model: Some("One".into()),
        os: Some("QidOS".into()),
        os_version: Some("1.0".into()),
        last_seen: Some(1_000),
    }
}

fn subscription(id: &str, realm: &str) -> ScimEventSubscriptionRecord {
    ScimEventSubscriptionRecord {
        id: id.into(),
        realm_id: realm.into(),
        callback_url: "https://events.example.com/hook".into(),
        event_types: vec!["user.created".into()],
        enabled: true,
        created_at: 1_000,
    }
}

async fn exercise_aux_deletes(repo: &AnyRepository) {
    // Devices: wrong-owner preservation, success, missing, unrestricted.
    let record = device("aux-device", "corp");
    repo.upsert_scim_device(&record).await.unwrap();
    assert!(
        !repo
            .delete_scim_device("aux-device", Some("other"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_device("aux-device").await.unwrap(),
        Some(record.clone())
    );
    assert!(
        repo.delete_scim_device("aux-device", Some("corp"))
            .await
            .unwrap()
    );
    assert_eq!(repo.get_scim_device("aux-device").await.unwrap(), None);
    assert!(
        !repo
            .delete_scim_device("aux-device", Some("corp"))
            .await
            .unwrap()
    );
    assert!(!repo.delete_scim_device("aux-device", None).await.unwrap());
    assert!(
        !repo
            .delete_scim_device("missing-device", Some("corp"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .delete_scim_device("missing-device", None)
            .await
            .unwrap()
    );
    repo.upsert_scim_device(&record).await.unwrap();
    assert!(repo.delete_scim_device("aux-device", None).await.unwrap());
    assert_eq!(repo.get_scim_device("aux-device").await.unwrap(), None);

    // Subscriptions: same contract.
    let sub = subscription("aux-sub", "corp");
    repo.upsert_scim_event_subscription(&sub).await.unwrap();
    assert!(
        !repo
            .delete_scim_event_subscription("aux-sub", Some("other"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_event_subscription("aux-sub").await.unwrap(),
        Some(sub.clone())
    );
    assert!(
        repo.delete_scim_event_subscription("aux-sub", Some("corp"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_event_subscription("aux-sub").await.unwrap(),
        None
    );
    assert!(
        !repo
            .delete_scim_event_subscription("aux-sub", Some("corp"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .delete_scim_event_subscription("aux-sub", None)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .delete_scim_event_subscription("missing-sub", Some("corp"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .delete_scim_event_subscription("missing-sub", None)
            .await
            .unwrap()
    );
    repo.upsert_scim_event_subscription(&sub).await.unwrap();
    assert!(
        repo.delete_scim_event_subscription("aux-sub", None)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_event_subscription("aux-sub").await.unwrap(),
        None
    );

    // Stale-ID reuse: A is read and deleted, B recreates the same supplied ID
    // in another realm, and the stale A deletion with the old realm preserves B.
    let stale = device("stale-device", "corp");
    repo.upsert_scim_device(&stale).await.unwrap();
    let read = repo.get_scim_device("stale-device").await.unwrap().unwrap();
    assert_eq!(read, stale);
    assert!(
        repo.delete_scim_device("stale-device", Some("corp"))
            .await
            .unwrap()
    );
    let recreated = device("stale-device", "other");
    repo.upsert_scim_device(&recreated).await.unwrap();
    assert!(
        !repo
            .delete_scim_device("stale-device", Some("corp"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_device("stale-device").await.unwrap(),
        Some(recreated.clone())
    );
    assert!(
        repo.delete_scim_device("stale-device", Some("other"))
            .await
            .unwrap()
    );

    let stale_sub = subscription("stale-sub", "corp");
    repo.upsert_scim_event_subscription(&stale_sub)
        .await
        .unwrap();
    let read_sub = repo
        .get_scim_event_subscription("stale-sub")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_sub, stale_sub);
    assert!(
        repo.delete_scim_event_subscription("stale-sub", Some("corp"))
            .await
            .unwrap()
    );
    let recreated_sub = subscription("stale-sub", "other");
    repo.upsert_scim_event_subscription(&recreated_sub)
        .await
        .unwrap();
    assert!(
        !repo
            .delete_scim_event_subscription("stale-sub", Some("corp"))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_scim_event_subscription("stale-sub").await.unwrap(),
        Some(recreated_sub.clone())
    );
    assert!(
        repo.delete_scim_event_subscription("stale-sub", Some("other"))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn file_scim_aux_deletes_bind_realm() {
    let dir = std::env::temp_dir().join(format!("qid-scim-aux-{}", ulid::Ulid::new()));
    let repo = AnyRepository::connect(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    exercise_aux_deletes(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_scim_aux_deletes_bind_realm() {
    let dir = std::env::temp_dir().join(format!("qid-scim-aux-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = AnyRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    exercise_aux_deletes(&repo).await;
    if let AnyRepository::Sql(repo) = repo {
        repo.close().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}
