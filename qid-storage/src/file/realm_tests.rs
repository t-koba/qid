use super::persistence_tests::{
    TestFile, assert_pending, complete, fail_next_flush, pause_next_write,
};
use super::*;
use serde_json::Value;

const RETAINED: &[&str] = &[
    "audit_events",
    "audit_retention_configs",
    "siem_deliveries",
    "marketplace_connectors",
    "relationship_tuples",
];

fn fixture(realm: &str) -> Value {
    fn replace_values(value: &mut Value, realm: &str) {
        match value {
            Value::String(text) => *text = text.replace("realm", realm),
            Value::Object(fields) => {
                for value in fields.values_mut() {
                    replace_values(value, realm);
                }
            }
            Value::Array(values) => {
                for value in values {
                    replace_values(value, realm);
                }
            }
            _ => {}
        }
    }
    let mut fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/realm_store.json")).unwrap();
    for records in fixture.as_object_mut().unwrap().values_mut() {
        if let Value::Object(entries) = records {
            *entries = std::mem::take(entries)
                .into_iter()
                .map(|(key, mut value)| {
                    replace_values(&mut value, realm);
                    (key.replace("realm", realm), value)
                })
                .collect();
        } else {
            replace_values(records, realm);
        }
    }
    fixture
}

fn merge(store: &mut Value, fixture: Value, only_retained: bool) {
    for (field, value) in fixture.as_object().unwrap() {
        if only_retained && !RETAINED.contains(&field.as_str()) {
            continue;
        }
        match value {
            Value::Object(entries) => store[field]
                .as_object_mut()
                .unwrap()
                .extend(entries.clone()),
            Value::Array(entries) => store[field].as_array_mut().unwrap().extend(entries.clone()),
            _ => panic!("unexpected fixture field {field}"),
        }
    }
}

fn seeded_store(deleted: bool) -> Store {
    let mut value = serde_json::to_value(Store::default()).unwrap();
    merge(&mut value, fixture("realm-peer"), false);
    merge(&mut value, fixture("realm"), deleted);
    let mut store: Store = serde_json::from_value(value).unwrap();
    store.rekey_ciam_progressive_profiles().unwrap();
    // Non-user tokens outside the deleted realm have no user ownership link.
    for subject in ["service", "workload"] {
        let mut token = store.access_tokens["realm-peer-record"].clone();
        token.jti = subject.into();
        token.user_id = subject.into();
        token.family_id = None;
        store.access_tokens.insert(subject.into(), token);
    }
    if !deleted {
        // Cross-realm direct owners do not make a deleted session's children
        // independent. Exercise both session and family links and user subjects.
        let mut family = store.token_families["realm-peer-record"].clone();
        family.id = "linked-family".into();
        family.session_id = Some("realm-record".into());
        store.token_families.insert(family.id.clone(), family);
        let mut code = store.authorization_codes["realm-peer-record"].clone();
        code.code_hash = "linked-code".into();
        code.session_id = Some("realm-record".into());
        store
            .authorization_codes
            .insert(code.code_hash.clone(), code);
        for (id, subject, family, realm) in [
            (
                "linked-token",
                "service",
                Some("linked-family"),
                "realm-peer",
            ),
            ("user-token", "realm-user", None, "realm-peer"),
            ("realm-service-token", "service", None, "realm"),
        ] {
            let mut token = store.access_tokens["service"].clone();
            token.jti = id.into();
            token.user_id = subject.into();
            token.family_id = family.map(String::from);
            token.realm_id = realm.into();
            store.access_tokens.insert(id.into(), token);
        }
    }
    store
}

async fn snapshot(repo: &FileRepository) -> Value {
    serde_json::to_value(&*repo.store.read().await).unwrap()
}

#[tokio::test]
async fn realm_deletion_immediate_is_atomic_and_survives_reopen_and_recreation() {
    let (file, repo) = TestFile::new().await;
    *repo.store.write().await = seeded_store(false);
    repo.save().await.unwrap();
    let before = snapshot(&repo).await;

    // Deterministically pause/fail persistence. While paused neither readers
    // nor another save can observe/persist the tentative deletion.
    let (reached, resume) = fail_next_flush(&repo);
    let realm: RealmId = "realm".into();
    let mut deletion = Box::pin(repo.delete_realm(&realm));
    assert_pending(deletion.as_mut()).await;
    complete(reached).await.unwrap();
    assert!(repo.store.try_read().is_err());
    assert!(repo.save_lock.try_lock().is_err());
    resume.send(()).unwrap();
    assert!(complete(deletion).await.is_err());
    assert_eq!(snapshot(&repo).await, before);
    drop(repo);

    let repo = file.reopen().await;
    assert_eq!(snapshot(&repo).await, before);
    // An actual filesystem write failure also restores all memory and disk.
    tokio::fs::create_dir(file.0.with_extension("tmp"))
        .await
        .unwrap();
    assert!(repo.delete_realm(&realm).await.is_err());
    assert_eq!(snapshot(&repo).await, before);
    tokio::fs::remove_dir(file.0.with_extension("tmp"))
        .await
        .unwrap();
    drop(repo);
    let repo = file.reopen().await;
    assert_eq!(snapshot(&repo).await, before);

    repo.delete_realm(&realm).await.unwrap();
    let expected = serde_json::to_value(seeded_store(true)).unwrap();
    assert_eq!(snapshot(&repo).await, expected);
    repo.delete_realm(&realm).await.unwrap();
    assert_eq!(snapshot(&repo).await, expected);
    drop(repo);
    let repo = file.reopen().await;
    assert_eq!(snapshot(&repo).await, expected);
    repo.create_realm(
        &"new-tenant".into(),
        &realm,
        "https://new.example.com",
        None,
    )
    .await
    .unwrap();
    let mut expected = seeded_store(true);
    expected
        .realm_tenants
        .insert("realm".into(), "new-tenant".into());
    expected
        .realm_issuers
        .insert("realm".into(), "https://new.example.com".into());
    assert_eq!(
        snapshot(&repo).await,
        serde_json::to_value(expected).unwrap()
    );
    drop(repo);
}

#[tokio::test]
async fn realm_deletion_waits_for_save_lock_before_mutating_store() {
    let (_file, repo) = TestFile::new().await;
    *repo.store.write().await = seeded_store(false);
    let before = snapshot(&repo).await;
    let guard = repo.save_lock.lock().await;
    let realm: RealmId = "realm".into();
    let mut deletion = Box::pin(repo.delete_realm(&realm));
    assert_pending(deletion.as_mut()).await;
    assert_eq!(snapshot(&repo).await, before);
    drop(guard);
    complete(deletion).await.unwrap();
}

#[tokio::test]
async fn realm_deletion_interval_keeps_accepted_cleanup_dirty_until_flush_succeeds() {
    // Set the mode directly to avoid starting a background task that retains
    // the file/process lock beyond the lifetime of this deterministic test.
    let (file, mut repo) = TestFile::new().await;
    *repo.store.write().await = seeded_store(false);
    repo.save().await.unwrap();
    repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(60));
    repo.delete_realm(&"realm".into()).await.unwrap();
    let expected = serde_json::to_value(seeded_store(true)).unwrap();
    assert_eq!(snapshot(&repo).await, expected);
    assert!(repo.dirty.load(Ordering::Acquire));
    tokio::fs::create_dir(file.0.with_extension("tmp"))
        .await
        .unwrap();
    assert!(repo.flush().await.is_err());
    assert!(repo.dirty.load(Ordering::Acquire));
    assert_eq!(snapshot(&repo).await, expected);
    tokio::fs::remove_dir(file.0.with_extension("tmp"))
        .await
        .unwrap();
    repo.flush().await.unwrap();
    assert!(!repo.dirty.load(Ordering::Acquire));
    drop(repo);
    let repo = file.reopen().await;
    assert_eq!(snapshot(&repo).await, expected);
}

#[tokio::test]
async fn realm_deletion_cleans_legacy_file_orphans_without_parent() {
    let (_file, repo) = TestFile::new().await;
    let mut store = seeded_store(false);
    store.realm_issuers.remove("realm");
    store.realm_tenants.remove("realm");
    *repo.store.write().await = store;
    repo.delete_realm(&"realm".into()).await.unwrap();
    assert_eq!(
        snapshot(&repo).await,
        serde_json::to_value(seeded_store(true)).unwrap()
    );
}

#[tokio::test]
async fn cancelled_immediate_realm_deletion_finishes_persist_or_rollback() {
    for fail in [false, true] {
        let (file, repo) = TestFile::new().await;
        *repo.store.write().await = seeded_store(false);
        repo.save().await.unwrap();
        let before = serde_json::to_value(seeded_store(false)).unwrap();
        let (reached, resume) = pause_next_write(&repo, fail);
        let realm: RealmId = "realm".into();
        let mut deletion = Box::pin(repo.delete_realm(&realm));
        assert_pending(deletion.as_mut()).await;
        complete(reached).await.unwrap();
        let temp: Store =
            serde_json::from_slice(&tokio::fs::read(file.0.with_extension("tmp")).await.unwrap())
                .unwrap();
        assert_eq!(
            serde_json::to_value(temp).unwrap(),
            serde_json::to_value(seeded_store(true)).unwrap()
        );
        drop(deletion);
        assert!(repo.store.try_read().is_err());
        assert!(repo.save_lock.try_lock().is_err());
        resume.send(()).unwrap();
        drop(complete(repo.save_lock.lock()).await);
        let expected = if fail {
            before
        } else {
            serde_json::to_value(seeded_store(true)).unwrap()
        };
        assert_eq!(snapshot(&repo).await, expected);
        drop(repo);
        let repo = file.reopen().await;
        assert_eq!(snapshot(&repo).await, expected);
        if fail {
            repo.delete_realm(&realm).await.unwrap();
            let deleted = serde_json::to_value(seeded_store(true)).unwrap();
            assert_eq!(snapshot(&repo).await, deleted);
        }
        drop(repo);
    }
}
