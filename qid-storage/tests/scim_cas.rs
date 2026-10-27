use qid_core::error::{QidError, QidResult};
use qid_core::{
    models::{ScimGroup, ScimUser},
    tenant::{RealmId, TenantId},
};
use qid_storage::{AnyRepository, RealmRepository, ScimMutation, ScimRepository};

// Both writers have read the same version before either mutation. No scheduler
// ordering or sleeps are needed: exactly one changed replacement can succeed.
async fn exercise_cas(repo: &AnyRepository) {
    for realm in ["corp", "other"] {
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from(realm),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let user = ScimUser {
        id: "user".into(),
        realm_id: "corp".into(),
        external_id: None,
        user_name: "alice".into(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    repo.create_scim_user(&user).await.unwrap();
    let mut wrong_owner = user.clone();
    wrong_owner.realm_id = "other".into();
    wrong_owner.user_name = "intruder".into();
    assert!(repo.update_scim_user(&wrong_owner).await.is_err());
    assert_eq!(
        serde_json::to_value(repo.get_scim_user(&user.id).await.unwrap()).unwrap(),
        serde_json::to_value(Some(&user)).unwrap()
    );
    // Repeated failures exceed pool capacity: no transaction may leak a lock
    // or partially persist a failed mutation. Conversion errors occur after begin.
    for _ in 0..12 {
        assert!(
            repo.mutate_scim_user(
                &user.id,
                Box::new(|_| Err(QidError::BadRequest {
                    message: "caller rejected mutation".into(),
                }))
            )
            .await
            .is_err()
        );
        assert!(
            repo.mutate_scim_user("missing", Box::new(|_| panic!("missing callback")))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.mutate_scim_user(
                &user.id,
                Box::new(|current| {
                    let mut changed = current.clone();
                    changed.realm_id = "other".into();
                    Ok(ScimMutation::Replace(changed))
                })
            )
            .await
            .is_err()
        );
        if matches!(repo, AnyRepository::Sql(_)) {
            assert!(
                repo.mutate_scim_user(
                    &user.id,
                    Box::new(|current| {
                        let mut changed = current.clone();
                        changed.deprovisioned_at = Some(u64::MAX);
                        Ok(ScimMutation::Replace(changed))
                    })
                )
                .await
                .is_err()
            );
        }
        assert_eq!(
            serde_json::to_value(repo.get_scim_user(&user.id).await.unwrap()).unwrap(),
            serde_json::to_value(Some(&user)).unwrap()
        );
    }
    if matches!(repo, AnyRepository::Sql(_)) {
        let mut occupied = user.clone();
        occupied.id = "occupied".into();
        occupied.user_name = "taken".into();
        repo.create_scim_user(&occupied).await.unwrap();
        for _ in 0..12 {
            // An UPDATE constraint error, not just a callback error, must roll
            // back and release the writer lock before the next attempt.
            assert!(
                repo.mutate_scim_user(
                    &user.id,
                    Box::new(|current| {
                        let mut changed = current.clone();
                        changed.user_name = "taken".into();
                        Ok(ScimMutation::Replace(changed))
                    })
                )
                .await
                .is_err()
            );
            assert_eq!(
                repo.get_scim_user(&user.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .user_name,
                user.user_name
            );
        }
        repo.delete_scim_user(&occupied.id).await.unwrap();
    }
    let mut first = repo.get_scim_user(&user.id).await.unwrap().unwrap();
    let mut second = repo.get_scim_user(&user.id).await.unwrap().unwrap();
    first.user_name = "first".into();
    second.user_name = "second".into();
    let (a, b) = tokio::join!(
        cas_user(repo, &user, Some(&first)),
        cas_user(repo, &user, Some(&second)),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a, b);
    let winner = if a { first } else { second };
    assert_eq!(
        repo.get_scim_user(&user.id)
            .await
            .unwrap()
            .unwrap()
            .user_name,
        winner.user_name
    );
    assert!(!cas_user(repo, &user, None).await.unwrap());
    // Same ID in a different realm must not satisfy the checked snapshot.
    let mut wrong_realm = winner.clone();
    wrong_realm.realm_id = "other".into();
    assert!(!cas_user(repo, &wrong_realm, None).await.unwrap());
    // Server-owned changes must not be overwritten by an old SCIM snapshot.
    let mut lifecycle = winner.clone();
    lifecycle.external_id = Some("external".into());
    lifecycle.user_name = "lifecycle".into();
    lifecycle.name_json = serde_json::json!({"givenName": "Alice"});
    lifecycle.emails_json = serde_json::json!([{"value": "alice@example.com"}]);
    lifecycle.enterprise_json = serde_json::json!({"department": "Engineering"});
    lifecycle.directory_provider_id = Some("directory".into());
    lifecycle.deprovisioned_at = Some(1234);
    repo.update_scim_user(&lifecycle).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_scim_user(&user.id).await.unwrap()).unwrap(),
        serde_json::to_value(Some(&lifecycle)).unwrap()
    );
    assert!(!cas_user(repo, &winner, Some(&winner)).await.unwrap());
    // Deleting after an update succeeds only with the new snapshot; a stale
    // update after deletion must never resurrect the row (notably on files).
    let mut deactivated = lifecycle.clone();
    deactivated.active = false;
    let (updated, deleted) = tokio::join!(
        cas_user(repo, &lifecycle, Some(&deactivated)),
        cas_user(repo, &lifecycle, None),
    );
    let updated = updated.unwrap();
    assert_ne!(updated, deleted.unwrap());
    if updated {
        assert!(!cas_user(repo, &lifecycle, None).await.unwrap());
        assert!(cas_user(repo, &deactivated, None).await.unwrap());
    }
    assert!(!cas_user(repo, &lifecycle, Some(&winner)).await.unwrap());
    assert!(repo.get_scim_user(&user.id).await.unwrap().is_none());
    repo.update_scim_user(&lifecycle).await.unwrap();
    assert!(repo.get_scim_user(&user.id).await.unwrap().is_none());

    let group = ScimGroup {
        id: "group".into(),
        realm_id: "corp".into(),
        display_name: "Team".into(),
        members_json: serde_json::json!([]),
    };
    repo.create_scim_group(&group).await.unwrap();
    let mut wrong_owner = group.clone();
    wrong_owner.realm_id = "other".into();
    wrong_owner.display_name = "intruder".into();
    wrong_owner.members_json = serde_json::json!([{"value": "intruder"}]);
    assert!(matches!(
        repo.update_scim_group(&wrong_owner).await,
        Err(QidError::BadRequest { .. })
    ));
    assert_eq!(
        serde_json::to_value(repo.get_scim_group(&group.id).await.unwrap()).unwrap(),
        serde_json::to_value(Some(&group)).unwrap()
    );
    let mut group = group;
    group.display_name = "Updated Team".into();
    group.members_json = serde_json::json!([{"value": "member", "type": "User"}]);
    repo.update_scim_group(&group).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_scim_group(&group.id).await.unwrap()).unwrap(),
        serde_json::to_value(Some(&group)).unwrap()
    );
    if matches!(repo, AnyRepository::Sql(_)) {
        let mut occupied = group.clone();
        occupied.id = "occupied".into();
        occupied.display_name = "taken".into();
        repo.create_scim_group(&occupied).await.unwrap();
        for _ in 0..12 {
            assert!(
                repo.mutate_scim_group(
                    &group.id,
                    Box::new(|current| {
                        let mut changed = current.clone();
                        changed.display_name = "taken".into();
                        Ok(ScimMutation::Replace(changed))
                    })
                )
                .await
                .is_err()
            );
            assert_eq!(
                repo.get_scim_group(&group.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .display_name,
                group.display_name
            );
        }
        repo.delete_scim_group(&occupied.id).await.unwrap();
    }
    let mut first = repo.get_scim_group(&group.id).await.unwrap().unwrap();
    let mut second = repo.get_scim_group(&group.id).await.unwrap().unwrap();
    first.display_name = "first".into();
    second.members_json = serde_json::json!([{"value": "member"}]);
    let (a, b) = tokio::join!(
        cas_group(repo, &group, Some(&first)),
        cas_group(repo, &group, Some(&second)),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a, b);
    let winner = if a { first } else { second };
    assert_eq!(
        serde_json::to_value(repo.get_scim_group(&group.id).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&winner).unwrap()
    );
    assert!(!cas_group(repo, &group, None).await.unwrap());
    let mut wrong_realm = winner.clone();
    wrong_realm.realm_id = "other".into();
    assert!(!cas_group(repo, &wrong_realm, None).await.unwrap());
    let mut changed = winner.clone();
    changed.display_name = "changed again".into();
    let (updated, deleted) = tokio::join!(
        cas_group(repo, &winner, Some(&changed)),
        cas_group(repo, &winner, None),
    );
    let updated = updated.unwrap();
    assert_ne!(updated, deleted.unwrap());
    if updated {
        assert!(!cas_group(repo, &winner, None).await.unwrap());
        assert!(cas_group(repo, &changed, None).await.unwrap());
    }
    assert!(!cas_group(repo, &winner, Some(&winner)).await.unwrap());
    assert!(repo.get_scim_group(&group.id).await.unwrap().is_none());
    repo.update_scim_group(&winner).await.unwrap();
    assert!(repo.get_scim_group(&group.id).await.unwrap().is_none());
}

#[tokio::test]
async fn file_scim_compare_and_mutate() {
    let dir = std::env::temp_dir().join(format!("qid-scim-cas-{}", ulid::Ulid::new()));
    let repo = AnyRepository::connect(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    exercise_cas(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_scim_compare_and_mutate() {
    let dir = std::env::temp_dir().join(format!("qid-scim-cas-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = AnyRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    exercise_cas(&repo).await;
    if let AnyRepository::Sql(repo) = repo {
        repo.close().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

// Exact-snapshot equality is just one possible caller predicate, not storage
// policy (HTTP wildcard/list and ETag projection are tested in qid-scim).
async fn cas_user(
    repo: &AnyRepository,
    expected: &ScimUser,
    replacement: Option<&ScimUser>,
) -> QidResult<bool> {
    Ok(repo
        .mutate_scim_user(
            &expected.id,
            Box::new(move |current| {
                Ok(
                    if serde_json::to_value(current).unwrap()
                        != serde_json::to_value(expected).unwrap()
                    {
                        ScimMutation::Reject
                    } else {
                        replacement
                            .cloned()
                            .map_or(ScimMutation::Delete, ScimMutation::Replace)
                    },
                )
            }),
        )
        .await?
        .is_some())
}

// Exact-snapshot equality is just one possible caller predicate, not storage
// policy (HTTP wildcard/list and ETag projection are tested in qid-scim).
async fn cas_group(
    repo: &AnyRepository,
    expected: &ScimGroup,
    replacement: Option<&ScimGroup>,
) -> QidResult<bool> {
    Ok(repo
        .mutate_scim_group(
            &expected.id,
            Box::new(move |current| {
                Ok(
                    if serde_json::to_value(current).unwrap()
                        != serde_json::to_value(expected).unwrap()
                    {
                        ScimMutation::Reject
                    } else {
                        replacement
                            .cloned()
                            .map_or(ScimMutation::Delete, ScimMutation::Replace)
                    },
                )
            }),
        )
        .await?
        .is_some())
}

fn scim_user(id: &str, realm: &str, user_name: &str) -> ScimUser {
    ScimUser {
        id: id.into(),
        realm_id: realm.into(),
        external_id: None,
        user_name: user_name.into(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    }
}

fn assert_create_conflict(result: QidResult<()>) {
    match result {
        Err(QidError::Conflict { .. }) => {}
        Err(other) => panic!("expected Conflict, got {other:?}"),
        Ok(()) => panic!("expected Conflict, got Ok"),
    }
}

// Shared create-only contract: a taken record ID or a taken
// (realm_id, user_name) is a conflict that changes no row, while the same
// user name in another realm succeeds.
async fn exercise_create_user_conflict(repo: &AnyRepository) {
    for realm in ["corp", "other"] {
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from(realm),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let alice = scim_user("alice-id", "corp", "alice");
    repo.create_scim_user(&alice).await.unwrap();

    // A duplicate record ID with a different user name is refused and the
    // incumbent is unchanged.
    let mut id_collision = scim_user("alice-id", "corp", "mallory");
    id_collision.active = false;
    assert_create_conflict(repo.create_scim_user(&id_collision).await);
    assert_eq!(
        serde_json::to_value(repo.get_scim_user("alice-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&alice)).unwrap()
    );

    // A duplicate user name in the same realm is refused and the incumbent
    // is unchanged, including under a fresh record ID.
    let mut name_collision = scim_user("mallory-id", "corp", "alice");
    name_collision.active = false;
    assert_create_conflict(repo.create_scim_user(&name_collision).await);
    assert_eq!(
        serde_json::to_value(repo.get_scim_user("alice-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&alice)).unwrap()
    );
    assert!(repo.get_scim_user("mallory-id").await.unwrap().is_none());
    assert_eq!(
        repo.list_scim_users(&RealmId::from("corp"))
            .await
            .unwrap()
            .len(),
        1
    );

    // A globally colliding ID from another realm is refused and creates
    // nothing in that realm.
    let foreign_id = scim_user("alice-id", "other", "alice");
    assert_create_conflict(repo.create_scim_user(&foreign_id).await);
    assert_eq!(
        repo.get_scim_user("alice-id")
            .await
            .unwrap()
            .unwrap()
            .realm_id,
        "corp"
    );
    assert!(
        repo.list_scim_users(&RealmId::from("other"))
            .await
            .unwrap()
            .is_empty()
    );

    // The same user name in another realm is allowed.
    let other_alice = scim_user("other-alice-id", "other", "alice");
    repo.create_scim_user(&other_alice).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_scim_user("other-alice-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&other_alice)).unwrap()
    );
    assert_eq!(
        serde_json::to_value(repo.get_scim_user("alice-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&alice)).unwrap()
    );
}

#[tokio::test]
async fn file_scim_create_user_conflict() {
    let dir = std::env::temp_dir().join(format!("qid-scim-create-{}", ulid::Ulid::new()));
    let repo = AnyRepository::connect(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    exercise_create_user_conflict(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_scim_create_user_conflict() {
    let dir = std::env::temp_dir().join(format!("qid-scim-create-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = AnyRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    exercise_create_user_conflict(&repo).await;
    if let AnyRepository::Sql(repo) = repo {
        repo.close().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn scim_group(id: &str, realm: &str, display_name: &str) -> ScimGroup {
    ScimGroup {
        id: id.into(),
        realm_id: realm.into(),
        display_name: display_name.into(),
        members_json: serde_json::json!([]),
    }
}

// Shared create-only contract: a taken record ID or a taken
// (realm_id, display_name) is a conflict that changes no row, while the same
// display name in another realm succeeds.
async fn exercise_create_group_conflict(repo: &AnyRepository) {
    for realm in ["corp", "other"] {
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from(realm),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let mut engineers = scim_group("eng-id", "corp", "engineers");
    engineers.members_json = serde_json::json!(["alice"]);
    repo.create_scim_group(&engineers).await.unwrap();

    // A duplicate record ID with a different display name is refused and
    // the incumbent is unchanged.
    let mut id_collision = scim_group("eng-id", "corp", "executives");
    id_collision.members_json = serde_json::json!(["mallory"]);
    assert_create_conflict(repo.create_scim_group(&id_collision).await);
    assert_eq!(
        serde_json::to_value(repo.get_scim_group("eng-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&engineers)).unwrap()
    );

    // A duplicate display name in the same realm is refused and the
    // incumbent is unchanged, including under a fresh record ID.
    let mut name_collision = scim_group("exec-id", "corp", "engineers");
    name_collision.members_json = serde_json::json!(["mallory"]);
    assert_create_conflict(repo.create_scim_group(&name_collision).await);
    assert_eq!(
        serde_json::to_value(repo.get_scim_group("eng-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&engineers)).unwrap()
    );
    assert!(repo.get_scim_group("exec-id").await.unwrap().is_none());
    assert_eq!(
        repo.list_scim_groups(&RealmId::from("corp"))
            .await
            .unwrap()
            .len(),
        1
    );

    // A globally colliding ID from another realm is refused and creates
    // nothing in that realm.
    let foreign_id = scim_group("eng-id", "other", "engineers");
    assert_create_conflict(repo.create_scim_group(&foreign_id).await);
    assert_eq!(
        repo.get_scim_group("eng-id")
            .await
            .unwrap()
            .unwrap()
            .realm_id,
        "corp"
    );
    assert!(
        repo.list_scim_groups(&RealmId::from("other"))
            .await
            .unwrap()
            .is_empty()
    );

    // The same display name in another realm is allowed.
    let other_engineers = scim_group("other-eng-id", "other", "engineers");
    repo.create_scim_group(&other_engineers).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_scim_group("other-eng-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&other_engineers)).unwrap()
    );
    assert_eq!(
        serde_json::to_value(repo.get_scim_group("eng-id").await.unwrap()).unwrap(),
        serde_json::to_value(Some(&engineers)).unwrap()
    );
}

#[tokio::test]
async fn file_scim_create_group_conflict() {
    let dir = std::env::temp_dir().join(format!("qid-scim-group-create-{}", ulid::Ulid::new()));
    let repo = AnyRepository::connect(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    exercise_create_group_conflict(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_scim_create_group_conflict() {
    let dir = std::env::temp_dir().join(format!("qid-scim-group-create-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = AnyRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    exercise_create_group_conflict(&repo).await;
    if let AnyRepository::Sql(repo) = repo {
        repo.close().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}
