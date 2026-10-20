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
    lifecycle.directory_provider_id = Some("directory".into());
    lifecycle.deprovisioned_at = Some(1234);
    repo.update_scim_user(&lifecycle).await.unwrap();
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

    let group = ScimGroup {
        id: "group".into(),
        realm_id: "corp".into(),
        display_name: "Team".into(),
        members_json: serde_json::json!([]),
    };
    repo.create_scim_group(&group).await.unwrap();
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
