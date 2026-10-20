//! Deterministic interleaving: capture the client condition at V1, commit V2,
//! then evaluate each mutation against the current resource.
use super::*;
use crate::inbound::{groups::delete_group_record, write::WriteError};
use axum::{http::StatusCode, response::IntoResponse};
use qid_core::{
    models::{ScimGroup, ScimUser},
    tenant::{RealmId, TenantId},
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{AnyRepository, RealmRepository, ScimRepository};

fn patch(path: &str, value: &str) -> PatchRequest {
    serde_json::from_value(
        serde_json::json!({"Operations": [{"op": "replace", "path": path, "value": value}]}),
    )
    .unwrap()
}

fn assert_stale<T: std::fmt::Debug>(result: Result<T, WriteError>) {
    let error = result.unwrap_err();
    assert_eq!(error.status_code(), 412);
    assert_eq!(
        error.into_response().status(),
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
async fn conditions_match_current_resources_on_both_backends() {
    for sql in [false, true] {
        let dir = std::env::temp_dir().join(format!("qid-scim-conditional-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = if sql {
            format!("sqlite:{}", dir.join("store.db").display())
        } else {
            dir.join("store.json").to_str().unwrap().to_string()
        };
        let repo = Arc::new(AnyRepository::connect(&url).await.unwrap());
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from("corp"),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        let state = SharedState::new(
            test_helpers::test_config(),
            repo.clone(),
            Arc::new(LocalSigner::from_secret("test", b"test-secret")),
            serde_json::json!({}),
        )
        .unwrap();
        let user = ScimUser {
            id: "user".into(),
            realm_id: "corp".into(),
            external_id: None,
            user_name: "alice".into(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: Some("directory".into()),
            deprovisioned_at: Some(1234),
            active: true,
        };
        let group = ScimGroup {
            id: "group".into(),
            realm_id: "corp".into(),
            display_name: "Team".into(),
            members_json: serde_json::json!([]),
        };
        repo.create_scim_user(&user).await.unwrap();
        repo.create_scim_group(&group).await.unwrap();
        exercise_current_conditions(&state, &user, &group).await;
        // A specific stale condition (including a list with no current match)
        // must reject every mutation after an intervening write or deletion.
        let version = format!("W/\"other\", {}", crate::response::scim_user_version(&user));
        let checked_user = check_user_preconditions(&state, &user.id, Some("corp"), Some(&version))
            .await
            .unwrap();
        let group_version = crate::response::scim_group_version(&group);
        let checked_group =
            check_group_preconditions(&state, &group.id, Some("corp"), Some(&group_version))
                .await
                .unwrap();
        patch_user_record(
            &state,
            &user.id,
            patch("userName", "winner"),
            checked_user.clone(),
        )
        .await
        .unwrap();
        patch_group_record(
            &state,
            &group.id,
            patch("displayName", "winner"),
            checked_group.clone(),
        )
        .await
        .unwrap();
        for missing in [false, true] {
            if missing {
                repo.delete_scim_user(&user.id).await.unwrap();
                repo.delete_scim_group(&group.id).await.unwrap();
            }
            let put_user = super::super::parse_create_user(
                serde_json::json!({"realm": "corp", "userName": "loser"}),
            )
            .unwrap();
            let put_group = serde_json::from_value(
                serde_json::json!({"realm": "corp", "displayName": "loser"}),
            )
            .unwrap();
            assert_stale(
                replace_user_record(&state, &user.id, put_user, checked_user.clone()).await,
            );
            assert_stale(
                patch_user_record(
                    &state,
                    &user.id,
                    patch("userName", "loser"),
                    checked_user.clone(),
                )
                .await,
            );
            assert_stale(delete_user_record(&state, &user.id, false, checked_user.clone()).await);
            assert_stale(delete_user_record(&state, &user.id, true, checked_user.clone()).await);
            assert_stale(
                replace_group_record(&state, &group.id, put_group, checked_group.clone()).await,
            );
            assert_stale(
                patch_group_record(
                    &state,
                    &group.id,
                    patch("displayName", "loser"),
                    checked_group.clone(),
                )
                .await,
            );
            assert_stale(delete_group_record(&state, &group.id, checked_group.clone()).await);
            let stored_user = repo.get_scim_user(&user.id).await.unwrap();
            let stored_group = repo.get_scim_group(&group.id).await.unwrap();
            if missing {
                assert!(stored_user.is_none());
                assert!(stored_group.is_none());
            } else {
                let stored_user = stored_user.unwrap();
                assert_eq!(stored_user.user_name, "winner");
                assert_eq!(
                    stored_user.directory_provider_id.as_deref(),
                    Some("directory")
                );
                assert_eq!(stored_user.deprovisioned_at, Some(1234));
                assert!(stored_user.active);
                assert_eq!(stored_group.unwrap().display_name, "winner");
            }
        }
        drop(state);
        let repo = Arc::try_unwrap(repo).ok().unwrap();
        if let AnyRepository::Sql(repo) = repo {
            repo.close().await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

// Capture the condition while V1 is current, then deterministically commit V2.
// Both entry points (HTTP headers and Bulk's precheck) must retain all candidates.
async fn exercise_current_conditions(
    state: &SharedState<AnyRepository>,
    user: &ScimUser,
    group: &ScimGroup,
) {
    use crate::inbound::write::Condition;
    use axum::http::{HeaderMap, HeaderValue, header::IF_MATCH};
    for provider_only in [false, true] {
        for mode in ["wildcard", "list", "specific"] {
            for operation in ["patch", "put", "soft_delete", "hard_delete"] {
                state.repo.update_scim_user(user).await.unwrap();
                state.repo.update_scim_group(group).await.unwrap();
                let mut v2 = user.clone();
                v2.directory_provider_id = Some("new-directory".into());
                let mut g2 = group.clone();
                if !provider_only {
                    v2.name_json = serde_json::json!({"familyName": "V2"});
                    v2.deprovisioned_at = Some(5678);
                    g2.members_json = serde_json::json!([{"value": "V2"}]);
                }
                let version = |v1: String, v2: String| match mode {
                    "wildcard" => "*".to_string(),
                    "list" => format!("{v1}, {v2}"),
                    _ => v1,
                };
                let uv = version(
                    crate::response::scim_user_version(user),
                    crate::response::scim_user_version(&v2),
                );
                let gv = version(
                    crate::response::scim_group_version(group),
                    crate::response::scim_group_version(&g2),
                );
                let mut headers = HeaderMap::new();
                headers.insert(IF_MATCH, HeaderValue::from_str(&uv).unwrap());
                crate::response::check_if_match(
                    &headers,
                    &crate::response::scim_user_version(user),
                )
                .unwrap();
                let uc = Condition::from_headers(user.realm_id.clone(), &headers);
                let gc = check_group_preconditions(state, &group.id, Some("corp"), Some(&gv))
                    .await
                    .unwrap();
                // Also exercise Bulk's user precheck; the same condition is applied.
                let bulk_uc = check_user_preconditions(state, &user.id, Some("corp"), Some(&uv))
                    .await
                    .unwrap();
                let uc = if operation == "put" { bulk_uc } else { uc };
                state.repo.update_scim_user(&v2).await.unwrap();
                state.repo.update_scim_group(&g2).await.unwrap();
                let ur = match operation {
                    "patch" => {
                        patch_user_record(state, &user.id, patch("userName", "requested"), uc)
                            .await
                            .map(Some)
                    }
                    "put" => replace_user_record(
                        state,
                        &user.id,
                        super::super::parse_create_user(
                            serde_json::json!({"realm": "corp", "userName": "requested"}),
                        )
                        .unwrap(),
                        uc,
                    )
                    .await
                    .map(Some),
                    _ => delete_user_record(state, &user.id, operation == "hard_delete", uc)
                        .await
                        .map(|_| None),
                };
                let gr = match operation {
                    "patch" => {
                        patch_group_record(state, &group.id, patch("displayName", "requested"), gc)
                            .await
                            .map(Some)
                    }
                    "put" => replace_group_record(
                        state,
                        &group.id,
                        serde_json::from_value(
                            serde_json::json!({"realm": "corp", "displayName": "requested"}),
                        )
                        .unwrap(),
                        gc,
                    )
                    .await
                    .map(Some),
                    _ => delete_group_record(state, &group.id, gc)
                        .await
                        .map(|_| None),
                };
                if mode == "specific" && !provider_only {
                    assert_stale(ur);
                    assert_stale(gr);
                    assert_eq!(
                        serde_json::to_value(state.repo.get_scim_user(&user.id).await.unwrap())
                            .unwrap(),
                        serde_json::to_value(Some(&v2)).unwrap()
                    );
                    assert_eq!(
                        serde_json::to_value(state.repo.get_scim_group(&group.id).await.unwrap())
                            .unwrap(),
                        serde_json::to_value(Some(&g2)).unwrap()
                    );
                } else {
                    let ur = ur.unwrap();
                    let gr = gr.unwrap();
                    let stored = state.repo.get_scim_user(&user.id).await.unwrap();
                    if operation == "hard_delete" {
                        assert!(stored.is_none());
                    } else {
                        let stored = stored.unwrap();
                        assert_eq!(stored.directory_provider_id, v2.directory_provider_id);
                        assert_eq!(stored.deprovisioned_at, v2.deprovisioned_at);
                        assert_eq!(stored.name_json, v2.name_json);
                        if let Some(returned) = ur {
                            assert_eq!(stored.user_name, "requested");
                            assert_eq!(
                                serde_json::to_value(returned).unwrap(),
                                serde_json::to_value(stored).unwrap()
                            );
                        } else {
                            assert!(!stored.active);
                        }
                    }
                    let stored = state.repo.get_scim_group(&group.id).await.unwrap();
                    if let Some(returned) = gr {
                        let stored = stored.unwrap();
                        assert_eq!(stored.display_name, "requested");
                        assert_eq!(stored.members_json, g2.members_json);
                        assert_eq!(
                            serde_json::to_value(returned).unwrap(),
                            serde_json::to_value(stored).unwrap()
                        );
                    } else {
                        assert!(stored.is_none());
                    }
                }
                // Recreate rows deleted by successful conditions before next case.
                if state.repo.get_scim_user(&user.id).await.unwrap().is_none() {
                    state.repo.create_scim_user(user).await.unwrap();
                }
                if state
                    .repo
                    .get_scim_group(&group.id)
                    .await
                    .unwrap()
                    .is_none()
                {
                    state.repo.create_scim_group(group).await.unwrap();
                }
            }
        }
    }
    // An ownership-only change must be preserved AND its restrictions must be
    // enforced using the new owner, not the unowned precheck row.
    for operation in ["patch", "put"] {
        let mut unowned = user.clone();
        unowned.directory_provider_id = None;
        state.repo.update_scim_user(&unowned).await.unwrap();
        let version = crate::response::scim_user_version(&unowned);
        let condition = check_user_preconditions(state, &user.id, Some("corp"), Some(&version))
            .await
            .unwrap();
        state.repo.update_scim_user(user).await.unwrap();
        assert_eq!(version, crate::response::scim_user_version(user));
        let result = if operation == "patch" {
            patch_user_record(state, &user.id, patch("externalId", "client"), condition).await
        } else {
            replace_user_record(state, &user.id, super::super::parse_create_user(
                serde_json::json!({"realm": "corp", "userName": "requested", "externalId": "client"})).unwrap(), condition).await
        };
        assert_eq!(result.unwrap_err().status_code(), 409);
        assert_eq!(
            serde_json::to_value(state.repo.get_scim_user(&user.id).await.unwrap()).unwrap(),
            serde_json::to_value(Some(user)).unwrap()
        );
    }
    state.repo.update_scim_user(user).await.unwrap();
    state.repo.update_scim_group(group).await.unwrap();
}
#[tokio::test]
async fn conditional_put_rejects_explicit_realm_move_preserves_omitted() {
    use crate::inbound::write::Condition;
    use axum::http::{HeaderMap, HeaderValue, header::IF_MATCH};
    for sql in [false, true] {
        let dir = std::env::temp_dir().join(format!("qid-scim-realm-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = if sql {
            format!("sqlite:{}", dir.join("store.db").display())
        } else {
            dir.join("store.json").to_str().unwrap().to_string()
        };
        let repo = std::sync::Arc::new(AnyRepository::connect(&url).await.unwrap());
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from("corp"),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        repo.create_realm(
            &TenantId::from("tenant"),
            &RealmId::from("other"),
            "https://other.example.com",
            None,
        )
        .await
        .unwrap();
        let state = SharedState::new(
            test_helpers::test_config(),
            repo.clone(),
            std::sync::Arc::new(LocalSigner::from_secret("test", b"test-secret")),
            serde_json::json!({}),
        )
        .unwrap();
        let user = ScimUser {
            id: "u-realm".into(),
            realm_id: "other".into(),
            external_id: None,
            user_name: "base".into(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        };
        let group = ScimGroup {
            id: "g-realm".into(),
            realm_id: "other".into(),
            display_name: "base".into(),
            members_json: serde_json::json!([]),
        };
        repo.create_scim_user(&user).await.unwrap();
        repo.create_scim_group(&group).await.unwrap();
        // Omitted realm on create keeps the documented default.
        let created = create_user_record(
            &state,
            super::super::parse_create_user(serde_json::json!({"userName": "created"})).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(created.realm_id, "corp");
        let req = serde_json::from_value::<super::super::CreateGroup>(
            serde_json::json!({"displayName": "created"}),
        )
        .unwrap();
        assert!(req.realm.is_none());
        assert_eq!(
            create_group_record(&state, req).await.unwrap().realm_id,
            "corp"
        );
        // Direct If-Match and Bulk version share the record path.
        for via_bulk in [false, true] {
            let before_user = repo.get_scim_user(&user.id).await.unwrap().unwrap();
            let version = crate::response::scim_user_version(&before_user);
            let expected = if via_bulk {
                check_user_preconditions(&state, &user.id, None, Some(&version))
                    .await
                    .unwrap()
            } else {
                let mut headers = HeaderMap::new();
                headers.insert(IF_MATCH, HeaderValue::from_str(&version).unwrap());
                Condition::from_headers("other".to_string(), &headers)
            };
            let explicit = super::super::parse_create_user(
                serde_json::json!({"realm": "corp", "userName": "moved"}),
            )
            .unwrap();
            assert_eq!(
                replace_user_record(&state, &user.id, explicit, expected)
                    .await
                    .unwrap_err()
                    .status_code(),
                400
            );
            let stored = repo.get_scim_user(&user.id).await.unwrap().unwrap();
            assert_eq!(stored.realm_id, "other");
            assert_eq!(stored.user_name, before_user.user_name);
            let version = crate::response::scim_user_version(&stored);
            let expected = if via_bulk {
                check_user_preconditions(&state, &user.id, None, Some(&version))
                    .await
                    .unwrap()
            } else {
                let mut headers = HeaderMap::new();
                headers.insert(IF_MATCH, HeaderValue::from_str(&version).unwrap());
                Condition::from_headers("other".to_string(), &headers)
            };
            let omitted =
                super::super::parse_create_user(serde_json::json!({"userName": "kept"})).unwrap();
            assert!(omitted.realm.is_none());
            let kept = replace_user_record(&state, &user.id, omitted, expected)
                .await
                .unwrap();
            assert_eq!(kept.realm_id, "other");
            assert_eq!(kept.user_name, "kept");
            let before_group = repo.get_scim_group(&group.id).await.unwrap().unwrap();
            let version = crate::response::scim_group_version(&before_group);
            let expected = if via_bulk {
                check_group_preconditions(&state, &group.id, None, Some(&version))
                    .await
                    .unwrap()
            } else {
                let mut headers = HeaderMap::new();
                headers.insert(IF_MATCH, HeaderValue::from_str(&version).unwrap());
                Condition::from_headers("other".to_string(), &headers)
            };
            let explicit = serde_json::from_value::<super::super::CreateGroup>(
                serde_json::json!({"realm": "corp", "displayName": "moved"}),
            )
            .unwrap();
            assert_eq!(
                replace_group_record(&state, &group.id, explicit, expected)
                    .await
                    .unwrap_err()
                    .status_code(),
                400
            );
            let stored = repo.get_scim_group(&group.id).await.unwrap().unwrap();
            assert_eq!(stored.realm_id, "other");
            assert_eq!(stored.display_name, before_group.display_name);
            let version = crate::response::scim_group_version(&stored);
            let expected = if via_bulk {
                check_group_preconditions(&state, &group.id, None, Some(&version))
                    .await
                    .unwrap()
            } else {
                let mut headers = HeaderMap::new();
                headers.insert(IF_MATCH, HeaderValue::from_str(&version).unwrap());
                Condition::from_headers("other".to_string(), &headers)
            };
            let omitted = serde_json::from_value::<super::super::CreateGroup>(
                serde_json::json!({"displayName": "kept"}),
            )
            .unwrap();
            assert!(omitted.realm.is_none());
            let kept = replace_group_record(&state, &group.id, omitted, expected)
                .await
                .unwrap();
            assert_eq!(kept.realm_id, "other");
            assert_eq!(kept.display_name, "kept");
        }
        // Scoped context stays authoritative over an explicit body realm.
        {
            let current = repo.get_scim_user(&user.id).await.unwrap().unwrap();
            let expected = check_user_preconditions(
                &state,
                &user.id,
                Some("other"),
                Some(&crate::response::scim_user_version(&current)),
            )
            .await
            .unwrap();
            let mut req = super::super::parse_create_user(
                serde_json::json!({"realm": "corp", "userName": "ctx"}),
            )
            .unwrap();
            req.realm = Some("other".to_string());
            let kept = replace_user_record(&state, &user.id, req, expected)
                .await
                .unwrap();
            assert_eq!(kept.realm_id, "other");
            assert_eq!(kept.user_name, "ctx");
            let current = repo.get_scim_group(&group.id).await.unwrap().unwrap();
            let expected = check_group_preconditions(
                &state,
                &group.id,
                Some("other"),
                Some(&crate::response::scim_group_version(&current)),
            )
            .await
            .unwrap();
            let mut req = serde_json::from_value::<super::super::CreateGroup>(
                serde_json::json!({"realm": "corp", "displayName": "ctx"}),
            )
            .unwrap();
            req.realm = Some("other".to_string());
            let kept = replace_group_record(&state, &group.id, req, expected)
                .await
                .unwrap();
            assert_eq!(kept.realm_id, "other");
            assert_eq!(kept.display_name, "ctx");
        }
        drop(state);
        let repo = std::sync::Arc::try_unwrap(repo).ok().unwrap();
        if let AnyRepository::Sql(repo) = repo {
            repo.close().await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
