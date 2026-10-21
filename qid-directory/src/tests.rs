use super::*;
use qid_core::{state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::FileRepository;

async fn setup() -> Arc<SharedState<FileRepository>> {
    let path = std::env::temp_dir().join(format!("qid-directory-{}.json", ulid::Ulid::new()));
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    Arc::new(
        SharedState::new(
            test_helpers::test_config(),
            repo,
            signer,
            serde_json::json!({}),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn hr_import_creates_moves_and_deprovisions_scim_user() {
    let state = setup().await;
    let results = import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-1".to_string(),
            user_name: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Engineering".to_string()),
            manager_external_id: Some("hr-manager".to_string()),
            event: LifecycleEvent::Joiner,
        }],
    )
    .await
    .unwrap();
    assert_eq!(results[0].action, HrImportAction::Created);
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].enterprise_json["department"], "Engineering");
    assert_eq!(
        user_employment_state(&users[0]),
        Some(EmploymentState::Active)
    );

    let user_id = users[0].id.clone();
    let results = import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-1".to_string(),
            user_name: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Platform".to_string()),
            manager_external_id: None,
            event: LifecycleEvent::Mover,
        }],
    )
    .await
    .unwrap();
    assert_eq!(results[0].action, HrImportAction::Updated);
    let moved = state.repo.get_scim_user(&user_id).await.unwrap().unwrap();
    assert_eq!(moved.enterprise_json["department"], "Platform");
    assert!(moved.active);

    let results = import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-1".to_string(),
            user_name: "alice@example.com".to_string(),
            email: None,
            display_name: None,
            department: None,
            manager_external_id: None,
            event: LifecycleEvent::Leaver,
        }],
    )
    .await
    .unwrap();
    assert_eq!(results[0].action, HrImportAction::Deprovisioned);
    let deprovisioned = state.repo.get_scim_user(&user_id).await.unwrap().unwrap();
    assert!(!deprovisioned.active);
    assert_eq!(
        user_employment_state(&deprovisioned),
        Some(EmploymentState::Inactive)
    );
    assert!(deprovisioned.deprovisioned_at.is_some());
    assert_eq!(
        deprovisioned.enterprise_json["deprovisioned_at"],
        serde_json::Value::from(deprovisioned.deprovisioned_at.unwrap())
    );

    // A later HR reactivation starts a new lifecycle and clears the old
    // authoritative timestamp without depending on mover attribute semantics.
    let results = import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-1".to_string(),
            user_name: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Research".to_string()),
            manager_external_id: Some("hr-manager-2".to_string()),
            event: LifecycleEvent::Mover,
        }],
    )
    .await
    .unwrap();
    assert_eq!(results[0].action, HrImportAction::Updated);
    let reactivated = state.repo.get_scim_user(&user_id).await.unwrap().unwrap();
    assert!(reactivated.active);
    assert_eq!(reactivated.deprovisioned_at, None);
    assert!(
        reactivated
            .enterprise_json
            .get("deprovisioned_at")
            .is_none()
    );
}

#[tokio::test]
async fn deprovision_sla_audit_reports_met_pending_violated_and_missing() {
    let state = setup().await;
    let mut met_user = ScimUser {
        id: "user-met".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("hr-met".to_string()),
        user_name: "met@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: false,
    };
    mark_deprovisioned(&mut met_user, 1_050);
    state.repo.create_scim_user(&met_user).await.unwrap();
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-pending".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-pending".to_string()),
            user_name: "pending@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-violated".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-violated".to_string()),
            user_name: "violated@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();

    let findings = audit_deprovision_sla(
        &state,
        "corp",
        &[
            DeprovisionEvent {
                external_id: "hr-met".to_string(),
                occurred_at: 1_000,
                provider_id: None,
            },
            DeprovisionEvent {
                external_id: "hr-pending".to_string(),
                occurred_at: 2_000,
                provider_id: None,
            },
            DeprovisionEvent {
                external_id: "hr-violated".to_string(),
                occurred_at: 1_000,
                provider_id: None,
            },
            DeprovisionEvent {
                external_id: "hr-missing".to_string(),
                occurred_at: 1_000,
                provider_id: None,
            },
        ],
        100,
        2_050,
    )
    .await
    .unwrap();

    assert_eq!(findings[0].status, DeprovisionSlaStatus::Met);
    assert_eq!(findings[0].deprovisioned_at, Some(1_050));
    assert_eq!(findings[1].status, DeprovisionSlaStatus::Pending);
    assert_eq!(findings[2].status, DeprovisionSlaStatus::Violated);
    assert_eq!(findings[3].status, DeprovisionSlaStatus::MissingUser);
}

#[tokio::test]
async fn ldap_sync_creates_updates_deactivates_missing_and_tracks_unchanged() {
    let state = setup().await;
    let first = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[
            LdapDirectoryEntry {
                dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
                uid: "alice@example.com".to_string(),
                mail: Some("alice@example.com".to_string()),
                display_name: Some("Alice Example".to_string()),
                department: Some("Engineering".to_string()),
                manager_dn: Some("uid=manager,ou=people,dc=example,dc=com".to_string()),
                enabled: true,
            },
            LdapDirectoryEntry {
                dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                uid: "bob@example.com".to_string(),
                mail: Some("bob@example.com".to_string()),
                display_name: Some("Bob Example".to_string()),
                department: Some("Sales".to_string()),
                manager_dn: None,
                enabled: true,
            },
        ],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(first.created_user_ids.len(), 2);
    assert!(first.updated_user_ids.is_empty());

    let second = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
            uid: "alice@example.com".to_string(),
            mail: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Platform".to_string()),
            manager_dn: Some("uid=manager,ou=people,dc=example,dc=com".to_string()),
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 20,
        },
    )
    .await
    .unwrap();
    assert_eq!(second.updated_user_ids.len(), 1);
    assert_eq!(second.deactivated_user_ids.len(), 1);

    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    let alice = users
        .iter()
        .find(|user| user.user_name == "alice@example.com")
        .unwrap();
    let bob = users
        .iter()
        .find(|user| user.user_name == "bob@example.com")
        .unwrap();
    assert_eq!(alice.enterprise_json["source"], LDAP_SOURCE_SCHEMA);
    assert_eq!(alice.enterprise_json["department"], "Platform");
    assert_eq!(user_employment_state(alice), Some(EmploymentState::Active));
    assert_eq!(
        alice.enterprise_json["manager"]["externalId"],
        "uid=manager,ou=people,dc=example,dc=com"
    );
    assert!(alice.active);
    assert!(!bob.active);
    assert_eq!(user_employment_state(bob), Some(EmploymentState::Inactive));
    assert_eq!(bob.deprovisioned_at, Some(20));
    assert_eq!(bob.enterprise_json["deprovisioned_at"], 20);
    let alice_id = alice.id.clone();

    let third = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
            uid: "alice@example.com".to_string(),
            mail: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Platform".to_string()),
            manager_dn: Some("uid=manager,ou=people,dc=example,dc=com".to_string()),
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 20,
        },
    )
    .await
    .unwrap();
    assert_eq!(third.unchanged_user_ids, vec![alice_id]);
}

#[tokio::test]
async fn ldap_sync_skips_break_glass_accounts_when_deactivating_missing_users() {
    let state = setup().await;
    let mut user = ScimUser {
        id: "break-glass-user".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("uid=local-admin,ou=people,dc=example,dc=com".to_string()),
        user_name: "local-admin@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({
            "source": LDAP_SOURCE_SCHEMA,
            "ldap_dn": "uid=local-admin,ou=people,dc=example,dc=com"
        }),
        directory_provider_id: Some("provider-a".to_string()),
        deprovisioned_at: None,
        active: true,
    };
    mark_break_glass(&mut user);
    state.repo.create_scim_user(&user).await.unwrap();

    let result = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 30,
        },
    )
    .await
    .unwrap();

    assert!(result.deactivated_user_ids.is_empty());
    assert_eq!(
        result.break_glass_skipped_user_ids,
        vec!["break-glass-user"]
    );
    let preserved = state
        .repo
        .get_scim_user("break-glass-user")
        .await
        .unwrap()
        .unwrap();
    assert!(preserved.active);
    assert_eq!(
        preserved.enterprise_json["break_glass_source"],
        BREAK_GLASS_SCHEMA
    );
}

#[tokio::test]
async fn manager_chain_resolves_managers_and_reports_cycles() {
    let state = setup().await;
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[
            LdapDirectoryEntry {
                dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
                uid: "alice@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                enabled: true,
            },
            LdapDirectoryEntry {
                dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                uid: "bob@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: Some("uid=carol,ou=people,dc=example,dc=com".to_string()),
                enabled: true,
            },
            LdapDirectoryEntry {
                dn: "uid=carol,ou=people,dc=example,dc=com".to_string(),
                uid: "carol@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: None,
                enabled: true,
            },
        ],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 40,
        },
    )
    .await
    .unwrap();
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    let alice_id = users
        .iter()
        .find(|user| user.user_name == "alice@example.com")
        .unwrap()
        .id
        .clone();
    let bob_id = users
        .iter()
        .find(|user| user.user_name == "bob@example.com")
        .unwrap()
        .id
        .clone();
    let carol_id = users
        .iter()
        .find(|user| user.user_name == "carol@example.com")
        .unwrap()
        .id
        .clone();

    let chain = resolve_manager_chain(&state, &alice_id).await.unwrap();
    assert_eq!(chain.manager_user_ids, vec![bob_id.clone(), carol_id]);
    assert_eq!(chain.unresolved_manager_external_id, None);
    assert!(!chain.cycle_detected);

    let mut bob = state.repo.get_scim_user(&bob_id).await.unwrap().unwrap();
    bob.enterprise_json["manager"] =
        serde_json::json!({ "externalId": "uid=alice,ou=people,dc=example,dc=com" });
    state.repo.update_scim_user(&bob).await.unwrap();

    let cyclic = resolve_manager_chain(&state, &alice_id).await.unwrap();
    assert_eq!(cyclic.manager_user_ids, vec![bob_id]);
    assert_eq!(
        cyclic.unresolved_manager_external_id,
        Some("uid=alice,ou=people,dc=example,dc=com".to_string())
    );
    assert!(cyclic.cycle_detected);
}

#[tokio::test]
async fn ldap_sync_rejects_duplicate_dns() {
    let state = setup().await;
    let err = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[
            LdapDirectoryEntry {
                dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
                uid: "alice@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: None,
                enabled: true,
            },
            LdapDirectoryEntry {
                dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
                uid: "alice2@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: None,
                enabled: true,
            },
        ],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 10,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, QidError::BadRequest { .. }));
}

#[tokio::test]
async fn nested_group_expansion_flattens_users_and_stops_cycles() {
    let state = setup().await;
    for user_id in ["user-a", "user-b"] {
        state
            .repo
            .create_scim_user(&ScimUser {
                id: user_id.to_string(),
                realm_id: "corp".to_string(),
                external_id: None,
                user_name: format!("{user_id}@example.com"),
                name_json: serde_json::json!({}),
                emails_json: serde_json::json!([]),
                enterprise_json: serde_json::json!({}),
                directory_provider_id: None,
                deprovisioned_at: None,
                active: true,
            })
            .await
            .unwrap();
    }
    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-root".to_string(),
            realm_id: "corp".to_string(),
            display_name: "root".to_string(),
            members_json: serde_json::json!([
                {"value":"user-a"},
                {"value":"group-child", "type":"Group"},
                {"value":"group-missing", "type":"Group"},
                {"value":"group-other-realm", "type":"Group"}
            ]),
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-child".to_string(),
            realm_id: "corp".to_string(),
            display_name: "child".to_string(),
            members_json: serde_json::json!([
                {"value":"user-b"},
                {"value":"group-root", "type":"Group"}
            ]),
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-other-realm".to_string(),
            realm_id: "other".to_string(),
            display_name: "outside".to_string(),
            members_json: serde_json::json!([{"value":"user-outside"}]),
        })
        .await
        .unwrap();

    let expanded = expand_nested_group_members(&state, "group-root")
        .await
        .unwrap();
    assert_eq!(expanded.group_id, "group-root");
    assert_eq!(expanded.user_ids, vec!["user-a", "user-b"]);
    assert_eq!(expanded.nested_group_ids, vec!["group-child"]);
}

#[tokio::test]
async fn dynamic_group_sync_replaces_user_members_and_preserves_nested_groups() {
    let state = setup().await;
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-platform".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-platform".to_string()),
            user_name: "platform@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({
                "department": "Platform",
                "manager": { "externalId": "hr-manager" }
            }),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-sales".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-sales".to_string()),
            user_name: "sales@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({ "department": "Sales" }),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-child".to_string(),
            realm_id: "corp".to_string(),
            display_name: "child".to_string(),
            members_json: serde_json::json!([]),
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-dynamic".to_string(),
            realm_id: "corp".to_string(),
            display_name: "platform-users".to_string(),
            members_json: serde_json::json!([
                {"value":"user-sales", "type":"User"},
                {"value":"group-child", "type":"Group"}
            ]),
        })
        .await
        .unwrap();

    let result = sync_dynamic_group_members(
        &state,
        "group-dynamic",
        &DynamicGroupRule {
            match_mode: DynamicGroupMatchMode::All,
            conditions: vec![
                DynamicGroupCondition {
                    field: DynamicGroupField::Department,
                    operator: DynamicGroupOperator::Eq,
                    value: Some("Platform".to_string()),
                },
                DynamicGroupCondition {
                    field: DynamicGroupField::Active,
                    operator: DynamicGroupOperator::Eq,
                    value: Some("true".to_string()),
                },
            ],
        },
    )
    .await
    .unwrap();

    assert_eq!(result.matched_user_ids, vec!["user-platform"]);
    assert_eq!(result.added_user_ids, vec!["user-platform"]);
    assert_eq!(result.removed_user_ids, vec!["user-sales"]);
    let group = state
        .repo
        .get_scim_group("group-dynamic")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        group.members_json,
        serde_json::json!([
            {"value":"group-child", "type":"Group"},
            {"value":"user-platform", "type":"User"}
        ])
    );
}

#[tokio::test]
async fn dynamic_group_any_mode_requires_at_least_one_condition() {
    let user = ScimUser {
        id: "user".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("hr-1".to_string()),
        user_name: "alice@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({
            "department": "Engineering",
            "employment_state": "active"
        }),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    assert!(!dynamic_group_rule_matches(
        &DynamicGroupRule {
            match_mode: DynamicGroupMatchMode::Any,
            conditions: vec![],
        },
        &user
    ));
    assert!(dynamic_group_rule_matches(
        &DynamicGroupRule {
            match_mode: DynamicGroupMatchMode::Any,
            conditions: vec![DynamicGroupCondition {
                field: DynamicGroupField::UserName,
                operator: DynamicGroupOperator::Contains,
                value: Some("@example.com".to_string()),
            }],
        },
        &user
    ));
    assert!(dynamic_group_rule_matches(
        &DynamicGroupRule {
            match_mode: DynamicGroupMatchMode::All,
            conditions: vec![DynamicGroupCondition {
                field: DynamicGroupField::EmploymentState,
                operator: DynamicGroupOperator::Eq,
                value: Some("active".to_string()),
            }],
        },
        &user
    ));
}

#[tokio::test]
async fn ldap_sync_is_provider_scoped_with_shared_dn() {
    let state = setup().await;
    let dn = "uid=shared,ou=people,dc=example,dc=com".to_string();
    let first_a = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: dn.clone(),
            uid: "shared-a@example.com".to_string(),
            mail: None,
            display_name: None,
            department: Some("Engineering".to_string()),
            manager_dn: None,
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(first_a.created_user_ids.len(), 1);
    let first_b = sync_ldap_entries(
        &state,
        "corp",
        "provider-b",
        &[LdapDirectoryEntry {
            dn: dn.clone(),
            uid: "shared-b@example.com".to_string(),
            mail: None,
            display_name: None,
            department: Some("Sales".to_string()),
            manager_dn: None,
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 11,
        },
    )
    .await
    .unwrap();
    assert_eq!(first_b.created_user_ids.len(), 1);
    assert_ne!(first_a.created_user_ids, first_b.created_user_ids);
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert_eq!(users.len(), 2);
    for user in &users {
        assert_eq!(user.external_id.as_deref(), Some(dn.as_str()));
        assert_eq!(user.enterprise_json["source"], LDAP_SOURCE_SCHEMA);
    }

    let user_a_id = first_a.created_user_ids[0].clone();
    let user_b_id = first_b.created_user_ids[0].clone();
    let update_a = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: dn.clone(),
            uid: "shared-a@example.com".to_string(),
            mail: None,
            display_name: None,
            department: Some("Platform".to_string()),
            manager_dn: None,
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 20,
        },
    )
    .await
    .unwrap();
    assert_eq!(update_a.updated_user_ids, vec![user_a_id.clone()]);
    let user_b = state.repo.get_scim_user(&user_b_id).await.unwrap().unwrap();
    assert_eq!(user_b.user_name, "shared-b@example.com");
    assert_eq!(user_b.enterprise_json["department"], "Sales");
    assert!(user_b.active);

    let deactivate_a = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 30,
        },
    )
    .await
    .unwrap();
    assert_eq!(deactivate_a.deactivated_user_ids, vec![user_a_id.clone()]);
    let user_a = state.repo.get_scim_user(&user_a_id).await.unwrap().unwrap();
    assert!(!user_a.active);
    let user_b = state.repo.get_scim_user(&user_b_id).await.unwrap().unwrap();
    assert!(user_b.active);
    assert_eq!(user_b.enterprise_json["department"], "Sales");
}

#[tokio::test]
async fn ldap_manager_chain_resolves_only_within_owning_provider() {
    let state = setup().await;
    let shared_manager_dn = "uid=manager,ou=people,dc=example,dc=com".to_string();
    let mut user_ids = Vec::new();
    let mut manager_ids = Vec::new();

    for (provider_id, user_dn, user_name, manager_name) in [
        (
            "provider-a",
            "uid=alice,ou=people,dc=example,dc=com",
            "alice@example.com",
            "manager-a@example.com",
        ),
        (
            "provider-b",
            "uid=bob,ou=people,dc=example,dc=com",
            "bob@example.com",
            "manager-b@example.com",
        ),
    ] {
        let result = sync_ldap_entries(
            &state,
            "corp",
            provider_id,
            &[
                LdapDirectoryEntry {
                    dn: user_dn.to_string(),
                    uid: user_name.to_string(),
                    mail: None,
                    display_name: None,
                    department: None,
                    manager_dn: Some(shared_manager_dn.clone()),
                    enabled: true,
                },
                LdapDirectoryEntry {
                    dn: shared_manager_dn.clone(),
                    uid: manager_name.to_string(),
                    mail: None,
                    display_name: None,
                    department: None,
                    manager_dn: None,
                    enabled: true,
                },
            ],
            LdapSyncOptions {
                deactivate_missing: false,
                synced_at: 70,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.created_user_ids.len(), 2);
        user_ids.push(result.created_user_ids[0].clone());
        manager_ids.push(result.created_user_ids[1].clone());
    }

    let chain_a = resolve_manager_chain(&state, &user_ids[0]).await.unwrap();
    let chain_b = resolve_manager_chain(&state, &user_ids[1]).await.unwrap();
    assert_eq!(chain_a.manager_user_ids, vec![manager_ids[0].clone()]);
    assert_eq!(chain_b.manager_user_ids, vec![manager_ids[1].clone()]);
}

#[tokio::test]
async fn ldap_sync_ignores_unrelated_ownerless_fake_marker() {
    let state = setup().await;
    // Forged enterprise keys on an ownerless row must not confer ownership and
    // must not block an unrelated sync.
    let forged = ScimUser {
        id: "ghost-user".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("uid=ghost,ou=people,dc=example,dc=com".to_string()),
        user_name: "ghost@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({
            "source": LDAP_SOURCE_SCHEMA,
            "ldap_provider_id": "provider-a",
            "ldap_dn": "uid=ghost,ou=people,dc=example,dc=com"
        }),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    let forged_before = forged.clone();
    state.repo.create_scim_user(&forged).await.unwrap();
    let result = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
            uid: "alice@example.com".to_string(),
            mail: None,
            display_name: None,
            department: Some("Platform".to_string()),
            manager_dn: None,
            enabled: true,
        }],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 40,
        },
    )
    .await
    .unwrap();
    assert_eq!(result.created_user_ids.len(), 1);
    let ghost = state
        .repo
        .get_scim_user("ghost-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ghost.external_id, forged_before.external_id);
    assert_eq!(ghost.user_name, forged_before.user_name);
    assert_eq!(ghost.enterprise_json, forged_before.enterprise_json);
    assert_eq!(ghost.directory_provider_id, None);
    assert!(ghost.active);
    let alice = state
        .repo
        .get_scim_user(&result.created_user_ids[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.directory_provider_id, Some("provider-a".to_string()));
    assert_eq!(
        alice.external_id.as_deref(),
        Some("uid=alice,ou=people,dc=example,dc=com")
    );
}

#[tokio::test]
async fn ldap_sync_rejects_colliding_unowned_dn_before_any_write() {
    let state = setup().await;
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "ghost-user".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("uid=clash,ou=people,dc=example,dc=com".to_string()),
            user_name: "ghost@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({
                "source": LDAP_SOURCE_SCHEMA,
                "ldap_provider_id": "provider-a",
                "ldap_dn": "uid=clash,ou=people,dc=example,dc=com"
            }),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "owned-user".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("uid=owned,ou=people,dc=example,dc=com".to_string()),
            user_name: "owned@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({
                "source": LDAP_SOURCE_SCHEMA,
                "ldap_dn": "uid=owned,ou=people,dc=example,dc=com"
            }),
            directory_provider_id: Some("provider-a".to_string()),
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();
    let err = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[
            LdapDirectoryEntry {
                dn: "uid=clash,ou=people,dc=example,dc=com".to_string(),
                uid: "clash@example.com".to_string(),
                mail: None,
                display_name: None,
                department: None,
                manager_dn: None,
                enabled: true,
            },
            LdapDirectoryEntry {
                dn: "uid=owned,ou=people,dc=example,dc=com".to_string(),
                uid: "owned@example.com".to_string(),
                mail: None,
                display_name: None,
                department: Some("Platform".to_string()),
                manager_dn: None,
                enabled: true,
            },
        ],
        LdapSyncOptions {
            deactivate_missing: true,
            synced_at: 41,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    // No writes happened: no clash user was created, the owned user is untouched.
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert_eq!(users.len(), 2);
    let owned = state
        .repo
        .get_scim_user("owned-user")
        .await
        .unwrap()
        .unwrap();
    assert!(owned.active);
    assert!(owned.enterprise_json.get("department").is_none());
    let ghost = state
        .repo
        .get_scim_user("ghost-user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ghost.directory_provider_id, None);
    assert!(ghost.active);
}

#[tokio::test]
async fn ldap_sync_rejects_duplicate_owned_keys() {
    let state = setup().await;
    for id in ["dup-one", "dup-two"] {
        state
            .repo
            .create_scim_user(&ScimUser {
                id: id.to_string(),
                realm_id: "corp".to_string(),
                external_id: Some("uid=dup,ou=people,dc=example,dc=com".to_string()),
                user_name: format!("{id}@example.com"),
                name_json: serde_json::json!({}),
                emails_json: serde_json::json!([]),
                enterprise_json: serde_json::json!({
                    "source": LDAP_SOURCE_SCHEMA,
                    "ldap_dn": "uid=dup,ou=people,dc=example,dc=com"
                }),
                directory_provider_id: Some("provider-a".to_string()),
                deprovisioned_at: None,
                active: true,
            })
            .await
            .unwrap();
    }
    let err = sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 50,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
}

#[tokio::test]
async fn ldap_sync_rejects_blank_provider_id() {
    let state = setup().await;
    for provider_id in ["", "   "] {
        let err = sync_ldap_entries(
            &state,
            "corp",
            provider_id,
            &[],
            LdapSyncOptions {
                deactivate_missing: false,
                synced_at: 60,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, QidError::BadRequest { .. }),
            "expected bad request for {provider_id:?}, got {err:?}"
        );
    }
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert!(users.is_empty());
}

#[tokio::test]
async fn ldap_disabled_snapshot_stamps_preserves_clears_and_restamps() {
    let state = setup().await;
    let dn = "uid=carol,ou=people,dc=example,dc=com".to_string();
    let enabled = LdapDirectoryEntry {
        dn: dn.clone(),
        uid: "carol@example.com".to_string(),
        mail: None,
        display_name: None,
        department: None,
        manager_dn: None,
        enabled: true,
    };
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        std::slice::from_ref(&enabled),
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_000,
        },
    )
    .await
    .unwrap();
    let user = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap()
        .into_iter()
        .find(|user| user.external_id.as_deref() == Some(dn.as_str()))
        .unwrap();
    assert!(user.active);
    assert_eq!(user.deprovisioned_at, None);
    assert!(user.enterprise_json.get("deprovisioned_at").is_none());

    let disabled = LdapDirectoryEntry {
        enabled: false,
        ..enabled.clone()
    };
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        std::slice::from_ref(&disabled),
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_050,
        },
    )
    .await
    .unwrap();
    let user = state.repo.get_scim_user(&user.id).await.unwrap().unwrap();
    assert!(!user.active);
    assert_eq!(user.deprovisioned_at, Some(1_050));
    assert_eq!(user.enterprise_json["deprovisioned_at"], 1_050);
    assert_eq!(
        user_employment_state(&user),
        Some(EmploymentState::Inactive)
    );
    let findings = audit_deprovision_sla(
        &state,
        "corp",
        &[DeprovisionEvent {
            external_id: dn.clone(),
            occurred_at: 1_000,
            provider_id: None,
        }],
        100,
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(findings[0].status, DeprovisionSlaStatus::Met);
    assert_eq!(findings[0].deprovisioned_at, Some(1_050));

    // Repeated disabled snapshots preserve the first timestamp.
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        std::slice::from_ref(&disabled),
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_080,
        },
    )
    .await
    .unwrap();
    let user = state.repo.get_scim_user(&user.id).await.unwrap().unwrap();
    assert_eq!(user.deprovisioned_at, Some(1_050));
    assert_eq!(user.enterprise_json["deprovisioned_at"], 1_050);

    // Reactivation clears the authoritative timestamp and stale marker.
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        std::slice::from_ref(&enabled),
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_100,
        },
    )
    .await
    .unwrap();
    let user = state.repo.get_scim_user(&user.id).await.unwrap().unwrap();
    assert!(user.active);
    assert_eq!(user.deprovisioned_at, None);
    assert!(user.enterprise_json.get("deprovisioned_at").is_none());

    // A later disable gets a fresh timestamp.
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[disabled],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_200,
        },
    )
    .await
    .unwrap();
    let user = state.repo.get_scim_user(&user.id).await.unwrap().unwrap();
    assert!(!user.active);
    assert_eq!(user.deprovisioned_at, Some(1_200));
    assert_eq!(user.enterprise_json["deprovisioned_at"], 1_200);
}

#[tokio::test]
async fn ldap_first_seen_disabled_user_gets_transition_timestamp() {
    let state = setup().await;
    let dn = "uid=first-disabled,ou=people,dc=example,dc=com".to_string();
    sync_ldap_entries(
        &state,
        "corp",
        "provider-a",
        &[LdapDirectoryEntry {
            dn: dn.clone(),
            uid: "first-disabled@example.com".to_string(),
            mail: None,
            display_name: None,
            department: None,
            manager_dn: None,
            enabled: false,
        }],
        LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 1_050,
        },
    )
    .await
    .unwrap();
    let user = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap()
        .into_iter()
        .find(|user| user.external_id.as_deref() == Some(dn.as_str()))
        .unwrap();
    assert!(!user.active);
    assert_eq!(user.deprovisioned_at, Some(1_050));
    assert_eq!(user.enterprise_json["deprovisioned_at"], 1_050);
    assert_eq!(
        user_employment_state(&user),
        Some(EmploymentState::Inactive)
    );
}

#[tokio::test]
async fn audit_deprovision_sla_ignores_forged_enterprise_marker() {
    let state = setup().await;
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-forged".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-forged".to_string()),
            user_name: "forged@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({ "deprovisioned_at": 1_050 }),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: false,
        })
        .await
        .unwrap();
    let findings = audit_deprovision_sla(
        &state,
        "corp",
        &[DeprovisionEvent {
            external_id: "hr-forged".to_string(),
            occurred_at: 1_000,
            provider_id: None,
        }],
        100,
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(findings[0].status, DeprovisionSlaStatus::Violated);
    assert_eq!(findings[0].deprovisioned_at, None);
}

#[tokio::test]
async fn audit_deprovision_sla_disambiguates_shared_dn_by_provider_id() {
    let state = setup().await;
    let dn = "uid=shared,ou=people,dc=example,dc=com".to_string();
    let mut user_a = ScimUser {
        id: "user-shared-a".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some(dn.clone()),
        user_name: "shared-a@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("provider-a".to_string()),
        deprovisioned_at: None,
        active: false,
    };
    mark_deprovisioned(&mut user_a, 1_050);
    state.repo.create_scim_user(&user_a).await.unwrap();
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-shared-b".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some(dn.clone()),
            user_name: "shared-b@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: Some("provider-b".to_string()),
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();

    // Legacy provider-less events fail closed instead of selecting the first match.
    let legacy = DeprovisionEvent {
        external_id: dn.clone(),
        occurred_at: 1_000,
        provider_id: None,
    };
    let err = audit_deprovision_sla(&state, "corp", std::slice::from_ref(&legacy), 100, 2_000)
        .await
        .expect_err("ambiguous legacy event must conflict");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    assert!(
        err.to_string().contains("provider_id"),
        "conflict must tell caller to provide provider_id: {err}"
    );

    // Explicit provider scope reports each owner's actual SLA.
    let finding_a = audit_deprovision_sla(
        &state,
        "corp",
        &[DeprovisionEvent {
            external_id: dn.clone(),
            occurred_at: 1_000,
            provider_id: Some("provider-a".to_string()),
        }],
        100,
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(finding_a.len(), 1);
    assert_eq!(finding_a[0].user_id.as_deref(), Some("user-shared-a"));
    assert_eq!(finding_a[0].status, DeprovisionSlaStatus::Met);
    assert_eq!(finding_a[0].deprovisioned_at, Some(1_050));

    let finding_b = audit_deprovision_sla(
        &state,
        "corp",
        &[DeprovisionEvent {
            external_id: dn.clone(),
            occurred_at: 1_000,
            provider_id: Some("provider-b".to_string()),
        }],
        100,
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(finding_b.len(), 1);
    assert_eq!(finding_b[0].user_id.as_deref(), Some("user-shared-b"));
    assert_eq!(finding_b[0].status, DeprovisionSlaStatus::Violated);
    assert_eq!(finding_b[0].deprovisioned_at, None);

    // Blank provider scope is rejected, never treated as legacy.
    let blank_err = audit_deprovision_sla(
        &state,
        "corp",
        &[DeprovisionEvent {
            external_id: dn.clone(),
            occurred_at: 1_000,
            provider_id: Some("  ".to_string()),
        }],
        100,
        2_000,
    )
    .await
    .expect_err("blank provider_id must be rejected");
    assert!(
        matches!(blank_err, qid_core::error::QidError::BadRequest { .. }),
        "expected bad request, got {blank_err:?}"
    );

    // Old JSON without provider_id remains parseable as a legacy event.
    let legacy_json: DeprovisionEvent =
        serde_json::from_value(serde_json::json!({ "external_id": dn, "occurred_at": 1_000 }))
            .unwrap();
    assert_eq!(legacy_json.provider_id, None);
}

#[test]
fn find_deprovision_user_is_order_independent_for_shared_dn() {
    let dn = "uid=shared,ou=people,dc=example,dc=com".to_string();
    let user_a = ScimUser {
        id: "user-shared-a".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some(dn.clone()),
        user_name: "shared-a@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("provider-a".to_string()),
        deprovisioned_at: Some(1_050),
        active: false,
    };
    let user_b = ScimUser {
        id: "user-shared-b".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some(dn.clone()),
        user_name: "shared-b@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("provider-b".to_string()),
        deprovisioned_at: None,
        active: true,
    };
    let forward = vec![user_a.clone(), user_b.clone()];
    let mut reversed = forward.clone();
    reversed.reverse();
    for users in [&forward, &reversed] {
        let legacy = DeprovisionEvent {
            external_id: dn.clone(),
            occurred_at: 1_000,
            provider_id: None,
        };
        let err = find_deprovision_user(users, &legacy).expect_err("legacy must conflict");
        assert!(
            matches!(err, qid_core::error::QidError::Conflict { .. }),
            "expected conflict, got {err:?}"
        );
        for (provider, expected_id) in [
            ("provider-a", "user-shared-a"),
            ("provider-b", "user-shared-b"),
        ] {
            let event = DeprovisionEvent {
                external_id: dn.clone(),
                occurred_at: 1_000,
                provider_id: Some(provider.to_string()),
            };
            let resolved = find_deprovision_user(users, &event)
                .unwrap()
                .expect("scoped event must resolve");
            assert_eq!(resolved.id, expected_id);
        }
    }

    // Duplicate rows within one provider fail closed even when scoped.
    let duplicated = vec![user_a.clone(), user_a.clone()];
    let scoped = DeprovisionEvent {
        external_id: dn.clone(),
        occurred_at: 1_000,
        provider_id: Some("provider-a".to_string()),
    };
    let err = find_deprovision_user(&duplicated, &scoped).expect_err("duplicate must conflict");
    assert!(
        matches!(err, qid_core::error::QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
}

#[tokio::test]
async fn hr_import_rejects_duplicate_joiners_before_any_write() {
    let state = setup().await;
    let err = import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-dup".to_string(),
                user_name: "dup-one@example.com".to_string(),
                email: Some("dup-one@example.com".to_string()),
                display_name: None,
                department: Some("Engineering".to_string()),
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
            HrRecord {
                external_id: "hr-dup".to_string(),
                user_name: "dup-two@example.com".to_string(),
                email: Some("dup-two@example.com".to_string()),
                display_name: None,
                department: Some("Sales".to_string()),
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
        ],
    )
    .await
    .expect_err("repeated HR key must conflict");
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert!(users.is_empty(), "preflight must leave storage unchanged");
}

#[tokio::test]
async fn hr_import_rejects_joiner_leaver_repeated_key_before_any_create() {
    let state = setup().await;
    let err = import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-flap".to_string(),
                user_name: "flap@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
            HrRecord {
                external_id: "hr-flap".to_string(),
                user_name: "flap@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Leaver,
            },
        ],
    )
    .await
    .expect_err("repeated key across joiner/leaver must conflict");
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert!(
        users.is_empty(),
        "joiner prefix must not be created before the repeated-key conflict"
    );

    // A missing leaver later in the batch also fails before earlier writes.
    let err = import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-new".to_string(),
                user_name: "new@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
            HrRecord {
                external_id: "hr-missing".to_string(),
                user_name: "missing@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Leaver,
            },
        ],
    )
    .await
    .expect_err("missing leaver target must fail before writes");
    assert!(
        matches!(err, QidError::NotFound { .. }),
        "expected not found, got {err:?}"
    );
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert!(
        users.is_empty(),
        "valid prefix must not be written before the missing-target failure"
    );
}

#[tokio::test]
async fn hr_import_leaver_conflicts_on_provider_owned_duplicates_without_mutation() {
    let state = setup().await;
    for (id, provider) in [
        ("user-shared-a", "provider-a"),
        ("user-shared-b", "provider-b"),
    ] {
        state
            .repo
            .create_scim_user(&ScimUser {
                id: id.to_string(),
                realm_id: "corp".to_string(),
                external_id: Some("hr-shared".to_string()),
                user_name: format!("{id}@example.com"),
                name_json: serde_json::json!({}),
                emails_json: serde_json::json!([]),
                enterprise_json: serde_json::json!({}),
                directory_provider_id: Some(provider.to_string()),
                deprovisioned_at: None,
                active: true,
            })
            .await
            .unwrap();
    }
    state
        .repo
        .create_scim_user(&ScimUser {
            id: "user-ok".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("hr-ok".to_string()),
            user_name: "ok@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({ "department": "Engineering" }),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        })
        .await
        .unwrap();

    // A single ambiguous leaver fails closed and changes neither duplicate.
    let err = import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-shared".to_string(),
            user_name: "shared@example.com".to_string(),
            email: None,
            display_name: None,
            department: None,
            manager_external_id: None,
            event: LifecycleEvent::Leaver,
        }],
    )
    .await
    .expect_err("shared external_id must conflict");
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    for id in ["user-shared-a", "user-shared-b"] {
        let user = state.repo.get_scim_user(id).await.unwrap().unwrap();
        assert!(user.active, "{id} must stay active");
        assert_eq!(user.deprovisioned_at, None, "{id} must stay unmarked");
    }

    // A later ambiguous key also blocks an earlier deterministic prefix write.
    let err = import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-ok".to_string(),
                user_name: "ok@example.com".to_string(),
                email: None,
                display_name: None,
                department: Some("Platform".to_string()),
                manager_external_id: None,
                event: LifecycleEvent::Mover,
            },
            HrRecord {
                external_id: "hr-shared".to_string(),
                user_name: "shared@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Leaver,
            },
        ],
    )
    .await
    .expect_err("ambiguous suffix must block prefix writes");
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    let ok = state.repo.get_scim_user("user-ok").await.unwrap().unwrap();
    assert_eq!(
        ok.enterprise_json
            .get("department")
            .and_then(|v| v.as_str()),
        Some("Engineering"),
        "deterministic prefix must not be written before the conflict"
    );
    for id in ["user-shared-a", "user-shared-b"] {
        let user = state.repo.get_scim_user(id).await.unwrap().unwrap();
        assert!(user.active, "{id} must stay active");
    }
}

#[test]
fn find_hr_user_is_order_independent_for_shared_external_id() {
    let shared = "hr-shared".to_string();
    let user_a = ScimUser {
        id: "user-shared-a".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some(shared.clone()),
        user_name: "shared-a@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("provider-a".to_string()),
        deprovisioned_at: None,
        active: true,
    };
    let user_b = ScimUser {
        id: "user-shared-b".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some(shared.clone()),
        user_name: "shared-b@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({
            "ldap_dn": shared.clone(),
            "source": LDAP_SOURCE_SCHEMA,
        }),
        directory_provider_id: Some("provider-b".to_string()),
        deprovisioned_at: None,
        active: true,
    };
    let forward = vec![user_a.clone(), user_b.clone()];
    let mut reversed = forward.clone();
    reversed.reverse();
    for users in [&forward, &reversed] {
        let err = find_hr_user(users, &shared).expect_err("shared key must conflict");
        assert!(
            matches!(err, QidError::Conflict { .. }),
            "expected conflict, got {err:?}"
        );
    }
    // A unique target resolves the same way in either order, and forged
    // enterprise markers never create a match on their own.
    let forged_only = ScimUser {
        id: "user-forged".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("hr-other".to_string()),
        user_name: "forged@example.com".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({ "ldap_dn": shared.clone() }),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    assert!(
        find_hr_user(std::slice::from_ref(&forged_only), &shared)
            .unwrap()
            .is_none()
    );
    for users in [
        vec![user_a.clone(), forged_only.clone()],
        vec![forged_only.clone(), user_a.clone()],
    ] {
        let resolved = find_hr_user(&users, &shared)
            .unwrap()
            .expect("unique target must resolve");
        assert_eq!(resolved.id, "user-shared-a");
    }
}

#[tokio::test]
async fn hr_mover_none_clears_department_and_manager_with_group_and_chain_effects() {
    let state = setup().await;
    import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-manager".to_string(),
                user_name: "manager@example.com".to_string(),
                email: Some("manager@example.com".to_string()),
                display_name: None,
                department: Some("Engineering".to_string()),
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
            HrRecord {
                external_id: "hr-alice".to_string(),
                user_name: "alice@example.com".to_string(),
                email: Some("alice@example.com".to_string()),
                display_name: None,
                department: Some("Engineering".to_string()),
                manager_external_id: Some("hr-manager".to_string()),
                event: LifecycleEvent::Joiner,
            },
        ],
    )
    .await
    .unwrap();
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    let alice_id = users
        .iter()
        .find(|user| user.external_id.as_deref() == Some("hr-alice"))
        .unwrap()
        .id
        .clone();
    // Unrelated enterprise data must survive mover clearing.
    let mut alice = state.repo.get_scim_user(&alice_id).await.unwrap().unwrap();
    alice.enterprise_json["costCenter"] = serde_json::json!("CC-42");
    state.repo.update_scim_user(&alice).await.unwrap();

    state
        .repo
        .create_scim_group(&ScimGroup {
            id: "group-eng".to_string(),
            realm_id: "corp".to_string(),
            display_name: "eng".to_string(),
            members_json: serde_json::json!([]),
        })
        .await
        .unwrap();
    let eng_rule = DynamicGroupRule {
        match_mode: DynamicGroupMatchMode::All,
        conditions: vec![DynamicGroupCondition {
            field: DynamicGroupField::Department,
            operator: DynamicGroupOperator::Eq,
            value: Some("Engineering".to_string()),
        }],
    };
    let first = sync_dynamic_group_members(&state, "group-eng", &eng_rule)
        .await
        .unwrap();
    assert!(first.matched_user_ids.contains(&alice_id));
    let chain = resolve_manager_chain(&state, &alice_id).await.unwrap();
    assert!(
        !chain.manager_user_ids.is_empty(),
        "manager must resolve before clearing"
    );

    import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-alice".to_string(),
            user_name: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            department: None,
            manager_external_id: None,
            event: LifecycleEvent::Mover,
        }],
    )
    .await
    .unwrap();
    let cleared = state.repo.get_scim_user(&alice_id).await.unwrap().unwrap();
    assert!(
        cleared.enterprise_json.get("department").is_none(),
        "mover None must clear department"
    );
    assert!(
        cleared.enterprise_json.get("manager").is_none(),
        "mover None must clear manager"
    );
    assert_eq!(
        cleared.enterprise_json.get("costCenter"),
        Some(&serde_json::json!("CC-42")),
        "unrelated enterprise data must survive"
    );

    let second = sync_dynamic_group_members(&state, "group-eng", &eng_rule)
        .await
        .unwrap();
    assert!(
        !second.matched_user_ids.contains(&alice_id),
        "cleared user must leave the department group"
    );
    assert!(second.removed_user_ids.contains(&alice_id));
    let chain = resolve_manager_chain(&state, &alice_id).await.unwrap();
    assert!(
        chain.manager_user_ids.is_empty(),
        "cleared manager must not resolve the former manager"
    );
    assert_eq!(chain.unresolved_manager_external_id, None);

    // `Some` still sets after clearing.
    import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-alice".to_string(),
            user_name: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            department: Some("Research".to_string()),
            manager_external_id: Some("hr-manager".to_string()),
            event: LifecycleEvent::Mover,
        }],
    )
    .await
    .unwrap();
    let reset = state.repo.get_scim_user(&alice_id).await.unwrap().unwrap();
    assert_eq!(reset.enterprise_json["department"], "Research");
    assert_eq!(reset.enterprise_json["manager"]["externalId"], "hr-manager");

    // Joiner `None` preserves instead of clearing.
    import_hr_records(
        &state,
        "corp",
        vec![HrRecord {
            external_id: "hr-alice".to_string(),
            user_name: "alice-renamed@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            department: None,
            manager_external_id: None,
            event: LifecycleEvent::Joiner,
        }],
    )
    .await
    .unwrap();
    let preserved = state.repo.get_scim_user(&alice_id).await.unwrap().unwrap();
    assert_eq!(preserved.enterprise_json["department"], "Research");
    assert_eq!(
        preserved.enterprise_json["manager"]["externalId"],
        "hr-manager"
    );
}

mod directory_http_truthfulness {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use qid_core::config::{DirectoryConnectionConfig, DirectoryProviderConfig};
    use qid_core::models::{Admin, AdminElevation};
    use tower::ServiceExt;

    const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";
    const CONFIGURED_PROVIDER_ID: &str = "ad-main";
    const UNKNOWN_PROVIDER_ID: &str = "missing-provider";
    const DISABLED_PROVIDER_ID: &str = "ad-retired";

    async fn setup_routes() -> (Router, Arc<FileRepository>, String) {
        let path =
            std::env::temp_dir().join(format!("qid-directory-routes-{}.json", ulid::Ulid::new()));
        let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
        repo.migrate().await.unwrap();
        let mut config = test_helpers::test_config();
        config.realms[0].tenant_id = Some("test".to_string());
        config.realms[0].protocols.directory.providers = vec![DirectoryProviderConfig {
            id: CONFIGURED_PROVIDER_ID.to_string(),
            provider_type: "active-directory".to_string(),
            enabled: true,
            connection: DirectoryConnectionConfig {
                url: "ldap://ad.example.com".to_string(),
                base_dn: Some("dc=example,dc=com".to_string()),
                ..Default::default()
            },
            sync: Default::default(),
            attribute_mapping: Default::default(),
        }];
        config.realms[0]
            .protocols
            .directory
            .providers
            .push(DirectoryProviderConfig {
                id: DISABLED_PROVIDER_ID.to_string(),
                provider_type: "ldap".to_string(),
                enabled: false,
                connection: DirectoryConnectionConfig {
                    url: "ldaps://retired.example.com".to_string(),
                    ..Default::default()
                },
                sync: Default::default(),
                attribute_mapping: Default::default(),
            });
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let state =
            Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
        let repo = state.repo.clone();
        let now = qid_core::util::now_seconds();
        let admin = Admin {
            id: "directory-admin-id".to_string(),
            tenant_id: "test".to_string(),
            subject: "directory-admin".to_string(),
            roles: vec!["directory.admin".to_string()],
            created_at: now,
        };
        repo.upsert_admin(&admin).await.unwrap();
        let elevation = AdminElevation {
            id: format!("admin-session-{}", ulid::Ulid::new()),
            tenant_id: "test".to_string(),
            admin_id: admin.id.clone(),
            acr: Some("urn:qid:acr:phishing-resistant".to_string()),
            amr: vec!["hwk".to_string()],
            elevation_expires_at: now + 300,
            created_at: now,
        };
        repo.store_admin_elevation(&elevation).await.unwrap();
        let app = directory_routes::<FileRepository>().with_state(state);
        (app, repo, elevation.id)
    }

    async fn directory_call(
        app: Router,
        method: Method,
        uri: &str,
        session: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(session) = session {
            builder = builder.header(ADMIN_SESSION_ID_HEADER, session);
        }
        let response = app
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn patch_known_provider_returns_501_without_fabricated_status() {
        let (app, _repo, session) = setup_routes().await;
        let (status, body) = directory_call(
            app,
            Method::PATCH,
            &format!("/directory/v1/providers/{CONFIGURED_PROVIDER_ID}"),
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["error"], "unsupported");
        assert_eq!(body["id"], CONFIGURED_PROVIDER_ID);
        assert!(
            body["detail"].as_str().unwrap().contains("configuration"),
            "501 detail must explain configuration-managed provider state: {body}"
        );
        assert!(
            !body.to_string().contains("connected"),
            "must not fabricate provider status: {body}"
        );
    }

    #[tokio::test]
    async fn trigger_sync_known_provider_returns_501_and_records_no_audit_event() {
        let (app, repo, session) = setup_routes().await;
        let (status, body) = directory_call(
            app,
            Method::POST,
            &format!("/directory/v1/providers/{CONFIGURED_PROVIDER_ID}/sync"),
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["error"], "unsupported");
        assert!(
            body.to_string().contains("qid-worker directory-sync"),
            "501 detail must identify the supported CLI path: {body}"
        );
        assert!(
            !body.to_string().contains("sync_triggered"),
            "must not claim a sync was triggered: {body}"
        );
        let events = repo.list_audit_events(None, 100).await.unwrap();
        assert!(
            events.is_empty(),
            "unsupported sync must not record an audit event"
        );
    }

    #[tokio::test]
    async fn sync_status_known_provider_returns_501_without_idle_state() {
        let (app, _repo, session) = setup_routes().await;
        let (status, body) = directory_call(
            app,
            Method::GET,
            &format!("/directory/v1/providers/{CONFIGURED_PROVIDER_ID}/sync/status"),
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["error"], "unsupported");
        assert!(
            body["detail"].as_str().unwrap().contains("does not track"),
            "501 detail must explain that no HTTP status is tracked: {body}"
        );
        assert!(
            !body.to_string().contains("idle"),
            "must not invent idle sync state: {body}"
        );
    }

    #[tokio::test]
    async fn unknown_provider_returns_404_for_unsupported_operations() {
        for (method, uri) in [
            (
                Method::GET,
                format!("/directory/v1/providers/{UNKNOWN_PROVIDER_ID}"),
            ),
            (
                Method::PATCH,
                format!("/directory/v1/providers/{UNKNOWN_PROVIDER_ID}"),
            ),
            (
                Method::POST,
                format!("/directory/v1/providers/{UNKNOWN_PROVIDER_ID}/sync"),
            ),
            (
                Method::GET,
                format!("/directory/v1/providers/{UNKNOWN_PROVIDER_ID}/sync/status"),
            ),
        ] {
            let (app, _repo, session) = setup_routes().await;
            let (status, body) = directory_call(app, method, &uri, Some(&session)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "for {uri}");
            assert_eq!(body["error"], "provider not found", "for {uri}");
            assert_eq!(body["id"], UNKNOWN_PROVIDER_ID, "for {uri}");
        }
    }

    #[tokio::test]
    async fn the_provider_list_advertises_only_the_types_the_sync_connects() {
        let (app, _repo, session) = setup_routes().await;
        let (status, body) =
            directory_call(app, Method::GET, "/directory/v1/providers", Some(&session)).await;
        assert_eq!(status, StatusCode::OK);
        let supported = body["supported"]
            .as_array()
            .expect("the supported types are a list");
        let types: Vec<&str> = supported
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert_eq!(types, vec!["ldap", "active-directory"]);
        // The list keeps the disabled providers, so the operator sees them.
        let listed = body["providers"]
            .as_array()
            .expect("the providers are a list");
        let entries: Vec<(&str, bool)> = listed
            .iter()
            .map(|provider| {
                (
                    provider["id"].as_str().unwrap_or_default(),
                    provider["enabled"].as_bool().unwrap_or_default(),
                )
            })
            .collect();
        assert!(entries.contains(&(CONFIGURED_PROVIDER_ID, true)));
        assert!(entries.contains(&(DISABLED_PROVIDER_ID, false)));
    }

    #[tokio::test]
    async fn get_provider_config_and_auth_boundaries_stay_intact() {
        let (app, _repo, session) = setup_routes().await;
        let (status, body) = directory_call(
            app,
            Method::GET,
            &format!("/directory/v1/providers/{CONFIGURED_PROVIDER_ID}"),
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], CONFIGURED_PROVIDER_ID);
        assert_eq!(body["type"], "active-directory");
        assert_eq!(body["url"], "ldap://ad.example.com");

        let (app, _, _) = setup_routes().await;
        let (status, _) = directory_call(
            app,
            Method::POST,
            &format!("/directory/v1/providers/{CONFIGURED_PROVIDER_ID}/sync"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[test]
fn preserves_the_configured_bind_dn() {
    use qid_core::config::DirectoryConnectionConfig;
    let config = DirectoryConnectionConfig {
        url: "ldaps://ad.example.com:636".to_string(),
        bind_dn: Some("CN=svc,OU=Users,DC=example,DC=com".to_string()),
        ..Default::default()
    };
    assert_eq!(
        crate::connector::bind_dn_for(&config).unwrap(),
        Some("CN=svc,OU=Users,DC=example,DC=com".to_string())
    );
}

#[test]
fn preserves_an_already_escaped_bind_dn() {
    use qid_core::config::DirectoryConnectionConfig;
    let config = DirectoryConnectionConfig {
        url: "ldaps://ad.example.com:636".to_string(),
        bind_dn: Some("CN=svc\\,ou,OU=Users,DC=example,DC=com".to_string()),
        ..Default::default()
    };
    assert_eq!(
        crate::connector::bind_dn_for(&config).unwrap(),
        Some("CN=svc\\,ou,OU=Users,DC=example,DC=com".to_string())
    );
}

#[test]
fn rejects_a_bind_dn_with_a_control_character() {
    use qid_core::config::DirectoryConnectionConfig;
    let config = DirectoryConnectionConfig {
        url: "ldaps://ad.example.com:636".to_string(),
        bind_dn: Some("CN=svc\u{1},DC=example".to_string()),
        ..Default::default()
    };
    assert!(crate::connector::bind_dn_for(&config).is_err());
}

#[tokio::test]
async fn sasl_bind_fails_instead_of_falling_back_to_a_simple_bind() {
    let err = crate::connector::ldap_sasl_scram_sha256_bind("CN=svc")
        .await
        .unwrap_err();
    assert!(err.contains("not implemented"), "{err}");
}

#[test]
fn requires_the_paged_results_control() {
    use ldap3::controls::Control;
    let err = crate::connector::paged_results_cookie(&[]).unwrap_err();
    assert!(err.message().contains("PagedResults"), "{}", err.message());
    let other = Control(
        None,
        ldap3::controls::RawControl {
            ctype: "1.2.3".to_string(),
            crit: false,
            val: None,
        },
    );
    assert!(crate::connector::paged_results_cookie(&[other]).is_err());
}

#[test]
fn reads_the_paged_results_cookie() {
    use ldap3::controls::{Control, ControlType, PagedResults, RawControl};
    let raw: RawControl = PagedResults {
        size: 1,
        cookie: vec![7],
    }
    .into();
    let ctrls = vec![Control(Some(ControlType::PagedResults), raw)];
    assert_eq!(
        crate::connector::paged_results_cookie(&ctrls).unwrap(),
        vec![7]
    );
}

#[tokio::test]
async fn webhook_ingest_rejects_an_empty_external_id() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    let err = connector
        .ingest_json(&serde_json::json!([{"external_id": "", "event": "joiner"}]))
        .expect_err("an empty external id must be rejected");
    assert!(err.message().contains("external_id"), "{}", err.message());
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert!(users.is_empty(), "a rejected record must not be stored");
}

#[tokio::test]
async fn webhook_ingest_validates_the_batch_before_storing_it() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    let err = connector
        .ingest_json(&serde_json::json!([
            {"external_id": "hr-1", "event": "joiner"},
            {"external_id": "hr-2", "event": "not-an-event"}
        ]))
        .expect_err("an invalid record must be rejected");
    assert!(err.message().contains("event"), "{}", err.message());
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert!(
        users.is_empty(),
        "a rejected batch must leave no prefix behind"
    );
}

#[tokio::test]
async fn hr_import_rejects_joiner_mover_repeated_key_before_any_create() {
    let state = setup().await;
    let err = import_hr_records(
        &state,
        "corp",
        vec![
            HrRecord {
                external_id: "hr-move".to_string(),
                user_name: "move@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Joiner,
            },
            HrRecord {
                external_id: "hr-move".to_string(),
                user_name: "move@example.com".to_string(),
                email: None,
                display_name: None,
                department: None,
                manager_external_id: None,
                event: LifecycleEvent::Mover,
            },
        ],
    )
    .await
    .expect_err("repeated key across joiner/mover must conflict");
    assert!(
        matches!(err, QidError::Conflict { .. }),
        "expected conflict, got {err:?}"
    );
    let users = state
        .repo
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .unwrap();
    assert!(
        users.is_empty(),
        "the joiner prefix must not be created before the repeated-key conflict"
    );
}

#[test]
fn rejects_a_paged_results_control_without_a_value() {
    use ldap3::controls::{Control, ControlType, RawControl};
    let ctrls = vec![Control(
        Some(ControlType::PagedResults),
        RawControl {
            ctype: "1.2.840.113556.1.4.319".to_string(),
            crit: false,
            val: None,
        },
    )];
    let err = crate::connector::paged_results_cookie(&ctrls)
        .expect_err("a control without a value must fail closed");
    assert!(err.message().contains("unusable"), "{}", err.message());
}

#[test]
fn a_sasl_bind_without_a_bind_dn_is_an_error() {
    let err = crate::connector::sasl_bind_dn(None).expect_err("a SASL bind needs a bind DN");
    assert!(err.message().contains("bind DN"), "{}", err.message());
    assert_eq!(
        crate::connector::sasl_bind_dn(Some("CN=svc")).unwrap(),
        "CN=svc"
    );
}

#[tokio::test]
async fn webhook_ingest_trims_the_external_id_it_stores() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    connector
        .ingest_json(&serde_json::json!([{"external_id": "  hr-1  ", "event": "joiner"}]))
        .expect("a padded identifier is accepted");
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].uid, "hr-1");
    assert_eq!(users[0].dn, "hr-1");
}

#[test]
fn rejects_a_malformed_paged_results_control() {
    use ldap3::controls::{Control, ControlType, RawControl};
    let ctrls = vec![Control(
        Some(ControlType::PagedResults),
        RawControl {
            ctype: "1.2.840.113556.1.4.319".to_string(),
            crit: false,
            val: Some(b"not a paged results value".to_vec()),
        },
    )];
    let err = crate::connector::paged_results_cookie(&ctrls)
        .expect_err("a malformed control must fail closed");
    assert!(err.message().contains("unusable"), "{}", err.message());
}

#[test]
fn a_configured_bind_dn_needs_a_usable_password() {
    let dn = "CN=svc".to_string();
    let err = qid_core::config::bind_credentials(Some(dn.as_str()), None)
        .expect_err("a bind DN needs a password");
    assert!(err.message().contains("bind password"), "{}", err.message());
    let err = qid_core::config::bind_credentials(Some(dn.as_str()), Some(""))
        .expect_err("an empty password is an unauthenticated bind");
    assert!(err.message().contains("bind password"), "{}", err.message());
    let err = qid_core::config::bind_credentials(Some("  "), Some("secret"))
        .expect_err("a blank bind DN is no bind DN");
    assert!(err.message().contains("bind DN"), "{}", err.message());
    assert_eq!(
        qid_core::config::bind_credentials(Some(dn.as_str()), Some("secret")).unwrap(),
        Some(("CN=svc", "secret"))
    );
    assert_eq!(
        qid_core::config::bind_credentials(None, None).unwrap(),
        None,
        "no bind DN means an anonymous search"
    );
}

#[tokio::test]
async fn webhook_ingest_trims_the_manager_reference() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    connector
        .ingest_json(&serde_json::json!([
            {"external_id": "hr-1", "event": "joiner", "manager_external_id": "  hr-mgr  "},
            {"external_id": "hr-2", "event": "joiner", "manager_external_id": "  "}
        ]))
        .expect("the records are accepted");
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert_eq!(users[0].manager_dn.as_deref(), Some("hr-mgr"));
    assert_eq!(users[1].manager_dn, None);
}

#[test]
fn a_bind_credential_must_be_usable_in_both_directions() {
    let err = qid_core::config::bind_credentials(Some("CN=svc"), Some("  "))
        .expect_err("a blank password is no credential");
    assert!(err.message().contains("bind password"), "{}", err.message());
    let err = qid_core::config::bind_credentials(None, Some("secret"))
        .expect_err("a password without a bind DN would search anonymously");
    assert!(err.message().contains("bind DN"), "{}", err.message());
    assert_eq!(
        qid_core::config::bind_credentials(None, Some("  ")).unwrap(),
        None,
        "a blank password is no credential either"
    );
}

#[tokio::test]
async fn webhook_ingest_normalizes_every_attribute_like_the_csv_connector() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    connector
        .ingest_json(&serde_json::json!([
            {"external_id": "hr-1", "event": "joiner", "email": "  hr@example.com  ",
             "display_name": "  HR Person  ", "department": "  Research  "},
            {"external_id": "hr-2", "event": "joiner", "email": "   ", "display_name": "",
             "department": "  "}
        ]))
        .expect("the records are accepted");
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert_eq!(users[0].mail.as_deref(), Some("hr@example.com"));
    assert_eq!(users[0].display_name.as_deref(), Some("HR Person"));
    assert_eq!(users[0].department.as_deref(), Some("Research"));
    assert_eq!(users[1].mail, None);
    assert_eq!(users[1].display_name, None);
    assert_eq!(users[1].department, None);
}

#[test]
fn a_bind_credential_fault_is_a_configuration_error() {
    // A misconfigured provider is the operator's configuration, not a server
    // fault, so it must not surface as an internal error.
    let err = qid_core::config::bind_credentials(Some("CN=svc"), None)
        .expect_err("a bind DN needs a password");
    assert!(
        matches!(err, qid_core::error::QidError::Config { .. }),
        "the fault must be a configuration error"
    );
    let err = qid_core::config::bind_credentials(None, Some("secret"))
        .expect_err("a password needs a bind DN");
    assert!(
        matches!(err, qid_core::error::QidError::Config { .. }),
        "the fault must be a configuration error"
    );
}

#[tokio::test]
async fn webhook_ingest_reads_the_event_like_the_csv_connector() {
    use crate::connector::{DirectoryConnector, WebhookHrConnector};
    use qid_core::config::{DirectoryAttributeMapping, DirectorySyncConfig};
    let mut connector = WebhookHrConnector::new();
    connector
        .ingest_json(&serde_json::json!([
            {"external_id": "hr-1", "event": " Joiner "},
            {"external_id": "hr-2", "event": "LEAVER"}
        ]))
        .expect("the records are accepted");
    let users = connector
        .fetch_users(
            &DirectorySyncConfig::default(),
            &DirectoryAttributeMapping::default(),
        )
        .await
        .unwrap();
    assert!(users[0].enabled, "a joiner is an enabled user");
    assert!(!users[1].enabled, "a leaver is a disabled user");
}

/// The panic hook is process-wide, so only one test may own it at a time.
static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn an_unusable_paged_results_control_is_an_error_and_not_a_panic() {
    use ldap3::controls::{Control, ControlType, RawControl};
    use std::sync::{Mutex, OnceLock};

    // The panic hook records what would have been printed.
    static PANICS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    let panics = PANICS.get_or_init(|| Mutex::new(Vec::new()));
    let _guard = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let owner = std::thread::current().id();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == owner {
            panics
                .lock()
                .expect("the panic record")
                .push(info.to_string());
        }
    }));

    // A sequence with no elements reaches the parse, and the parse panics.
    let raw = RawControl {
        ctype: "1.2.840.113556.1.4.319".to_string(),
        crit: false,
        val: Some(vec![0x30, 0x00]),
    };
    let ctrls = vec![Control(Some(ControlType::PagedResults), raw)];
    let err = crate::connector::paged_results_cookie(&ctrls)
        .expect_err("an unusable control is an error");
    assert!(err.message().contains("unusable PagedResults control"));

    let missing = RawControl {
        ctype: "1.2.840.113556.1.4.319".to_string(),
        crit: false,
        val: None,
    };
    let ctrls = vec![Control(Some(ControlType::PagedResults), missing)];
    let err = crate::connector::paged_results_cookie(&ctrls)
        .expect_err("a control without a value is an error");
    std::panic::set_hook(previous);

    assert!(err.message().contains("unusable PagedResults control"));
    assert!(
        panics.lock().expect("the panic record").is_empty(),
        "an unusable control must not reach the panic hook"
    );
}

#[test]
fn concurrent_paging_control_parses_leave_the_panic_hook_installed() {
    use ldap3::controls::{Control, ControlType, RawControl};
    use std::sync::atomic::{AtomicBool, Ordering};

    // The panic hook is process-wide: two callers must not leave the silent
    // hook installed for the rest of the process. Hold the lock so the other
    // hook test does not replace the hook while this one runs, and restore
    // the hook so this test leaves the process as it found it.
    static PANIC_SEEN: AtomicBool = AtomicBool::new(false);
    let _guard = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        PANIC_SEEN.store(true, Ordering::SeqCst);
    }));

    // The race needs the swaps to overlap, so the parses run in parallel and
    // repeat. Every thread checks the hook after its own parse: without the
    // serialized swap a parse can leave the silent hook installed, and the
    // next check sees it.
    static SILENT_HOOK_SEEN: AtomicBool = AtomicBool::new(false);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..50 {
                    let raw = RawControl {
                        ctype: "1.2.840.113556.1.4.319".to_string(),
                        crit: false,
                        val: Some(vec![0x30, 0x00]),
                    };
                    let ctrls = vec![Control(Some(ControlType::PagedResults), raw)];
                    let _ = crate::connector::paged_results_cookie(&ctrls);

                    // The hook must still be the one this test installed. A
                    // concurrent parse elsewhere in the test binary can hold
                    // the silent hook for a moment, so the check is retried.
                    for _ in 0..20 {
                        PANIC_SEEN.store(false, Ordering::SeqCst);
                        let _ = std::panic::catch_unwind(|| panic!("the test panic"));
                        if PANIC_SEEN.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    if !PANIC_SEEN.load(Ordering::SeqCst) {
                        SILENT_HOOK_SEEN.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("the parse thread finishes");
    }

    // The hook must also be intact once every parse is done.
    for _ in 0..20 {
        PANIC_SEEN.store(false, Ordering::SeqCst);
        let _ = std::panic::catch_unwind(|| panic!("the test panic"));
        if PANIC_SEEN.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    if !PANIC_SEEN.load(Ordering::SeqCst) {
        SILENT_HOOK_SEEN.store(true, Ordering::SeqCst);
    }

    let silent = SILENT_HOOK_SEEN.load(Ordering::SeqCst);
    std::panic::set_hook(previous);
    assert!(
        !silent,
        "the panic hook must be restored after concurrent parses"
    );
}
