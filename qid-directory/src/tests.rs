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
    assert!(
        deprovisioned.enterprise_json["deprovisioned_at"]
            .as_u64()
            .is_some()
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
            },
            DeprovisionEvent {
                external_id: "hr-pending".to_string(),
                occurred_at: 2_000,
            },
            DeprovisionEvent {
                external_id: "hr-violated".to_string(),
                occurred_at: 1_000,
            },
            DeprovisionEvent {
                external_id: "hr-missing".to_string(),
                occurred_at: 1_000,
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
