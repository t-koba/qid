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
        active: true,
    };
    mark_break_glass(&mut user);
    state.repo.create_scim_user(&user).await.unwrap();

    let result = sync_ldap_entries(
        &state,
        "corp",
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
                {"value":"group-child", "type":"Group"}
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
