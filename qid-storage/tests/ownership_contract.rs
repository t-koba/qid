//! Cross-backend contract tests for owner-bound and globally keyed storage records.
//!
//! Every contract body lives in the shared support module and runs once per
//! backend, so the file and SQL backends answer the same ownership or identity
//! questions the same way.

mod support;

#[tokio::test]
async fn workload_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_workload_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-workload-identity").await;
    support::assert_workload_identity_ownership(&file).await;
}

#[tokio::test]
async fn ciam_consent_grant_owner_conflict_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_consent_grant_owner_conflict(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-consent-grant").await;
    support::assert_ciam_consent_grant_owner_conflict(&file).await;
}

#[tokio::test]
async fn ciam_progressive_profile_owner_conflict_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_progressive_profile_owner_conflict(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-progressive-profile").await;
    support::assert_ciam_progressive_profile_owner_conflict(&file).await;
}

#[tokio::test]
async fn ciam_consent_grant_revoke_idempotent_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_consent_grant_revoke_idempotent(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-consent-revoke").await;
    support::assert_ciam_consent_grant_revoke_idempotent(&file).await;
}

#[tokio::test]
async fn client_id_uniqueness_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_client_id_uniqueness(&sql).await;
    let file = support::file_repo("ownership-contract-client-id-uniqueness").await;
    support::assert_client_id_uniqueness(&file).await;
}

#[tokio::test]
async fn client_id_ambiguity_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_client_id_ambiguity(&sql).await;
    let file = support::file_repo("ownership-contract-client-id-ambiguity").await;
    support::assert_client_id_ambiguity(&file).await;
}

#[tokio::test]
async fn workload_identity_delete_scope_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_workload_identity_delete_scope(&sql).await;
    let file = support::file_repo("ownership-contract-workload-identity-delete").await;
    support::assert_workload_identity_delete_scope(&file).await;
}

#[tokio::test]
async fn user_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_user_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-user-identity").await;
    support::assert_user_identity_ownership(&file).await;
}

#[tokio::test]
async fn device_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_device_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-device-identity").await;
    support::assert_device_identity_ownership(&file).await;
}

#[tokio::test]
async fn device_heartbeat_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_device_heartbeat_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-device-heartbeat").await;
    support::assert_device_heartbeat_ownership(&file).await;
}

#[tokio::test]
async fn fedcm_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_fedcm_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-fedcm-identity").await;
    support::assert_fedcm_identity_ownership(&file).await;
}

#[tokio::test]
async fn service_account_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_service_account_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-service-account").await;
    support::assert_service_account_identity_ownership(&file).await;
}

#[tokio::test]
async fn service_account_realm_delete_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_service_account_realm_delete(&sql).await;
    let file = support::file_repo("ownership-contract-service-account-delete").await;
    support::assert_service_account_realm_delete(&file).await;
}

#[tokio::test]
async fn webauthn_credential_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_webauthn_credential_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-webauthn-credential").await;
    support::assert_webauthn_credential_identity_ownership(&file).await;
}

#[tokio::test]
async fn audit_event_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_audit_event_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-audit-event").await;
    support::assert_audit_event_identity_ownership(&file).await;
}

#[tokio::test]
async fn admin_approval_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_admin_approval_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-admin-approval").await;
    support::assert_admin_approval_identity_ownership(&file).await;
}

#[tokio::test]
async fn admin_upsert_preserves_identity_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_admin_upsert_preserves_identity(&sql).await;
    let file = support::file_repo("ownership-contract-admin-upsert").await;
    support::assert_admin_upsert_preserves_identity(&file).await;
}

#[tokio::test]
async fn admin_legacy_file_ambiguity_fails_closed_without_changes() {
    use qid_core::{error::QidError, models::Admin};
    use qid_storage::{AdminRepository, FileRepository};

    let dir = std::env::temp_dir().join(format!("qid-admin-legacy-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let first = Admin {
        id: "first-admin".into(),
        tenant_id: "tenant".into(),
        subject: "subject".into(),
        roles: vec!["reader".into()],
        created_at: 1,
    };
    repo.upsert_admin(&first).await.unwrap();
    drop(repo);
    let second = Admin {
        id: "second-admin".into(),
        roles: vec!["auditor".into()],
        created_at: 2,
        ..first.clone()
    };
    let mut fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    fixture["admins"][&second.id] = serde_json::to_value(&second).unwrap();
    let before = serde_json::to_vec(&fixture).unwrap();
    std::fs::write(&path, &before).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert!(matches!(
        repo.get_admin(&first.tenant_id, &first.subject).await,
        Err(QidError::Conflict { .. })
    ));
    let incoming = Admin {
        id: "incoming-admin".into(),
        roles: vec!["admin".into()],
        created_at: 3,
        ..first.clone()
    };
    // Neither a new ID nor an incumbent ID may update an ambiguous identity.
    for id in [&incoming.id, &first.id, &second.id] {
        let attempt = Admin {
            id: id.clone(),
            ..incoming.clone()
        };
        assert!(matches!(
            repo.upsert_admin(&attempt).await,
            Err(QidError::Conflict { .. })
        ));
        for admin in [&first, &second] {
            assert_eq!(
                serde_json::to_value(repo.get_admin_by_id(&admin.id).await.unwrap()).unwrap(),
                serde_json::to_value(admin).unwrap()
            );
        }
        assert!(repo.get_admin_by_id(&incoming.id).await.unwrap().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    assert!(
        repo.get_admin("other-tenant", &first.subject)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_admin(&first.tenant_id, "absent")
            .await
            .unwrap()
            .is_none()
    );
    drop(repo);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn admin_elevation_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_admin_elevation_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-admin-elevation").await;
    support::assert_admin_elevation_identity_ownership(&file).await;
}

#[tokio::test]
async fn ciam_verification_challenge_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_verification_challenge_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-verification").await;
    support::assert_ciam_verification_challenge_identity_ownership(&file).await;
}

#[tokio::test]
async fn password_reset_token_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_password_reset_token_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-password-reset").await;
    support::assert_password_reset_token_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_access_review_decision_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_access_review_decision_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-review-decision").await;
    support::assert_iga_access_review_decision_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_certification_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_certification_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-certification").await;
    support::assert_iga_certification_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_finding_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_finding_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-finding").await;
    support::assert_iga_finding_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_access_request_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_access_request_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-access-request").await;
    support::assert_iga_access_request_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_approval_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_approval_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-approval").await;
    support::assert_iga_approval_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_access_grant_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_access_grant_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-access-grant").await;
    support::assert_iga_access_grant_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_jit_privilege_grant_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_jit_privilege_grant_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-jit-grant").await;
    support::assert_iga_jit_privilege_grant_identity_ownership(&file).await;
}

#[tokio::test]
async fn iga_access_review_campaign_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_iga_access_review_campaign_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-iga-campaign").await;
    support::assert_iga_access_review_campaign_identity_ownership(&file).await;
}

#[tokio::test]
async fn realm_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_realm_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-realm-identity").await;
    support::assert_realm_identity_ownership(&file).await;
}

#[tokio::test]
async fn policy_bundle_identity_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_policy_bundle_identity_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-policy-bundle").await;
    support::assert_policy_bundle_identity_ownership(&file).await;
}

#[tokio::test]
async fn policy_bundle_foreign_key_failure_remains_storage_error() {
    use qid_core::{error::QidError, models::PolicyBundle};
    use qid_storage::PolicyRepository;

    let sql = support::sql_repo().await;
    let bundle = PolicyBundle {
        id: "orphan-bundle".to_string(),
        realm_id: "missing-realm".to_string(),
        name: "allow".to_string(),
        source_hash: "hash".to_string(),
        compiled_json: serde_json::json!({"rules": []}),
        version: 1,
        active: true,
    };
    let err = sql.create_policy_bundle(&bundle).await.unwrap_err();
    assert!(matches!(err, QidError::Storage { .. }), "{}", err.message());
}

#[tokio::test]
async fn client_delete_realm_scope_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_client_delete_realm_scope(&sql).await;
    let file = support::file_repo("ownership-contract-client-delete").await;
    support::assert_client_delete_realm_scope(&file).await;
}

#[tokio::test]
async fn client_update_missing_id_preserves_backend_specific_semantics() {
    let sql = support::sql_repo().await;
    support::assert_client_missing_update_semantics(&sql, false).await;
    let file = support::file_repo("ownership-contract-client-update-missing").await;
    support::assert_client_missing_update_semantics(&file, true).await;
}

#[tokio::test]
async fn client_update_identity_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_client_update_identity(&sql).await;
    let file = support::file_repo("ownership-contract-client-update").await;
    support::assert_client_update_identity(&file).await;
}

#[tokio::test]
async fn rebac_tuple_identity_conflict_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_rebac_tuple_identity_conflict(&sql).await;
    let file = support::file_repo("ownership-contract-rebac-tuple").await;
    support::assert_rebac_tuple_identity_conflict(&file).await;
}

#[tokio::test]
async fn rebac_tuple_delete_namespace_isolated_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_rebac_tuple_delete_namespace_isolated(&sql).await;
    let file = support::file_repo("ownership-contract-rebac-tuple-delete").await;
    support::assert_rebac_tuple_delete_namespace_isolated(&file).await;
}

#[tokio::test]
async fn par_request_identity_conflict_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_par_request_identity_conflict(&sql).await;
    let file = support::file_repo("ownership-contract-par-request").await;
    support::assert_par_request_identity_conflict(&file).await;
}

#[tokio::test]
async fn device_authorization_grant_create_only_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_device_authorization_grant_create_only(&sql).await;
    let file = support::file_repo("ownership-contract-device-grant").await;
    support::assert_device_authorization_grant_create_only(&file).await;
}

#[tokio::test]
async fn backchannel_authentication_grant_create_only_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_backchannel_authentication_grant_create_only(&sql).await;
    let file = support::file_repo("ownership-contract-backchannel-grant").await;
    support::assert_backchannel_authentication_grant_create_only(&file).await;
}

#[tokio::test]
async fn totp_step_claim_is_user_bound_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_totp_step_owner_bound(&sql).await;
    let file = support::file_repo("ownership-contract-totp-step").await;
    support::assert_totp_step_owner_bound(&file).await;
}

#[tokio::test]
async fn ssf_stream_realm_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ssf_stream_realm_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-ssf-stream").await;
    support::assert_ssf_stream_realm_ownership(&file).await;
}

#[tokio::test]
async fn ssf_set_jti_replay_key_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ssf_set_jti_replay_key(&sql).await;
    let file = support::file_repo("ownership-contract-ssf-set-jti").await;
    support::assert_ssf_set_jti_replay_key(&file).await;
}

#[tokio::test]
async fn custom_domain_tenant_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_custom_domain_tenant_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-custom-domain").await;
    support::assert_custom_domain_tenant_ownership(&file).await;
}

#[tokio::test]
async fn delegated_admin_lifecycle_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_delegated_admin_lifecycle(&sql).await;
    sql.close().await;
    let file = support::file_repo("ownership-contract-delegated-admin").await;
    support::assert_delegated_admin_lifecycle(&file).await;
}

#[tokio::test]
async fn ciam_brand_tenant_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_brand_tenant_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-brand").await;
    support::assert_ciam_brand_tenant_ownership(&file).await;
}

#[tokio::test]
async fn ciam_identity_link_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_identity_link_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-identity-link-owner").await;
    support::assert_ciam_identity_link_ownership(&file).await;
}

#[tokio::test]
async fn ciam_identity_link_delete_scope_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_ciam_identity_link_delete_scope(&sql).await;
    let file = support::file_repo("ownership-contract-ciam-link-delete").await;
    support::assert_ciam_identity_link_delete_scope(&file).await;
}

#[tokio::test]
async fn marketplace_connector_tenant_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_marketplace_connector_tenant_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-marketplace-connector").await;
    support::assert_marketplace_connector_tenant_ownership(&file).await;
}

#[tokio::test]
async fn usage_billing_event_tenant_ownership_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_usage_billing_event_tenant_ownership(&sql).await;
    let file = support::file_repo("ownership-contract-usage-billing-event").await;
    support::assert_usage_billing_event_tenant_ownership(&file).await;
}

#[tokio::test]
async fn vc_credential_status_identity_collision_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_vc_credential_status_identity_collision(&sql).await;
    let file = support::file_repo("ownership-contract-vc-status").await;
    support::assert_vc_credential_status_identity_collision(&file).await;
}

#[tokio::test]
async fn audit_retention_stream_identity_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_audit_retention_stream_identity(&sql).await;
    let file = support::file_repo("ownership-contract-audit-retention").await;
    support::assert_audit_retention_stream_identity(&file).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_session_creation_holds_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_concurrent_session_creation(&sql).await;
    sql.close().await;
    let file = support::file_repo("ownership-contract-session-create").await;
    support::assert_concurrent_session_creation(&file).await;
}

#[tokio::test]
async fn admin_elevation_without_source_session_stays_unbound_in_both_backends() {
    let sql = support::sql_repo().await;
    support::assert_admin_elevation_without_source_session(&sql).await;
    let file = support::file_repo("ownership-contract-admin-elevation-unbound").await;
    support::assert_admin_elevation_without_source_session(&file).await;
}
#[test]
fn legacy_admin_elevation_json_defaults_source_session_to_none() {
    let legacy = serde_json::json!({"id":"legacy-elevation","tenant_id":"legacy-tenant","admin_id":"legacy-admin","acr":null,"amr":[],"elevation_expires_at":1_700_000_100u64,"created_at":1_700_000_001u64});
    let elevation: qid_core::models::AdminElevation =
        serde_json::from_value(legacy).expect("legacy elevation without provenance must load");
    assert_eq!(elevation.source_session_id, None);
}
#[tokio::test]
async fn file_admin_elevation_source_session_survives_reopen_and_legacy_omission() {
    use qid_core::models::{Admin, AdminElevation};
    use qid_storage::{AdminRepository, FileRepository};
    let dir = std::env::temp_dir().join(format!("qid-admin-elevation-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create isolated file repo directory");
    let path = dir
        .join("repository.json")
        .to_str()
        .expect("UTF-8 path")
        .to_string();
    let admin = Admin {
        id: "file-elevation-admin".into(),
        tenant_id: "file-elevation-tenant".into(),
        subject: "file-elevation-owner".into(),
        roles: vec!["admin".into()],
        created_at: 1_700_000_000,
    };
    let elevation = AdminElevation {
        id: "file-elevation".into(),
        tenant_id: admin.tenant_id.clone(),
        admin_id: admin.id.clone(),
        source_session_id: Some("browser-session-file".into()),
        acr: Some("phr".into()),
        amr: vec!["webauthn".into()],
        elevation_expires_at: 1_700_000_100,
        created_at: 1_700_000_001,
    };
    let first = FileRepository::new(&path).await.expect("open file repo");
    first.migrate().await.expect("migrate file repo");
    first.upsert_admin(&admin).await.expect("store admin");
    first
        .store_admin_elevation(&elevation)
        .await
        .expect("store elevation");
    drop(first);
    let reopened = FileRepository::new(&path).await.expect("reopen file repo");
    reopened.migrate().await.expect("migrate reopened repo");
    let stored = reopened
        .get_admin_elevation(&elevation.id)
        .await
        .expect("load reopened elevation")
        .expect("elevation persists");
    assert_eq!(
        stored.source_session_id.as_deref(),
        Some("browser-session-file")
    );
    drop(reopened);
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read store")).expect("parse store");
    state["admin_elevations"][&elevation.id]
        .as_object_mut()
        .expect("elevation object")
        .remove("source_session_id");
    std::fs::write(
        &path,
        serde_json::to_vec(&state).expect("encode legacy state"),
    )
    .expect("write legacy state");
    let legacy = FileRepository::new(&path).await.expect("open legacy repo");
    legacy.migrate().await.expect("migrate legacy repo");
    let stored = legacy
        .get_admin_elevation(&elevation.id)
        .await
        .expect("load legacy elevation")
        .expect("legacy elevation persists");
    assert_eq!(stored.source_session_id, None);
    drop(legacy);
    std::fs::remove_dir_all(dir).expect("cleanup isolated file repo");
}
#[tokio::test]
async fn legacy_sql_admin_elevation_migrates_with_source_session_unavailable() {
    use qid_core::models::{Admin, AdminElevation};
    use qid_storage::{AdminRepository, SqlRepository};
    let dir = std::env::temp_dir().join(format!("qid-admin-elevation-sql-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create isolated SQL directory");
    let path = dir
        .join("repository.db")
        .to_str()
        .expect("UTF-8 DB path")
        .to_string();
    let url = format!("sqlite:{path}");
    let repo = SqlRepository::connect(&url)
        .await
        .expect("connect SQL repository");
    repo.migrate().await.expect("run fresh migrations");
    let admin = Admin {
        id: "legacy-sql-admin".into(),
        tenant_id: "legacy-sql-tenant".into(),
        subject: "legacy-sql-owner".into(),
        roles: vec!["admin".into()],
        created_at: 1_700_000_000,
    };
    repo.upsert_admin(&admin)
        .await
        .expect("store legacy SQL admin");
    let elevation = AdminElevation {
        id: "legacy-sql-elevation".into(),
        tenant_id: admin.tenant_id,
        admin_id: admin.id,
        source_session_id: None,
        acr: None,
        amr: Vec::new(),
        elevation_expires_at: 1_700_000_100,
        created_at: 1_700_000_001,
    };
    repo.store_admin_elevation(&elevation)
        .await
        .expect("store SQL elevation");
    repo.close().await;
    let pool = sqlx::any::AnyPoolOptions::new()
        .connect(&url)
        .await
        .expect("open legacy SQL DB");
    sqlx::query("ALTER TABLE admin_elevations DROP COLUMN source_session_id")
        .execute(&pool)
        .await
        .expect("restore legacy table shape");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 20261031000001")
        .execute(&pool)
        .await
        .expect("mark provenance migration unapplied");
    pool.close().await;
    let migrated = SqlRepository::connect(&url)
        .await
        .expect("reconnect legacy SQL DB");
    migrated
        .migrate()
        .await
        .expect("apply provenance migration to legacy DB");
    let stored = migrated
        .get_admin_elevation(&elevation.id)
        .await
        .expect("load migrated legacy elevation")
        .expect("legacy SQL elevation remains");
    assert_eq!(stored.source_session_id, None);
    migrated.close().await;
    std::fs::remove_dir_all(dir).expect("cleanup isolated SQL directory");
}

#[tokio::test]
async fn service_account_legacy_file_ambiguity_fails_closed_without_changes() {
    use qid_core::error::QidError;
    use qid_core::models::ServiceAccount;
    use qid_storage::{FileRepository, ServiceAccountRepository};

    let dir = std::env::temp_dir().join(format!("qid-service-legacy-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    repo.create_service_account(&ServiceAccount {
        id: "realm-record".into(),
        realm_id: "realm".into(),
        client_id: "realm-client".into(),
        description: Some("first principal".into()),
        created_at: 1,
    })
    .await
    .unwrap();
    drop(repo);
    let mut fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut second = fixture["service_accounts"]["realm-record"].clone();
    second["id"] = "second-principal".into();
    second["description"] = "preserve this principal too".into();
    fixture["service_accounts"]["second-principal"] = second;
    let before = serde_json::to_vec(&fixture).unwrap();
    std::fs::write(&path, &before).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert!(matches!(
        repo.get_service_account_by_client_id("realm", "realm-client")
            .await,
        Err(QidError::Conflict { .. })
    ));
    let accounts = repo.list_service_accounts("realm").await.unwrap();
    assert_eq!(accounts.len(), 2);
    for account in &accounts {
        assert_eq!(
            serde_json::to_value(account).unwrap(),
            fixture["service_accounts"][&account.id]
        );
    }
    let attempt = ServiceAccount {
        id: "third-principal".into(),
        ..accounts[0].clone()
    };
    assert!(matches!(
        repo.create_service_account(&attempt).await,
        Err(QidError::Conflict { .. })
    ));
    assert!(
        repo.get_service_account_by_client_id("another-realm", "realm-client")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_service_account_by_client_id("realm", "absent")
            .await
            .unwrap()
            .is_none()
    );
    drop(repo);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn service_account_identity_migration_preserves_duplicates_and_retries_after_external_repair()
{
    use qid_storage::{ServiceAccountRepository, SqlRepository};
    use std::borrow::Cow;

    const VERSION: i64 = 20261101000001;
    let dir = std::env::temp_dir().join(format!("qid-service-migration-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("legacy.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    // Build a real pre-uniqueness database, with its historical migration ledger.
    let mut legacy = sqlx::migrate!("./migrations");
    legacy.migrations = Cow::Owned(
        legacy
            .iter()
            .filter(|m| m.version < VERSION)
            .cloned()
            .collect(),
    );
    legacy.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO service_accounts (id, realm_id, client_id, description, created_at) VALUES ('first', 'realm', 'client', 'first principal', 1), ('second', 'realm', 'client', 'second principal', 2), ('foreign', 'other-realm', 'client', 'independent principal', 3)")
        .execute(&pool).await.unwrap();
    let read_rows = || {
        sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(
            "SELECT id, realm_id, client_id, description, created_at FROM service_accounts ORDER BY id",
        )
    };
    let before = read_rows().fetch_all(&pool).await.unwrap();
    let ledger_before: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    for _ in 0..2 {
        let error = repo
            .migrate()
            .await
            .expect_err("legacy ambiguity must block migration")
            .to_string();
        assert!(
            error.contains("duplicate service_accounts realm_id/client_id"),
            "{error}"
        );
        assert!(
            error.contains("repair externally and retry migration"),
            "{error}"
        );
        assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), before);
        assert_eq!(
            sqlx::query_as::<_, (i64, Vec<u8>)>(
                "SELECT version, checksum FROM _sqlx_migrations ORDER BY version"
            )
            .fetch_all(&pool)
            .await
            .unwrap(),
            ledger_before
        );
        assert_eq!(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_service_accounts_realm_client_unique'"
        ).fetch_one(&pool).await.unwrap(), 0);
    }
    // Deliberate test-side operator repair changes only an identity binding,
    // retaining both principals and every other field. The product never chooses.
    sqlx::query(
        "UPDATE service_accounts SET client_id = 'explicitly-repaired-client' WHERE id = 'second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let repaired = read_rows().fetch_all(&pool).await.unwrap();
    let mut expected = before;
    expected.iter_mut().find(|row| row.0 == "second").unwrap().2 =
        "explicitly-repaired-client".into();
    assert_eq!(repaired, expected);
    repo.migrate().await.expect("retry after explicit repair");
    repo.migrate().await.expect("migration is idempotent");
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 20261101000001 AND success = 1"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let incumbent = repo
        .get_service_account_by_client_id("realm", "client")
        .await
        .unwrap()
        .unwrap();
    let duplicate = qid_core::models::ServiceAccount {
        id: "refused".into(),
        ..incumbent
    };
    assert!(matches!(
        repo.create_service_account(&duplicate).await,
        Err(qid_core::error::QidError::Conflict { .. })
    ));
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    pool.close().await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn custom_domain_legacy_file_uppercase_collision_preserves_incumbent() {
    use qid_core::models::CustomDomain;
    use qid_storage::{FileRepository, SaasRepository};

    let dir = std::env::temp_dir().join(format!("qid-domain-legacy-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/realm_store.json")).unwrap();
    let mut domain = fixture["custom_domains"]["realm-record"].clone();
    domain["hostname"] = "LOGIN.Example.COM".into();
    domain["dns_challenge_name"] = "_qid.login.example.com".into();
    domain["dns_challenge_value"] = "legacy-proof".into();
    let empty = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    empty.migrate().await.unwrap();
    drop(empty);
    let mut store: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    store["realm_tenants"] = serde_json::json!({"realm": "tenant", "other-realm": "other-tenant"});
    store["custom_domains"]["realm-record"] = domain;
    let before = serde_json::to_vec(&store).unwrap();
    std::fs::write(&path, &before).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let incumbent = repo.list_custom_domains("tenant").await.unwrap();
    assert_eq!(incumbent.len(), 1);
    assert_eq!(incumbent[0].hostname, "LOGIN.Example.COM");
    for (tenant, realm) in [("tenant", "realm"), ("other-tenant", "other-realm")] {
        let attempt = CustomDomain {
            id: "refused".into(),
            tenant_id: tenant.into(),
            realm_id: realm.into(),
            hostname: "login.example.com".into(),
            ..incumbent[0].clone()
        };
        // Canonical input and valid ownership must reach the hostname guard.
        attempt.validate().unwrap();
        let error = repo.store_custom_domain(&attempt).await.unwrap_err();
        assert!(error.to_string().contains("hostname already exists"));
        assert_eq!(repo.list_custom_domains("tenant").await.unwrap(), incumbent);
        assert!(
            repo.list_custom_domains("other-tenant")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn custom_domain_hostname_migration_preserves_duplicates_and_retries_after_external_repair() {
    use qid_core::tenant::{RealmId, TenantId};
    use qid_storage::{RealmRepository, SaasRepository, SqlRepository};
    use std::borrow::Cow;

    const VERSION: i64 = 20261101000002;
    let dir = std::env::temp_dir().join(format!("qid-domain-migration-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("legacy.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    let mut legacy = sqlx::migrate!("./migrations");
    legacy.migrations = Cow::Owned(
        legacy
            .iter()
            .filter(|m| m.version < VERSION)
            .cloned()
            .collect(),
    );
    legacy.run(&pool).await.unwrap();
    for (tenant, realm) in [("tenant", "realm"), ("other-tenant", "other-realm")] {
        repo.create_realm(
            &TenantId::from(tenant),
            &RealmId::from(realm),
            &format!("https://{realm}.example.com"),
            None,
        )
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO custom_domains (id, tenant_id, realm_id, hostname, certificate_ref, verified, verification_status, dns_challenge_name, dns_challenge_value) VALUES ('first', 'tenant', 'realm', 'LOGIN.Example.COM', 'first-cert', 0, 'pending', '_qid.login.example.com', 'first-proof'), ('second', 'other-tenant', 'other-realm', 'login.example.com', 'second-cert', 0, 'pending', '_qid.login.example.com', 'second-proof')")
        .execute(&pool).await.unwrap();
    // Compare every stored domain field, not only the colliding hostname.
    let read_rows = || {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                i64,
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<i64>,
            ),
        >(
            "SELECT id, tenant_id, realm_id, hostname, certificate_ref, verified, verification_status, dns_challenge_name, dns_challenge_value, certificate_expires_at, certificate_renew_after, last_verified_at FROM custom_domains ORDER BY id",
        )
    };
    let before = read_rows().fetch_all(&pool).await.unwrap();
    let ledger_before: Vec<(i64, Vec<u8>, i64)> =
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    for _ in 0..2 {
        let error = repo.migrate().await.unwrap_err().to_string();
        assert!(error.contains("duplicate LOWER(hostname)"), "{error}");
        assert!(
            error.contains("repair externally; retry migration"),
            "{error}"
        );
        assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), before);
        assert_eq!(
            sqlx::query_as::<_, (i64, Vec<u8>, i64)>(
                "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version"
            )
            .fetch_all(&pool)
            .await
            .unwrap(),
            ledger_before
        );
        let index_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_custom_domains_hostname_lower_unique'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(index_count, 0);
    }
    // Only this explicit test-side repair changes a binding; retain both rows.
    sqlx::query("UPDATE custom_domains SET hostname = 'repaired.example.com' WHERE id = 'second'")
        .execute(&pool)
        .await
        .unwrap();
    let mut repaired = before;
    repaired.iter_mut().find(|row| row.0 == "second").unwrap().3 = "repaired.example.com".into();
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    repo.migrate().await.expect("retry after explicit repair");
    repo.migrate().await.expect("migration is idempotent");
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 20261101000002 AND success = 1"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let incumbent = repo.list_custom_domains("tenant").await.unwrap().remove(0);
    for (tenant, realm) in [("tenant", "realm"), ("other-tenant", "other-realm")] {
        let attempt = qid_core::models::CustomDomain {
            id: "refused".into(),
            tenant_id: tenant.into(),
            realm_id: realm.into(),
            hostname: "login.example.com".into(),
            ..incumbent.clone()
        };
        attempt.validate().unwrap();
        assert!(matches!(
            repo.store_custom_domain(&attempt).await,
            Err(qid_core::error::QidError::Storage { .. })
        ));
        assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    }
    // Bypass model validation to prove the index itself rejects case variants
    // on both insert and update, without overwriting either incumbent.
    for sql in [
        "INSERT INTO custom_domains (id, tenant_id, realm_id, hostname, certificate_ref, verified) VALUES ('raw', 'other-tenant', 'other-realm', 'Login.Example.Com', 'raw-cert', 0)",
        "UPDATE custom_domains SET hostname = 'Login.Example.Com' WHERE id = 'second'",
    ] {
        assert!(
            sqlx::query(sql)
                .execute(&pool)
                .await
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .is_unique_violation()
        );
        assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    }
    pool.close().await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn ciam_identity_link_concurrent_subject_holds_in_both_backends() {
    let file = support::file_repo("ownership-contract-ciam-link-race").await;
    support::assert_ciam_identity_link_concurrent_subject(&file).await;
    let sql = support::sql_repo().await;
    support::assert_ciam_identity_link_concurrent_subject(&sql).await;
    sql.close().await;
}

#[tokio::test]
async fn webauthn_legacy_file_raw_id_ambiguity_fails_closed_without_changes() {
    use qid_core::{error::QidError, models::WebAuthnCredential};
    use qid_storage::{CredentialRepository, FileRepository};

    let dir = std::env::temp_dir().join(format!("qid-webauthn-legacy-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let credential = WebAuthnCredential {
        id: "first".into(),
        user_id: "alice".into(),
        credential_id: vec![1],
        public_key: vec![2],
        counter: 7,
        aaguid: vec![3; 16],
        device_name: Some("Alice key".into()),
        created_at: 1,
    };
    repo.store_webauthn_credential(&credential).await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_webauthn_credentials("alice").await.unwrap()).unwrap(),
        serde_json::json!([credential])
    );
    assert!(
        repo.get_webauthn_credentials("bob")
            .await
            .unwrap()
            .is_empty()
    );
    drop(repo);

    // Seed an old file directly: distinct records and users share one raw ID.
    let mut fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    fixture["webauthn_credentials"]["bob"] = serde_json::json!([WebAuthnCredential {
        id: "second".into(),
        user_id: "bob".into(),
        public_key: vec![4],
        counter: 9,
        aaguid: vec![5; 16],
        device_name: Some("Bob key".into()),
        created_at: 2,
        ..credential
    }]);
    let before = serde_json::to_vec_pretty(&fixture).unwrap();
    std::fs::write(&path, &before).unwrap();

    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    for user in ["alice", "bob", "absent"] {
        assert!(matches!(
            repo.get_webauthn_credentials(user).await,
            Err(QidError::Conflict { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    drop(repo);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn webauthn_raw_id_migration_preserves_duplicates_and_retries_after_external_repair() {
    use qid_core::tenant::{RealmId, TenantId};
    use qid_storage::{RealmRepository, SqlRepository};
    use std::borrow::Cow;

    const VERSION: i64 = 20261105000001;
    let dir = std::env::temp_dir().join(format!("qid-webauthn-migration-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("legacy.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    let mut legacy = sqlx::migrate!("./migrations");
    legacy.migrations = Cow::Owned(
        legacy
            .iter()
            .filter(|m| m.version < VERSION)
            .cloned()
            .collect(),
    );
    legacy.run(&pool).await.unwrap();
    repo.create_realm(
        &TenantId::from("tenant"),
        &RealmId::from("realm"),
        "https://webauthn-migration.example.com",
        None,
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO users (id, realm_id) VALUES ('alice', 'realm'), ('bob', 'realm')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO credentials_webauthn (id, user_id, credential_id, public_key, counter, aaguid, device_name, created_at) VALUES ('first', 'alice', 'AQ==', 'Ag==', 7, 'Aw==', 'Alice key', 1), ('second', 'bob', 'AQ==', 'BA==', 9, 'BQ==', 'Bob key', 2)")
        .execute(&pool).await.unwrap();
    // Snapshot every credential and ledger field, not just the duplicate ID.
    let read_rows = || {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                i64,
                String,
                Option<String>,
                i64,
            ),
        >(
            "SELECT id, user_id, credential_id, public_key, counter, aaguid, device_name, created_at FROM credentials_webauthn ORDER BY id",
        )
    };
    let read_ledger = || {
        sqlx::query_as::<_, (i64, String, String, i64, Vec<u8>, i64)>(
            "SELECT version, description, CAST(installed_on AS TEXT), success, checksum, execution_time FROM _sqlx_migrations ORDER BY version",
        )
    };
    let before = read_rows().fetch_all(&pool).await.unwrap();
    let ledger_before = read_ledger().fetch_all(&pool).await.unwrap();
    let error = repo.migrate().await.unwrap_err().to_string();
    assert!(error.contains("duplicate credential_id"), "{error}");
    assert!(
        error.contains("inspect/repair externally; retry"),
        "{error}"
    );
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), before);
    assert_eq!(read_ledger().fetch_all(&pool).await.unwrap(), ledger_before);
    let index_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_credentials_webauthn_credential_id_unique'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(index_count, 0, "failed migration retained its unique index");

    // This is an explicit test/operator repair, never migration-side selection.
    sqlx::query("UPDATE credentials_webauthn SET credential_id = 'Bg==' WHERE id = 'second'")
        .execute(&pool)
        .await
        .unwrap();
    let repaired = read_rows().fetch_all(&pool).await.unwrap();
    repo.migrate().await.unwrap();
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    let ledger_after = read_ledger().fetch_all(&pool).await.unwrap();
    assert_eq!(&ledger_after[..ledger_before.len()], &ledger_before);
    assert_eq!(ledger_after.len(), ledger_before.len() + 1);
    assert_eq!(ledger_after.last().unwrap().0, VERSION);
    assert_eq!(ledger_after.last().unwrap().3, 1);
    // Prove the migrated index itself, independent of repository checks.
    assert!(
        sqlx::query("UPDATE credentials_webauthn SET credential_id = 'AQ==' WHERE id = 'second'")
            .execute(&pool)
            .await
            .unwrap_err()
            .as_database_error()
            .unwrap()
            .is_unique_violation()
    );
    assert_eq!(read_rows().fetch_all(&pool).await.unwrap(), repaired);
    pool.close().await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
