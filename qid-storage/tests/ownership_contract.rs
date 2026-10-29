//! Cross-backend contract tests for the owner-bound storage resources.
//!
//! Every contract body lives in the shared support module and runs once per
//! backend, so the file and the SQL backend answer the same owner questions
//! the same way.

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
