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
