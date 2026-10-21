use qid_crypto::totp::TotpVerifier;
use qid_mfa::{
    MfaFactorKind, MfaPolicy, RecoveryCodeBatch, create_totp_enrollment, verify_totp_at,
};
use std::collections::BTreeSet;

#[test]
fn admin_step_up_requires_phishing_resistant_factor() {
    let policy = MfaPolicy::default();

    assert!(policy.step_up_satisfies_policy(&["urn:qid:amr:webauthn".to_string()], true));
    assert!(!policy.step_up_satisfies_policy(&["urn:qid:amr:totp".to_string()], true));
    assert!(policy.step_up_satisfies_policy(&["urn:qid:amr:totp".to_string()], false));
}

#[test]
fn recovery_code_is_consumed_once_and_normalized() {
    let mut batch = RecoveryCodeBatch::generate(4).expect("recovery code generation");
    let code = batch.codes[0].display_code.clone();
    let normalized_variant = format!(" {} ", code.to_ascii_lowercase().replace('-', " "));

    assert!(batch.verify(&normalized_variant).is_some());
    assert!(batch.consume(&normalized_variant));
    assert!(!batch.consume(&normalized_variant));
    assert_eq!(batch.codes.len(), 3);
}

#[test]
fn totp_verification_requires_enabled_credential_and_time_window() {
    let mut plan =
        create_totp_enrollment("totp-1", "user-1", "alice@example.com", "qid", 6, 30, 100)
            .expect("TOTP enrollment");
    let verifier = TotpVerifier::new(6, 30);
    let code = verifier
        .generate_code(&plan.credential.secret, 1_000_000)
        .unwrap();

    assert!(!verify_totp_at(&plan.credential, &code, 1_000_000));
    plan.credential.enabled = true;
    assert!(verify_totp_at(&plan.credential, &code, 1_000_000));
    assert!(verify_totp_at(&plan.credential, &code, 1_000_030));
    assert!(!verify_totp_at(&plan.credential, &code, 1_000_090));
}

#[test]
fn policy_validation_rejects_admin_policy_without_allowed_webauthn() {
    let policy = MfaPolicy {
        allowed: BTreeSet::from([MfaFactorKind::Totp, MfaFactorKind::RecoveryCode]),
        require_phishing_resistant_for_admin: true,
        allow_recovery_code_for_step_up: true,
    };

    assert!(policy.validate().is_err());
}
