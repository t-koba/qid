use qid_crypto::totp::TotpVerifier;
use qid_mfa::push::{
    PushChallengeStatus, PushDevice, PushFatigueState, PushMfaConfig, create_push_challenge,
    verify_push_response,
};
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
fn push_fatigue_is_user_scoped_and_clearable() {
    let state = PushFatigueState::new();
    let config = PushMfaConfig {
        fatigue_max_pending: 2,
        fatigue_window_seconds: 300,
        ..PushMfaConfig::default()
    };

    assert!(
        !state
            .check_and_record("user-1", &config)
            .expect("record push")
    );
    assert!(
        !state
            .check_and_record("user-1", &config)
            .expect("record push")
    );
    assert!(
        state
            .check_and_record("user-1", &config)
            .expect("record push")
    );
    assert!(
        !state
            .check_and_record("user-2", &config)
            .expect("record push")
    );
    state.clear("user-1").expect("clear push state");
    assert!(
        !state
            .check_and_record("user-1", &config)
            .expect("record push")
    );
}

#[test]
fn push_challenge_rejects_wrong_code_and_non_pending_status() {
    let device = PushDevice {
        id: "device-1".to_string(),
        user_id: "user-1".to_string(),
        device_name: "Alice phone".to_string(),
        platform: "ios".to_string(),
        push_token: "token".to_string(),
        created_at: 100,
        enabled: true,
    };
    let config = PushMfaConfig::default();
    let mut challenge = create_push_challenge(
        "challenge-1".to_string(),
        "user-1".to_string(),
        &device,
        "123456".to_string(),
        Some("Tokyo, Japan".to_string()),
        Some("Chrome on macOS".to_string()),
        Some("203.0.113.10".to_string()),
        &config,
    );

    assert!(verify_push_response(&challenge, "123456"));
    assert!(!verify_push_response(&challenge, "000000"));
    challenge.status = PushChallengeStatus::Denied;
    assert!(!verify_push_response(&challenge, "123456"));
}

#[test]
fn policy_validation_rejects_admin_policy_without_allowed_webauthn() {
    let policy = MfaPolicy {
        allowed: BTreeSet::from([MfaFactorKind::Totp, MfaFactorKind::RecoveryCode]),
        require_phishing_resistant_for_admin: true,
        allow_recovery_code_for_step_up: true,
        push_resend_cooldown_seconds: 30,
        push_fatigue_max_pending: 5,
        push_fatigue_window_seconds: 300,
    };

    assert!(policy.validate().is_err());
}
