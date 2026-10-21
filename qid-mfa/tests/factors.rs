use qid_crypto::totp::TotpVerifier;
use qid_mfa::{RecoveryCodeBatch, create_totp_enrollment, verify_totp_at};

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
