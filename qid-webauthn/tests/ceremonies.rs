use qid_core::{config::PasskeyConfig, models::WebAuthnCredential};
use qid_webauthn::{
    AttestationPolicy, PasskeyBinding, PasskeyPolicy, WebAuthnRp, ceremony_state_key,
    challenge_is_fresh, evaluate_passkey_inventory,
};
use std::collections::BTreeSet;

fn credential(id: &str, public_key: serde_json::Value, aaguid: Vec<u8>) -> WebAuthnCredential {
    WebAuthnCredential {
        id: id.to_string(),
        user_id: "user-1".to_string(),
        credential_id: id.as_bytes().to_vec(),
        public_key: serde_json::to_vec(&public_key).expect("public key JSON"),
        counter: 0,
        aaguid,
        device_name: Some("security key".to_string()),
        created_at: 100,
    }
}

#[test]
fn rp_config_accepts_scoped_origin_and_rejects_cross_site_origin() {
    let config = PasskeyConfig {
        enabled: true,
        preferred: true,
        rp_id: Some("example.com".to_string()),
        rp_origin: Some("https://login.example.com".to_string()),
        rp_name: "qid".to_string(),
        attestation: None,
    };

    let rp = WebAuthnRp::from_config("https://id.example.com", &config).expect("RP config");
    assert_eq!(rp.rp_id, "example.com");
    assert_eq!(rp.rp_origin, "https://login.example.com");

    let invalid = PasskeyConfig {
        rp_origin: Some("https://evil.example.net".to_string()),
        ..config
    };
    assert!(WebAuthnRp::from_config("https://id.example.com", &invalid).is_err());
}

#[test]
fn strict_attestation_requires_aaguid_allow_list() {
    let invalid = PasskeyPolicy {
        attestation: AttestationPolicy::Strict,
        ..PasskeyPolicy::default()
    };
    assert!(invalid.validate().is_err());

    let valid = PasskeyPolicy {
        attestation: AttestationPolicy::Strict,
        allow_aaguid: BTreeSet::from(["01020304".to_string()]),
        ..PasskeyPolicy::default()
    };
    assert!(valid.validate().is_ok());
}

#[test]
fn inventory_reports_hardware_bound_and_synced_credentials() {
    let hardware = credential(
        "hardware",
        serde_json::json!({
            "resident_key": true,
            "hardware_bound": true,
            "attachment": "cross-platform"
        }),
        vec![1, 2, 3, 4],
    );
    let synced = credential(
        "synced",
        serde_json::json!({
            "resident_key": true,
            "backup_eligible": true,
            "attachment": "platform"
        }),
        Vec::new(),
    );

    let report = evaluate_passkey_inventory(
        "user-1",
        &[hardware, synced],
        &PasskeyPolicy::default(),
        true,
    )
    .expect("passkey inventory");

    assert_eq!(report.hardware_bound, 1);
    assert_eq!(report.synced, 1);
    assert!(report.recovery_ready);
    assert!(report.violations.is_empty());
    assert_eq!(report.credentials[0].binding, PasskeyBinding::HardwareBound);
    assert_eq!(report.credentials[1].binding, PasskeyBinding::Synced);
}

#[test]
fn inventory_enforces_aaguid_deny_list_and_resident_key() {
    let denied = credential(
        "denied",
        serde_json::json!({
            "resident_key": false,
            "hardware_bound": true
        }),
        vec![0xde, 0xad],
    );
    let policy = PasskeyPolicy {
        deny_aaguid: BTreeSet::from(["dead".to_string()]),
        minimum_recovery_passkeys: 2,
        ..PasskeyPolicy::default()
    };

    let report =
        evaluate_passkey_inventory("user-1", &[denied], &policy, true).expect("passkey inventory");

    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("denied AAGUID"))
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("not discoverable"))
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("insufficient recovery passkeys"))
    );
}

#[test]
fn ceremony_state_key_is_scoped_and_challenge_ttl_is_enforced() {
    let first = ceremony_state_key("realm-1", "user-1", "ceremony-1");
    let second = ceremony_state_key("realm-2", "user-1", "ceremony-1");

    assert_ne!(first, second);
    assert_eq!(first.len(), 64);
    assert!(challenge_is_fresh(100, 130, 30));
    assert!(!challenge_is_fresh(100, 131, 30));
    assert!(!challenge_is_fresh(130, 100, 30));
}
