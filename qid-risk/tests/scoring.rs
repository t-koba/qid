use qid_risk::{
    DestinationReputation, DevicePostureSignal, DeviceTrustState, GeoPoint, LoginSignal, PepSignal,
    RiskInput, RiskOutcome, TenantPolicySignal, TokenSignal, detects_impossible_travel,
    evaluate_risk,
};

#[test]
fn managed_known_good_request_is_allowed() {
    let evaluation = evaluate_risk(&RiskInput {
        device_trust: DeviceTrustState::Managed,
        destination_reputation: DestinationReputation::KnownGood,
        phishing_resistant_mfa_satisfied: true,
        ..default_input()
    });

    assert_eq!(evaluation.outcome, RiskOutcome::Allow);
    assert!(evaluation.score < 50);
    assert!(evaluation.required_amr.is_empty());
}

#[test]
fn compromised_device_is_denied_even_with_strong_token() {
    let evaluation = evaluate_risk(&RiskInput {
        device_trust: DeviceTrustState::Compromised,
        destination_reputation: DestinationReputation::KnownGood,
        phishing_resistant_mfa_satisfied: true,
        token: Some(TokenSignal {
            sender_constrained: true,
            acr: Some("urn:qid:acr:phishing-resistant".to_string()),
            amr: vec!["webauthn".to_string()],
            ..Default::default()
        }),
        ..default_input()
    });

    assert_eq!(evaluation.outcome, RiskOutcome::Deny);
    assert_eq!(evaluation.required_amr, vec!["webauthn", "admin_review"]);
}

#[test]
fn impossible_travel_with_anonymous_network_quarantines() {
    let input = RiskInput {
        previous_login: Some(LoginSignal {
            epoch_seconds: 1_000,
            location: Some(GeoPoint {
                latitude: 35.6762,
                longitude: 139.6503,
            }),
            ip: None,
            asn: None,
        }),
        current_login: Some(LoginSignal {
            epoch_seconds: 2_000,
            location: Some(GeoPoint {
                latitude: 40.7128,
                longitude: -74.0060,
            }),
            ip: None,
            asn: None,
        }),
        impossible_travel: true,
        anonymous_network: true,
        phishing_resistant_mfa_satisfied: true,
        device_trust: DeviceTrustState::Managed,
        destination_reputation: DestinationReputation::KnownGood,
        ..default_input()
    };

    assert!(detects_impossible_travel(&input));
    let evaluation = evaluate_risk(&input);
    assert_eq!(evaluation.outcome, RiskOutcome::Quarantine);
    assert_eq!(evaluation.required_amr, vec!["webauthn"]);
}

#[test]
fn pep_privacy_category_forces_tunnel_without_step_up() {
    let evaluation = evaluate_risk(&RiskInput {
        device_trust: DeviceTrustState::Managed,
        destination_reputation: DestinationReputation::KnownGood,
        pep: Some(PepSignal {
            destination_category: Some("banking".to_string()),
            ..Default::default()
        }),
        ..default_input()
    });

    assert_eq!(evaluation.outcome, RiskOutcome::ForceTunnel);
    assert!(evaluation.pep_force_tunnel);
    assert_eq!(evaluation.audit_level.as_deref(), Some("high"));
    assert!(evaluation.required_amr.is_empty());
}

#[test]
fn tenant_and_posture_risk_requires_step_up() {
    let evaluation = evaluate_risk(&RiskInput {
        device_trust: DeviceTrustState::Registered,
        destination_reputation: DestinationReputation::KnownGood,
        device_posture: Some(DevicePostureSignal {
            managed: false,
            encrypted: true,
            edr: false,
            os_outdated: false,
            jailbreak_or_root: false,
        }),
        tenant_policy: Some(TenantPolicySignal {
            current_country: Some("ZZ".to_string()),
            allowed_countries: vec!["JP".to_string()],
            network_allowed: Some(true),
            working_hours_allowed: Some(true),
        }),
        ..default_input()
    });

    assert_eq!(evaluation.outcome, RiskOutcome::StepUp);
    assert_eq!(
        evaluation.required_acr.as_deref(),
        Some("urn:qid:acr:phishing-resistant")
    );
    assert!(
        evaluation
            .labels
            .contains(&"country-not-allowed".to_string())
    );
}

fn default_input() -> RiskInput {
    RiskInput {
        realm_id: None,
        subject: Some("user-1".to_string()),
        previous_login: None,
        current_login: None,
        device_trust: DeviceTrustState::Unknown,
        high_risk_asn: false,
        anonymous_network: false,
        destination_reputation: DestinationReputation::Unknown,
        phishing_resistant_mfa_satisfied: false,
        step_up_succeeded: false,
        new_device: false,
        impossible_travel: false,
        unmanaged_device: false,
        malicious_destination: false,
        pep: None,
        device_posture: None,
        tenant_policy: None,
        token: None,
    }
}
