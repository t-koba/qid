use qid_core::{
    config::{AdminSecurityConfig, QidConfig},
    models::Session,
};

// Called with sessions issued by real authentication flows, not synthetic claims.
// This catches config/producer drift that a YAML syntax check cannot detect.
pub fn assert_admin_assurance(session: &Session, webauthn: bool, totp: bool) {
    let default = AdminSecurityConfig::default();
    assert_eq!(default.required_acr, "phr");
    assert_eq!(default.required_amr, ["webauthn"]);
    assert_requirement(&default, session, webauthn);
    for sample in [
        "03-api-and-service-access/high-assurance-remote-signers.yaml",
        "10-storage-and-ops/emergency-read-only.yaml",
        "13-operator-governance/delegated-admin-step-up.yaml",
        "13-operator-governance/breakglass-admin-approval.yaml",
    ] {
        let security = sample_security(sample);
        assert_eq!(security.required_acr, default.required_acr, "{sample}");
        assert_eq!(security.required_amr, default.required_amr, "{sample}");
        assert_requirement(&security, session, webauthn);
    }
    let security = sample_security("02-application-sign-in/totp-admin-step-up.yaml");
    assert_eq!(security.required_acr, "urn:qid:acr:totp");
    assert_eq!(security.required_amr, ["totp"]);
    assert_requirement(&security, session, totp);

    let policy: serde_json::Value =
        match serde_json::from_str(include_str!("../../../config/policies/admin.json")) {
            Ok(policy) => policy,
            Err(err) => panic!("admin.json must parse as JSON: {err}"),
        };
    assert_eq!(policy["default_decision"], "deny");
    let rules = match policy["rules"].as_array() {
        Some(rules) => rules,
        None => panic!("admin.json rules must be an array"),
    };
    assert_eq!(rules.len(), 2);
    for rule in rules {
        assert_eq!(rule["type"], "allow");
        let condition = &rule["conditions"][0];
        assert_eq!(condition["field"], "acr");
        assert_eq!(condition["op"], "equals");
        assert_eq!(condition["value"], default.required_acr);
        assert_eq!(
            session.acr.as_deref() == condition["value"].as_str(),
            webauthn
        );
    }
}

fn sample_security(sample: &str) -> AdminSecurityConfig {
    let path = format!("{}/../config/usecases/{sample}", env!("CARGO_MANIFEST_DIR"));
    match QidConfig::from_file(&path) {
        Ok(config) => config.admin.security,
        Err(err) => panic!("sample {sample} must load: {err}"),
    }
}

fn assert_requirement(security: &AdminSecurityConfig, session: &Session, accepted: bool) {
    assert!(security.require_step_up);
    assert!(security.require_reason);
    assert_eq!(
        session.acr.as_deref() == Some(security.required_acr.as_str())
            && security
                .required_amr
                .iter()
                .any(|method| session.amr.contains(method)),
        accepted
    );
    if accepted {
        // The examples describe this exact authentication method, not invented
        // hardware classification or a combination of independent factors.
        assert_eq!(session.acr.as_deref(), Some(security.required_acr.as_str()));
        assert_eq!(session.amr, security.required_amr);
    }
}
