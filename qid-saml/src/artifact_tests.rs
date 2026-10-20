use super::*;

#[test]
fn issue_instant_uses_parsed_rfc3339_and_xml_schema_timezone_bounds() {
    assert!(valid_issue_instant("2026-10-18T00:00:00Z"));
    assert!(valid_issue_instant("2026-10-18T00:00:00+14:00"));
    assert!(!valid_issue_instant("2026-10-18T00:00:00+14:01"));
    assert!(!valid_issue_instant("2026-10-18T00:00:00+00:00💥"));
}

#[test]
fn artifact_roundtrip() {
    let stored = store_artifact("<saml:Response/>", 3600, "realm", "sp").unwrap();
    let resolved = resolve_artifact(&stored.artifact, "realm", "sp").unwrap();
    assert_eq!(resolved, "<saml:Response/>");
    assert!(resolve_artifact(&stored.artifact, "realm", "sp").is_err());
}

#[test]
fn store_evicts_unredeemed_expired_artifacts() {
    let expired = store_artifact("<saml:Expired/>", 3600, "realm", "sp").unwrap();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&expired.artifact)
        .unwrap();
    let handle = hex::encode(&raw[4..]);
    {
        let mut store = ARTIFACTS.lock().unwrap_or_else(|e| e.into_inner());
        store.get_mut(&handle).unwrap().expires_at = 0;
        LAST_ARTIFACT_SWEEP.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    }

    let live = store_artifact("<saml:Live/>", 3600, "realm", "sp").unwrap();
    assert!(!ARTIFACTS.lock().unwrap().contains_key(&handle));
    assert_eq!(
        resolve_artifact(&live.artifact, "realm", "sp").unwrap(),
        "<saml:Live/>"
    );
}

#[test]
fn artifact_expired() {
    let stored = store_artifact("<saml:Response/>", 0, "realm", "sp").unwrap();
    {
        let mut store = ARTIFACTS.lock().unwrap_or_else(|e| e.into_inner());
        let handle_hex = {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&stored.artifact)
                .unwrap();
            hex::encode(&raw[4..])
        };
        if let Some(entry) = store.get_mut(&handle_hex) {
            entry.expires_at = 0;
        }
    }
    let result = resolve_artifact(&stored.artifact, "realm", "sp");
    assert!(result.is_err());
}

#[test]
fn artifact_invalid_base64() {
    let result = resolve_artifact("!!!not-base64!!!", "realm", "sp");
    assert!(result.is_err());
}

#[test]
fn artifact_wrong_type_code() {
    let raw = base64::engine::general_purpose::STANDARD.encode([
        0xffu8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let result = resolve_artifact(&raw, "realm", "sp");
    assert!(result.is_err());
}

#[test]
fn build_artifact_response_contains_elements() {
    let xml = build_artifact_response("_req123", "https://idp.example.com", "<saml:Response/>");
    assert!(xml.contains("ArtifactResponse"));
    assert!(xml.contains("_req123"));
    assert!(xml.contains("https://idp.example.com"));
    assert!(xml.contains("<saml:Response/>"));
    assert!(xml.contains("soap:Envelope"));
}

#[test]
fn iso_now_format() {
    let s = iso_now_utc();
    assert!(s.len() >= 24, "ISO string too short: {s}");
    assert!(s.ends_with('Z'), "should end with Z: {s}");
}
