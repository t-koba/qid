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
    let stored = store_artifact("<saml:Response/>", 3600, "realm", "sp", "abc").unwrap();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&stored.artifact)
        .unwrap();
    assert_eq!(raw.len(), 44);
    assert_eq!(&raw[..4], &[0, 4, 0, 0]);
    assert_eq!(
        hex::encode(&raw[4..24]),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(raw[24..].len(), 20);
    assert_eq!(stored.artifact.len(), 60);
    let resolved = resolve_artifact(&stored.artifact, "realm", "sp", "abc").unwrap();
    assert_eq!(resolved, "<saml:Response/>");
    assert!(resolve_artifact(&stored.artifact, "realm", "sp", "abc").is_err());
}

#[test]
fn store_evicts_unredeemed_expired_artifacts() {
    let expired = store_artifact("<saml:Expired/>", 3600, "realm", "sp", "abc").unwrap();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&expired.artifact)
        .unwrap();
    let handle = hex::encode(&raw[24..]);
    {
        let mut store = ARTIFACTS.lock().unwrap_or_else(|e| e.into_inner());
        store.get_mut(&handle).unwrap().expires_at = 0;
        LAST_ARTIFACT_SWEEP.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    }

    let live = store_artifact("<saml:Live/>", 3600, "realm", "sp", "abc").unwrap();
    assert!(!ARTIFACTS.lock().unwrap().contains_key(&handle));
    assert_eq!(
        resolve_artifact(&live.artifact, "realm", "sp", "abc").unwrap(),
        "<saml:Live/>"
    );
}

#[test]
fn artifact_expired() {
    let stored = store_artifact("<saml:Response/>", 0, "realm", "sp", "abc").unwrap();
    {
        let mut store = ARTIFACTS.lock().unwrap_or_else(|e| e.into_inner());
        let handle_hex = {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&stored.artifact)
                .unwrap();
            hex::encode(&raw[24..])
        };
        if let Some(entry) = store.get_mut(&handle_hex) {
            entry.expires_at = 0;
        }
    }
    let result = resolve_artifact(&stored.artifact, "realm", "sp", "abc");
    assert!(result.is_err());
}

#[test]
fn artifact_invalid_base64() {
    let result = resolve_artifact("!!!not-base64!!!", "realm", "sp", "abc");
    assert!(result.is_err());
}

#[test]
fn artifact_fixed_wire_vector_and_rejected_variants_preserve_handle() {
    // Independently specified SHA-1("abc") and handle bytes 00 through 13.
    let raw = hex::decode(concat!(
        "00040000a9993e364706816aba3e25717850c26c9cd0d89d",
        "000102030405060708090a0b0c0d0e0f10111213"
    ))
    .unwrap();
    ARTIFACTS.lock().unwrap().insert(
        "000102030405060708090a0b0c0d0e0f10111213".to_owned(),
        StoredArtifact {
            realm_id: "realm".to_owned(),
            sp_entity_id: "sp".to_owned(),
            response_xml: "<saml:Vector/>".to_owned(),
            expires_at: u64::MAX,
        },
    );
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    for index in [0, 1, 2, 3, 4, 23] {
        let mut invalid = raw.clone();
        invalid[index] ^= 1;
        assert!(matches!(
            resolve_artifact(&encode(&invalid), "realm", "sp", "abc"),
            Err(QidError::BadRequest { .. })
        ));
    }
    for length in [0, 23, 24, 43, 45, 64] {
        let mut invalid = raw.clone();
        invalid.resize(length, 0);
        assert!(matches!(
            resolve_artifact(&encode(&invalid), "realm", "sp", "abc"),
            Err(QidError::BadRequest { .. })
        ));
    }
    assert!(resolve_artifact(&encode(&raw), "realm", "sp", "other-idp").is_err());
    assert_eq!(
        resolve_artifact(&encode(&raw), "realm", "sp", "abc").unwrap(),
        "<saml:Vector/>"
    );
    assert!(resolve_artifact(&encode(&raw), "realm", "sp", "abc").is_err());
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
