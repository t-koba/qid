use qid_core::{error::QidError, models::WorkloadCertificate};
use serde_json::{Value, json};

fn certificate_json() -> Value {
    json!({
        "id": "cert", "realm_id": "realm", "workload_id": "workload",
        "spiffe_id": "spiffe://example.com/workload", "serial_number": "serial",
        "x5t_s256": "a".repeat(64), "public_key_sha256": "b".repeat(64),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "issuer_key_ref": "ca", "issued_at": 1, "not_before": 1, "not_after": 900,
        "revoked_at": null
    })
}

#[test]
fn workload_certificate_json_distinguishes_legacy_and_current_digests() {
    let current = certificate_json();
    let certificate: WorkloadCertificate = serde_json::from_value(current.clone()).unwrap();
    assert_eq!(certificate.csr_sha256, None);
    assert_eq!(serde_json::to_value(&certificate).unwrap(), current);

    let mut legacy = current.clone();
    legacy["csr_sha256"] = legacy
        .as_object_mut()
        .unwrap()
        .remove("public_key_sha256")
        .unwrap();
    let migrated: WorkloadCertificate = serde_json::from_value(legacy).unwrap();
    assert_eq!(migrated, certificate);
    assert_eq!(serde_json::to_value(migrated).unwrap(), current);

    let mut distinct = current.clone();
    distinct["csr_sha256"] = json!("c".repeat(64));
    let certificate: WorkloadCertificate = serde_json::from_value(distinct.clone()).unwrap();
    assert_eq!(certificate.public_key_sha256, "b".repeat(64));
    assert_eq!(
        certificate.csr_sha256.as_deref(),
        Some("c".repeat(64).as_str())
    );
    assert_eq!(serde_json::to_value(certificate).unwrap(), distinct);

    let mut no_digest = current.clone();
    no_digest
        .as_object_mut()
        .unwrap()
        .remove("public_key_sha256");
    assert!(serde_json::from_value::<WorkloadCertificate>(no_digest).is_err());
    let mut invalid_public_key = current.clone();
    invalid_public_key["csr_sha256"] = json!("c".repeat(64));
    for invalid in [Value::Null, json!(42)] {
        invalid_public_key["public_key_sha256"] = invalid;
        assert!(serde_json::from_value::<WorkloadCertificate>(invalid_public_key.clone()).is_err());
    }
    let mut explicit_null = current.clone();
    explicit_null["csr_sha256"] = Value::Null;
    let certificate: WorkloadCertificate = serde_json::from_value(explicit_null).unwrap();
    assert_eq!(serde_json::to_value(certificate).unwrap(), current);
}

#[test]
fn workload_certificate_validates_optional_csr_sha256() {
    let mut certificate: WorkloadCertificate = serde_json::from_value(certificate_json()).unwrap();
    certificate.validate().unwrap();
    certificate.csr_sha256 = Some("0123456789abcdef".repeat(4));
    certificate.validate().unwrap();
    for invalid in [
        "".to_string(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
    ] {
        certificate.csr_sha256 = Some(invalid);
        let error = certificate.validate().unwrap_err();
        assert!(matches!(error, QidError::BadRequest { .. }));
        assert!(error.message().contains("workload certificate csr_sha256"));
    }
}
