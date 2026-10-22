//! The SPIFFE ID rule every path that names a SPIFFE ID applies.

use qid_core::spiffe::{require_spiffe_trust_domain, spiffe_trust_domain, validate_spiffe_id};

#[test]
fn a_well_formed_spiffe_id_names_its_trust_domain() {
    assert_eq!(
        spiffe_trust_domain("spiffe://prod.example/ns/default/sa/api").expect("trust domain"),
        "prod.example"
    );
    assert!(validate_spiffe_id("spiffe://prod.example/ns/default/sa/api").is_ok());
}

#[test]
fn a_malformed_spiffe_id_is_refused() {
    for spiffe_id in [
        "http://example.com",
        "spiffe://",
        "spiffe:///ns/default/sa/api",
        "spiffe://prod.example/ns/default/sa/my app",
        "spiffe://prod.example/ns/default/sa/api?role=admin",
    ] {
        assert!(
            validate_spiffe_id(spiffe_id).is_err(),
            "the product must refuse {spiffe_id}"
        );
    }
}

#[test]
fn a_registration_must_name_the_trust_domain_of_its_spiffe_id() {
    assert!(
        require_spiffe_trust_domain("spiffe://prod.example/ns/default/sa/api", "prod.example")
            .is_ok()
    );
    assert!(
        require_spiffe_trust_domain("spiffe://prod.example/ns/default/sa/api", "other.example")
            .is_err()
    );
}
