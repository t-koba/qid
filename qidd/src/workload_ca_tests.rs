use super::*;

fn config() -> QidConfig {
    QidConfig::from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../config/usecases/07-workload-and-device-identity/spiffe-workload-svid.yaml"
    ))
    .unwrap()
}

fn protected_config(dir: &Path) -> QidConfig {
    let mut config = config();
    let passphrase = dir.join("passphrase");
    std::fs::write(&passphrase, "test-only-workload-protector").unwrap();
    config.crypto.key_passphrase_file = Some(passphrase.display().to_string());
    config
}

fn ca_paths(dir: &Path, name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let (private, public) = signing_key_paths(dir, name, "ES256");
    (
        encrypted_key_path(&private),
        public.with_extension("ca.pem"),
        private,
    )
}

#[test]
fn workload_ca_requires_protection_before_creating_or_reading_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config();
    config.profile = DeploymentProfile::Oidc;
    assert!(
        workload_ca::initialize(&config, dir.path(), None)
            .unwrap()
            .is_empty()
    );
    config.profile = DeploymentProfile::Workload;
    // Test the explicit absent-protector branch without mutating process environment.
    let err = workload_ca::initialize(&config, dir.path(), None)
        .err()
        .unwrap();
    assert!(err.to_string().contains("QID_KEY_PASSPHRASE"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let (encrypted, _, _) = ca_paths(dir.path(), "workload-ca");
    std::fs::write(encrypted, "not even an envelope").unwrap();
    let err = workload_ca::initialize(&config, dir.path(), None)
        .err()
        .unwrap();
    assert!(err.to_string().contains("QID_KEY_PASSPHRASE"));
}

#[test]
fn workload_ca_is_encrypted_stable_realm_isolated_and_absent_from_jwks() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = protected_config(dir.path());
    let mut second = config.realms[0].clone();
    second.id = "second".into();
    second.issuer = "https://second.example/realms/second".into();
    second.protocols.workload.workload_ca_key_ref = Some("second-ca".into());
    config.realms.push(second);
    let mut ca = config.crypto.keyrings[1].clone();
    ca.name = "second-ca".into();
    ca.realm_id = Some("second".into());
    config.crypto.keyrings.push(ca);
    let first = initialize_signing_material(&config, dir.path()).unwrap();
    use x509_parser::prelude::*;
    let (_, generated_pem) =
        parse_x509_pem(first.workload_cas["mesh"].certificate_pem.as_bytes()).unwrap();
    let (_, generated_ca) = X509Certificate::from_der(&generated_pem.contents).unwrap();
    let constraints = generated_ca.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    assert!(constraints.value.ca);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    assert_eq!(first.workload_cas.len(), 2);
    assert_ne!(
        first.workload_cas["mesh"].certificate_pem,
        first.workload_cas["second"].certificate_pem
    );
    assert_ne!(
        *first.workload_cas["mesh"].private_key_pem,
        *first.workload_cas["second"].private_key_pem
    );
    assert_eq!(first.jwks["keys"].as_array().unwrap().len(), 1);
    assert_eq!(first.jwks["keys"][0]["kid"], "deployment-jwt");
    let (encrypted, certificate, private) = ca_paths(dir.path(), "workload-ca");
    let (_, public) = signing_key_paths(dir.path(), "workload-ca", "ES256");
    let initialized_marker = certificate.with_extension("ca.state");
    assert!(!private.exists());
    assert!(!backup_key_path(&private).exists());
    assert!(!dir.path().join("workload-ca-key.pem").exists());
    let bytes = std::fs::read(&encrypted).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE KEY"));
    let second = initialize_signing_material(&config, dir.path()).unwrap();
    for realm in ["mesh", "second"] {
        assert_eq!(
            first.workload_cas[realm].certificate_pem,
            second.workload_cas[realm].certificate_pem
        );
        assert_eq!(
            *first.workload_cas[realm].private_key_pem,
            *second.workload_cas[realm].private_key_pem
        );
    }
    assert_eq!(std::fs::read(&encrypted).unwrap(), bytes);
    let (second_encrypted, second_certificate, _) = ca_paths(dir.path(), "second-ca");
    let second_bytes = std::fs::read(&second_encrypted).unwrap();
    let second_cert = std::fs::read(&second_certificate).unwrap();
    let protector = key_protector_from_config(&config, dir.path())
        .unwrap()
        .unwrap();
    let reused = protector
        .seal(
            &first.workload_cas["mesh"].private_key_pem,
            "second-ca",
            "ES256",
        )
        .unwrap();
    std::fs::write(&second_encrypted, serialize_encrypted_key(&reused).unwrap()).unwrap();
    std::fs::write(
        &second_certificate,
        &first.workload_cas["mesh"].certificate_pem,
    )
    .unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("reused across realms")
    );
    std::fs::write(second_encrypted, second_bytes).unwrap();
    std::fs::write(second_certificate, second_cert).unwrap();
    let original = std::fs::read(&certificate).unwrap();
    std::fs::write(&certificate, &first.workload_cas["second"].certificate_pem).unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("invalid or mismatched")
    );
    assert_eq!(std::fs::read(&encrypted).unwrap(), bytes);
    std::fs::write(&certificate, original).unwrap();
    let (jwt_encrypted, _, _) = ca_paths(dir.path(), "deployment-jwt");
    let jwt_bytes = std::fs::read(&jwt_encrypted).unwrap();
    let reused = protector
        .seal(
            &first.workload_cas["mesh"].private_key_pem,
            "deployment-jwt",
            "ES256",
        )
        .unwrap();
    std::fs::write(&jwt_encrypted, serialize_encrypted_key(&reused).unwrap()).unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("reused by JWT keyring")
    );
    std::fs::write(jwt_encrypted, jwt_bytes).unwrap();
    std::fs::remove_file(&encrypted).unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("incomplete existing")
    );
    assert!(!encrypted.exists());
    std::fs::write(&encrypted, bytes).unwrap();
    std::fs::remove_file(&encrypted).unwrap();
    std::fs::remove_file(&certificate).unwrap();
    std::fs::remove_file(&public).unwrap();
    assert!(initialized_marker.exists());
    let error = initialize_signing_material(&config, dir.path())
        .err()
        .unwrap();
    assert!(error.to_string().contains("initialization marker"));
    assert!(!encrypted.exists());
}

#[test]
fn workload_ca_legacy_partial_and_alias_state_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let config = protected_config(dir.path());
    for file in ["workload-ca.pem", "workload-ca-key.pem"] {
        let path = dir.path().join(file);
        std::fs::write(&path, "legacy sentinel").unwrap();
        let error = initialize_signing_material(&config, dir.path())
            .err()
            .unwrap();
        assert!(error.to_string().contains("legacy"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "legacy sentinel");
        assert!(!ca_paths(dir.path(), "workload-ca").0.exists());
        std::fs::remove_file(path).unwrap();
    }
    let mut alias = config.clone();
    alias.crypto.keyrings[0].name = "WORKLOAD-CA".into();
    let error = initialize_signing_material(&alias, dir.path())
        .err()
        .unwrap();
    assert!(error.to_string().contains("same local key path"));
    assert!(!ca_paths(dir.path(), "workload-ca").0.exists());
    let (encrypted, certificate, _) = ca_paths(dir.path(), "workload-ca");
    std::fs::write(
        dir.path()
            .join("signing-key-workload-ca-ES256-workload-ca-next.pem.enc"),
        "successor sentinel",
    )
    .unwrap();
    let error = initialize_signing_material(&config, dir.path())
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("successor files are not supported")
    );
    assert!(!encrypted.exists());
    std::fs::remove_file(
        dir.path()
            .join("signing-key-workload-ca-ES256-workload-ca-next.pem.enc"),
    )
    .unwrap();
    std::fs::write(&encrypted, "invalid existing envelope").unwrap();
    assert!(initialize_signing_material(&config, dir.path()).is_err());
    assert!(!certificate.exists());
    assert_eq!(
        std::fs::read_to_string(encrypted).unwrap(),
        "invalid existing envelope"
    );
}

#[test]
fn workload_ca_rejects_corrupt_or_wrongly_protected_material_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let config = protected_config(dir.path());
    initialize_signing_material(&config, dir.path()).unwrap();
    let (encrypted, certificate, private) = ca_paths(dir.path(), "workload-ca");
    let bytes = std::fs::read(&encrypted).unwrap();
    let cert = std::fs::read(&certificate).unwrap();
    let wrong = PassphraseProtector::new(b"wrong-passphrase".to_vec()).unwrap();
    assert!(workload_ca::initialize(&config, dir.path(), Some(&wrong)).is_err());
    std::fs::write(&certificate, "invalid certificate").unwrap();
    assert!(initialize_signing_material(&config, dir.path()).is_err());
    assert_eq!(
        std::fs::read_to_string(&certificate).unwrap(),
        "invalid certificate"
    );
    std::fs::write(&certificate, &cert).unwrap();
    let mut envelope = parse_encrypted_key(std::str::from_utf8(&bytes).unwrap()).unwrap();
    envelope.kid = "foreign-ca".into();
    std::fs::write(&encrypted, serialize_encrypted_key(&envelope).unwrap()).unwrap();
    assert!(initialize_signing_material(&config, dir.path()).is_err());
    assert_eq!(std::fs::read(&certificate).unwrap(), cert);
    std::fs::write(&encrypted, bytes).unwrap();
    std::fs::remove_file(&certificate).unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("incomplete existing")
    );
    assert!(!certificate.exists());
    std::fs::write(&private, "plaintext sentinel").unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("plaintext")
    );
    assert_eq!(
        std::fs::read_to_string(private).unwrap(),
        "plaintext sentinel"
    );
}

#[test]
fn workload_ca_preserves_explicitly_provisioned_identity_and_validates_constraints() {
    let dir = tempfile::tempdir().unwrap();
    let config = protected_config(dir.path());
    let protector = key_protector_from_config(&config, dir.path())
        .unwrap()
        .unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let original = params.clone().self_signed(&key).unwrap().pem();
    let (encrypted, certificate, _) = ca_paths(dir.path(), "workload-ca");
    let envelope = protector
        .seal(&key.serialize_pem(), "workload-ca", "ES256")
        .unwrap();
    std::fs::write(&encrypted, serialize_encrypted_key(&envelope).unwrap()).unwrap();
    std::fs::write(&certificate, &original).unwrap();
    let material = initialize_signing_material(&config, dir.path()).unwrap();
    assert_eq!(material.workload_cas["mesh"].certificate_pem, original);
    assert_eq!(
        *material.workload_cas["mesh"].private_key_pem,
        key.serialize_pem()
    );
    assert_eq!(std::fs::read_to_string(&certificate).unwrap(), original);
    for invalid in 0..5 {
        let mut bad = params.clone();
        match invalid {
            0 => bad.is_ca = rcgen::IsCa::NoCa,
            1 => bad.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature],
            2 => {
                bad.not_before = rcgen::date_time_ymd(2000, 1, 1);
                bad.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            3 => bad.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(1)),
            _ => {}
        }
        let pem = if invalid == 4 {
            let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let issuer = params.clone().self_signed(&issuer_key).unwrap();
            bad.signed_by(&key, &issuer, &issuer_key).unwrap().pem()
        } else {
            bad.self_signed(&key).unwrap().pem()
        };
        std::fs::write(&certificate, &pem).unwrap();
        assert!(initialize_signing_material(&config, dir.path()).is_err());
        assert_eq!(std::fs::read_to_string(&certificate).unwrap(), pem);
    }
    // Even if the envelope metadata claims ES256, another key type fails closed.
    let wrong_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let wrong = protector
        .seal(&wrong_key.serialize_pem(), "workload-ca", "ES256")
        .unwrap();
    std::fs::write(&encrypted, serialize_encrypted_key(&wrong).unwrap()).unwrap();
    assert!(
        initialize_signing_material(&config, dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("key must be ES256")
    );
}

#[test]
fn workload_ca_restart_does_not_mistake_another_active_keyring_for_successor() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = protected_config(dir.path());
    config.realms[0].protocols.workload.workload_ca_key_ref = Some("foo".into());
    config.crypto.keyrings[0].name = "foo-ES256-bar".into();
    config.crypto.keyrings[1].name = "foo".into();

    let first = initialize_signing_material(&config, dir.path()).unwrap();
    let second = initialize_signing_material(&config, dir.path()).unwrap();
    assert_eq!(
        first.workload_cas["mesh"].certificate_pem,
        second.workload_cas["mesh"].certificate_pem
    );
    assert_eq!(first.jwks, second.jwks);
}
