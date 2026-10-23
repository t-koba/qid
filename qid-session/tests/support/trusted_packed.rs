use super::*;
use base64::engine::general_purpose::STANDARD;
use qid_core::config::{AttestationModelStatus, PackedAttestationPolicy};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _},
};

const MODEL: &str = "11111111-1111-1111-1111-111111111111";

struct Pki {
    root: Vec<u8>,
    chain: Vec<Vec<u8>>,
    key: EcdsaKeyPair,
}

impl Pki {
    fn new(case: &str) -> anyhow::Result<Self> {
        let root_key = KeyPair::generate()?;
        let mut ca = CertificateParams::default();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut root_params = ca.clone();
        if case == "pinned-root" {
            root_params.not_after = rcgen::date_time_ymd(2000, 1, 1);
            root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        }
        let root = root_params.self_signed(&root_key)?;
        let intermediate_key = KeyPair::generate()?;
        let mut intermediate = ca.clone();
        intermediate
            .distinguished_name
            .push(DnType::CommonName, "Intermediate");
        match case {
            "non-ca" => intermediate.is_ca = IsCa::ExplicitNoCa,
            "intermediate-ku" => intermediate.key_usages = vec![KeyUsagePurpose::DigitalSignature],
            "expired-intermediate" => intermediate.not_after = rcgen::date_time_ymd(2000, 1, 1),
            _ => {}
        }
        if case == "path-length" {
            intermediate.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        }
        let intermediate_cert = intermediate.signed_by(&intermediate_key, &root, &root_key)?;
        let extra_key = KeyPair::generate()?;
        let mut extra = ca.clone();
        extra
            .distinguished_name
            .push(DnType::CommonName, "Extra Intermediate");
        let extra_cert = extra.signed_by(&extra_key, &intermediate_cert, &intermediate_key)?;
        let mut leaf = CertificateParams::default();
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.distinguished_name.push(DnType::CountryName, "JP");
        leaf.distinguished_name
            .push(DnType::OrganizationName, "Synthetic Authenticator");
        leaf.distinguished_name.push(
            DnType::OrganizationalUnitName,
            if case == "subject" {
                "Wrong OU"
            } else {
                "Authenticator Attestation"
            },
        );
        if case != "missing-aaguid" {
            let mut value = vec![4, 16]; // DER OCTET STRING.
            value.extend_from_slice(&[if case == "aaguid" { 0x22 } else { 0x11 }; 16]);
            let mut ext =
                CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4], value);
            ext.set_criticality(case == "critical-aaguid");
            leaf.custom_extensions.push(ext);
        }
        match case {
            "expired" => leaf.not_after = rcgen::date_time_ymd(2000, 1, 1),
            "future-cert" => leaf.not_before = rcgen::date_time_ymd(2099, 1, 1),
            "ca-leaf" => leaf.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
            "missing-bc" => leaf.is_ca = IsCa::NoCa,
            "leaf-ku" => leaf.key_usages = vec![KeyUsagePurpose::KeyEncipherment],
            "eku" => leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            "malformed-eku" | "empty-eku" => {
                let value = if case == "empty-eku" {
                    vec![0x30, 0]
                } else {
                    vec![0x30, 6, 6, 2, 0x2a, 3, 5, 0]
                }; // OID then invalid NULL suffix.
                leaf.custom_extensions
                    .push(CustomExtension::from_oid_content(&[2, 5, 29, 37], value));
            }
            "critical" => {
                let mut ext = CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![5, 0]);
                ext.set_criticality(true);
                leaf.custom_extensions.push(ext);
            }
            _ => {}
        }
        let key = KeyPair::generate()?;
        let leaf_cert = if case == "path-length" {
            leaf.signed_by(&key, &extra_cert, &extra_key)?
        } else {
            leaf.signed_by(&key, &intermediate_cert, &intermediate_key)?
        };
        let mut chain = vec![leaf_cert.der().to_vec()];
        if case == "path-length" {
            chain.push(extra_cert.der().to_vec());
        }
        chain.push(intermediate_cert.der().to_vec());
        Ok(Self {
            root: root.der().to_vec(),
            chain,
            key: EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &key.serialize_der(),
                &SystemRandom::new(),
            )
            .map_err(|_| anyhow::anyhow!("synthetic signing key"))?,
        })
    }

    fn policy(&self) -> anyhow::Result<PackedAttestationPolicy> {
        Ok(serde_json::from_value(json!({
            "metadata": {"not_before": 1, "expires_at": 4102444800u64,
                "models": {MODEL: {"status": "allowed", "roots": [STANDARD.encode(&self.root)]}}}
        }))?)
    }

    fn response(
        &self,
        challenge: &serde_json::Value,
        case: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let mut fields = attestation_fields()?;
        if case == "self" {
            // A genuine valid self-attestation uses the credential's own key.
            let CborValue::Bytes(auth_data) = &mut fields[1].1 else {
                anyhow::bail!("auth data")
            };
            auth_data.truncate(59); // RP/flags/counter/AAGUID/credential ID.
            let key = self.key.public_key().as_ref();
            auth_data.extend(cbor(CborValue::Map(vec![
                (1.into(), 2.into()),
                (3.into(), (-7).into()),
                ((-1).into(), 1.into()),
                ((-2).into(), CborValue::Bytes(key[1..33].to_vec())),
                ((-3).into(), CborValue::Bytes(key[33..65].to_vec())),
            ]))?);
        }
        let CborValue::Bytes(auth_data) = &fields[1].1 else {
            anyhow::bail!("auth data")
        };
        let mut response = registration_response(challenge, &[]);
        let mut client_data = URL_SAFE_NO_PAD.decode(
            response["response"]["response"]["clientDataJSON"]
                .as_str()
                .context("client data")?,
        )?;
        // Mutate before signing: these are valid statements over invalid ceremony data.
        if matches!(case, "origin" | "client-type") {
            let mut client: serde_json::Value = serde_json::from_slice(&client_data)?;
            if case == "origin" {
                client["origin"] = "https://other.example.com".into();
            } else {
                client["type"] = "webauthn.get".into();
            }
            client_data = serde_json::to_vec(&client)?;
        }
        if case == "boundaries" {
            client_data.resize(256, b' '); // Valid JSON trailing whitespace.
        }
        response["response"]["response"]["clientDataJSON"] =
            URL_SAFE_NO_PAD.encode(&client_data).into();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let mut sig = self
            .key
            .sign(&SystemRandom::new(), &signed)
            .map_err(|_| anyhow::anyhow!("sign"))?
            .as_ref()
            .to_vec();
        if case == "signature" {
            sig[10] ^= 1;
        }
        let mut chain = self.chain.clone();
        if case == "broken-chain" {
            *chain[1].last_mut().context("certificate signature")? ^= 1;
        }
        let mut stmt = vec![
            (
                "alg".into(),
                (if case == "algorithm" { -35 } else { -7 }).into(),
            ),
            ("sig".into(), CborValue::Bytes(sig)),
        ];
        if case != "self" {
            stmt.push((
                "x5c".into(),
                CborValue::Array(chain.into_iter().map(CborValue::Bytes).collect()),
            ));
        }
        fields[0].1 = (if case == "unsupported" {
            "tpm"
        } else if case == "none" {
            "none"
        } else {
            "packed"
        })
        .into();
        fields[2].1 = if case == "none" {
            CborValue::Map(vec![])
        } else {
            CborValue::Map(stmt)
        };
        if case == "boundaries" {
            // An ignored field pads the CBOR without changing signed authData.
            // Keep the byte-string header width constant despite ECDSA size variation.
            fields.push(("padding".into(), CborValue::Bytes(vec![0; 512])));
            let len = cbor(CborValue::Map(fields.clone()))?.len();
            fields.last_mut().context("padding")?.1 = CborValue::Bytes(vec![0; 512 + 2048 - len]);
        }
        let evidence = cbor(CborValue::Map(fields))?;
        if case == "boundaries" {
            assert_eq!(evidence.len(), 2048);
        }
        response["response"]["response"]["attestationObject"] =
            URL_SAFE_NO_PAD.encode(evidence).into();
        Ok(response)
    }
}

async fn finish(
    app: &TestApp,
    response: serde_json::Value,
) -> anyhow::Result<(StatusCode, String)> {
    post(
        app.router.clone(),
        "/api/v1/corp/auth/webauthn/finish",
        response,
        Some(&app.cookie),
    )
    .await
}

#[tokio::test]
async fn trusted_packed_route_enrolls_only_after_trust_and_ceremony_verification()
-> anyhow::Result<()> {
    let pki = Pki::new("valid")?;
    let policy = pki.policy()?;
    policy.validate(true)?;
    let app = app_with_policy(Some(policy)).await?;
    let challenge = start_with_attestation(&app, "direct").await?;
    let response = pki.response(&challenge, "valid")?;
    let evidence = URL_SAFE_NO_PAD.decode(
        response["response"]["response"]["attestationObject"]
            .as_str()
            .context("evidence")?,
    )?;
    eprintln!(
        "synthetic fixture: root={} leaf={} intermediate={} evidence={} client={}",
        pki.root.len(),
        pki.chain[0].len(),
        pki.chain[1].len(),
        evidence.len(),
        URL_SAFE_NO_PAD
            .decode(
                response["response"]["response"]["clientDataJSON"]
                    .as_str()
                    .context("client")?
            )?
            .len()
    );
    let (status, body) = finish(&app, response.clone()).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let stored = app.repo.get_webauthn_credentials("alice").await?;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].aaguid, [0x11; 16]);
    let (status, body) = finish(&app, response).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("no registration in progress"), "{body}");
    Ok(())
}

#[tokio::test]
async fn required_trust_failures_never_store_and_consume_the_ceremony() -> anyhow::Result<()> {
    let valid = Pki::new("valid")?;
    for case in [
        "expired-metadata",
        "future-metadata",
        "unknown-model",
        "blocked-model",
        "wrong-root",
        "none",
        "self",
        "unsupported",
        "algorithm",
        "signature",
        "broken-chain",
        "expired",
        "future-cert",
        "non-ca",
        "ca-leaf",
        "path-length",
        "critical",
        "aaguid",
        "missing-aaguid",
        "critical-aaguid",
        "subject",
        "missing-bc",
        "leaf-ku",
        "intermediate-ku",
        "expired-intermediate",
        "eku",
        "malformed-eku",
        "empty-eku",
        "evidence-limit",
        "client-limit",
        "certificate-limit",
        "count-limit",
        "challenge",
        "origin",
        "client-type",
    ] {
        let pki = Pki::new(case)?;
        let mut policy = pki.policy()?;
        match case {
            "expired-metadata" => policy.metadata.expires_at = 2,
            "future-metadata" => {
                policy.metadata.not_before = 4102444799;
            }
            "unknown-model" => {
                let model = policy.metadata.models.remove(MODEL).context("model")?;
                policy
                    .metadata
                    .models
                    .insert("22222222-2222-2222-2222-222222222222".into(), model);
            }
            "blocked-model" => {
                policy
                    .metadata
                    .models
                    .get_mut(MODEL)
                    .context("model")?
                    .status = AttestationModelStatus::Blocked
            }
            "wrong-root" => {
                policy
                    .metadata
                    .models
                    .get_mut(MODEL)
                    .context("model")?
                    .roots = vec![STANDARD.encode(&valid.root)]
            }
            "evidence-limit" => policy.limits.evidence_bytes = 100,
            "client-limit" => policy.limits.client_data_bytes = 1,
            "certificate-limit" => policy.limits.certificate_bytes = pki.chain[0].len() - 1,
            "count-limit" => policy.limits.certificates = 1,
            _ => {}
        }
        policy.validate(true)?;
        let app = app_with_policy(Some(policy)).await?;
        let challenge = start_with_attestation(&app, "direct").await?;
        let mut signing_challenge = challenge.clone();
        if case == "challenge" {
            signing_challenge["challenge"]["challenge"] = URL_SAFE_NO_PAD.encode([0; 32]).into();
        }
        let response = pki.response(&signing_challenge, case)?;
        let (status, body) = finish(&app, response).await?;
        assert_ne!(status, StatusCode::CREATED, "{case}: {body}");
        if matches!(case, "origin" | "client-type") {
            assert!(
                body.contains("webauthn finish registration:"),
                "{case}: {body}"
            );
        }
        assert!(
            app.repo.get_webauthn_credentials("alice").await?.is_empty(),
            "{case}"
        );
        // A cryptographically valid retry must not rescue the consumed ceremony.
        let (status, body) = finish(&app, pki.response(&challenge, "valid")?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {body}");
        assert!(
            body.contains("no registration in progress"),
            "{case}: {body}"
        );
        assert!(
            app.repo.get_webauthn_credentials("alice").await?.is_empty(),
            "{case} retry"
        );
    }
    Ok(())
}

#[tokio::test]
async fn trusted_packed_byte_limits_are_inclusive() -> anyhow::Result<()> {
    let pki = Pki::new("valid")?;
    let certificate_bytes = pki.chain.iter().map(Vec::len).max().context("chain")?;
    for dimension in ["evidence", "client", "certificate"] {
        for over_limit in [false, true] {
            let mut policy = pki.policy()?;
            // The identical valid fixture is exactly at the ceiling, or one byte over it.
            let excess = usize::from(over_limit);
            match dimension {
                "evidence" => policy.limits.evidence_bytes = 2048 - excess,
                "client" => policy.limits.client_data_bytes = 256 - excess,
                "certificate" => policy.limits.certificate_bytes = certificate_bytes - excess,
                _ => unreachable!(),
            }
            policy.validate(true)?;
            let app = app_with_policy(Some(policy)).await?;
            let challenge = start_with_attestation(&app, "direct").await?;
            let response = pki.response(&challenge, "boundaries")?;
            let (status, body) = finish(&app, response.clone()).await?;
            if over_limit {
                assert_ne!(status, StatusCode::CREATED, "{dimension}: {body}");
            } else {
                assert_eq!(status, StatusCode::CREATED, "{dimension}: {body}");
            }
            let expected = usize::from(!over_limit);
            assert_eq!(
                app.repo.get_webauthn_credentials("alice").await?.len(),
                expected
            );
            let (status, body) = finish(&app, response).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{dimension}: {body}");
            assert!(
                body.contains("no registration in progress"),
                "{dimension}: {body}"
            );
            assert_eq!(
                app.repo.get_webauthn_credentials("alice").await?.len(),
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn attestation_configuration_is_validated_not_silently_ignored() -> anyhow::Result<()> {
    let pki = Pki::new("valid")?;
    let policy = pki.policy()?;
    assert!(policy.validate(true).is_ok());
    assert!(policy.validate(false).is_err());
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.passkeys.enabled = true;
    config.realms[0].authentication.passkeys.attestation = Some(policy.clone());
    config.validate()?;
    config.realms[0].authentication.passkeys.enabled = false;
    assert!(config.validate().is_err());
    let duplicate = format!(
        r#"{{"metadata":{{"not_before":1,"expires_at":2,"models":{{"{MODEL}":{{"status":"allowed","roots":[]}},"{MODEL}":{{"status":"blocked","roots":[]}}}}}}}}"#
    );
    assert!(serde_json::from_str::<PackedAttestationPolicy>(&duplicate).is_err());
    for case in [
        "empty",
        "times",
        "id",
        "alias",
        "uppercase",
        "roots",
        "der",
        "trailing-der",
        "base64",
        "limit",
        "models",
        "root-count",
        "root-size",
    ] {
        let mut p = policy.clone();
        match case {
            "empty" => p.metadata.models.clear(),
            "times" => p.metadata.not_before = p.metadata.expires_at,
            "id" | "alias" => {
                let model = p.metadata.models.remove(MODEL).context("model")?;
                p.metadata.models.insert(
                    if case == "id" {
                        "111"
                    } else {
                        "11111111111111111111111111111111"
                    }
                    .into(),
                    model,
                );
            }
            "roots" => p
                .metadata
                .models
                .get_mut(MODEL)
                .context("model")?
                .roots
                .clear(),
            "der" | "base64" => {
                p.metadata.models.get_mut(MODEL).context("model")?.roots = vec![if case == "der" {
                    STANDARD.encode(b"not DER")
                } else {
                    "!".into()
                }]
            }
            "trailing-der" => {
                let mut der = pki.root.clone();
                der.push(0);
                p.metadata.models.get_mut(MODEL).context("model")?.roots =
                    vec![STANDARD.encode(der)];
            }
            "limit" => p.limits.certificates = 0,
            "models" => {
                p.limits.models = 1;
                p.metadata.models.insert(
                    "22222222-2222-2222-2222-222222222222".into(),
                    p.metadata.models[MODEL].clone(),
                );
            }
            "uppercase" => {
                p.metadata.models.insert(
                    "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".into(),
                    p.metadata.models[MODEL].clone(),
                );
            }
            "root-count" => {
                p.metadata
                    .models
                    .get_mut(MODEL)
                    .context("model")?
                    .roots
                    .push(STANDARD.encode(&pki.root));
                p.limits.roots_per_model = 1;
            }
            "root-size" => p.limits.certificate_bytes = 1,
            _ => unreachable!(),
        }
        assert!(p.validate(true).is_err(), "{case}");
    }
    let mut json = serde_json::to_value(
        json!({"metadata": {"not_before": 1, "expires_at": 2, "models": {MODEL: {"status": "unknown", "roots": []}}}}),
    )?;
    assert!(serde_json::from_value::<PackedAttestationPolicy>(json.clone()).is_err());
    json["metadata"]["models"][MODEL]["status"] = "allowed".into();
    json["fetch_url"] = "https://example.invalid".into();
    assert!(serde_json::from_value::<PackedAttestationPolicy>(json).is_err());
    Ok(())
}

#[test]
fn realm_trust_and_ceremonies_do_not_leak_between_services() -> anyhow::Result<()> {
    use qid_session::webauthn::{WebAuthnService, WebAuthnState};
    let a = Pki::new("pinned-root")?;
    let b = Pki::new("valid")?;
    let policy_a = a.policy()?;
    let policy_b = b.policy()?;
    let service_a = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?
        .with_attestation(Some(&policy_a));
    let service_b = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?
        .with_attestation(Some(&policy_b));
    let state = WebAuthnState::new();
    let options = service_a.start_registration(&state, "a", "alice", "alice", "Alice")?;
    service_b.start_registration(&state, "b", "alice", "alice", "Alice")?;
    let response = a.response(&json!({"challenge": options}), "valid")?["response"].clone();
    assert!(
        service_b
            .finish_registration(&state, "b", "alice", response.clone())
            .is_err()
    );
    assert!(
        service_a
            .finish_registration(&state, "a", "alice", response)
            .is_ok()
    );
    Ok(())
}

#[test]
fn metadata_that_expires_between_start_and_finish_cannot_enroll() -> anyhow::Result<()> {
    use qid_session::webauthn::{WebAuthnService, WebAuthnState};
    let pki = Pki::new("valid")?;
    let mut policy = pki.policy()?;
    let state = WebAuthnState::new();
    let service = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?
        .with_attestation(Some(&policy));
    let options = service.start_registration(&state, "corp", "alice", "alice", "Alice")?;
    let response = pki.response(&json!({"challenge": options}), "valid")?["response"].clone();
    // Deterministically advance the metadata boundary, not the wall clock. No
    // sleep or start-time cached trust: the service is rebuilt on each request.
    policy.metadata.expires_at = qid_core::util::now_seconds();
    let service = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?
        .with_attestation(Some(&policy));
    assert!(
        service
            .finish_registration(&state, "corp", "alice", response.clone())
            .is_err()
    );
    policy.metadata.expires_at = 4102444800;
    let service = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?
        .with_attestation(Some(&policy));
    let error = service
        .finish_registration(&state, "corp", "alice", response)
        .err()
        .context("consumed ceremony")?;
    assert!(error.message().contains("no registration in progress"));
    Ok(())
}

#[test]
fn self_attestation_fixture_is_valid_without_required_trust() -> anyhow::Result<()> {
    use qid_session::webauthn::{WebAuthnService, WebAuthnState};
    let pki = Pki::new("valid")?;
    let service = WebAuthnService::new("id.example.com", "qid", "https://id.example.com")?;
    let state = WebAuthnState::new();
    let options = service.start_registration(&state, "corp", "alice", "alice", "Alice")?;
    let response = pki.response(&json!({"challenge": options}), "self")?["response"].clone();
    assert!(
        service
            .finish_registration(&state, "corp", "alice", response)
            .is_ok()
    );
    Ok(())
}
