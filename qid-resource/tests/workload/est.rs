use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};

fn folded_base64(bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

fn policy() -> WorkloadProtocolConfig {
    WorkloadProtocolConfig {
        est: true,
        jwt_svid: true,
        x509_svid: true,
        workload_ca_key_ref: Some("test-ca".into()),
        ..Default::default()
    }
}
async fn setup_est() -> (axum::Router, Arc<SharedState<SqlRepository>>, String) {
    setup_with_workload_policy(policy()).await
}
fn request(realm: &str, resource: &str, token: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(if resource == "cacerts" {
            Method::GET
        } else {
            Method::POST
        })
        .uri(format!("/.well-known/est/{realm}/{resource}"))
        .header("authorization", token)
        .header("content-type", "application/pkcs10")
        .header("content-transfer-encoding", "base64")
        .body(body.into())
        .unwrap()
}
async fn call(
    app: &axum::Router,
    resource: &str,
    token: &str,
    body: impl Into<Body>,
) -> axum::response::Response {
    app.clone()
        .oneshot(request("test", resource, token, body))
        .await
        .unwrap()
}
async fn cms_body(response: axum::response::Response) -> Vec<u8> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/pkcs7-mime; smime-type=certs-only"
    );
    assert_eq!(response.headers()["content-transfer-encoding"], "base64");
    let encoded = response.into_body().collect().await.unwrap().to_bytes();
    assert!(encoded.ends_with(b"\r\n"));
    let mut compact = Vec::with_capacity(encoded.len());
    let mut line_len = 0;
    let mut i = 0;
    while i < encoded.len() {
        match encoded[i] {
            b'\r' if encoded.get(i + 1) == Some(&b'\n') && line_len > 0 => {
                i += 2;
                line_len = 0;
            }
            b'\r' | b'\n' => panic!("invalid MIME base64 fold"),
            byte => {
                line_len += 1;
                assert!(line_len <= 76, "MIME base64 line exceeds 76 characters");
                compact.push(byte);
                i += 1;
            }
        }
    }
    let der = STANDARD.decode(compact).unwrap();
    // Structural assertion for the existing cms certs-only helper, not merely a cert parser.
    let ci = ContentInfo::from_der(&der).unwrap();
    assert_eq!(ci.content_type.to_string(), "1.2.840.113549.1.7.2");
    let sd = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    assert!(sd.signer_infos.0.is_empty());
    assert!(sd.digest_algorithms.is_empty());
    assert!(sd.encap_content_info.econtent.is_none());
    assert_eq!(
        sd.encap_content_info.econtent_type.to_string(),
        "1.2.840.113549.1.7.1"
    );
    let certs = sd.certificates.unwrap();
    assert_eq!(certs.0.len(), 1);
    let CertificateChoices::Certificate(cert) = certs.0.get(0).unwrap() else {
        panic!("not X.509")
    };
    cert.to_der().unwrap()
}
async fn stored(state: &SharedState<SqlRepository>) -> Vec<WorkloadCertificate> {
    state
        .repo
        .list_workload_certificates(&"test".into(), None)
        .await
        .unwrap()
}
// Rebuild only the router/config for defense-in-depth runtime gate tests.
fn reconfigure(
    app: axum::Router,
    state: Arc<SharedState<SqlRepository>>,
    change: impl FnOnce(&mut SharedState<SqlRepository>),
) -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    drop(app);
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    change(&mut state);
    let state = Arc::new(state);
    (
        qid_resource::workload_routes().with_state(state.clone()),
        state,
    )
}

#[tokio::test]
async fn est_auth_gates_and_realm_isolation() {
    for gate in ["est", "jwt", "x509", "ca", "ambiguous"] {
        let (app, state, token) = setup_est().await;
        let (app, state) = reconfigure(app, state, |s| match gate {
            "est" => s.config.realms[0].protocols.workload.est = false,
            "jwt" => s.config.realms[0].protocols.workload.jwt_svid = false,
            "x509" => s.config.realms[0].protocols.workload.x509_svid = false,
            "ca" => {
                s.workload_cas.remove("test");
            }
            _ => s.config.realms[1].issuer = s.config.realms[0].issuer.clone(),
        });
        for resource in ["cacerts", "simpleenroll", "simplereenroll"] {
            assert_eq!(
                call(&app, resource, &token, "").await.status(),
                StatusCode::NOT_FOUND,
                "{gate}/{resource}"
            );
        }
        state.repo.as_ref().clone().close().await;
    }
    let (app, state, token) = setup_est().await;
    let (app, state) = reconfigure(app, state, |s| {
        s.config.realms[1].protocols.workload = policy()
    });
    let mut claims = state
        .signer
        .decode_signature_only(token.strip_prefix("Bearer ").unwrap())
        .unwrap()
        .claims;
    claims.sub = Some("spiffe://prod.example/unregistered".into());
    let unregistered = format!("Bearer {}", state.signer.sign(&claims).unwrap());
    let provisioning = provisioning_token(&state, WORKLOAD_SPIFFE_ID, "test", "tenant-1");
    for resource in ["cacerts", "simpleenroll", "simplereenroll"] {
        for bad in ["", "Bearer invalid", &unregistered, &provisioning] {
            assert_eq!(
                call(&app, resource, bad, "").await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(request("missing", resource, &token, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        // Both realms register the SAME SPIFFE identity, but issuers and CAs differ.
        assert_eq!(
            app.clone()
                .oneshot(request("second", resource, &token, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut claims = state
        .signer
        .decode_signature_only(token.strip_prefix("Bearer ").unwrap())
        .unwrap()
        .claims;
    claims.iss = Some("https://second.example".into());
    let other_token = format!("Bearer {}", state.signer.sign(&claims).unwrap());
    let other_ca = cms_body(
        app.oneshot(request("second", "cacerts", &other_token, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        other_ca,
        x509_parser::pem::parse_x509_pem(state.workload_cas["second"].certificate_pem.as_bytes())
            .unwrap()
            .1
            .contents
    );
    assert_ne!(
        other_ca,
        x509_parser::pem::parse_x509_pem(state.workload_cas["test"].certificate_pem.as_bytes())
            .unwrap()
            .1
            .contents
    );
    assert!(stored(&state).await.is_empty());
    state.repo.as_ref().clone().close().await;
}

#[tokio::test]
async fn est_rejects_mime_base64_der_and_pop_before_issuance() {
    let (app, state, token) = setup_est().await;
    let (_, csr) = spoofed_csr();
    let encoded = folded_base64(csr.der());
    for (header, value) in [
        ("content-type", "application/json"),
        ("content-type", "application/pkcs10; charset=utf-8"),
        ("content-type", "application/pkcs7-mime"),
        ("content-transfer-encoding", "binary"),
    ] {
        let mut req = request("test", "simpleenroll", &token, encoded.clone());
        req.headers_mut().insert(header, value.parse().unwrap());
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }
    for header in ["content-type", "content-transfer-encoding"] {
        let mut req = request("test", "simpleenroll", &token, encoded.clone());
        req.headers_mut().remove(header);
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let mut req = request("test", "simpleenroll", &token, encoded.clone());
        let duplicate = req.headers()[header].clone();
        req.headers_mut().append(header, duplicate);
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }
    let mut bad_pop = csr.der().to_vec();
    *bad_pop.last_mut().unwrap() ^= 1;
    let mut trailing = csr.der().to_vec();
    trailing.push(0);
    let unwrapped = STANDARD.encode(csr.der());
    for bad in [
        "".into(),
        "!!!!".into(),
        format!("{encoded}="),
        format!(" {encoded}"),
        format!("{encoded}\n"),
        format!("{encoded}\r"),
        format!("{}\r\n{}", &unwrapped[..77], &unwrapped[77..]),
        csr.pem().unwrap(),
        folded_base64(&bad_pop),
        folded_base64(&trailing),
        folded_base64(&[csr.der().as_ref(), csr.der().as_ref()].concat()),
    ] {
        assert_eq!(
            call(&app, "simpleenroll", &token, bad).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(&app, "simpleenroll", &token, "A".repeat(16_385))
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(stored(&state).await.is_empty());
    assert!(
        state
            .repo
            .list_audit_events(Some(&"test".into()), 10)
            .await
            .unwrap()
            .is_empty()
    );
    state.repo.as_ref().clone().close().await;
}

#[tokio::test]
async fn est_enroll_cms_policy_and_rekeyed_reenroll() {
    let (app, state, token) = setup_est().await;
    let ca = cms_body(call(&app, "cacerts", &token, "").await).await;
    assert_eq!(
        ca,
        x509_parser::pem::parse_x509_pem(state.workload_cas["test"].certificate_pem.as_bytes())
            .unwrap()
            .1
            .contents
    );
    let (key, csr) = spoofed_csr();
    let folded = folded_base64(csr.der());
    let mut req = request("test", "simpleenroll", &token, folded);
    req.headers_mut()
        .insert("content-type", "APPLICATION/PKCS10".parse().unwrap());
    req.headers_mut()
        .insert("content-transfer-encoding", "BASE64".parse().unwrap());
    let leaf = cms_body(app.clone().oneshot(req).await.unwrap()).await;
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca).unwrap();
    cert.verify_signature(Some(ca_cert.public_key())).unwrap();
    assert_eq!(cert.public_key().raw, key.public_key_der());
    assert_eq!(
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        WORKLOAD_SPIFFE_ID
    );
    assert_eq!(
        cert.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names,
        vec![x509_parser::extensions::GeneralName::URI(
            WORKLOAD_SPIFFE_ID
        )]
    );
    assert!(!cert.is_ca());
    assert_eq!(cert.key_usage().unwrap().unwrap().value.flags, 1);
    assert!(
        cert.extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .client_auth
    );
    assert_eq!(
        cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp(),
        3600
    );
    let prior = stored(&state).await;
    assert_eq!(prior.len(), 1);
    assert_eq!(
        prior[0].csr_sha256,
        Some(qid_core::util::sha256_hex(csr.der()))
    );
    assert_eq!(prior[0].x5t_s256, qid_core::util::sha256_hex(&leaf));
    assert_eq!(
        prior[0].public_key_sha256,
        qid_core::util::sha256_hex(cert.public_key().raw)
    );
    let events = state
        .repo
        .list_audit_events(Some(&"test".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "workload.certificate.est.simpleenroll");
    assert_eq!(events[0].actor, "workload-api");
    assert_eq!(events[0].target_id, prior[0].id);
    assert_eq!(
        events[0].metadata_json["csr_sha256"],
        prior[0].csr_sha256.as_deref().unwrap()
    );
    let (new_key, new_csr) = spoofed_csr();
    let new_leaf =
        cms_body(call(&app, "simplereenroll", &token, folded_base64(new_csr.der())).await).await;
    let (_, new_cert) = x509_parser::parse_x509_certificate(&new_leaf).unwrap();
    assert_eq!(new_cert.public_key().raw, new_key.public_key_der());
    assert_ne!(new_cert.public_key().raw, cert.public_key().raw);
    new_cert
        .verify_signature(Some(ca_cert.public_key()))
        .unwrap();
    assert_eq!(stored(&state).await.len(), 2);
    assert!(stored(&state).await.iter().all(|c| c.revoked_at.is_none()));
    assert!(
        state
            .repo
            .list_audit_events(Some(&"test".into()), 10)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "workload.certificate.est.simplereenroll")
    );
    state.repo.as_ref().clone().close().await;
}

#[tokio::test]
async fn est_reenroll_requires_current_exact_owned_predecessor() {
    for case in [
        "absent",
        "realm",
        "workload_and_spiffe",
        "revoked",
        "expired",
        "future",
    ] {
        let (app, state, token) = setup_est().await;
        let (_, csr) = spoofed_csr();
        if case != "absent" {
            let mut claims = state
                .signer
                .decode_signature_only(token.strip_prefix("Bearer ").unwrap())
                .unwrap()
                .claims;
            let realm = if case == "realm" {
                claims.iss = Some("https://second.example".into());
                "second"
            } else {
                "test"
            };
            if case == "workload_and_spiffe" {
                let spiffe = "spiffe://prod.example/foreign";
                state
                    .repo
                    .create_workload_identity(&WorkloadIdentity {
                        id: "foreign".into(),
                        realm_id: "test".into(),
                        spiffe_id: spiffe.into(),
                        trust_domain: "prod.example".into(),
                        description: None,
                        authorities_json: serde_json::Value::Null,
                    })
                    .await
                    .unwrap();
                claims.sub = Some(spiffe.into());
            }
            let owner_token = format!("Bearer {}", state.signer.sign(&claims).unwrap());
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    &format!("/api/v1/{realm}/workload-certificates/csr"),
                    serde_json::json!({"csr_pem": csr.pem().unwrap()}).to_string(),
                    &owner_token,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let cert = json(response).await;
            let mut cert: WorkloadCertificate =
                serde_json::from_value(cert["certificate"].clone()).unwrap();
            match case {
                "revoked" => cert.revoked_at = Some(cert.issued_at),
                "expired" => {
                    cert.issued_at -= 7200;
                    cert.not_before -= 7200;
                    cert.not_after -= 7200;
                }
                "future" => {
                    cert.issued_at += 7200;
                    cert.not_before += 7200;
                    cert.not_after += 7200;
                }
                _ => {}
            }
            state.repo.store_workload_certificate(&cert).await.unwrap();
        }
        let before = stored(&state).await;
        let events = state
            .repo
            .list_audit_events(Some(&"test".into()), 10)
            .await
            .unwrap();
        assert_eq!(
            call(&app, "simplereenroll", &token, folded_base64(csr.der()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "{case}"
        );
        assert_eq!(stored(&state).await, before);
        assert_eq!(
            state
                .repo
                .list_audit_events(Some(&"test".into()), 10)
                .await
                .unwrap()
                .len(),
            events.len()
        );
        state.repo.as_ref().clone().close().await;
    }
}

#[tokio::test]
async fn est_collection_exact_limit_and_zero() {
    let (_, csr) = spoofed_csr();
    let body = folded_base64(csr.der());
    for limit in [0, body.len() - 1, body.len()] {
        let (app, state, token) = setup_with_workload_policy(WorkloadProtocolConfig {
            max_csr_bytes: limit,
            ..policy()
        })
        .await;
        let response = call(&app, "simpleenroll", &token, body.clone()).await;
        assert_eq!(
            response.status(),
            if limit == body.len() {
                StatusCode::OK
            } else {
                StatusCode::PAYLOAD_TOO_LARGE
            }
        );
        state.repo.as_ref().clone().close().await;
    }
}

#[tokio::test]
#[ignore = "required dedicated CI invocation installs pinned Python cryptography; never silently skipped there"]
async fn independent_python_est_client() {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };
    let (app, state, token) = setup_est().await;
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let tls_cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("TLS provider");
    }
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        tls_cert.pem().into_bytes(),
        tls_key.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(
        axum_server::from_tcp_rustls(listener, tls)
            .handle(handle.clone())
            .serve(app.into_make_service()),
    );
    let fixture = serde_json::json!({
        "url": format!("https://{address}/.well-known/est/test/"),
        "token": token, "tls_cert": tls_cert.pem(),
        "ca_cert": state.workload_cas["test"].certificate_pem, "spiffe": WORKLOAD_SPIFFE_ID,
    })
    .to_string();
    // Bound child execution, kill/reap on timeout, and retain server/DB cleanup results on failure.
    let client = tokio::task::spawn_blocking(move || -> Result<std::process::Output, String> {
        let mut child = Command::new("python3").args(["-c", include_str!("est_client.py")])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        let write = child.stdin.take().unwrap().write_all(fixture.as_bytes());
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline && write.is_ok() => std::thread::sleep(Duration::from_millis(20)),
                result => {
                    let kill = child.kill();
                    let reap = child.wait_with_output();
                    return Err(format!("client wait/write/timeout: {result:?}, {write:?}; kill={kill:?}; reap={reap:?}"));
                }
            }
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        write.map_err(|e| e.to_string())?;
        Ok(output)
    }).await;
    handle.shutdown();
    let server_result = tokio::time::timeout(Duration::from_secs(5), server).await;
    let issued = stored(&state).await;
    state.repo.as_ref().clone().close().await;
    assert!(
        matches!(server_result, Ok(Ok(Ok(())))),
        "server cleanup: {server_result:?}; client: {client:?}"
    );
    let output = client.unwrap().unwrap();
    assert!(
        output.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(issued.len(), 2);
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
