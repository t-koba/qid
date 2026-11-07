mod common;
use common::sql_repo;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    jwt::{Audience, JwtClaims, Signer},
    models::{WorkloadCertificate, WorkloadIdentity},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

const WORKLOAD_SPIFFE_ID: &str = "spiffe://prod.example/ns/default/sa/api";

async fn setup() -> (axum::Router, Arc<SharedState<SqlRepository>>, String) {
    let config = test_helpers::test_config();
    let repo = Arc::new(sql_repo("qid_test_resource_workload").await);
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo, signer.clone(), serde_json::json!({})).unwrap());

    let identity = WorkloadIdentity {
        id: "workload-api".to_string(),
        realm_id: "test".to_string(),
        spiffe_id: WORKLOAD_SPIFFE_ID.to_string(),
        trust_domain: "prod.example".to_string(),
        description: Some("API workload".to_string()),
        authorities_json: serde_json::Value::Null,
    };
    state
        .repo
        .create_workload_identity(&identity)
        .await
        .unwrap();
    let now = qid_core::util::now_seconds();
    let token = signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(WORKLOAD_SPIFFE_ID.to_string()),
            aud: Some(Audience::single("qid-workload-api".to_string())),
            exp: Some((now + 3600) as usize),
            nbf: Some((now - 10) as usize),
            iat: Some(now as usize),
            jti: Some("workload-test-svid".to_string()),
            extra: std::collections::HashMap::new(),
        })
        .unwrap();
    let router = qid_resource::workload_routes()
        .merge(qid_resource::spiffe_routes(&state.config.server.paths))
        .with_state(state.clone());
    (router, state, format!("Bearer {token}"))
}

async fn setup_with_workload_ca() -> (axum::Router, Arc<SharedState<SqlRepository>>, String) {
    setup_with_workload_ca_limit(16_384).await
}

async fn setup_with_workload_ca_limit(
    max_csr_bytes: usize,
) -> (axum::Router, Arc<SharedState<SqlRepository>>, String) {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.workload.max_csr_bytes = max_csr_bytes;
    let mut other = config.realms[0].clone();
    other.id = "second".into();
    other.issuer = "https://second.example".into();
    config.realms.push(other);
    let repo = Arc::new(sql_repo("qid_test_resource_workload").await);
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    repo.create_realm(
        &"tenant-1".into(),
        &"second".into(),
        "https://second.example",
        None,
    )
    .await
    .unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qid test workload CA");
        dn
    };
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = params.clone().self_signed(&ca_key).unwrap();
    let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let other_cert = params.self_signed(&other_key).unwrap();
    let state = Arc::new(
        SharedState::new(config, repo, signer.clone(), serde_json::json!({}))
            .unwrap()
            .with_workload_ca(
                "test".into(),
                "test-ca".into(),
                ca_cert.pem(),
                ca_key.serialize_pem(),
            )
            .with_workload_ca(
                "second".into(),
                "second-ca".into(),
                other_cert.pem(),
                other_key.serialize_pem(),
            ),
    );
    let identity = WorkloadIdentity {
        id: "workload-api".to_string(),
        realm_id: "test".to_string(),
        spiffe_id: WORKLOAD_SPIFFE_ID.to_string(),
        trust_domain: "prod.example".to_string(),
        description: Some("API workload".to_string()),
        authorities_json: serde_json::Value::Null,
    };
    state
        .repo
        .create_workload_identity(&identity)
        .await
        .unwrap();
    let mut other_identity = identity.clone();
    other_identity.id = "second-workload".into();
    other_identity.realm_id = "second".into();
    state
        .repo
        .create_workload_identity(&other_identity)
        .await
        .unwrap();
    let now = qid_core::util::now_seconds();
    let token = signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(WORKLOAD_SPIFFE_ID.to_string()),
            aud: Some(Audience::single("qid-workload-api".to_string())),
            exp: Some((now + 3600) as usize),
            nbf: Some((now - 10) as usize),
            iat: Some(now as usize),
            jti: Some("workload-test-svid-with-ca".to_string()),
            extra: std::collections::HashMap::new(),
        })
        .unwrap();
    let router = qid_resource::workload_routes()
        .merge(qid_resource::spiffe_routes(&state.config.server.paths))
        .with_state(state.clone());
    (router, state, format!("Bearer {token}"))
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn json_request(method: Method, uri: &str, body: String, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header(axum::http::header::AUTHORIZATION, token)
        .body(Body::from(body))
        .unwrap()
}

fn provisioning_token(
    state: &SharedState<SqlRepository>,
    spiffe_id: &str,
    realm_id: &str,
    tenant_id: &str,
) -> String {
    let now = qid_core::util::now_seconds();
    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "realm_id".to_string(),
        serde_json::Value::String(realm_id.to_string()),
    );
    extra.insert(
        "tenant_id".to_string(),
        serde_json::Value::String(tenant_id.to_string()),
    );
    let token = state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(spiffe_id.to_string()),
            aud: Some(Audience::single("qid-workload-provisioning".to_string())),
            exp: Some((now + 3600) as usize),
            nbf: Some((now - 10) as usize),
            iat: Some(now as usize),
            jti: Some(format!("provisioning-{realm_id}-{tenant_id}-{spiffe_id}")),
            extra,
        })
        .unwrap();
    format!("Bearer {token}")
}

#[tokio::test]
async fn workload_identity_provisioning_token_requires_realm_and_tenant_binding() {
    let (app, state, _) = setup().await;
    let spiffe_id = "spiffe://prod.example/ns/default/sa/worker";
    let good_token = provisioning_token(&state, spiffe_id, "test", "tenant-1");
    let create_body = format!(
        r#"{{
            "spiffe_id":"{spiffe_id}",
            "trust_domain":"prod.example",
            "description":"Worker workload"
        }}"#
    );

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            create_body,
            &good_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;
    assert_eq!(created["spiffe_id"], spiffe_id);

    let bad_spiffe_id = "spiffe://prod.example/ns/default/sa/other-worker";
    let wrong_realm_token = provisioning_token(&state, bad_spiffe_id, "other", "tenant-1");
    let create_body = format!(
        r#"{{
            "spiffe_id":"{bad_spiffe_id}",
            "trust_domain":"prod.example",
            "description":"Other worker workload"
        }}"#
    );
    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            create_body,
            &wrong_realm_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registering_a_spiffe_id_again_updates_its_identity() {
    let (app, state, _) = setup().await;
    let spiffe_id = "spiffe://prod.example/ns/default/sa/worker";
    let token = provisioning_token(&state, spiffe_id, "test", "tenant-1");
    let body = format!(
        r#"{{
            "spiffe_id":"{spiffe_id}",
            "trust_domain":"prod.example",
            "description":"First registration"
        }}"#
    );

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;
    let identity_id = created["id"].as_str().unwrap().to_string();

    // Registering the same SPIFFE ID again updates that identity: it
    // keeps its ID and states the new description.
    let body = format!(
        r#"{{
            "spiffe_id":"{spiffe_id}",
            "trust_domain":"prod.example",
            "description":"Second registration"
        }}"#
    );
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json(response).await;
    assert_eq!(updated["id"], identity_id.as_str());
    assert_eq!(updated["description"], "Second registration");

    // The realm holds one identity for that SPIFFE ID.
    let listed = state
        .repo
        .list_workload_identities(&"test".into())
        .await
        .unwrap();
    let workers: Vec<_> = listed
        .iter()
        .filter(|identity| identity.spiffe_id == spiffe_id)
        .collect();
    assert_eq!(
        workers.len(),
        1,
        "the realm must hold one identity for the SPIFFE ID"
    );
    assert_eq!(workers[0].id, identity_id);
    assert_eq!(
        workers[0].description.as_deref(),
        Some("Second registration")
    );
}

#[tokio::test]
async fn a_registration_must_name_the_trust_domain_of_its_spiffe_id() {
    let (app, state, _) = setup().await;
    let spiffe_id = "spiffe://prod.example/ns/default/sa/worker";
    let token = provisioning_token(&state, spiffe_id, "test", "tenant-1");
    let body = format!(
        r#"{{
            "spiffe_id":"{spiffe_id}",
            "trust_domain":"other.example",
            "description":"Mismatched trust domain"
        }}"#
    );

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_registration_refuses_a_spiffe_id_the_product_cannot_use() {
    let (app, state, _) = setup().await;
    let spiffe_id = "spiffe://prod.example/ns/default/sa/my app";
    let token = provisioning_token(&state, spiffe_id, "test", "tenant-1");
    let body = format!(
        r#"{{
            "spiffe_id":"{spiffe_id}",
            "trust_domain":"prod.example",
            "description":"Malformed SPIFFE ID"
        }}"#
    );

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-identities",
            body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The realm holds no identity for that ID.
    let listed = state
        .repo
        .list_workload_identities(&"test".into())
        .await
        .unwrap();
    assert!(
        listed
            .iter()
            .all(|identity| identity.spiffe_id != spiffe_id),
        "a refused SPIFFE ID must not be stored"
    );
}

#[tokio::test]
async fn issued_certificate_reports_spki_digest_not_a_missing_csr_digest() {
    let (app, state, token) = setup_with_workload_ca().await;
    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-certificates",
            format!(r#"{{"workload_id":"workload-api","spiffe_id":"{WORKLOAD_SPIFFE_ID}"}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    let certificate = &body["certificate"];
    let private_key = rcgen::KeyPair::from_pem(body["private_key_pem"].as_str().unwrap()).unwrap();
    let expected = qid_core::util::sha256_hex(private_key.public_key_der());
    assert_eq!(certificate["public_key_sha256"], expected);
    assert!(certificate.get("csr_sha256").is_none());
    let stored = state
        .repo
        .list_workload_certificates(&"test".into(), Some("workload-api"))
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].public_key_sha256, expected);
}

#[tokio::test]
async fn workload_certificate_lifecycle_requires_bound_workload_svid() {
    let (app, state, token) = setup().await;
    let workload_id = state
        .repo
        .get_workload_identity_by_spiffe(&"test".into(), WORKLOAD_SPIFFE_ID)
        .await
        .unwrap()
        .unwrap()
        .id;

    let certificate_pem =
        "-----BEGIN CERTIFICATE-----\\nZmFrZS1jZXJ0LWJ5dGVz\\n-----END CERTIFICATE-----";
    let issue_body = format!(
        r#"{{
            "workload_id":"{workload_id}",
            "spiffe_id":"spiffe://prod.example/ns/default/sa/api",
            "serial_number":"01",
            "x5t_s256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "public_key_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "certificate_pem":"{certificate_pem}",
            "issuer_key_ref":"kms://workload-ca/prod",
            "issued_at":1800000000,
            "not_before":1800000000,
            "not_after":1800003600
        }}"#
    );
    let issue_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/test/workload-certificates",
            issue_body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(issue_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let certificate_id = "workload-cert-1";
    state
        .repo
        .store_workload_certificate(&WorkloadCertificate {
            id: certificate_id.to_string(),
            realm_id: "test".to_string(),
            workload_id: workload_id.clone(),
            spiffe_id: WORKLOAD_SPIFFE_ID.to_string(),
            serial_number: "01".to_string(),
            x5t_s256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            public_key_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            csr_sha256: None,
            certificate_pem: certificate_pem.replace("\\n", "\n"),
            issuer_key_ref: "qid-ca://workload/test".to_string(),
            issued_at: 1_800_000_000,
            not_before: 1_800_000_000,
            not_after: 1_800_003_600,
            revoked_at: None,
        })
        .await
        .expect("store CA-issued workload certificate failed");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/test/workload-certificates?workload_id={workload_id}"
                ))
                .header(axum::http::header::AUTHORIZATION, &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let listed = json(list_response).await;
    let listed_certificate = listed["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|certificate| certificate["id"] == certificate_id)
        .expect("issued certificate missing");
    assert_eq!(listed_certificate["revoked_at"], serde_json::Value::Null);

    let revoke_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            &format!("/api/v1/test/workload-certificates/{certificate_id}/revoke"),
            r#"{"revoked_at":1800000100}"#.to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::NO_CONTENT);

    let list_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/test/workload-certificates?workload_id={workload_id}"
                ))
                .header(axum::http::header::AUTHORIZATION, &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = json(list_response).await;
    let listed_certificate = listed["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|certificate| certificate["id"] == certificate_id)
        .expect("revoked certificate missing");
    assert_eq!(listed_certificate["revoked_at"], 1_800_000_100);
}

#[tokio::test]
async fn workload_certificate_access_does_not_follow_reused_record_id() {
    let (app, state, _) = setup().await;
    let workload_id = "workload-api";
    let certificate_id = "workload-retained-cert";
    let certificate = WorkloadCertificate {
        id: certificate_id.to_string(),
        realm_id: "test".to_string(),
        workload_id: workload_id.to_string(),
        spiffe_id: WORKLOAD_SPIFFE_ID.to_string(),
        serial_number: "01".to_string(),
        x5t_s256: "a".repeat(64),
        public_key_sha256: "b".repeat(64),
        csr_sha256: None,
        certificate_pem: "-----BEGIN CERTIFICATE-----\\nZmFrZQ==\\n-----END CERTIFICATE-----"
            .to_string(),
        issuer_key_ref: "qid-ca://workload/test".to_string(),
        issued_at: 1_800_000_000,
        not_before: 1_800_000_000,
        not_after: 1_800_003_600,
        revoked_at: None,
    };
    state
        .repo
        .store_workload_certificate(&certificate)
        .await
        .unwrap();
    state
        .repo
        .delete_workload_identity(&"test".into(), workload_id)
        .await
        .unwrap();
    let replacement_spiffe = "spiffe://prod.example/ns/default/sa/reassigned";
    state
        .repo
        .create_workload_identity(&WorkloadIdentity {
            id: workload_id.to_string(),
            realm_id: "test".to_string(),
            spiffe_id: replacement_spiffe.to_string(),
            trust_domain: "prod.example".to_string(),
            description: Some("Reassigned workload".to_string()),
            authorities_json: serde_json::Value::Null,
        })
        .await
        .unwrap();
    let now = qid_core::util::now_seconds();
    let token = state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(replacement_spiffe.to_string()),
            aud: Some(Audience::single("qid-workload-api".to_string())),
            exp: Some((now + 3600) as usize),
            nbf: Some((now - 10) as usize),
            iat: Some(now as usize),
            jti: Some("workload-reassigned-svid".to_string()),
            extra: std::collections::HashMap::new(),
        })
        .unwrap();
    let token = format!("Bearer {token}");
    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/test/workload-certificates?workload_id={workload_id}"
                ))
                .header(axum::http::header::AUTHORIZATION, &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    assert!(
        json(listed).await["certificates"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let revoked = app
        .oneshot(json_request(
            Method::POST,
            &format!("/api/v1/test/workload-certificates/{certificate_id}/revoke"),
            r#"{"revoked_at":1800000100}"#.to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let retained = state
        .repo
        .list_workload_certificates(&"test".into(), None)
        .await
        .unwrap();
    assert_eq!(retained, vec![certificate]);
}

#[tokio::test]
async fn fetch_x509_svid_issues_private_key_certificate_and_bundle_from_qid_ca() {
    let (app, state, token) = setup_with_workload_ca().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/test/spiffe/workload-api/x509-svid?spiffe_id={}",
                    urlencoding::encode(WORKLOAD_SPIFFE_ID)
                ))
                .header(axum::http::header::AUTHORIZATION, &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    let svid = &body["svids"][0];
    assert_eq!(svid["spiffe_id"], WORKLOAD_SPIFFE_ID);
    assert!(
        svid["private_key"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(
        svid["certificate_chain"][0]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );

    assert_svid_chain(
        svid,
        &state.workload_cas["test"].certificate_pem,
        &state.workload_cas["second"].certificate_pem,
    );
    let now = qid_core::util::now_seconds();
    let second_token = state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://second.example".into()),
            sub: Some(WORKLOAD_SPIFFE_ID.into()),
            aud: Some(Audience::single("qid-workload-api")),
            exp: Some((now + 3600) as usize),
            nbf: None,
            iat: Some(now as usize),
            jti: Some("second-svid".into()),
            extra: Default::default(),
        })
        .unwrap();
    let second_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/second/spiffe/workload-api/x509-svid")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {second_token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = json(second_response).await;
    assert_svid_chain(
        &second_body["svids"][0],
        &state.workload_cas["second"].certificate_pem,
        &state.workload_cas["test"].certificate_pem,
    );
    let cross_realm = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/second/spiffe/workload-api/x509-svid")
                .header(axum::http::header::AUTHORIZATION, &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_realm.status(), StatusCode::UNAUTHORIZED);

    let stored = state
        .repo
        .list_workload_certificates(&"test".into(), None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].spiffe_id, WORKLOAD_SPIFFE_ID);
    assert_eq!(stored[0].issuer_key_ref, "test-ca");

    let bundle_response = qid_resource::workload_routes()
        .merge(qid_resource::spiffe_routes(&state.config.server.paths))
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/spiffe-bundle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle_response.status(), StatusCode::OK);
    let bundle = json(bundle_response).await;
    assert_eq!(
        bundle["bundles"]["id.example.com"],
        serde_json::json!([state.workload_cas["test"].certificate_pem])
    );
    assert_eq!(
        bundle["bundles"]["second.example"],
        serde_json::json!([state.workload_cas["second"].certificate_pem])
    );
    assert!(
        bundle["bundles"]["id.example.com"][0]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
}

fn assert_svid_chain(svid: &serde_json::Value, expected_ca: &str, foreign_ca: &str) {
    use x509_parser::prelude::*;
    let chain = svid["certificate_chain"][0].as_str().unwrap();
    let (remaining, leaf_pem) = parse_x509_pem(chain.as_bytes()).unwrap();
    assert_eq!(std::str::from_utf8(remaining).unwrap(), expected_ca);
    let (_, ca_pem) = parse_x509_pem(expected_ca.as_bytes()).unwrap();
    let (_, foreign_pem) = parse_x509_pem(foreign_ca.as_bytes()).unwrap();
    let (_, leaf) = X509Certificate::from_der(&leaf_pem.contents).unwrap();
    let (_, ca) = X509Certificate::from_der(&ca_pem.contents).unwrap();
    let (_, foreign) = X509Certificate::from_der(&foreign_pem.contents).unwrap();
    leaf.verify_signature(Some(ca.public_key())).unwrap();
    assert!(leaf.verify_signature(Some(foreign.public_key())).is_err());
    let client_key = rcgen::KeyPair::from_pem(svid["private_key"].as_str().unwrap()).unwrap();
    assert_eq!(leaf.public_key().raw, client_key.public_key_der());
    assert!(
        leaf.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::URI(uri) if *uri == WORKLOAD_SPIFFE_ID))
    );
}

fn spoofed_csr() -> (rcgen::KeyPair, rcgen::CertificateSigningRequest) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["attacker.example".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "spiffe://attacker.example/admin");
    params.subject_alt_names.push(rcgen::SanType::URI(
        "spiffe://attacker.example/admin".try_into().unwrap(),
    ));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let csr = params.serialize_request(&key).unwrap();
    (key, csr)
}

const CSR_ROUTE: &str = "/api/v1/test/workload-certificates/csr";

async fn post_csr(app: &axum::Router, token: &str, pem: &str) -> axum::response::Response {
    app.clone()
        .oneshot(json_request(
            Method::POST,
            CSR_ROUTE,
            serde_json::json!({"csr_pem": pem}).to_string(),
            token,
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn csr_issuance_uses_only_authenticated_identity_and_policy() {
    use x509_parser::{extensions::GeneralName, prelude::*};
    let (app, state, token) = setup_with_workload_ca().await;
    let (key, csr) = spoofed_csr();
    let pem = format!(" \t\r\n{}\n\t ", csr.pem().unwrap());
    let response = post_csr(&app, &token, &pem).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert!(body.get("private_key_pem").is_none());
    assert!(!body.to_string().contains("PRIVATE KEY"));
    let cert: WorkloadCertificate = serde_json::from_value(body["certificate"].clone()).unwrap();
    assert!(cert.id.starts_with("wcert_"));
    assert_eq!(cert.realm_id, "test");
    assert_eq!(cert.workload_id, "workload-api");
    assert_eq!(cert.spiffe_id, WORKLOAD_SPIFFE_ID);
    assert_eq!(
        cert.csr_sha256,
        Some(qid_core::util::sha256_hex(pem.as_bytes()))
    );
    assert_eq!(cert.not_after - cert.not_before, 3600);
    assert_eq!(cert.issued_at, cert.not_before);
    let chain: Vec<_> = Pem::iter_from_buffer(cert.certificate_pem.as_bytes())
        .map(Result::unwrap)
        .collect();
    assert_eq!(chain.len(), 2);
    let (_, leaf) = parse_x509_certificate(&chain[0].contents).unwrap();
    let (_, ca) = parse_x509_certificate(&chain[1].contents).unwrap();
    leaf.verify_signature(Some(ca.public_key())).unwrap();
    assert_eq!(
        leaf.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        WORKLOAD_SPIFFE_ID
    );
    assert_eq!(leaf.subject().iter().count(), 1);
    assert_eq!(
        leaf.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names,
        vec![GeneralName::URI(WORKLOAD_SPIFFE_ID)]
    );
    assert_eq!(leaf.public_key().raw, key.public_key_der());
    assert_eq!(
        cert.public_key_sha256,
        qid_core::util::sha256_hex(leaf.public_key().raw)
    );
    assert_eq!(
        cert.x5t_s256,
        qid_core::util::sha256_hex(&chain[0].contents)
    );
    assert_eq!(
        leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
        3600
    );
    assert!(!leaf.is_ca());
    assert!(
        leaf.basic_constraints()
            .unwrap()
            .is_none_or(|ext| !ext.value.ca)
    );
    assert_eq!(leaf.key_usage().unwrap().unwrap().value.flags, 1);
    let eku = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth);
    assert!(
        !eku.server_auth
            && !eku.any
            && !eku.code_signing
            && !eku.email_protection
            && !eku.time_stamping
            && !eku.ocsp_signing
            && eku.other.is_empty()
    );
    assert_eq!(cert.issuer_key_ref, "test-ca");
    assert_eq!(
        chain[1].contents,
        x509_parser::pem::parse_x509_pem(state.workload_cas["test"].certificate_pem.as_bytes())
            .unwrap()
            .1
            .contents
    );
    let stored = state
        .repo
        .list_workload_certificates(&"test".into(), Some("workload-api"))
        .await
        .unwrap();
    assert_eq!(stored, vec![cert.clone()]);
    let events = state
        .repo
        .list_audit_events(Some(&"test".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.actor, "workload-api");
    assert_eq!(event.realm_id.as_deref(), Some("test"));
    assert_eq!(event.target_id, cert.id);
    assert_eq!(
        event.metadata_json["csr_sha256"],
        cert.csr_sha256.as_deref().unwrap()
    );
    assert_eq!(event.metadata_json["spiffe_id"], WORKLOAD_SPIFFE_ID);
    assert!(
        !serde_json::to_string(event)
            .unwrap()
            .contains("CERTIFICATE REQUEST")
    );

    // Repeated revocation retains the existing timestamp-update semantics.
    let now = qid_core::util::now_seconds();
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            &format!("/api/v1/test/workload-certificates/{}/revoke", cert.id),
            serde_json::json!({"revoked_at": now}).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            &format!("/api/v1/test/workload-certificates/{}/revoke", cert.id),
            serde_json::json!({"revoked_at": now + 1}).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut revoked = state
        .repo
        .list_workload_certificates(&"test".into(), Some("workload-api"))
        .await
        .unwrap();
    assert_eq!(revoked.remove(0).revoked_at, Some(now + 1));
    state.repo.as_ref().clone().close().await;
}

#[tokio::test]
async fn csr_route_rejects_invalid_envelopes_and_signatures_without_storage_or_audit() {
    use base64::Engine;
    let (app, state, token) = setup_with_workload_ca().await;
    let (_, csr) = spoofed_csr();
    let pem = csr.pem().unwrap();
    let encode = |der: &[u8]| {
        format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    };
    let mut bad_signature = csr.der().to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut trailing_der = csr.der().to_vec();
    trailing_der.extend_from_slice(&[0, 0]);
    let doubled_der = [csr.der().as_ref(), csr.der().as_ref()].concat();
    let invalid = vec![
        String::new(),
        "not PEM".into(),
        format!("prefix{pem}"),
        format!("{pem}suffix"),
        format!("{pem}{pem}"),
        format!("-----BEGIN CERTIFICATE REQUEST-----\n{pem}"),
        pem.replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"),
        pem.replace("CERTIFICATE REQUEST", "CERTIFICATE"),
        format!("\u{a0}{pem}"),
        format!("{pem}\u{a0}"),
        "-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----".into(),
        encode(b"invalid DER"),
        encode(&trailing_der),
        encode(&doubled_der),
        encode(&bad_signature),
        pem.replace(
            "-----END CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----garbage",
        ),
    ];
    for (index, pem) in invalid.iter().enumerate() {
        let response = post_csr(&app, &token, pem).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "case {index}");
        let body = json(response).await;
        assert_eq!(
            body,
            serde_json::json!({"error": "bad request: invalid workload CSR"}),
            "case {index}"
        );
    }
    for field in ["workload_id", "spiffe_id", "ttl_seconds", "id"] {
        let mut body = serde_json::json!({"csr_pem": pem});
        body[field] = "spoofed".into();
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                CSR_ROUTE,
                body.to_string(),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(
        state
            .repo
            .list_workload_certificates(&"test".into(), None)
            .await
            .unwrap()
            .is_empty()
    );
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
async fn csr_route_requires_workload_authentication_and_realm_ca() {
    let (app, state, token) = setup_with_workload_ca().await;
    let (_, csr) = spoofed_csr();
    let pem = csr.pem().unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(CSR_ROUTE)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"csr_pem": pem}).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut claims = state
        .signer
        .decode_with_aud(token.strip_prefix("Bearer ").unwrap(), "qid-workload-api")
        .unwrap()
        .claims;
    claims.sub = Some("spiffe://prod.example/unregistered".into());
    let unregistered = format!("Bearer {}", state.signer.sign(&claims).unwrap());
    assert_eq!(
        post_csr(&app, &unregistered, &pem).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let provisioning = provisioning_token(&state, WORKLOAD_SPIFFE_ID, "test", "tenant-1");
    assert_eq!(
        post_csr(&app, &provisioning, &pem).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/v1/second/workload-certificates/csr",
            serde_json::json!({"csr_pem": pem}).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    state.repo.as_ref().clone().close().await;
    let (app, state, token) = setup().await;
    assert_eq!(
        post_csr(&app, &token, &pem).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(
        state
            .repo
            .list_workload_certificates(&"test".into(), None)
            .await
            .unwrap()
            .is_empty()
    );
    state.repo.as_ref().clone().close().await;
}

#[tokio::test]
async fn csr_route_enforces_exact_byte_limit_and_zero_disables() {
    let (_, csr) = spoofed_csr();
    let pem = csr.pem().unwrap();
    for (limit, expected) in [
        (pem.len(), StatusCode::CREATED),
        (pem.len() - 1, StatusCode::BAD_REQUEST),
        (0, StatusCode::BAD_REQUEST),
    ] {
        let (app, state, token) = setup_with_workload_ca_limit(limit).await;
        let response = post_csr(&app, &token, &pem).await;
        assert_eq!(response.status(), expected, "limit {limit}");
        state.repo.as_ref().clone().close().await;
    }
}
