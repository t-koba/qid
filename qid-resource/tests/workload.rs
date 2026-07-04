use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    jwt::{JwtClaims, Signer},
    models::{WorkloadCertificate, WorkloadIdentity},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_resource_workload");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

const WORKLOAD_SPIFFE_ID: &str = "spiffe://prod.example/ns/default/sa/api";

async fn setup() -> (axum::Router, Arc<SharedState<SqlRepository>>, String) {
    let config = test_helpers::test_config();
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
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
            aud: Some("qid-workload-api".to_string()),
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
    let config = test_helpers::test_config();
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
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
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let state = Arc::new(
        SharedState::new(config, repo, signer.clone(), serde_json::json!({}))
            .unwrap()
            .with_workload_ca(ca_cert.pem(), ca_key.serialize_pem()),
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
    let now = qid_core::util::now_seconds();
    let token = signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(WORKLOAD_SPIFFE_ID.to_string()),
            aud: Some("qid-workload-api".to_string()),
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
            aud: Some("qid-workload-provisioning".to_string()),
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
            "csr_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
            csr_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
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
async fn fetch_x509_svid_issues_private_key_certificate_and_bundle_from_qid_ca() {
    let (app, state, token) = setup_with_workload_ca().await;

    let response = app
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

    let stored = state
        .repo
        .list_workload_certificates(&"test".into(), None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].spiffe_id, WORKLOAD_SPIFFE_ID);

    let bundle_response = qid_resource::workload_routes()
        .merge(qid_resource::spiffe_routes(&state.config.server.paths))
        .with_state(state)
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
    assert!(
        bundle["bundles"]["id.example.com"][0]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
}
