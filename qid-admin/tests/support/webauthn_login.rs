//! Synthetic authenticator inputs for qid-session's production login routes.
//!
//! Only the ceremony evidence is synthetic. Registration, assertion
//! verification, session creation and cookie issuance all happen inside
//! qid-session's handlers against the repository the admin router uses.

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value as CborValue;
use p256::{
    FieldBytes,
    ecdsa::{SigningKey, signature::Signer},
};
use qid_core::state::SharedState;
use qid_storage::AnyRepository;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

const RP_ID: &str = "id.example.com";
const ORIGIN: &str = "https://id.example.com";
const USER: &str = "operator";
const EMAIL: &str = "operator@example.com";

fn signing_key() -> SigningKey {
    // One fixed synthetic authenticator key: it registers the credential and
    // signs later assertions, so verification proves a real ceremony.
    SigningKey::from_bytes(&FieldBytes::from([0x11; 32])).unwrap()
}

fn cbor(value: CborValue) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
}

/// One router owns the in-memory WebAuthn ceremony state, so start/finish
/// pairs must use clones of it rather than separately built routers.
pub(crate) fn auth_router(state: &Arc<SharedState<AnyRepository>>) -> Router {
    qid_session::auth_routes(&state.paths).with_state(state.clone())
}

async fn post(
    router: &Router,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, parsed)
}

fn cookie_from(headers: &HeaderMap) -> String {
    let value = headers.get("set-cookie").unwrap().to_str().unwrap();
    value.split(';').next().unwrap().to_string()
}

/// Real password route: credential verification and session creation both run
/// in qid-session. The returned cookie is the one the production handler set.
pub(crate) async fn password_login(router: &Router, password: &str) -> (String, String) {
    let (status, headers, body) = post(
        router,
        "/api/v1/test/auth/password",
        json!({"email": EMAIL, "password": password}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "password login: {body}");
    let session_id = body["session"].as_str().unwrap().to_string();
    let cookie = cookie_from(&headers);
    assert!(cookie.ends_with(&session_id));
    (cookie, session_id)
}

/// Real WebAuthn registration through qid-session's start/finish routes, using
/// the password session solely as the enrollment session the routes require.
pub(crate) async fn register(router: &Router, cookie: &str) {
    let (status, _, challenge) = post(
        router,
        "/api/v1/test/auth/webauthn/start",
        json!({"email": EMAIL}),
        Some(cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "registration start: {challenge}");

    let point = signing_key().verifying_key().to_sec1_point(false);
    let point = point.as_bytes();
    let cose = CborValue::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        ((-2).into(), CborValue::Bytes(point[1..33].to_vec())),
        ((-3).into(), CborValue::Bytes(point[33..65].to_vec())),
    ]);
    let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x41); // UP + attested credential data.
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0x11; 16]); // AAGUID.
    auth_data.extend_from_slice(&4u16.to_be_bytes());
    auth_data.extend_from_slice(b"cred");
    auth_data.extend(cbor(cose));
    let attestation = cbor(CborValue::Map(vec![
        ("fmt".into(), "none".into()),
        ("authData".into(), CborValue::Bytes(auth_data)),
        ("attStmt".into(), CborValue::Map(vec![])),
    ]));
    let client_data = URL_SAFE_NO_PAD.encode(
        json!({
            "type": "webauthn.create",
            "challenge": challenge["challenge"]["challenge"],
            "origin": ORIGIN,
            "crossOrigin": false,
        })
        .to_string(),
    );
    let (status, _, body) = post(
        router,
        "/api/v1/test/auth/webauthn/finish",
        json!({
            "user_id": USER,
            "response": {
                "id": URL_SAFE_NO_PAD.encode(b"cred"),
                "rawId": URL_SAFE_NO_PAD.encode(b"cred"),
                "type": "public-key",
                "response": {
                    "clientDataJSON": client_data,
                    "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                },
            },
        }),
        Some(cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration finish: {body}");
}

/// Real WebAuthn authentication: the assertion is verified by qid-session and
/// `complete_webauthn_authentication` creates the `phr`/`webauthn` session.
pub(crate) async fn webauthn_login(router: &Router) -> (String, String) {
    let (status, _, challenge) = post(
        router,
        "/api/v1/test/auth/webauthn/auth/start",
        json!({"email": EMAIL}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authentication start: {challenge}");

    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": challenge["challenge"]["challenge"],
        "origin": ORIGIN,
        "crossOrigin": false,
    }))
    .unwrap();
    let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x01); // User present, same as enrollment.
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature: p256::ecdsa::Signature = signing_key().sign(&signed);
    let signature = signature.to_der().as_bytes().to_vec();

    let (status, headers, body) = post(
        router,
        "/api/v1/test/auth/webauthn/auth/finish",
        json!({
            "email": EMAIL,
            "response": {
                "id": URL_SAFE_NO_PAD.encode(b"cred"),
                "rawId": URL_SAFE_NO_PAD.encode(b"cred"),
                "type": "public-key",
                "response": {
                    "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                    "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                    "signature": URL_SAFE_NO_PAD.encode(signature),
                    "userHandle": URL_SAFE_NO_PAD.encode(&Sha256::digest(USER.as_bytes())[..16]),
                },
            },
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authentication finish: {body}");
    let session_id = body["session"].as_str().unwrap().to_string();
    let cookie = cookie_from(&headers);
    assert!(cookie.ends_with(&session_id));
    (cookie, session_id)
}
