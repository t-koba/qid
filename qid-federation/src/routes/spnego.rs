//! HTTP Negotiate endpoint for inbound Kerberos/SPNEGO federation.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
};
use base64::{
    Engine,
    alphabet::STANDARD,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
    },
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path as FsPath, sync::Arc};

use crate::{
    ExternalIdentityClaims, HomeRealmDiscoveryRequest, InboundIdentityProvider,
    InboundProviderKind, kerberos_acceptor::accept_negotiate_token,
};

use super::{
    broker_login_plan_error_response, exec_broker_login_plan, plan_broker_login,
    providers_from_config,
};

/// HTTP token size budget for the fixture; not a Kerberos protocol limit.
const MAX_NEGOTIATE_TOKEN_BYTES: usize = 1024 * 1024;

/// Accept both padded and unpadded standard base64 Negotiate tokens.
static NEGOTIATE_BASE64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, Deserialize)]
pub(crate) struct SpnegoNegotiateQuery {
    #[serde(default)]
    idp: Option<String>,
}

fn error_response(status: StatusCode, error: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

/// Challenge the client without revealing why the token was rejected.
fn reject(error: &'static str) -> Response {
    let mut response = error_response(StatusCode::UNAUTHORIZED, error);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
    response
}

/// Add the acceptor's AP-REP so the client can verify mutual completion.
fn with_mutual_reply(mut response: Response, reply: Option<Vec<u8>>) -> Response {
    if let Some(reply) = reply {
        let value = format!("Negotiate {}", NEGOTIATE_BASE64.encode(reply));
        // The scheme and standard base64 are visible ASCII, so an acceptor
        // reply always yields a valid header; skip it if that invariant breaks
        // rather than emitting an unchecked value.
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
    }
    response
}

fn negotiate_token(headers: &HeaderMap) -> Result<Vec<u8>, &'static str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err("negotiate_required");
    };
    if values.next().is_some() {
        return Err("negotiate_required");
    }
    let Ok(raw) = value.to_str() else {
        return Err("negotiate_required");
    };
    let Some((scheme, encoded)) = raw.split_once(' ') else {
        return Err("negotiate_required");
    };
    if !scheme.eq_ignore_ascii_case("Negotiate") || encoded.trim().is_empty() {
        return Err("negotiate_required");
    }
    // Bound the input before decoding so a large header cannot allocate a
    // proportionally large token.
    if encoded.len() > MAX_NEGOTIATE_TOKEN_BYTES * 4 / 3 + 4 {
        return Err("invalid_token");
    }
    let token = NEGOTIATE_BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| "invalid_token")?;
    if token.is_empty() || token.len() > MAX_NEGOTIATE_TOKEN_BYTES {
        return Err("invalid_token");
    }
    Ok(token)
}

/// Validate one inbound Negotiate token and feed its identity through the
/// federation broker. Multi-leg SPNEGO is not supported: an incomplete
/// exchange fails closed, and no negotiation state is kept. On success the
/// acceptor's AP-REP is returned so the client can verify mutual completion.
pub async fn spnego_negotiate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Query(params): Query<SpnegoNegotiateQuery>,
    headers: HeaderMap,
) -> Response {
    let realm_config = match state.config.realms.iter().find(|r| r.id == realm) {
        Some(config) => config,
        None => return error_response(StatusCode::NOT_FOUND, "realm_not_found"),
    };
    if !realm_config.protocols.federation.enabled {
        return error_response(StatusCode::NOT_FOUND, "federation_disabled");
    }

    let providers = providers_from_config(&realm_config.protocols.federation.inbound_providers);
    let candidates: Vec<&InboundIdentityProvider> = providers
        .iter()
        .filter(|provider| {
            provider.enabled
                && provider.kind == InboundProviderKind::KerberosSpnego
                && params.idp.as_deref().is_none_or(|idp| provider.id == idp)
        })
        .collect();
    let provider = match candidates.as_slice() {
        [provider] => *provider,
        [] => return error_response(StatusCode::BAD_REQUEST, "provider_not_found"),
        _ => return error_response(StatusCode::BAD_REQUEST, "ambiguous_provider"),
    };
    let Some(kerberos) = &provider.kerberos_spnego else {
        return error_response(StatusCode::BAD_REQUEST, "kerberos_not_configured");
    };

    let token = match negotiate_token(&headers) {
        Ok(token) => token,
        Err(error) => return reject(error),
    };
    // The acceptor checks ticket, authenticator, time, replay, service and
    // client realm; its errors never leave this module.
    let accepted = match accept_negotiate_token(
        FsPath::new(&kerberos.keytab_path),
        &kerberos.service_principal,
        &kerberos.realm,
        Arc::clone(&state.shared_cache),
        &token,
    ) {
        Ok(accepted) => accepted,
        Err(_) => return reject("ticket_rejected"),
    };
    let identity = accepted.identity;

    let claims = ExternalIdentityClaims {
        issuer: provider.issuer.clone(),
        subject: identity.client_principal.clone(),
        claims: BTreeMap::from([
            (
                "realm".to_string(),
                serde_json::Value::String(identity.client_realm),
            ),
            (
                "principal".to_string(),
                serde_json::Value::String(identity.client_principal),
            ),
        ]),
    };
    let plan = match plan_broker_login(
        state.repo.as_ref(),
        &realm,
        &provider.id,
        &providers,
        &HomeRealmDiscoveryRequest {
            idp_hint: Some(provider.id.clone()),
            login_hint: None,
            domain: None,
            social_provider: None,
        },
        &claims,
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) => return broker_login_plan_error_response(error),
    };

    match exec_broker_login_plan(state.repo.as_ref(), &realm, &provider.id, &claims, &plan).await {
        Ok(uid) => with_mutual_reply(
            Json(serde_json::json!({
                "status": "linked",
                "provider": provider.id,
                "provider_kind": provider.kind.as_str(),
                "local_user_id": uid,
            }))
            .into_response(),
            accepted.reply,
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "login_plan_execution_failed",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Method, Request},
    };
    use http_body_util::BodyExt;
    use qid_core::{
        tenant::{RealmId, TenantId},
        test_helpers,
    };
    use qid_crypto::LocalSigner;
    use qid_storage::{FileRepository, RealmRepository};
    use std::path::PathBuf;
    use tower::ServiceExt;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("qid-spnego-route-{}", ulid::Ulid::new()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn test_app(
        federation_enabled: bool,
        providers: serde_json::Value,
    ) -> (Router, TestDirectory) {
        let directory = TestDirectory::new();
        let repo = Arc::new(
            FileRepository::new(directory.0.join("store.json").to_str().unwrap())
                .await
                .unwrap(),
        );
        repo.migrate().await.unwrap();
        repo.create_realm(
            &TenantId::from("tenant-1"),
            &RealmId::from("test"),
            "https://id.example.com",
            Some("Test Realm"),
        )
        .await
        .unwrap();
        let mut config = test_helpers::test_config();
        let federation = &mut config.realms[0].protocols.federation;
        federation.enabled = federation_enabled;
        federation.inbound_providers = serde_json::from_value(providers).unwrap();
        let state = Arc::new(
            SharedState::new(
                config,
                repo,
                Arc::new(LocalSigner::from_secret(
                    "spnego-route-test",
                    b"test-secret",
                )),
                serde_json::json!({}),
            )
            .unwrap(),
        );
        (
            super::super::federation_routes::<FileRepository>().with_state(state),
            directory,
        )
    }

    fn kerberos_providers(keytab_path: &str) -> serde_json::Value {
        serde_json::json!([{
            "id": "corp-kerberos",
            "kind": "kerberos_spnego",
            "issuer": "https://id.example.com/kerberos",
            "enabled": true,
            "jit_provisioning": true,
            "account_linking": true,
            "claim_mappings": [
                { "source": "principal", "target": "display_name", "required": false }
            ],
            "kerberos_spnego": {
                "realm": "QID.MIT.TEST",
                "service_principal": "HTTP/qid.example@QID.MIT.TEST",
                "keytab_path": keytab_path
            }
        }])
    }

    fn oidc_providers() -> serde_json::Value {
        serde_json::json!([{
            "id": "corp-oidc",
            "kind": "oidc",
            "issuer": "https://provider.example.com",
            "enabled": true
        }])
    }

    async fn post(
        app: &Router,
        uri: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder().method(Method::POST).uri(uri);
        if let Some(value) = authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn error(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn success_reply_is_standard_base64_and_omitted_when_absent() {
        let body = Json(serde_json::json!({ "status": "linked" })).into_response();
        let with_reply = with_mutual_reply(body, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(with_reply.headers()[WWW_AUTHENTICATE], "Negotiate AQID");
        assert_eq!(with_reply.status(), StatusCode::OK);

        let without_reply = with_mutual_reply(
            Json(serde_json::json!({ "status": "linked" })).into_response(),
            None,
        );
        assert!(!without_reply.headers().contains_key(WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn negotiate_route_challenges_missing_wrong_and_invalid_credentials() {
        let (app, _dir) = test_app(true, kerberos_providers("/nonexistent/absent.keytab")).await;
        let uri = "/federation/test/spnego/negotiate";
        for (authorization, expected) in [
            (None, "negotiate_required"),
            (Some("Basic dXNlcjpwYXNz"), "negotiate_required"),
            (Some("Negotiate "), "negotiate_required"),
            (Some("negOtiate !!!not-base64"), "invalid_token"),
        ] {
            let (status, headers, body) = post(&app, uri, authorization).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(headers[WWW_AUTHENTICATE], "Negotiate");
            assert_eq!(error(&body), expected);
        }
    }

    #[tokio::test]
    async fn negotiate_route_rejects_duplicate_headers_and_oversized_tokens() {
        let (app, _dir) = test_app(true, kerberos_providers("/nonexistent/absent.keytab")).await;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/federation/test/spnego/negotiate")
            .header(AUTHORIZATION, "Negotiate b2s")
            .header(AUTHORIZATION, "Negotiate b2s")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[WWW_AUTHENTICATE], "Negotiate");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            error(std::str::from_utf8(&body).unwrap()),
            "negotiate_required"
        );

        let oversized = "A".repeat(MAX_NEGOTIATE_TOKEN_BYTES * 4 / 3 + 5);
        let (status, headers, body) = post(
            &app,
            "/federation/test/spnego/negotiate",
            Some(&format!("Negotiate {oversized}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[WWW_AUTHENTICATE], "Negotiate");
        assert_eq!(error(&body), "invalid_token");
    }

    #[tokio::test]
    async fn negotiate_route_rejects_unknown_realm_and_disabled_federation() {
        let (app, _dir) = test_app(true, kerberos_providers("/nonexistent/absent.keytab")).await;
        let (status, _, body) = post(
            &app,
            "/federation/unknown/spnego/negotiate",
            Some("Negotiate b2s"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error(&body), "realm_not_found");

        let (app, _dir) = test_app(false, kerberos_providers("/nonexistent/absent.keytab")).await;
        let (status, _, body) = post(
            &app,
            "/federation/test/spnego/negotiate",
            Some("Negotiate b2s"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error(&body), "federation_disabled");
    }

    #[tokio::test]
    async fn negotiate_route_requires_an_unambiguous_kerberos_provider() {
        let uri = "/federation/test/spnego/negotiate";
        for providers in [oidc_providers(), serde_json::json!([])] {
            let (app, _dir) = test_app(true, providers).await;
            let (status, _, body) = post(&app, uri, Some("Negotiate b2s")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error(&body), "provider_not_found");
        }

        let mut two = serde_json::from_value::<Vec<serde_json::Value>>(kerberos_providers(
            "/nonexistent/absent.keytab",
        ))
        .unwrap();
        let mut second = two[0].clone();
        second["id"] = serde_json::json!("other-kerberos");
        two.push(second);
        let (app, _dir) = test_app(true, serde_json::json!(two)).await;
        let (status, _, body) = post(&app, uri, Some("Negotiate b2s")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error(&body), "ambiguous_provider");

        let (status, _, body) = post(
            &app,
            "/federation/test/spnego/negotiate?idp=unknown",
            Some("Negotiate b2s"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error(&body), "provider_not_found");
    }

    #[tokio::test]
    async fn negotiate_route_rejects_invalid_tickets_without_leaking_configuration() {
        let marker = format!("qid-secret-keytab-marker-{}", ulid::Ulid::new());
        let keytab_path = format!("/nonexistent/{marker}.keytab");
        let (app, _dir) = test_app(true, kerberos_providers(&keytab_path)).await;
        let token_bytes = [0xa5u8; 32];
        let token = NEGOTIATE_BASE64.encode(token_bytes);
        for encoded in [token.clone(), token.trim_end_matches('=').to_string()] {
            let (status, headers, body) = post(
                &app,
                "/federation/test/spnego/negotiate?idp=corp-kerberos",
                Some(&format!("Negotiate {encoded}")),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(headers[WWW_AUTHENTICATE], "Negotiate");
            assert_eq!(error(&body), "ticket_rejected");
            assert!(!body.contains(&keytab_path), "keytab path leaked");
            assert!(!body.contains(&marker), "key reference leaked");
            assert!(!body.contains(&encoded), "token leaked");
            assert!(!body.contains("a5a5"), "key-shaped bytes leaked");
        }
    }
}
