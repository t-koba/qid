//! Browser-bound, single-use transaction proofs for inbound federation callbacks.
//!
//! An orchestrator starts a transaction from the browser, forwards the issued
//! `state` proof to the external provider, and the provider returns it to a qid
//! callback together with its authorization code. qid spends the proof before
//! any token exchange, login planning, user creation, link storage or audit write.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use qid_core::{
    jwt::{Audience, JwtClaims},
    state::SharedState,
    util,
};
use qid_storage::prelude::*;
use rand::RngCore;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

/// Browser cookie carrying the secret that binds a callback proof to one agent.
pub(crate) const COOKIE_NAME: &str = "__Host-qid-federation-tx";

const AUDIENCE: &str = "qid-federation-callback";
const JWT_TYP: &str = "qid-federation-tx+jwt";
const PURPOSE: &str = "qid-federation-callback-transaction";
const CACHE_NAMESPACE: &str = "federation-tx:";

const REALM_CLAIM: &str = "realm";
const PROVIDER_CLAIM: &str = "provider";
const VERIFIER_CLAIM: &str = "verifier";
const PURPOSE_CLAIM: &str = "purpose";
const SOCIAL_PROVIDER_CLAIM: &str = "social_provider";

#[derive(Debug, Deserialize)]
pub(crate) struct TransactionStartQuery {
    pub(crate) provider: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FederationTransaction {
    pub(crate) realm: String,
    pub(crate) provider: String,
}

#[derive(Debug)]
pub(crate) struct TransactionError(&'static str);

impl IntoResponse for TransactionError {
    fn into_response(self) -> Response {
        invalid_transaction(self.0)
    }
}

fn invalid_transaction(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid_transaction", "message": message})),
    )
        .into_response()
}

fn internal_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "transaction_error", "message": message})),
    )
        .into_response()
}

fn cache_key(realm: &str, jti: &str) -> String {
    format!("{CACHE_NAMESPACE}{realm}:{jti}")
}

/// Issue a browser-bound proof for an enabled inbound provider.
pub(crate) async fn start<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Query(query): Query<TransactionStartQuery>,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "realm_not_found"})),
        )
            .into_response();
    };
    if !realm_config.protocols.federation.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation_disabled"})),
        )
            .into_response();
    }
    if !realm_config
        .protocols
        .federation
        .inbound_providers
        .iter()
        .any(|provider| provider.id == query.provider && provider.enabled)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "provider_not_found"})),
        )
            .into_response();
    }

    let ttl = realm_config.protocols.federation.transaction_ttl_seconds;
    let mut secret_bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = util::base64_url_encode(&secret_bytes);
    let verifier = util::sha256_base64url(secret.as_bytes());
    let jti = ulid::Ulid::new().to_string();
    let now = util::now_seconds();

    let mut extra = HashMap::new();
    extra.insert(REALM_CLAIM.to_string(), serde_json::json!(realm));
    extra.insert(
        PROVIDER_CLAIM.to_string(),
        serde_json::json!(query.provider),
    );
    extra.insert(VERIFIER_CLAIM.to_string(), serde_json::json!(verifier));
    extra.insert(PURPOSE_CLAIM.to_string(), serde_json::json!(PURPOSE));
    if let Some(social_provider) = realm_config
        .protocols
        .federation
        .inbound_providers
        .iter()
        .find(|provider| provider.id == query.provider)
        .and_then(|provider| provider.social_provider.as_deref())
    {
        extra.insert(
            SOCIAL_PROVIDER_CLAIM.to_string(),
            serde_json::json!(social_provider),
        );
    }
    let claims = JwtClaims {
        iss: Some(realm_config.issuer.clone()),
        sub: None,
        aud: Some(Audience::single(AUDIENCE)),
        exp: Some(now.saturating_add(ttl) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(jti.clone()),
        extra,
    };
    let Ok(state_token) = state.signer.sign_with_typ(&claims, JWT_TYP) else {
        return internal_error("transaction proof signing failed");
    };

    state
        .shared_cache
        .set(&cache_key(&realm, &jti), verifier.into_bytes(), ttl);

    let Ok(cookie) = HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={secret}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl}"
    )) else {
        return internal_error("transaction cookie construction failed");
    };
    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({"state": state_token, "expires_in": ttl})),
    )
        .into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name.trim() == COOKIE_NAME {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn string_claim<'a>(claims: &'a JwtClaims, name: &str) -> Result<&'a str, TransactionError> {
    claims
        .extra
        .get(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or(TransactionError("incomplete transaction proof"))
}

/// Verify and spend a transaction proof before any callback identity effect.
///
/// `expected_provider` binds the proof to a path provider for social callbacks;
/// OIDC callbacks pass `None` and select the provider from the verified claim.
pub(crate) fn verify<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    realm: &str,
    state_token: Option<&str>,
    expected_provider: Option<&str>,
) -> Result<FederationTransaction, TransactionError> {
    let token = state_token
        .filter(|value| !value.trim().is_empty())
        .ok_or(TransactionError("missing transaction proof"))?;
    let decoded = state
        .signer
        .decode_with_aud(token, AUDIENCE)
        .map_err(|_| TransactionError("invalid transaction proof"))?;
    if decoded.header.typ.as_deref() != Some(JWT_TYP) {
        return Err(TransactionError("invalid transaction purpose"));
    }
    let claims = decoded.claims;
    if string_claim(&claims, PURPOSE_CLAIM)? != PURPOSE {
        return Err(TransactionError("invalid transaction purpose"));
    }

    let proof_realm = string_claim(&claims, REALM_CLAIM)?;
    if proof_realm != realm {
        return Err(TransactionError("transaction realm mismatch"));
    }
    let provider = string_claim(&claims, PROVIDER_CLAIM)?;
    // Social routes name the social provider in the path; the proof may carry
    // that name alongside the canonical provider id from the issuer query.
    let social_provider = claims
        .extra
        .get(SOCIAL_PROVIDER_CLAIM)
        .and_then(|value| value.as_str());
    if expected_provider
        .is_some_and(|expected| expected != provider && social_provider != Some(expected))
    {
        return Err(TransactionError("transaction provider mismatch"));
    }
    let verifier = string_claim(&claims, VERIFIER_CLAIM)?;
    let now = util::now_seconds();
    if claims.exp.is_none_or(|exp| exp as u64 <= now)
        || claims.iat.is_some_and(|iat| iat as u64 > now)
    {
        return Err(TransactionError("transaction proof expired"));
    }

    let cookie = cookie_value(headers).ok_or(TransactionError("missing transaction cookie"))?;
    if !util::constant_time_eq(util::sha256_base64url(cookie.as_bytes()), verifier) {
        return Err(TransactionError("transaction cookie mismatch"));
    }

    let jti = claims
        .jti
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(TransactionError("incomplete transaction proof"))?;
    match state.shared_cache.take(&cache_key(proof_realm, jti)) {
        Some(cached) if util::constant_time_eq(&cached, verifier.as_bytes()) => {
            Ok(FederationTransaction {
                realm: proof_realm.to_string(),
                provider: provider.to_string(),
            })
        }
        _ => Err(TransactionError("transaction proof replayed or expired")),
    }
}

pub(crate) fn routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new().route("/federation/:realm/transaction/start", get(start::<R>))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use axum::response::Response as AxumResponse;
    use http_body_util::BodyExt;
    use qid_core::{tenant::RealmId, test_helpers};
    use qid_crypto::LocalSigner;
    use qid_storage::FileRepository;
    use std::path::PathBuf;

    /// Issue a proof through the production start handler and return its
    /// `state` value plus a `Cookie` header suitable for the callback.
    pub(crate) async fn issue_transaction<R: Repository>(
        state: &Arc<SharedState<R>>,
        realm: &str,
        provider: &str,
    ) -> (String, String) {
        let response = start(
            State(state.clone()),
            Path(realm.to_string()),
            Query(TransactionStartQuery {
                provider: provider.to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .expect("start handler sets the browser cookie")
            .to_string();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        let token = body["state"].as_str().expect("state proof").to_string();
        (token, cookie)
    }

    pub(crate) async fn start_handler<R: Repository>(
        state: &Arc<SharedState<R>>,
        realm: &str,
        provider: &str,
    ) -> AxumResponse {
        start(
            State(state.clone()),
            Path(realm.to_string()),
            Query(TransactionStartQuery {
                provider: provider.to_string(),
            }),
        )
        .await
    }

    pub(crate) async fn provider_stub() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/token",
                axum::routing::post(|| async {
                    Json(serde_json::json!({"access_token": "stub-access-token"}))
                }),
            )
            .route(
                "/userinfo",
                axum::routing::get(|| async {
                    Json(serde_json::json!({
                        "sub": "user-123",
                        "email": "user@example.com",
                        "email_verified": true
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stub listener");
        let address = listener.local_addr().expect("stub address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{address}"), handle)
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(kind: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("qid-federation-tx-{}-{kind}", ulid::Ulid::new()));
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) struct Fixture {
        pub(crate) state: Arc<SharedState<FileRepository>>,
        pub(crate) repo: Arc<FileRepository>,
        // Dropped last: state and repository release their files first.
        _directory: TestDirectory,
    }

    pub(crate) async fn fixture(provider_id: &str, kind: &str, base_url: &str) -> Fixture {
        fixture_with_providers(&[provider_id], kind, base_url).await
    }

    /// Configure a single provider that advertises RFC 9207 front-channel
    /// issuer support, so callbacks must carry `iss`.
    pub(crate) async fn fixture_with_issuer_support(
        provider_id: &str,
        kind: &str,
        base_url: &str,
        supported: bool,
    ) -> Fixture {
        fixture_with_alias_support(&[provider_id], kind, base_url, None, None, supported).await
    }

    /// First provider is fully configured; later ones are enabled but lack the
    /// client settings so a callback selecting them fails before any exchange.
    pub(crate) async fn fixture_with_providers(
        provider_ids: &[&str],
        kind: &str,
        base_url: &str,
    ) -> Fixture {
        fixture_with_alias_support(provider_ids, kind, base_url, None, None, false).await
    }

    /// Configure distinct issuers for providers sharing one callback target.
    pub(crate) async fn fixture_with_issuers(
        provider_ids: &[&str],
        issuers: &[&str],
        kind: &str,
        base_url: &str,
    ) -> Fixture {
        fixture_with_alias_support(provider_ids, kind, base_url, None, Some(issuers), false).await
    }

    /// Give every social provider the same callback alias, so only the verified
    /// transaction and its issuer distinguish them.
    pub(crate) async fn fixture_with_social_alias(
        provider_ids: &[&str],
        alias: &str,
        base_url: &str,
    ) -> Fixture {
        fixture_with_alias_support(provider_ids, "social", base_url, Some(alias), None, false).await
    }

    pub(crate) async fn fixture_with_social_alias_and_issuers(
        provider_ids: &[&str],
        alias: &str,
        issuers: &[&str],
        base_url: &str,
    ) -> Fixture {
        fixture_with_alias_support(
            provider_ids,
            "social",
            base_url,
            Some(alias),
            Some(issuers),
            false,
        )
        .await
    }

    async fn fixture_with_alias_support(
        provider_ids: &[&str],
        kind: &str,
        base_url: &str,
        shared_social_alias: Option<&str>,
        issuers: Option<&[&str]>,
        issuer_parameter_supported: bool,
    ) -> Fixture {
        let mut config = test_helpers::test_config();
        let federation = &mut config.realms[0].protocols.federation;
        federation.enabled = true;
        let providers: Vec<serde_json::Value> = provider_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let mut provider = serde_json::json!({
                    "id": id,
                    "kind": kind,
                    "issuer": issuers
                        .and_then(|values| values.get(index))
                        .copied()
                        .unwrap_or("https://provider.example.com"),
                    "enabled": true,
                    "authorization_response_iss_parameter_supported": issuer_parameter_supported,
                    "social_provider": if kind == "social" {
                        Some(
                            shared_social_alias.map(str::to_string).unwrap_or_else(|| {
                                if index == 0 {
                                    "google".to_string()
                                } else {
                                    format!("google-{id}")
                                }
                            }),
                        )
                    } else {
                        None
                    },
                });
                if index == 0 {
                    let object = provider.as_object_mut().expect("provider object");
                    object.insert("client_id".into(), serde_json::json!("qid-broker-client"));
                    object.insert(
                        "client_secret".into(),
                        serde_json::json!("qid-broker-secret"),
                    );
                    object.insert(
                        "token_url".into(),
                        serde_json::json!(format!("{base_url}/token")),
                    );
                    object.insert(
                        "userinfo_url".into(),
                        serde_json::json!(format!("{base_url}/userinfo")),
                    );
                    object.insert("jit_provisioning".into(), serde_json::json!(true));
                    object.insert("account_linking".into(), serde_json::json!(true));
                }
                provider
            })
            .collect();
        federation.inbound_providers =
            serde_json::from_value(serde_json::Value::Array(providers)).expect("provider config");
        let directory = TestDirectory::new(kind);
        let repo = Arc::new(
            FileRepository::new(directory.0.join("store.json").to_str().expect("utf8 path"))
                .await
                .expect("repository"),
        );
        repo.migrate().await.expect("migrate");
        let state = Arc::new(
            SharedState::new(
                config,
                repo.clone(),
                Arc::new(LocalSigner::from_secret(
                    "federation-tx-test",
                    b"test-secret",
                )),
                serde_json::json!({}),
            )
            .expect("shared state"),
        );
        Fixture {
            state,
            repo,
            _directory: directory,
        }
    }

    pub(crate) async fn assert_no_identity_effects(fixture: &Fixture, provider_id: &str) {
        let realm = RealmId("test".to_string());
        assert!(
            fixture
                .repo
                .list_users(&realm)
                .await
                .expect("list users")
                .is_empty()
        );
        assert!(
            fixture
                .repo
                .list_audit_events(Some(&realm), 100)
                .await
                .expect("list audit events")
                .is_empty()
        );
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, provider_id, "user-123")
                .await
                .expect("lookup identity link")
                .is_none()
        );
    }

    #[tokio::test]
    async fn transaction_start_route_issues_a_proof() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let fixture = fixture("configured-provider", "oidc", "http://127.0.0.1:1").await;
        let app =
            super::super::federation_routes::<FileRepository>().with_state(fixture.state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/federation/test/transaction/start?provider=configured-provider")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::SET_COOKIE));
    }

    #[tokio::test]
    async fn transaction_start_sets_browser_cookie_and_single_use_proof() {
        let fixture = fixture("configured-provider", "oidc", "http://127.0.0.1:1").await;
        let response = start_handler(&fixture.state, "test", "configured-provider").await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie_header = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("cookie header");
        assert!(cookie_header.starts_with(&format!("{COOKIE_NAME}=")));
        assert!(cookie_header.contains("; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"));
        assert!(!cookie_header.to_ascii_lowercase().contains("domain="));
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(body["expires_in"], 300);

        let (token, cookie) =
            issue_transaction(&fixture.state, "test", "configured-provider").await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().expect("cookie"));
        let verified = verify(&fixture.state, &headers, "test", Some(&token), None)
            .expect("first use succeeds");
        assert_eq!(verified.provider, "configured-provider");
        assert!(verify(&fixture.state, &headers, "test", Some(&token), None).is_err());
    }
}
