//! Exercise the worker against the real inbound routes, not canned SCIM responses.
use super::*;
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use qid_core::{models::ScimGroup, state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

// The route host owns authentication. This test host binds one fixture bearer to
// the target realm; request query/body realm values never become authority.
async fn authenticate(mut request: Request<Body>, next: Next) -> Response {
    if request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        != Some("Bearer route-test")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    request.extensions_mut().insert(ScimRequestContext {
        realm_id: "other".into(),
    });
    next.run(request).await
}
struct RouteTransport {
    app: Router,
    writes: Mutex<Vec<String>>,
}
#[async_trait]
impl OutboundScimTransport for RouteTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        let url = reqwest::Url::parse(&request.url).unwrap();
        if request.method != "GET" {
            self.writes.lock().unwrap().push(request.method.clone());
        }
        let mut builder = Request::builder()
            .method(request.method.as_str())
            .uri(format!(
                "{}{}",
                url.path(),
                url.query().map(|q| format!("?{q}")).unwrap_or_default()
            ));
        for (key, value) in request.headers {
            builder = builder.header(key, value);
        }
        let response = self
            .app
            .clone()
            .oneshot(
                builder
                    .body(Body::from(
                        request.body.map(|b| b.to_string()).unwrap_or_default(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        Ok(OutboundScimHttpResponse {
            status,
            body: if bytes.is_empty() {
                None
            } else {
                Some(serde_json::from_slice(&bytes).unwrap())
            },
        })
    }
}
#[tokio::test]
async fn qid_to_qid_groups_keep_identity_across_reconciliation() {
    crate::test_support::with_repo(async |repo, _| {
        super::tests::seed(&repo).await;
        let mut source = ScimGroup {
            id: "stable-source-id".into(),
            realm_id: "corp".into(),
            // Deliberate same-externalId decoy outside the target realm.
            external_id: Some("stable-source-id".into()),
            display_name: "Engineering".into(),
            members_json: serde_json::json!([]),
        };
        repo.create_scim_group(&source).await.unwrap();
        let mut config = test_helpers::test_config();
        config.realms[0].id = "other".into();
        config.realms[0].protocols.scim.cursor_secret =
            Some("0123456789abcdef0123456789abcdef".into());
        let state = Arc::new(
            SharedState::new(
                config,
                Arc::new(repo.clone()),
                Arc::new(LocalSigner::from_secret("test", b"test-secret")),
                serde_json::json!({}),
            )
            .unwrap(),
        );
        let transport = RouteTransport {
            app: scim_routes()
                .with_state(state)
                .layer(middleware::from_fn(authenticate)),
            writes: Mutex::new(vec![]),
        };
        let mut config = super::tests::config(false);
        // The source realm and authenticated target realm are intentionally different.
        config.scim_bearer_token = Some("route-test".into());
        let mut unauthorized = config.clone();
        unauthorized.scim_bearer_token = None;
        let refused = run_scim_outbound_sync_with_transport(
            &repo,
            unauthorized,
            ScimOutboundSyncOptions::default(),
            &transport,
        )
        .await
        .unwrap();
        assert_eq!((refused.synced, refused.failed), (0, 1));
        assert!(transport.writes.lock().unwrap().is_empty());
        let sync = || {
            run_scim_outbound_sync_with_transport(
                &repo,
                config.clone(),
                ScimOutboundSyncOptions::default(),
                &transport,
            )
        };
        let first = sync().await.unwrap();
        assert_eq!((first.synced, first.failed), (1, 0), "{first:?}");
        let target = repo
            .list_scim_groups(&"other".into())
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_ne!(target.id, source.id);
        assert_eq!(target.external_id.as_deref(), Some(source.id.as_str()));
        assert_eq!(target.display_name, source.display_name);
        let second = sync().await.unwrap();
        assert_eq!((second.synced, second.skipped, second.failed), (0, 1, 0));
        assert_eq!(*transport.writes.lock().unwrap(), ["POST"]);
        source.display_name = "Platform".into();
        repo.update_scim_group(&source).await.unwrap();
        let third = sync().await.unwrap();
        assert_eq!((third.synced, third.failed), (1, 0));
        let targets = repo.list_scim_groups(&"other".into()).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, target.id);
        assert_eq!(targets[0].external_id, target.external_id);
        assert_eq!(targets[0].display_name, "Platform");
        assert_eq!(*transport.writes.lock().unwrap(), ["POST", "PUT"]);
    })
    .await;
}
