use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use qid_core::{
    models::{
        CheckRequest, CheckResponse, ExpandRequest, ExpandResponse, ReadRequest, ReadResponse,
        RelationshipTuple, TupleDeleteRequest, TupleWriteRequest,
    },
    state::SharedState,
};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::rebac;

use super::require_admin_session;

pub fn rebac_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/iga/v1/rebac/check", post(check_handler::<R>))
        .route("/iga/v1/rebac/expand", post(expand_handler::<R>))
        .route("/iga/v1/rebac/tuples", post(write_tuples_handler::<R>))
        .route(
            "/iga/v1/rebac/tuples/delete",
            post(delete_tuples_handler::<R>),
        )
        .route("/iga/v1/rebac/tuples/read", post(read_tuples_handler::<R>))
}

async fn check_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let namespace = scoped_namespace(&admin.tenant_id, &req.namespace);
    let subject_namespace = scoped_namespace(&admin.tenant_id, &req.subject.namespace);
    let allowed = rebac::check(
        &*state.repo,
        &namespace,
        &req.object_id,
        &req.relation,
        &subject_namespace,
        &req.subject.subject_id,
    )
    .await
    .unwrap_or(false);
    Json(CheckResponse { allowed }).into_response()
}

async fn expand_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<ExpandRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let namespace = scoped_namespace(&admin.tenant_id, &req.namespace);
    let tree = match rebac::expand(&*state.repo, &namespace, &req.object_id, &req.relation).await {
        Ok(tree) => tree,
        Err(error) => return rebac_error_response(error),
    };
    Json(ExpandResponse { tree }).into_response()
}

async fn write_tuples_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<TupleWriteRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tuples = scoped_tuples(&admin.tenant_id, req.tuples);
    if let Err(error) = rebac::write_tuples(&*state.repo, &tuples).await {
        return rebac_error_response(error);
    }
    Json(serde_json::json!({"status": "created"})).into_response()
}

async fn delete_tuples_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<TupleDeleteRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tuples = scoped_tuples(&admin.tenant_id, req.tuples);
    if let Err(error) = rebac::delete_tuples(&*state.repo, &tuples).await {
        return rebac_error_response(error);
    }
    Json(serde_json::json!({"status": "deleted"})).into_response()
}

fn rebac_error_response(error: qid_core::error::QidError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "rebac_storage_error",
            "message": error.to_string(),
        })),
    )
        .into_response()
}

async fn read_tuples_handler<R: AdminRepository + RebacRepository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<ReadRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let relation = if req.relation.is_empty() {
        None
    } else {
        Some(req.relation.as_str())
    };
    let namespace = scoped_namespace(&admin.tenant_id, &req.namespace);
    let tuples = match state
        .repo
        .list_relationship_tuples(&namespace, &req.object_id, relation)
        .await
    {
        Ok(tuples) => tuples,
        Err(error) => return rebac_error_response(error),
    };
    Json(ReadResponse {
        tuples: unscoped_tuples(&admin.tenant_id, tuples),
    })
    .into_response()
}

fn scoped_namespace(tenant_id: &str, namespace: &str) -> String {
    format!("{tenant_id}::{namespace}")
}

fn unscoped_namespace<'a>(tenant_id: &str, namespace: &'a str) -> &'a str {
    let prefix = format!("{tenant_id}::");
    namespace.strip_prefix(&prefix).unwrap_or(namespace)
}

fn scoped_tuples(tenant_id: &str, tuples: Vec<RelationshipTuple>) -> Vec<RelationshipTuple> {
    tuples
        .into_iter()
        .map(|mut tuple| {
            tuple.namespace = scoped_namespace(tenant_id, &tuple.namespace);
            tuple.subject_namespace = scoped_namespace(tenant_id, &tuple.subject_namespace);
            tuple
        })
        .collect()
}

fn unscoped_tuples(tenant_id: &str, tuples: Vec<RelationshipTuple>) -> Vec<RelationshipTuple> {
    tuples
        .into_iter()
        .map(|mut tuple| {
            tuple.namespace = unscoped_namespace(tenant_id, &tuple.namespace).to_string();
            tuple.subject_namespace =
                unscoped_namespace(tenant_id, &tuple.subject_namespace).to_string();
            tuple
        })
        .collect()
}

#[cfg(test)]
mod read_tests {
    use super::read_tuples_handler;
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode},
        routing::post,
    };
    use http_body_util::BodyExt;
    use qid_core::{
        error::{QidError, QidResult},
        models::{Admin, AdminApproval, AdminElevation, RelationshipTuple},
        state::SharedState,
    };
    use qid_storage::prelude::{AdminRepository, RebacRepository};
    use std::sync::Arc;
    use tower::ServiceExt;

    enum ReadMode {
        Empty,
        Fail,
    }

    struct FakeReadRepo {
        admin: Admin,
        elevation: AdminElevation,
        mode: ReadMode,
    }

    #[async_trait]
    impl AdminRepository for FakeReadRepo {
        async fn get_admin(&self, _tenant_id: &str, _subject: &str) -> QidResult<Option<Admin>> {
            Ok(None)
        }

        async fn get_admin_by_id(&self, id: &str) -> QidResult<Option<Admin>> {
            if id == self.admin.id {
                Ok(Some(self.admin.clone()))
            } else {
                Ok(None)
            }
        }

        async fn upsert_admin(&self, _admin: &Admin) -> QidResult<()> {
            Ok(())
        }

        async fn get_admin_elevation(&self, id: &str) -> QidResult<Option<AdminElevation>> {
            if id == self.elevation.id {
                Ok(Some(self.elevation.clone()))
            } else {
                Ok(None)
            }
        }

        async fn store_admin_elevation(&self, _elevation: &AdminElevation) -> QidResult<()> {
            Ok(())
        }

        async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>> {
            let _ = id;
            Ok(None)
        }

        async fn store_admin_approval(&self, _approval: &AdminApproval) -> QidResult<()> {
            Ok(())
        }

        async fn consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool> {
            let _ = id;
            Ok(false)
        }
    }

    #[async_trait]
    impl RebacRepository for FakeReadRepo {
        async fn create_relationship_tuple(&self, _tuple: &RelationshipTuple) -> QidResult<()> {
            Ok(())
        }

        async fn delete_relationship_tuple(&self, _tuple: &RelationshipTuple) -> QidResult<()> {
            Ok(())
        }

        async fn list_relationship_tuples(
            &self,
            _namespace: &str,
            _object_id: &str,
            _relation: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            match self.mode {
                ReadMode::Empty => Ok(Vec::new()),
                ReadMode::Fail => Err(QidError::Storage {
                    message: "tuple read failed".to_string(),
                }),
            }
        }

        async fn list_relationship_tuples_by_subject(
            &self,
            _namespace: &str,
            _object_id: &str,
            _relation: &str,
            _subject_namespace: &str,
            _subject_id: &str,
            _subject_relation: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            Ok(Vec::new())
        }
    }

    fn test_app(mode: ReadMode) -> (Router, String) {
        let now = qid_core::util::now_seconds();
        let admin = Admin {
            id: "admin-1".to_string(),
            tenant_id: "test-tenant".to_string(),
            subject: "test-admin".to_string(),
            roles: vec!["security.admin".to_string()],
            created_at: now,
        };
        let elevation = AdminElevation {
            id: "session-1".to_string(),
            tenant_id: "test-tenant".to_string(),
            admin_id: admin.id.clone(),
            acr: Some("urn:qid:acr:phishing-resistant".to_string()),
            amr: vec!["hwk".to_string()],
            elevation_expires_at: now + 300,
            created_at: now,
        };
        let session_id = elevation.id.clone();
        let repo = Arc::new(FakeReadRepo {
            admin,
            elevation,
            mode,
        });
        let config = qid_core::test_helpers::test_config();
        let signer = Arc::new(qid_crypto::LocalSigner::from_secret("test", b"test-secret"));
        let state =
            Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
        let app = Router::new()
            .route(
                "/iga/v1/rebac/tuples/read",
                post(read_tuples_handler::<FakeReadRepo>),
            )
            .with_state(state);
        (app, session_id)
    }

    async fn post_read(app: Router, session_id: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/iga/v1/rebac/tuples/read")
                    .header("Content-Type", "application/json")
                    .header("x-qid-admin-session-id", session_id)
                    .body(Body::from(
                        r#"{"namespace":"document","object_id":"doc-1","relation":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn read_returns_storage_error_when_repository_fails() {
        let (app, session_id) = test_app(ReadMode::Fail);
        let (status, body) = post_read(app, &session_id).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "rebac_storage_error");
    }

    #[tokio::test]
    async fn read_returns_empty_list_on_successful_empty_read() {
        let (app, session_id) = test_app(ReadMode::Empty);
        let (status, body) = post_read(app, &session_id).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tuples"], serde_json::json!([]));
    }
}
