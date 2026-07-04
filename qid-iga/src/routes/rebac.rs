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

async fn read_tuples_handler<R: Repository>(
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
    let tuples = state
        .repo
        .list_relationship_tuples(&namespace, &req.object_id, relation)
        .await
        .unwrap_or_default();
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
