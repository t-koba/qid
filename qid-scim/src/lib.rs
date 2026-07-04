//! SCIM 2.0 server endpoints.
#![forbid(unsafe_code)]

mod filter;
mod inbound;
mod outbound;
mod response;

pub use outbound::{
    OutboundAttributeSource, OutboundDrift, OutboundGroupReconciliationPlan, OutboundOperation,
    OutboundOrphanAction, OutboundOrphanCleanupPlan, OutboundOrphanCleanupPolicy,
    OutboundProvisioningExecutionPlan, OutboundProvisioningPlan, OutboundProvisioningResult,
    OutboundRetryDecision, OutboundRetryPolicy, OutboundScimClientConfig, OutboundScimHttpRequest,
    OutboundScimHttpResponse, OutboundScimTransport, OutboundUserMapping,
    ReqwestOutboundScimTransport, build_outbound_scim_request,
    default_outbound_orphan_cleanup_policy, default_outbound_retry_policy,
    default_outbound_user_mapping, execute_outbound_user_provisioning,
    plan_outbound_group_entitlement_reconciliation, plan_outbound_orphan_cleanup,
    plan_outbound_retry, plan_outbound_user_execution, plan_outbound_user_provisioning,
    render_outbound_user,
};

use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use qid_core::state::SharedState;
use qid_core::tenant::RealmId;
use qid_storage::{ScimDeviceRecord, ScimEventSubscriptionRecord, prelude::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const RFC_9944_DEVICE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:device:2.0:Device";
pub const RFC_9967_EVENT_SUBSCRIPTION_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:EventSubscription";

#[derive(Debug, Clone)]
pub struct ScimRequestContext {
    pub realm_id: String,
}

fn scoped_realm(context: Option<&ScimRequestContext>, requested: String) -> String {
    context
        .map(|context| context.realm_id.clone())
        .unwrap_or(requested)
}

pub fn scim_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    scim_routes_at("/scim/v2")
}

pub fn scim_routes_at<R: Repository>(base_path: &str) -> Router<Arc<SharedState<R>>> {
    let base_path = normalize_base_path(base_path);
    Router::new()
        .route(
            &scim_path(&base_path, "/ServiceProviderConfig"),
            get(inbound::service_provider_config),
        )
        .route(
            &scim_path(&base_path, "/Schemas"),
            get(inbound::schemas::<R>),
        )
        .route(
            &scim_path(&base_path, "/ResourceTypes"),
            get(inbound::resource_types::<R>),
        )
        .route(
            &scim_path(&base_path, "/Users"),
            get(inbound::list_users::<R>).post(inbound::create_user::<R>),
        )
        .route(
            &scim_path(&base_path, "/Users/:id"),
            get(inbound::get_user::<R>)
                .put(inbound::replace_user::<R>)
                .patch(inbound::patch_user::<R>)
                .delete(inbound::delete_user::<R>),
        )
        .route(
            &scim_path(&base_path, "/Groups"),
            get(inbound::list_groups::<R>).post(inbound::create_group::<R>),
        )
        .route(
            &scim_path(&base_path, "/Groups/:id"),
            get(inbound::get_group::<R>)
                .put(inbound::replace_group::<R>)
                .patch(inbound::patch_group::<R>)
                .delete(inbound::delete_group::<R>),
        )
        .route(&scim_path(&base_path, "/Bulk"), post(inbound::bulk::<R>))
        // RFC 9944: Device schema endpoint.
        .route(
            &scim_path(&base_path, "/Devices"),
            get(list_devices::<R>).post(create_device::<R>),
        )
        .route(
            &scim_path(&base_path, "/Devices/:id"),
            get(get_device::<R>).delete(delete_device::<R>),
        )
        // RFC 9967: Event subscription endpoint.
        .route(
            &scim_path(&base_path, "/EventSubscriptions"),
            get(list_event_subscriptions::<R>).post(create_event_subscription::<R>),
        )
        .route(
            &scim_path(&base_path, "/EventSubscriptions/:id"),
            get(get_event_subscription::<R>).delete(delete_event_subscription::<R>),
        )
}

fn normalize_base_path(base_path: &str) -> String {
    let trimmed = base_path.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "/scim/v2".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn scim_path(base_path: &str, suffix: &str) -> String {
    format!("{base_path}{suffix}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimDevice {
    pub id: String,
    #[serde(default = "default_realm")]
    pub realm_id: String,
    pub display_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEventSubscription {
    pub id: String,
    #[serde(default = "default_realm")]
    pub realm_id: String,
    pub callback_url: String,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: u64,
}

fn default_realm() -> String {
    "test".to_string()
}

async fn list_devices<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    axum::extract::Query(query): axum::extract::Query<inbound::ListQuery>,
) -> impl IntoResponse {
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm);
    let devices = match state.repo.list_scim_devices(&RealmId(realm)).await {
        Ok(devices) => devices
            .into_iter()
            .map(record_to_device)
            .collect::<Vec<_>>(),
        Err(error) => return qid_http::error_response(error),
    };
    let resources: Vec<serde_json::Value> =
        devices.iter().map(rfc_9944_device_response_ref).collect();
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": devices.len(),
        "Resources": resources
    }))
    .into_response()
}

async fn create_device<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(req): Json<ScimDevice>,
) -> impl IntoResponse {
    let device = ScimDevice {
        id: req.id,
        realm_id: scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm_id),
        ..req
    };
    if let Err(error) = state
        .repo
        .upsert_scim_device(&device_to_record(&device))
        .await
    {
        return qid_http::error_response(error);
    }
    (StatusCode::CREATED, Json(rfc_9944_device_response(device))).into_response()
}

async fn get_device<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_scim_device(&id).await {
        Ok(Some(device))
            if context
                .as_ref()
                .is_none_or(|ctx| ctx.realm_id == device.realm_id) =>
        {
            Json(rfc_9944_device_response(record_to_device(device))).into_response()
        }
        Ok(Some(_)) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("scim device {id}"),
        }),
        Ok(None) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("scim device {id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

async fn delete_device<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(ctx) = context.as_ref() {
        match state.repo.get_scim_device(&id).await {
            Ok(Some(device)) if device.realm_id == ctx.realm_id => {}
            Ok(Some(_)) | Ok(None) => {
                return qid_http::error_response(qid_core::error::QidError::NotFound {
                    resource: format!("scim device {id}"),
                });
            }
            Err(error) => return qid_http::error_response(error),
        }
    }
    match state.repo.delete_scim_device(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("scim device {id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

fn rfc_9944_device_response_ref(device: &ScimDevice) -> serde_json::Value {
    rfc_9944_device_response(device.clone())
}

fn rfc_9944_device_response(device: ScimDevice) -> serde_json::Value {
    serde_json::json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:Device",
            RFC_9944_DEVICE_SCHEMA,
        ],
        "id": device.id,
        "realm": device.realm_id,
        "displayName": device.display_name,
        RFC_9944_DEVICE_SCHEMA: {
            "manufacturer": device.manufacturer,
            "model": device.model,
            "os": device.os,
            "osVersion": device.os_version,
            "lastSeen": device.last_seen,
        }
    })
}

async fn list_event_subscriptions<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    axum::extract::Query(query): axum::extract::Query<inbound::ListQuery>,
) -> impl IntoResponse {
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm);
    let subs = match state
        .repo
        .list_scim_event_subscriptions(&RealmId(realm))
        .await
    {
        Ok(subs) => subs
            .into_iter()
            .map(record_to_event_subscription)
            .collect::<Vec<_>>(),
        Err(error) => return qid_http::error_response(error),
    };
    let resources: Vec<serde_json::Value> = subs
        .iter()
        .map(rfc_9967_subscription_response_ref)
        .collect();
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": subs.len(),
        "Resources": resources
    }))
    .into_response()
}

async fn create_event_subscription<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(req): Json<ScimEventSubscription>,
) -> impl IntoResponse {
    let realm_id = scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm_id);
    let allowed_hosts = match state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
    {
        Some(realm) => &realm.protocols.scim.event_callback_allowed_hosts,
        None => {
            return qid_http::error_response(qid_core::error::QidError::Unauthorized {
                message: "SCIM token realm is not configured".to_string(),
            });
        }
    };
    if let Err(error) = validate_callback_url(&req.callback_url, allowed_hosts) {
        return qid_http::error_response(error);
    }
    let sub = ScimEventSubscription {
        id: if req.id.is_empty() {
            ulid::Ulid::new().to_string()
        } else {
            req.id
        },
        realm_id,
        callback_url: req.callback_url,
        event_types: req.event_types,
        enabled: req.enabled,
        created_at: qid_core::util::now_seconds(),
    };
    if let Err(error) = state
        .repo
        .upsert_scim_event_subscription(&event_subscription_to_record(&sub))
        .await
    {
        return qid_http::error_response(error);
    }
    (
        StatusCode::CREATED,
        Json(rfc_9967_subscription_response(sub)),
    )
        .into_response()
}

async fn get_event_subscription<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_scim_event_subscription(&id).await {
        Ok(Some(sub))
            if context
                .as_ref()
                .is_none_or(|ctx| ctx.realm_id == sub.realm_id) =>
        {
            Json(rfc_9967_subscription_response(
                record_to_event_subscription(sub),
            ))
            .into_response()
        }
        Ok(Some(_)) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("event subscription {id}"),
        }),
        Ok(None) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("event subscription {id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

async fn delete_event_subscription<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(ctx) = context.as_ref() {
        match state.repo.get_scim_event_subscription(&id).await {
            Ok(Some(sub)) if sub.realm_id == ctx.realm_id => {}
            Ok(Some(_)) | Ok(None) => {
                return qid_http::error_response(qid_core::error::QidError::NotFound {
                    resource: format!("event subscription {id}"),
                });
            }
            Err(error) => return qid_http::error_response(error),
        }
    }
    match state.repo.delete_scim_event_subscription(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("event subscription {id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

fn validate_callback_url(
    callback_url: &str,
    allowed_hosts: &[String],
) -> qid_core::error::QidResult<()> {
    let parsed =
        url::Url::parse(callback_url).map_err(|error| qid_core::error::QidError::BadRequest {
            message: format!("SCIM event subscription callback URL is invalid: {error}"),
        })?;
    if parsed.scheme() != "https" {
        return Err(qid_core::error::QidError::BadRequest {
            message: "SCIM event subscription callback URL must use https".to_string(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(qid_core::error::QidError::BadRequest {
            message: "SCIM event subscription callback URL must not contain userinfo or fragment"
                .to_string(),
        });
    }
    let Some(host) = parsed.host_str() else {
        return Err(qid_core::error::QidError::BadRequest {
            message: "SCIM event subscription callback URL must include a host".to_string(),
        });
    };
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_private() || v4.is_link_local() || v4.is_broadcast()
                    }
                    std::net::IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
                }
        })
    {
        return Err(qid_core::error::QidError::BadRequest {
            message: "SCIM event subscription callback URL host is not allowed".to_string(),
        });
    }
    if allowed_hosts.is_empty()
        || !allowed_hosts
            .iter()
            .any(|allowed| callback_host_matches(host, allowed))
    {
        return Err(qid_core::error::QidError::BadRequest {
            message: "SCIM event subscription callback URL host is not allowlisted".to_string(),
        });
    }
    Ok(())
}

fn callback_host_matches(host: &str, allowed: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let allowed = allowed.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = allowed.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}")) && host != suffix
    } else {
        host == allowed
    }
}

fn rfc_9967_subscription_response_ref(sub: &ScimEventSubscription) -> serde_json::Value {
    rfc_9967_subscription_response(sub.clone())
}

fn rfc_9967_subscription_response(sub: ScimEventSubscription) -> serde_json::Value {
    serde_json::json!({
        "schemas": [RFC_9967_EVENT_SUBSCRIPTION_SCHEMA],
        "id": sub.id,
        "realm": sub.realm_id,
        "callback": sub.callback_url,
        "eventTypes": sub.event_types,
        "enabled": sub.enabled,
        "createdAt": sub.created_at,
    })
}

fn device_to_record(device: &ScimDevice) -> ScimDeviceRecord {
    ScimDeviceRecord {
        id: device.id.clone(),
        realm_id: device.realm_id.clone(),
        display_name: device.display_name.clone(),
        manufacturer: device.manufacturer.clone(),
        model: device.model.clone(),
        os: device.os.clone(),
        os_version: device.os_version.clone(),
        last_seen: device.last_seen,
    }
}

fn record_to_device(record: ScimDeviceRecord) -> ScimDevice {
    ScimDevice {
        id: record.id,
        realm_id: record.realm_id,
        display_name: record.display_name,
        manufacturer: record.manufacturer,
        model: record.model,
        os: record.os,
        os_version: record.os_version,
        last_seen: record.last_seen,
    }
}

fn event_subscription_to_record(
    subscription: &ScimEventSubscription,
) -> ScimEventSubscriptionRecord {
    ScimEventSubscriptionRecord {
        id: subscription.id.clone(),
        realm_id: subscription.realm_id.clone(),
        callback_url: subscription.callback_url.clone(),
        event_types: subscription.event_types.clone(),
        enabled: subscription.enabled,
        created_at: subscription.created_at,
    }
}

fn record_to_event_subscription(record: ScimEventSubscriptionRecord) -> ScimEventSubscription {
    ScimEventSubscription {
        id: record.id,
        realm_id: record.realm_id,
        callback_url: record.callback_url,
        event_types: record.event_types,
        enabled: record.enabled,
        created_at: record.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_url_requires_https_public_allowlisted_host() {
        let allowed = vec![
            "events.example.com".to_string(),
            "*.tenant.example.com".to_string(),
        ];
        assert!(validate_callback_url("https://events.example.com/scim/events", &allowed).is_ok());
        assert!(
            validate_callback_url("https://app.tenant.example.com/scim/events", &allowed).is_ok()
        );
        assert!(validate_callback_url("http://events.example.com/scim/events", &allowed).is_err());
        assert!(validate_callback_url("https://127.0.0.1/scim/events", &allowed).is_err());
        assert!(validate_callback_url("https://tenant.example.com/scim/events", &allowed).is_err());
        assert!(validate_callback_url("https://evil.example.net/scim/events", &allowed).is_err());
        assert!(
            validate_callback_url("https://events.example.com@evil.example.net/", &allowed)
                .is_err()
        );
    }
}
