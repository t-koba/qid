use axum::{Json, response::IntoResponse};

use crate::{
    CORE_DEVICE_SCHEMA, ENTERPRISE_USER_SCHEMA, RFC_9944_DEVICE_SCHEMA,
    RFC_9967_EVENT_SUBSCRIPTION_SCHEMA,
};

fn attr(name: &str, ty: &str, multi: bool, required: bool) -> serde_json::Value {
    serde_json::json!({"name": name, "type": ty, "multiValued": multi, "required": required})
}

/// A server-owned attribute: it is returned to clients, and a value supplied
/// in a request is accepted and ignored.
fn read_only_attr(name: &str, ty: &str, multi: bool, required: bool) -> serde_json::Value {
    serde_json::json!({"name": name, "type": ty, "multiValued": multi, "required": required, "readOnly": true})
}

/// The advertised `name` subattributes and their JSON types. This table owns
/// the vocabulary: the discovery document and the write validator both read
/// it, so the two cannot drift apart.
pub(crate) const NAME_SUBATTRIBUTES: [(&str, &str); 6] = [
    ("formatted", "string"),
    ("familyName", "string"),
    ("givenName", "string"),
    ("middleName", "string"),
    ("honorificPrefix", "string"),
    ("honorificSuffix", "string"),
];

/// The advertised `emails` subattributes and their JSON types.
pub(crate) const EMAIL_SUBATTRIBUTES: [(&str, &str); 4] = [
    ("value", "string"),
    ("display", "string"),
    ("type", "string"),
    ("primary", "boolean"),
];

fn complex(name: &str, multi: bool, table: &[(&str, &str)]) -> serde_json::Value {
    let subs = table
        .iter()
        .map(|(sub, ty)| attr(sub, ty, false, false))
        .collect::<Vec<_>>();
    serde_json::json!({"name": name, "type": "complex", "multiValued": multi, "required": false, "subAttributes": subs})
}

pub(crate) async fn service_provider_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": true, "maxOperations": 100, "maxPayloadSize": 1048576 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": []
    }))
}

pub(crate) async fn schemas() -> impl IntoResponse {
    // Advertise only implemented subsets, not full RFC attribute sets.
    // Custom schemas are rejected during configuration validation, so
    // discovery cannot list extensions whose values are silently discarded.
    let resources = vec![
        serde_json::json!({
        "id": "urn:ietf:params:scim:schemas:core:2.0:User",
        "name": "User",
        "description": "User Account",
        "attributes": [
            attr("userName", "string", false, true), attr("externalId", "string", false, false),
            attr("active", "boolean", false, false),
            complex("name", false, &NAME_SUBATTRIBUTES),
            complex("emails", true, &EMAIL_SUBATTRIBUTES),
        ]}),
        serde_json::json!({
        "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "name": "Group",
        "description": "Group",
        "attributes": [
            attr("displayName", "string", false, true), attr("members", "complex", true, false),
        ]}),
        serde_json::json!({
        "id": ENTERPRISE_USER_SCHEMA,
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": [
            attr("employeeNumber", "string", false, false), attr("costCenter", "string", false, false),
            attr("organization", "string", false, false), attr("division", "string", false, false),
            attr("department", "string", false, false), attr("manager", "complex", false, false),
        ]}),
        serde_json::json!({
        "id": CORE_DEVICE_SCHEMA,
        "name": "Device",
        "description": "Device (implemented subset)",
        "attributes": [
            attr("displayName", "string", false, false),
        ]}),
        serde_json::json!({
        "id": RFC_9944_DEVICE_SCHEMA,
        "name": "DeviceExtension",
        "description": "Device extension (implemented subset)",
        "attributes": [
            attr("manufacturer", "string", false, false), attr("model", "string", false, false),
            attr("os", "string", false, false), attr("osVersion", "string", false, false),
            attr("lastSeen", "integer", false, false),
        ]}),
        serde_json::json!({
        "id": RFC_9967_EVENT_SUBSCRIPTION_SCHEMA,
        "name": "EventSubscription",
        "description": "Event subscription (implemented subset)",
        "attributes": [
            attr("callback", "string", false, true), attr("eventTypes", "string", true, true),
            attr("enabled", "boolean", false, true),
            read_only_attr("createdAt", "integer", false, false),
            ]}),
    ];
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources,
    }))
}

pub(crate) async fn resource_types() -> impl IntoResponse {
    let user_extensions =
        vec![serde_json::json!({"schema": ENTERPRISE_USER_SCHEMA, "required": false})];
    let device_extensions =
        vec![serde_json::json!({"schema": RFC_9944_DEVICE_SCHEMA, "required": false})];
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 4,
        "Resources": [
            {"id": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User", "schemaExtensions": user_extensions},
            {"id": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"},
            {"id": "Device", "endpoint": "/Devices", "schema": CORE_DEVICE_SCHEMA, "schemaExtensions": device_extensions},
            {"id": "EventSubscription", "endpoint": "/EventSubscriptions", "schema": RFC_9967_EVENT_SUBSCRIPTION_SCHEMA}
        ]
    }))
}
