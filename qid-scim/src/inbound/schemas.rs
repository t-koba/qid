use axum::{Json, response::IntoResponse};

use crate::{ENTERPRISE_USER_SCHEMA, RFC_9944_DEVICE_SCHEMA, RFC_9967_EVENT_SUBSCRIPTION_SCHEMA};

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
    // Only schemas with implemented behavior are advertised: core User/Group
    // and the Enterprise User extension. Configured `custom_schemas` are
    // rejected at configuration validation time, so discovery never lists
    // extensions whose values would otherwise be silently discarded.
    let resources = vec![
        serde_json::json!({
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                { "name": "userName", "type": "string", "multiValued": false, "required": true },
                { "name": "externalId", "type": "string", "multiValued": false, "required": false },
                { "name": "active", "type": "boolean", "multiValued": false, "required": false }
            ]
        }),
        serde_json::json!({
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                { "name": "displayName", "type": "string", "multiValued": false, "required": true },
                { "name": "members", "type": "complex", "multiValued": true, "required": false }
            ]
        }),
        serde_json::json!({
            "id": ENTERPRISE_USER_SCHEMA,
            "name": "EnterpriseUser",
            "description": "Enterprise User",
            "attributes": [
                { "name": "employeeNumber", "type": "string", "multiValued": false, "required": false },
                { "name": "costCenter", "type": "string", "multiValued": false, "required": false },
                { "name": "organization", "type": "string", "multiValued": false, "required": false },
                { "name": "division", "type": "string", "multiValued": false, "required": false },
                { "name": "department", "type": "string", "multiValued": false, "required": false },
                { "name": "manager", "type": "complex", "multiValued": false, "required": false }
            ]
        }),
    ];
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources,
    }))
}

pub(crate) async fn resource_types() -> impl IntoResponse {
    let user_extensions = vec![serde_json::json!({
        "schema": ENTERPRISE_USER_SCHEMA,
        "required": false
    })];
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 4,
        "Resources": [
            {
                "id": "User",
                "endpoint": "/Users",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                "schemaExtensions": user_extensions,
            },
            { "id": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group" },
            { "id": "Device", "endpoint": "/Devices", "schema": RFC_9944_DEVICE_SCHEMA },
            { "id": "EventSubscription", "endpoint": "/EventSubscriptions", "schema": RFC_9967_EVENT_SUBSCRIPTION_SCHEMA }
        ]
    }))
}
