use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub paths: BTreeMap<String, BTreeMap<String, OpenApiOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<OpenApiComponents>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<OpenApiParameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responses: Option<BTreeMap<String, OpenApiResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiParameter {
    pub name: String,
    pub r#in: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiResponse {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<BTreeMap<String, OpenApiMediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiMediaType {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiComponents {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schemas: Option<BTreeMap<String, serde_json::Value>>,
}

pub fn generate_openapi_spec() -> OpenApiSpec {
    let mut paths = BTreeMap::new();
    let mut get_health = BTreeMap::new();
    get_health.insert(
        "get".to_string(),
        OpenApiOperation {
            summary: Some("Health check".to_string()),
            description: Some("Returns the health status".to_string()),
            operation_id: Some("health".to_string()),
            parameters: None,
            responses: Some(BTreeMap::from([(
                "200".to_string(),
                OpenApiResponse {
                    description: "OK".to_string(),
                    content: Some(BTreeMap::from([(
                        "application/json".to_string(),
                        OpenApiMediaType {
                            schema: Some(serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string"}
                                }
                            })),
                        },
                    )])),
                },
            )])),
        },
    );
    paths.insert("/health".to_string(), get_health);

    OpenApiSpec {
        openapi: "3.1.1".to_string(),
        info: OpenApiInfo {
            title: "API".to_string(),
            version: "0.1.0".to_string(),
            description: Some("API specification".to_string()),
        },
        paths,
        components: Some(OpenApiComponents {
            schemas: Some(BTreeMap::new()),
        }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonSchema {
    #[serde(rename = "$schema")]
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<BTreeMap<String, JsonSchemaProperty>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonSchemaProperty {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

pub fn generate_json_schema() -> JsonSchema {
    JsonSchema {
        schema: "https://json-schema.org/draft/2020-12/schema".to_string(),
        id: Some("https://example.com/schema.json".to_string()),
        title: Some("Example".to_string()),
        type_: "object".to_string(),
        properties: Some(BTreeMap::from([
            (
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    description: Some("The name".to_string()),
                },
            ),
            (
                "id".to_string(),
                JsonSchemaProperty {
                    type_: "integer".to_string(),
                    description: Some("The identifier".to_string()),
                },
            ),
        ])),
        required: Some(vec!["name".to_string()]),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiSpec {
    pub asyncapi: String,
    pub info: AsyncApiInfo,
    pub channels: BTreeMap<String, AsyncApiChannel>,
    pub components: AsyncApiComponents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiInfo {
    pub title: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiChannel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<AsyncApiOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish: Option<AsyncApiOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<AsyncApiMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsyncApiComponents {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schemas: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<BTreeMap<String, AsyncApiMessage>>,
}

pub fn generate_asyncapi_spec() -> AsyncApiSpec {
    let mut channels = BTreeMap::new();
    channels.insert(
        "user/signedup".to_string(),
        AsyncApiChannel {
            description: Some("User signup events".to_string()),
            subscribe: Some(AsyncApiOperation {
                summary: Some("Receive signup notifications".to_string()),
                message: Some(AsyncApiMessage {
                    name: Some("UserSignedUp".to_string()),
                    title: Some("User signed up".to_string()),
                    summary: Some("Emitted when a user signs up".to_string()),
                    content_type: Some("application/json".to_string()),
                    payload: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "userId": {"type": "string"},
                            "email": {"type": "string"}
                        }
                    })),
                }),
            }),
            publish: None,
        },
    );

    AsyncApiSpec {
        asyncapi: "3.0.0".to_string(),
        info: AsyncApiInfo {
            title: "Event API".to_string(),
            version: "0.1.0".to_string(),
            description: Some("Async event specification".to_string()),
        },
        channels,
        components: AsyncApiComponents {
            schemas: Some(BTreeMap::new()),
            messages: Some(BTreeMap::new()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_spec_serializes_and_has_required_fields() {
        let spec = generate_openapi_spec();
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["openapi"], "3.1.1");
        assert_eq!(json["info"]["title"], "API");
        assert!(json["paths"]["/health"]["get"]["operation_id"].is_string());
    }

    #[test]
    fn json_schema_serializes_and_is_valid() {
        let schema = generate_json_schema();
        let json = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            json["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(json["type"], "object");
        assert!(json["properties"]["name"]["type"].is_string());
        assert_eq!(json["required"], serde_json::json!(["name"]));
    }

    #[test]
    fn asyncapi_spec_serializes_and_has_required_fields() {
        let spec = generate_asyncapi_spec();
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["asyncapi"], "3.0.0");
        assert_eq!(json["info"]["title"], "Event API");
        assert!(json["channels"]["user/signedup"]["subscribe"]["message"].is_object());
    }
}
