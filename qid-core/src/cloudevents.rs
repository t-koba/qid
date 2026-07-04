use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudEvent {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacontenttype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataschema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub fn new_cloud_event(source: &str, type_: &str, data: serde_json::Value) -> CloudEvent {
    CloudEvent {
        specversion: "1.0".to_string(),
        id: ulid::Ulid::new().to_string(),
        source: source.to_string(),
        type_: type_.to_string(),
        datacontenttype: Some("application/json".to_string()),
        dataschema: None,
        subject: None,
        time: Some(crate::util::now_seconds().to_string()),
        data: Some(data),
    }
}

pub fn validate_cloud_event(event: &CloudEvent) -> QidResult<()> {
    if event.specversion != "1.0" {
        return Err(QidError::BadRequest {
            message: format!(
                "CloudEvents specversion must be 1.0, got: {}",
                event.specversion
            ),
        });
    }
    if event.id.is_empty() {
        return Err(QidError::BadRequest {
            message: "CloudEvents id must not be empty".to_string(),
        });
    }
    if event.source.is_empty() {
        return Err(QidError::BadRequest {
            message: "CloudEvents source must not be empty".to_string(),
        });
    }
    if event.type_.is_empty() {
        return Err(QidError::BadRequest {
            message: "CloudEvents type must not be empty".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cloud_event_sets_required_fields() {
        let event = new_cloud_event(
            "/test/source",
            "com.example.test",
            serde_json::json!({"key": "value"}),
        );
        assert_eq!(event.specversion, "1.0");
        assert!(!event.id.is_empty());
        assert_eq!(event.source, "/test/source");
        assert_eq!(event.type_, "com.example.test");
        assert_eq!(event.datacontenttype, Some("application/json".to_string()));
        assert!(event.time.is_some());
        assert_eq!(event.data, Some(serde_json::json!({"key": "value"})));
    }

    #[test]
    fn validates_valid_event() {
        let event = CloudEvent {
            specversion: "1.0".to_string(),
            id: "id-1".to_string(),
            source: "/source".to_string(),
            type_: "com.example.event".to_string(),
            datacontenttype: None,
            dataschema: None,
            subject: None,
            time: None,
            data: None,
        };
        validate_cloud_event(&event).unwrap();
    }

    #[test]
    fn validates_rejects_empty_required_fields() {
        let base = CloudEvent {
            specversion: "1.0".to_string(),
            id: "id-1".to_string(),
            source: "/source".to_string(),
            type_: "com.example.event".to_string(),
            datacontenttype: None,
            dataschema: None,
            subject: None,
            time: None,
            data: None,
        };

        let mut invalid = CloudEvent {
            specversion: "0.3".to_string(),
            ..base.clone()
        };
        assert!(validate_cloud_event(&invalid).is_err());

        invalid = CloudEvent {
            id: String::new(),
            ..base.clone()
        };
        assert!(validate_cloud_event(&invalid).is_err());

        invalid = CloudEvent {
            source: String::new(),
            ..base.clone()
        };
        assert!(validate_cloud_event(&invalid).is_err());

        invalid = CloudEvent {
            type_: String::new(),
            ..base
        };
        assert!(validate_cloud_event(&invalid).is_err());
    }

    #[test]
    fn cloud_event_serializes_and_deserializes() {
        let event = new_cloud_event(
            "/test",
            "com.example.test",
            serde_json::json!({"foo": "bar"}),
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloudEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.source, deserialized.source);
        assert_eq!(event.type_, deserialized.type_);
        assert_eq!(event.data, deserialized.data);
    }
}
