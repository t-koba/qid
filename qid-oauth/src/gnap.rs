//! Grant Negotiation and Authorization Protocol (RFC 9635/9767).

use qid_core::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapGrantRequest {
    pub access_token: Option<GnapAccessTokenRequest>,
    pub client: Option<GnapClient>,
    pub subject: Option<GnapSubjectRequest>,
    pub user: Option<GnapUserRequest>,
    pub interact: Option<GnapInteractRequest>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapAccessTokenRequest {
    pub access: Vec<GnapAccess>,
    pub flags: Vec<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapAccess {
    pub r#type: String,
    pub locations: Vec<String>,
    pub actions: Vec<String>,
    pub dat: Vec<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapClient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<GnapClientKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapClientKey {
    pub proof: String,
    pub jwk: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapSubjectRequest {
    pub sub_ids: Vec<GnapSubjectIdentifier>,
    pub assertion: Option<GnapAssertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapSubjectIdentifier {
    pub format: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapAssertion {
    pub format: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapUserRequest {
    pub reference: Option<String>,
    pub sub_ids: Vec<GnapSubjectIdentifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapInteractRequest {
    pub start: Vec<String>,
    pub finish: Option<GnapFinish>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapFinish {
    pub method: String,
    pub uri: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapGrantResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<GnapAccessTokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_r: Option<GnapContinue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<GnapSubjectResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interact: Option<GnapInteractResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapAccessTokenResponse {
    pub value: String,
    pub label: Option<String>,
    pub manage: Option<String>,
    pub access: Vec<GnapAccess>,
    pub flags: Vec<String>,
    pub expires_in: u64,
    pub key: Option<GnapClientKey>,
    pub bound: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapContinue {
    pub uri: String,
    pub wait: u64,
    pub access_token: Option<GnapContinuationAccessToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapContinuationAccessToken {
    pub value: String,
    pub managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapSubjectResponse {
    pub sub_ids: Vec<GnapSubjectIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnapInteractResponse {
    pub redirect: Option<String>,
    pub finish: Option<String>,
    pub user_code: Option<String>,
    pub user_code_uri: Option<String>,
}

pub fn parse_gnap_grant_request(body: &str) -> QidResult<GnapGrantRequest> {
    Ok(
        serde_json::from_str(body).map_err(|e| qid_core::error::QidError::BadRequest {
            message: format!("GNAP grant request parse error: {e}"),
        })?,
    )
}

pub fn serialize_gnap_grant_response(response: &GnapGrantResponse) -> QidResult<String> {
    serde_json::to_string_pretty(response).map_err(|e| qid_core::error::QidError::Internal {
        message: format!("GNAP grant response serialization error: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnap_grant_request_round_trip() {
        let request = GnapGrantRequest {
            access_token: Some(GnapAccessTokenRequest {
                access: vec![GnapAccess {
                    r#type: "api".to_string(),
                    locations: vec!["https://rs.example.com".to_string()],
                    actions: vec!["read".to_string(), "write".to_string()],
                    dat: vec!["resource".to_string()],
                    identifier: None,
                }],
                flags: vec!["bearer".to_string()],
                label: Some("token-1".to_string()),
            }),
            client: Some(GnapClient {
                key: Some(GnapClientKey {
                    proof: "httpsig".to_string(),
                    jwk: serde_json::json!({"kty": "EC"}),
                }),
                class_id: None,
            }),
            subject: None,
            user: None,
            interact: None,
            capabilities: vec!["user.identifier".to_string()],
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed = parse_gnap_grant_request(&json).unwrap();
        assert_eq!(parsed.client.unwrap().key.unwrap().proof, "httpsig");
    }

    #[test]
    fn gnap_grant_response_serialize() {
        let response = GnapGrantResponse {
            access_token: Some(GnapAccessTokenResponse {
                value: "token-value".to_string(),
                label: None,
                manage: Some("https://as.example.com/manage".to_string()),
                access: vec![],
                flags: vec![],
                expires_in: 3600,
                key: None,
                bound: None,
            }),
            continue_r: None,
            subject: None,
            interact: None,
            instance_id: Some("instance-1".to_string()),
        };
        let json = serialize_gnap_grant_response(&response).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("instance_id"));
    }

    #[test]
    fn gnap_subject_identifier_round_trip() {
        let sub = GnapSubjectIdentifier {
            format: "iss_sub".to_string(),
            id: "user-1".to_string(),
        };
        let json = serde_json::to_string(&sub).unwrap();
        let parsed: GnapSubjectIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.format, "iss_sub");
    }
}
