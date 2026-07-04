//! OIDC RP Metadata Choices 1.0 (RP registration metadata).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpMetadata {
    pub client_id: String,
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub subject_type: Option<String>,
    pub id_token_signed_response_alg: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub request_object_signing_alg: Option<String>,
    pub request_object_encryption_alg: Option<String>,
    pub request_object_encryption_enc: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub default_max_age: Option<u64>,
    pub require_auth_time: Option<bool>,
    pub default_acr_values: Vec<String>,
    pub initiate_login_uri: Option<String>,
    pub request_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub sector_identifier_uri: Option<String>,
}

pub fn validate_rp_metadata(meta: &RpMetadata) -> Result<(), String> {
    if meta.client_id.is_empty() {
        return Err("client_id is required".to_string());
    }
    if let Some(ref uri) = meta.logo_uri
        && !uri.starts_with("https://")
    {
        return Err("logo_uri must use https".to_string());
    }
    if let Some(ref uri) = meta.client_uri
        && !uri.starts_with("https://")
    {
        return Err("client_uri must use https".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_metadata_round_trip() {
        let meta = RpMetadata {
            client_id: "rp-1".to_string(),
            client_name: Some("Test RP".to_string()),
            subject_type: Some("pairwise".to_string()),
            id_token_signed_response_alg: Some("ES256".to_string()),
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: RpMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.client_id, "rp-1");
    }

    #[test]
    fn validate_rejects_empty_client_id() {
        let meta = RpMetadata {
            client_id: String::new(),
            ..Default::default()
        };
        assert!(validate_rp_metadata(&meta).is_err());
    }

    #[test]
    fn validate_requires_https_for_logo_uri() {
        let meta = RpMetadata {
            client_id: "rp-1".to_string(),
            logo_uri: Some("http://example.com/logo.png".to_string()),
            ..Default::default()
        };
        assert!(validate_rp_metadata(&meta).is_err());
    }
}
