//! OAuth shared validation helpers.

use crate::{
    config::{OAuthResourceServerConfig, RealmConfig},
    error::{QidError, QidResult},
};
use std::collections::BTreeSet;

/// Validate OAuth Rich Authorization Requests authorization details.
///
/// RFC 9396 defines `authorization_details` as a non-empty JSON array of
/// objects. qid accepts extension members, but every entry must carry a
/// non-empty string `type` so policy and token claims can reason about it.
pub fn validate_authorization_details(details: &serde_json::Value) -> QidResult<()> {
    let entries = details.as_array().ok_or_else(|| QidError::BadRequest {
        message: "authorization_details must be an array".to_string(),
    })?;
    if entries.is_empty() {
        return Err(QidError::BadRequest {
            message: "authorization_details must not be empty".to_string(),
        });
    }
    for (idx, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}] must be an object"),
            });
        };
        let Some(detail_type) = object.get("type").and_then(|value| value.as_str()) else {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}].type is required"),
            });
        };
        if detail_type.trim().is_empty() {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}].type must not be empty"),
            });
        }
    }
    Ok(())
}

pub fn resolve_token_audience(
    realm: &RealmConfig,
    requested_audiences: &[String],
    resources: &[String],
    scopes: &[String],
    cnf: Option<&serde_json::Value>,
) -> QidResult<Vec<String>> {
    let resource_servers = &realm.protocols.oauth.resource_servers;
    if resource_servers.is_empty() {
        return Ok(requested_audiences.to_vec());
    }
    let mut audiences = BTreeSet::new();
    let mut allowed_scopes = BTreeSet::new();
    let mut has_scope_restriction = false;
    for audience in requested_audiences {
        let server = resource_server_by_audience(resource_servers, audience).ok_or_else(|| {
            QidError::Unauthorized {
                message: format!("unknown resource server audience: {audience}"),
            }
        })?;
        require_sender_constraint(server, cnf)?;
        collect_allowed_scopes(server, &mut allowed_scopes, &mut has_scope_restriction);
        audiences.insert(audience.clone());
    }
    for resource in resources {
        let server = resource_server_by_resource(resource_servers, resource).ok_or_else(|| {
            QidError::Unauthorized {
                message: format!("unknown resource indicator: {resource}"),
            }
        })?;
        if !requested_audiences.is_empty() && !requested_audiences.contains(&server.audience) {
            return Err(QidError::Unauthorized {
                message: format!(
                    "resource indicator {resource} is not allowed for requested audience {}",
                    requested_audiences.join(" ")
                ),
            });
        }
        require_sender_constraint(server, cnf)?;
        collect_allowed_scopes(server, &mut allowed_scopes, &mut has_scope_restriction);
        audiences.insert(server.audience.clone());
    }
    if audiences.is_empty() {
        return Err(QidError::BadRequest {
            message: "audience or resource is required when OAuth resource servers are configured"
                .to_string(),
        });
    }
    validate_scopes(scopes, &allowed_scopes, has_scope_restriction)?;
    Ok(audiences.into_iter().collect())
}

fn resource_server_by_audience<'a>(
    resource_servers: &'a [OAuthResourceServerConfig],
    audience: &str,
) -> Option<&'a OAuthResourceServerConfig> {
    resource_servers
        .iter()
        .find(|server| server.audience == audience)
}

fn resource_server_by_resource<'a>(
    resource_servers: &'a [OAuthResourceServerConfig],
    resource: &str,
) -> Option<&'a OAuthResourceServerConfig> {
    resource_servers.iter().find(|server| {
        server
            .resources
            .iter()
            .any(|candidate| candidate == resource)
    })
}

fn require_sender_constraint(
    resource_server: &OAuthResourceServerConfig,
    cnf: Option<&serde_json::Value>,
) -> QidResult<()> {
    if (resource_server.require_sender_constraint || resource_server.high_risk) && cnf.is_none() {
        return Err(QidError::Unauthorized {
            message: format!(
                "sender-constrained token is required for audience {}",
                resource_server.audience
            ),
        });
    }
    Ok(())
}

fn collect_allowed_scopes(
    resource_server: &OAuthResourceServerConfig,
    allowed_scopes: &mut BTreeSet<String>,
    has_scope_restriction: &mut bool,
) {
    if resource_server.scopes.is_empty() {
        return;
    }
    *has_scope_restriction = true;
    allowed_scopes.extend(resource_server.scopes.iter().cloned());
}

fn validate_scopes(
    scopes: &[String],
    allowed_scopes: &BTreeSet<String>,
    has_scope_restriction: bool,
) -> QidResult<()> {
    if !has_scope_restriction {
        return Ok(());
    }
    for scope in scopes {
        if !allowed_scopes.contains(scope) {
            return Err(QidError::BadRequest {
                message: format!("requested scope {scope} is not allowed for resource server"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_authorization_details;
    use crate::config::{
        OAuthProtocolConfig, OAuthResourceServerConfig, ProtocolConfig, RealmConfig,
    };

    #[test]
    fn validates_authorization_details_shape() {
        validate_authorization_details(&serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["initiate"]
            }
        ]))
        .unwrap();

        assert!(validate_authorization_details(&serde_json::json!({ "type": "payment" })).is_err());
        assert!(validate_authorization_details(&serde_json::json!([])).is_err());
        assert!(
            validate_authorization_details(&serde_json::json!([{ "actions": ["read"] }])).is_err()
        );
        assert!(validate_authorization_details(&serde_json::json!([{ "type": " " }])).is_err());
    }

    #[test]
    fn resolves_registered_resource_audience_and_sender_constraint() {
        let realm = realm_with_resource_servers(vec![
            OAuthResourceServerConfig {
                audience: "api://payments".to_string(),
                resources: vec!["https://api.example.com/payments".to_string()],
                scopes: vec!["payments".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: true,
            },
            OAuthResourceServerConfig {
                audience: "api://profile".to_string(),
                resources: vec!["https://api.example.com/profile".to_string()],
                scopes: vec!["profile".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: false,
            },
        ]);
        let cnf = serde_json::json!({"jkt": "thumbprint"});
        let audiences = super::resolve_token_audience(
            &realm,
            &[],
            &["https://api.example.com/payments".to_string()],
            &["payments".to_string()],
            Some(&cnf),
        )
        .unwrap();
        assert_eq!(audiences, vec!["api://payments"]);
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://payments".to_string()],
                &[],
                &["payments".to_string()],
                None,
            )
            .is_err()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://payments".to_string()],
                &["https://api.example.com/profile".to_string()],
                &["payments".to_string()],
                Some(&cnf),
            )
            .is_err()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://profile".to_string()],
                &[],
                &["payments".to_string()],
                Some(&cnf),
            )
            .is_err()
        );
    }

    fn realm_with_resource_servers(
        resource_servers: Vec<OAuthResourceServerConfig>,
    ) -> RealmConfig {
        RealmConfig {
            id: "test".to_string(),
            issuer: "https://id.example.com".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig {
                oauth: OAuthProtocolConfig {
                    resource_servers,
                    ..OAuthProtocolConfig::default()
                },
                ..ProtocolConfig::default()
            },
            authentication: Default::default(),
            sessions: Default::default(),
            pep_registrations: Default::default(),
            policy: Default::default(),
        }
    }
}
