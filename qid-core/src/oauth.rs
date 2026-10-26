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
    if realm.protocols.oauth.resource_servers.is_empty() {
        return Ok(requested_audiences.to_vec());
    }
    let audiences = resolve_authorization_audience(realm, requested_audiences, resources, scopes)?;
    for audience in &audiences {
        if let Some(server) =
            resource_server_by_audience(&realm.protocols.oauth.resource_servers, audience)
        {
            require_sender_constraint(server, cnf)?;
        }
    }
    Ok(audiences)
}

/// Resolve an authorization target and its scope ceiling, without asserting
/// sender proof. Proof is checked by `resolve_token_audience` at issuance.
pub fn resolve_authorization_audience(
    realm: &RealmConfig,
    requested_audiences: &[String],
    resources: &[String],
    scopes: &[String],
) -> QidResult<Vec<String>> {
    let resource_servers = &realm.protocols.oauth.resource_servers;
    if resource_servers.is_empty() {
        if let Some(resource) = resources.first() {
            return Err(QidError::Unauthorized {
                message: format!("unknown resource indicator: {resource}"),
            });
        }
        return Ok(requested_audiences.to_vec());
    }
    let mut audiences = BTreeSet::new();
    let mut selected_servers = Vec::new();
    for audience in requested_audiences {
        let server = resource_server_by_audience(resource_servers, audience).ok_or_else(|| {
            QidError::Unauthorized {
                message: format!("unknown resource server audience: {audience}"),
            }
        })?;
        selected_servers.push(server);
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
        selected_servers.push(server);
        audiences.insert(server.audience.clone());
    }
    if audiences.is_empty() {
        return Err(QidError::BadRequest {
            message: "audience or resource is required when OAuth resource servers are configured"
                .to_string(),
        });
    }
    validate_scopes_per_target(scopes, &selected_servers)?;
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

/// Validate requested scopes against every selected target: each configured
/// resource-server scope list is that target's ceiling (RFC 8707 section 2.2
/// recommends downscoping to each resource's needs), so a scope must appear
/// in all selected servers that restrict scopes. Servers with an empty scope
/// list impose no restriction, preserving the current opt-in semantics.
fn validate_scopes_per_target(
    scopes: &[String],
    servers: &[&OAuthResourceServerConfig],
) -> QidResult<()> {
    for server in servers {
        if server.scopes.is_empty() {
            continue;
        }
        for scope in scopes {
            if !server.scopes.contains(scope) {
                return Err(QidError::BadRequest {
                    message: format!(
                        "requested scope {scope} is not allowed for resource server {}",
                        server.audience
                    ),
                });
            }
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

    fn server(audience: &str, scopes: Vec<&str>) -> OAuthResourceServerConfig {
        OAuthResourceServerConfig {
            audience: audience.to_string(),
            resources: Vec::new(),
            scopes: scopes.into_iter().map(str::to_string).collect(),
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        }
    }

    #[test]
    fn scope_ceiling_applies_per_target() {
        let realm = realm_with_resource_servers(vec![
            server("api://reader", vec!["read"]),
            server("api://admin", vec!["admin"]),
        ]);
        // Single restrictive target still enforces its ceiling.
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://reader".to_string()],
                &[],
                &["admin".to_string()],
                None,
            )
            .is_err()
        );
        // Adding a permissive target must not widen the restrictive ceiling.
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://reader".to_string(), "api://admin".to_string()],
                &[],
                &["admin".to_string()],
                None,
            )
            .is_err()
        );
        // A scope inside every selected ceiling succeeds with both audiences.
        let audiences = super::resolve_token_audience(
            &realm_with_resource_servers(vec![
                server("api://reader", vec!["read", "admin"]),
                server("api://admin", vec!["admin"]),
            ]),
            &["api://reader".to_string(), "api://admin".to_string()],
            &[],
            &["admin".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(audiences, vec!["api://admin", "api://reader"]);
    }

    #[test]
    fn unrestricted_target_imposes_no_scope_ceiling() {
        let realm = realm_with_resource_servers(vec![
            server("api://open", Vec::new()),
            server("api://reader", vec!["read"]),
        ]);
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://open".to_string(), "api://reader".to_string()],
                &[],
                &["read".to_string()],
                None,
            )
            .is_ok()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://open".to_string()],
                &[],
                &["anything".to_string()],
                None,
            )
            .is_ok()
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
