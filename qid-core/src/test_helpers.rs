//! Shared test utilities.
//!
//! Only available when feature `test-utils` is enabled.

use crate::config::{
    AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile,
    ObservabilityConfig, OpsConfig, PepRegistrationsConfig, PolicyConfig, ProtocolConfig,
    QidConfig, RealmConfig, ServerConfig, ServerPaths, SessionConfig, StorageConfig,
};

/// Create a minimal valid `QidConfig` for testing.
///
/// The config has a single realm named `"test"` with issuer
/// `"https://id.example.com"` and sensible defaults for all sub-configs.
pub fn test_config() -> QidConfig {
    QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8080".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "test".to_string(),
            issuer: "https://id.example.com".to_string(),
            display_name: Some("Test Realm".to_string()),
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    }
}
