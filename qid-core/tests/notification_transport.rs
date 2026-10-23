use qid_core::config::{
    AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile,
    ObservabilityConfig, OpsConfig, PepRegistrationsConfig, PolicyConfig, ProtocolConfig,
    QidConfig, RealmConfig, ServerConfig, ServerPaths, SessionConfig, StorageConfig,
};
use qid_core::jwt::{JwtClaims, Signer, TokenData};
use qid_core::notification::{
    NotificationChannel, NotificationRequest, NotificationResponse, NotificationTransport,
};
use std::sync::Arc;

struct TestSigner;

impl Signer for TestSigner {
    fn sign(&self, _claims: &JwtClaims) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn sign_with_typ(&self, _claims: &JwtClaims, _typ: &str) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn decode_signature_only(&self, _token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn decode_with_aud(
        &self,
        _token: &str,
        _expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn algorithm(&self) -> &'static str {
        "HS256"
    }
}

#[allow(clippy::expect_used)]
fn test_state() -> qid_core::state::SharedState<()> {
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            notification: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
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
    };
    qid_core::state::SharedState::new(
        config,
        Arc::new(()),
        Arc::new(TestSigner),
        serde_json::json!({"keys": []}),
    )
    .expect("test state")
}

struct StubTransport {
    status: u16,
}

#[async_trait::async_trait]
impl NotificationTransport for StubTransport {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        assert_eq!(request.channel, NotificationChannel::Email);
        Ok(NotificationResponse {
            status: self.status,
            provider_message_id: None,
            sent: true,
        })
    }
}

#[test]
fn notification_transport_is_absent_by_default() {
    let state = test_state();
    assert!(state.notification_transport.is_none());
}

#[test]
fn notification_transport_builder_stores_transport() {
    let state = test_state().with_notification_transport(Arc::new(StubTransport { status: 202 }));
    assert!(state.notification_transport.is_some());
}

#[tokio::test]
async fn notification_transport_is_object_safe_and_send_sync() {
    fn assert_object_safe(_: &dyn NotificationTransport) {}
    let transport: Arc<dyn NotificationTransport> = Arc::new(StubTransport { status: 202 });
    assert_object_safe(transport.as_ref());
    let response = transport
        .send(NotificationRequest {
            channel: NotificationChannel::Email,
            provider: "https://hooks.example.com/notify".to_string(),
            recipient: "alice@example.com".to_string(),
            subject: None,
            body: "message".to_string(),
            template_id: None,
            data_json: serde_json::json!({}),
        })
        .await
        .expect("stub transport sends");
    assert_eq!(response.status, 202);
    assert!(response.sent);
}

#[test]
fn notification_request_debug_redacts_delivery_contents() {
    let request = NotificationRequest {
        channel: NotificationChannel::Email,
        provider: "https://hooks.example.com/path-secret".to_string(),
        recipient: "alice@example.com".to_string(),
        subject: Some("verify-secret".to_string()),
        body: "one-time-challenge-secret".to_string(),
        template_id: None,
        data_json: serde_json::json!({"secret": "nested-secret"}),
    };
    let debug = format!("{request:?}");
    for secret in [
        "path-secret",
        "alice@example.com",
        "verify-secret",
        "one-time-challenge-secret",
        "nested-secret",
    ] {
        assert!(!debug.contains(secret), "debug leaked {secret}: {debug}");
    }
}

#[test]
fn notification_types_keep_serialized_shape() {
    let request = NotificationRequest {
        channel: NotificationChannel::Email,
        provider: "https://hooks.example.com/notify".to_string(),
        recipient: "alice@example.com".to_string(),
        subject: Some("Verify".to_string()),
        body: "code".to_string(),
        template_id: None,
        data_json: serde_json::json!({}),
    };
    let value = serde_json::to_value(&request).expect("request serializes");
    assert_eq!(value["channel"], "email");
    assert_eq!(
        serde_json::from_value::<NotificationRequest>(value).expect("request round-trips"),
        request
    );
    let response = NotificationResponse {
        status: 202,
        provider_message_id: Some("msg-1".to_string()),
        sent: true,
    };
    let value = serde_json::to_value(&response).expect("response serializes");
    assert_eq!(
        serde_json::from_value::<NotificationResponse>(value).expect("response round-trips"),
        response
    );
}

#[test]
fn provider_response_debug_does_not_expose_echoed_secrets() {
    let response = NotificationResponse {
        status: 200,
        sent: true,
        provider_message_id: Some("echoed-secret".into()),
    };
    assert!(!format!("{response:?}").contains("echoed-secret"));
}
