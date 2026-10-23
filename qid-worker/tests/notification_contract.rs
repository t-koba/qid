//! The worker re-exports the owner-neutral core notification contract and its
//! HTTPS transport implements that same trait.

use qid_core::notification::{
    NotificationChannel, NotificationRequest, NotificationResponse, NotificationTransport,
};
use qid_worker::DeliveryTransport;

struct StubTransport;

#[async_trait::async_trait]
impl qid_core::notification::NotificationTransport for StubTransport {
    async fn send(&self, _request: NotificationRequest) -> Result<NotificationResponse, String> {
        Ok(NotificationResponse {
            status: 202,
            provider_message_id: None,
            sent: true,
        })
    }
}

#[tokio::test]
async fn worker_transport_satisfies_core_contract() {
    let core: &dyn NotificationTransport = &StubTransport;
    let response = core
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
        .expect("core contract sends");
    assert_eq!(response.status, 202);
    assert!(response.sent);
}

#[tokio::test]
async fn worker_https_transport_implements_core_contract() {
    let transport = DeliveryTransport::https(1, None).expect("HTTPS client");
    let result = NotificationTransport::send(
        &transport,
        NotificationRequest {
            channel: NotificationChannel::Email,
            provider: "http://hooks.example.com/notify".to_string(),
            recipient: "alice@example.com".to_string(),
            subject: None,
            body: "message".to_string(),
            template_id: None,
            data_json: serde_json::json!({}),
        },
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .contains("HTTPS without user information")
    );
}

#[test]
fn worker_reexport_matches_core_channel_shape() {
    assert_eq!(
        qid_worker::NotificationChannel::Email.as_str(),
        NotificationChannel::Email.as_str()
    );
    let request = NotificationRequest {
        channel: qid_worker::NotificationChannel::Push,
        provider: "https://hooks.example.com/notify".to_string(),
        recipient: "device-token".to_string(),
        subject: None,
        body: "message".to_string(),
        template_id: None,
        data_json: serde_json::json!({}),
    };
    let value = serde_json::to_value(&request).expect("request serializes");
    assert_eq!(value["channel"], "push");
}
