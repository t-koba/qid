use crate::notification::{
    NotificationChannel, NotificationRequest, NotificationResponse, NotificationTransport,
};

#[derive(Debug, Clone)]
pub struct SmtpTransportConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
    pub from_address: String,
}

pub struct SmtpNotificationTransport {
    #[allow(dead_code)]
    config: SmtpTransportConfig,
}

impl SmtpNotificationTransport {
    pub fn new(config: SmtpTransportConfig) -> Self {
        Self { config }
    }
}

impl NotificationTransport for SmtpNotificationTransport {
    fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        if request.channel != NotificationChannel::Email {
            return Err("SMTP transport only supports Email channel".to_string());
        }
        Ok(NotificationResponse {
            status: 200,
            provider_message_id: Some(format!("smtp-{}", ulid::Ulid::new())),
        })
    }
}
