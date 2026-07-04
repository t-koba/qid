use qid_core::error::{QidError, QidResult};
use qid_core::models::AuditEvent;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::hex_sha256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDeliveryConfig {
    pub realm_id: Option<String>,
    pub channel: NotificationChannel,
    pub provider: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub template_id: Option<String>,
    pub data_json: serde_json::Value,
    pub now_epoch: u64,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
    pub completed_attempts: u32,
    pub retry_policy: NotificationRetryPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Push,
}

impl NotificationChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Push => "push",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for NotificationRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRetryDecision {
    pub retry: bool,
    pub attempt: u32,
    pub delay_ms: Option<u64>,
    /// First error message preserved across retries to avoid overwriting
    /// the original failure context.
    pub first_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRequest {
    pub channel: NotificationChannel,
    pub provider: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub template_id: Option<String>,
    pub data_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationResponse {
    pub status: u16,
    pub provider_message_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDeliveryReport {
    pub status: NotificationDeliveryStatus,
    pub realm_id: Option<String>,
    pub channel: NotificationChannel,
    pub provider: String,
    pub recipient_hash: String,
    pub provider_status: Option<u16>,
    pub provider_message_id: Option<String>,
    pub retry: NotificationRetryDecision,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeliveryStatus {
    Delivered,
    FailedRetryable,
    FailedPermanent,
}

pub trait NotificationTransport {
    fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String>;
}

pub async fn run_notification_delivery_job<R, T>(
    repo: &R,
    transport: &T,
    config: NotificationDeliveryConfig,
) -> QidResult<NotificationDeliveryReport>
where
    R: Repository,
    T: NotificationTransport,
{
    validate_notification_config(&config)?;
    let recipient_hash = hex_sha256(config.recipient.as_bytes());
    let body_hash = hex_sha256(config.body.as_bytes());
    let response = transport.send(NotificationRequest {
        channel: config.channel,
        provider: config.provider.clone(),
        recipient: config.recipient.clone(),
        subject: config.subject.clone(),
        body: config.body.clone(),
        template_id: config.template_id.clone(),
        data_json: config.data_json.clone(),
    });

    let (status, provider_status, provider_message_id, retry) = match response {
        Ok(response) if (200..300).contains(&response.status) => (
            NotificationDeliveryStatus::Delivered,
            Some(response.status),
            response.provider_message_id,
            NotificationRetryDecision {
                retry: false,
                attempt: config.completed_attempts + 1,
                delay_ms: None,
                first_error: None,
            },
        ),
        Ok(response) => {
            let retry = plan_notification_retry(
                config.retry_policy,
                config.completed_attempts,
                response.status,
            );
            let status = if retry.retry {
                NotificationDeliveryStatus::FailedRetryable
            } else {
                NotificationDeliveryStatus::FailedPermanent
            };
            (
                status,
                Some(response.status),
                response.provider_message_id,
                retry,
            )
        }
        Err(e) => {
            let first_error = Some(e);
            let mut retry =
                plan_notification_retry(config.retry_policy, config.completed_attempts, 503);
            retry.first_error = first_error;
            let status = if retry.retry {
                NotificationDeliveryStatus::FailedRetryable
            } else {
                NotificationDeliveryStatus::FailedPermanent
            };
            (status, None, None, retry)
        }
    };

    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: config.realm_id.clone(),
            actor: config.actor,
            action: "notification.deliver".to_string(),
            target_type: "notification".to_string(),
            target_id: recipient_hash.clone(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "status": status.clone(),
                "channel": config.channel,
                "provider": config.provider.clone(),
                "recipient_sha256": recipient_hash.clone(),
                "body_sha256": body_hash,
                "template_id": config.template_id.clone(),
                "subject_present": config.subject.is_some(),
                "provider_status": provider_status,
                "provider_message_id": provider_message_id.clone(),
                "retry": retry.clone(),
            }),
            created_at: config.now_epoch,
            previous_hash: None,
            event_hash: None,
        })
        .await?;
        Some(event_id)
    } else {
        None
    };

    Ok(NotificationDeliveryReport {
        status,
        realm_id: config.realm_id,
        channel: config.channel,
        provider: config.provider,
        recipient_hash,
        provider_status,
        provider_message_id,
        retry,
        audit_event_id,
    })
}

fn validate_notification_config(config: &NotificationDeliveryConfig) -> QidResult<()> {
    if config.provider.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "notification provider must not be empty".to_string(),
        });
    }
    if config.recipient.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "notification recipient must not be empty".to_string(),
        });
    }
    if config.body.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "notification body must not be empty".to_string(),
        });
    }
    if config.retry_policy.max_attempts == 0 {
        return Err(QidError::BadRequest {
            message: "notification retry max_attempts must be greater than zero".to_string(),
        });
    }
    if config.retry_policy.base_delay_ms == 0 || config.retry_policy.max_delay_ms == 0 {
        return Err(QidError::BadRequest {
            message: "notification retry delays must be greater than zero".to_string(),
        });
    }
    if config.retry_policy.base_delay_ms > config.retry_policy.max_delay_ms {
        return Err(QidError::BadRequest {
            message: "notification retry base_delay_ms must not exceed max_delay_ms".to_string(),
        });
    }
    match config.channel {
        NotificationChannel::Email => {
            if !config.recipient.contains('@') {
                return Err(QidError::BadRequest {
                    message: "email notification recipient must be an email address".to_string(),
                });
            }
        }
        NotificationChannel::Push => {
            if config.recipient.chars().any(char::is_whitespace) {
                return Err(QidError::BadRequest {
                    message: "push notification recipient token must not contain whitespace"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

pub fn plan_notification_retry(
    policy: NotificationRetryPolicy,
    completed_attempts: u32,
    status: u16,
) -> NotificationRetryDecision {
    let attempt = completed_attempts + 1;
    let retryable_status = status == 408 || status == 429 || (500..600).contains(&status);
    if !retryable_status || attempt >= policy.max_attempts {
        return NotificationRetryDecision {
            retry: false,
            attempt,
            delay_ms: None,
            first_error: None,
        };
    }

    let multiplier = 1_u64.checked_shl(completed_attempts).unwrap_or(u64::MAX);
    let delay_ms = policy
        .base_delay_ms
        .saturating_mul(multiplier)
        .min(policy.max_delay_ms);
    NotificationRetryDecision {
        retry: true,
        attempt,
        delay_ms: Some(delay_ms),
        first_error: None,
    }
}

// ---------------------------------------------------------------------------
// SMTP transport (behind feature "smtp-transport")
// ---------------------------------------------------------------------------

#[cfg(feature = "smtp-transport")]
pub mod smtp {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
    use serde::{Deserialize, Serialize};

    use crate::notification::{NotificationRequest, NotificationResponse};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SmtpTransportConfig {
        pub host: String,
        pub port: u16,
        pub username: String,
        pub password: String,
        pub use_tls: bool,
    }

    pub struct SmtpNotificationTransport {
        config: SmtpTransportConfig,
    }

    impl SmtpNotificationTransport {
        pub fn new(config: SmtpTransportConfig) -> Self {
            Self { config }
        }

        fn build_mailer(&self) -> AsyncSmtpTransport<Tokio1Executor> {
            let creds =
                Credentials::new(self.config.username.clone(), self.config.password.clone());
            if self.config.use_tls {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.host)
                    .unwrap()
                    .credentials(creds)
                    .port(self.config.port)
                    .build()
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.host)
                    .unwrap()
                    .credentials(creds)
                    .port(self.config.port)
                    .build()
            }
        }
    }

    impl super::NotificationTransport for SmtpNotificationTransport {
        fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
            let subject = request.subject.unwrap_or_default();
            let body = request.body;

            let email = Message::builder()
                .from(
                    request
                        .recipient
                        .parse()
                        .map_err(|e| format!("invalid from address: {e}"))?,
                )
                .to(request
                    .recipient
                    .parse()
                    .map_err(|e| format!("invalid to address: {e}"))?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)
                .map_err(|e| format!("failed to build message: {e}"))?;

            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime creation failed: {e}"))?;

            rt.block_on(async {
                let mailer = self.build_mailer();
                match mailer.send(email).await {
                    Ok(response) => {
                        let message_id = response.message().next().map(str::to_string);
                        Ok(NotificationResponse {
                            status: 200,
                            provider_message_id: message_id,
                        })
                    }
                    Err(e) => Ok(NotificationResponse {
                        status: 500,
                        provider_message_id: Some(format!("{e}")),
                    }),
                }
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn smtp_transport_is_constructable() {
            let config = SmtpTransportConfig {
                host: "mail.example.com".to_string(),
                port: 587,
                username: "user".to_string(),
                password: "pass".to_string(),
                use_tls: false,
            };
            let _transport = SmtpNotificationTransport::new(config);
        }
    }
}
