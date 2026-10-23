//! Owner-neutral notification transport contract.
//!
//! The worker owns delivery; this module only carries the channel, request,
//! response and transport types so daemons can hold a configured transport
//! without depending on the worker.

use serde::{Deserialize, Serialize};
use std::fmt;

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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRequest {
    pub channel: NotificationChannel,
    pub provider: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub template_id: Option<String>,
    pub data_json: serde_json::Value,
}

impl fmt::Debug for NotificationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationRequest")
            .field("channel", &self.channel)
            .field("provider", &"<redacted>")
            .field("recipient", &"<redacted>")
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .field("body", &"<redacted>")
            .field("template_id", &self.template_id)
            .field("data_json", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationResponse {
    pub status: u16,
    pub provider_message_id: Option<String>,
    pub sent: bool,
}

// Provider identifiers are untrusted and may echo request content.
impl fmt::Debug for NotificationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationResponse")
            .field("status", &self.status)
            .field("sent", &self.sent)
            .field(
                "provider_message_id",
                &self.provider_message_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[async_trait::async_trait]
pub trait NotificationTransport: Send + Sync {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String>;
}
