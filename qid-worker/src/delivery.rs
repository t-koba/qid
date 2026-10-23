use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use crate::{AuditSiemHttpRequest, AuditSiemHttpResponse, SiemWebhookTransport};
use qid_core::notification::{NotificationRequest, NotificationResponse, NotificationTransport};

pub struct DeliveryTransport {
    client: Option<reqwest::Client>,
    request_output: Option<PathBuf>,
    notification_provider: Option<String>,
}

impl DeliveryTransport {
    pub fn https(timeout_seconds: u64, request_output: Option<PathBuf>) -> Result<Self, String> {
        Self::build(timeout_seconds, request_output, None)
    }

    /// Construct an HTTPS transport pinned to the configured notification URL.
    ///
    /// Generic worker jobs may still use per-request endpoints via `https`; a
    /// daemon notification transport must not let its request choose a host.
    pub fn https_for_notification(
        timeout_seconds: u64,
        provider: impl Into<String>,
    ) -> Result<Self, String> {
        let provider = provider.into();
        let config = qid_core::config::ServerNotificationConfig {
            provider: provider.clone(),
            timeout_seconds,
        };
        config
            .validate()
            .map_err(|_| "invalid server.notification configuration".to_string())?;
        let url = reqwest::Url::parse(&provider)
            .map_err(|_| "invalid server.notification provider".to_string())?;
        if url.scheme() != "https" {
            return Err("notification provider must use HTTPS".to_string());
        }
        Self::build(timeout_seconds, None, Some(provider))
    }

    fn build(
        timeout_seconds: u64,
        request_output: Option<PathBuf>,
        notification_provider: Option<String>,
    ) -> Result<Self, String> {
        if timeout_seconds == 0 {
            return Err("delivery timeout must be greater than zero".to_string());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("failed to build delivery HTTP client: {error}"))?;
        Ok(Self {
            client: Some(client),
            request_output,
            notification_provider,
        })
    }

    pub fn dry_run(request_output: Option<PathBuf>) -> Self {
        Self {
            client: None,
            request_output,
            notification_provider: None,
        }
    }

    pub fn output_path(&self) -> Option<&std::path::Path> {
        self.request_output.as_deref()
    }

    async fn send(
        &self,
        method: &str,
        endpoint: &str,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Result<Option<(u16, Option<String>)>, String> {
        let url =
            reqwest::Url::parse(endpoint).map_err(|e| format!("invalid HTTPS endpoint: {e}"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("endpoint must be HTTPS without user information".into());
        }
        if let Some(path) = &self.request_output {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let value = serde_json::json!({"method":method,"url":endpoint,"headers":headers,"body":serde_json::from_slice::<serde_json::Value>(&body).map_err(|e| e.to_string())?});
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        }
        let Some(client) = &self.client else {
            return Ok(None);
        };
        let mut request = client.request(
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?,
            url,
        );
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("content-length") {
                request = request.header(name, value);
            }
        }
        let response = request.body(body).send().await.map_err(|e| e.to_string())?;
        let id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(Some((response.status().as_u16(), id)))
    }
}

#[async_trait::async_trait]
impl SiemWebhookTransport for DeliveryTransport {
    async fn send(&self, request: AuditSiemHttpRequest) -> Result<AuditSiemHttpResponse, String> {
        let result = self
            .send(&request.method, &request.url, request.headers, request.body)
            .await?;
        let (status, sent) = result.map_or((0, false), |(status, _)| (status, true));
        Ok(AuditSiemHttpResponse { status, sent })
    }
}

#[async_trait::async_trait]
impl NotificationTransport for DeliveryTransport {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        let provider = match self.notification_provider.as_deref() {
            Some(configured) if request.provider != configured => {
                return Err("notification provider does not match configured endpoint".into());
            }
            Some(configured) => configured,
            None => request.provider.as_str(),
        };
        let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let result = self.send("POST", provider, headers, body).await?;
        let (status, provider_message_id, sent) =
            result.map_or((0, None, false), |(status, id)| (status, id, true));
        Ok(NotificationResponse {
            status,
            provider_message_id,
            sent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_notification_transport_rejects_per_request_endpoint_override() {
        let transport =
            DeliveryTransport::https_for_notification(1, "https://hooks.example.com/notify")
                .expect("configured notification transport");
        let result = NotificationTransport::send(
            &transport,
            NotificationRequest {
                channel: crate::NotificationChannel::Email,
                provider: "https://attacker.example/exfil".to_string(),
                recipient: "recipient@example.com".to_string(),
                subject: None,
                body: "challenge-secret".to_string(),
                template_id: None,
                data_json: serde_json::json!({}),
            },
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            "notification provider does not match configured endpoint"
        );
    }

    #[tokio::test]
    async fn https_transport_rejects_insecure_notification_provider() {
        let transport = DeliveryTransport::https(1, None).expect("HTTPS client");
        let result = NotificationTransport::send(
            &transport,
            NotificationRequest {
                channel: crate::NotificationChannel::Email,
                provider: "http://mail.example.com/send".to_string(),
                recipient: "recipient@example.com".to_string(),
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
}
