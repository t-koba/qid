use async_trait::async_trait;
use qid_core::error::QidResult;

use super::OutboundScimHttpRequest;
use super::OutboundScimHttpResponse;

#[async_trait]
pub trait OutboundScimTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse>;
}

pub struct ReqwestOutboundScimTransport {
    client: reqwest::Client,
}

impl ReqwestOutboundScimTransport {
    /// Build the HTTP client, returning an internal error if initialization fails.
    pub fn new() -> QidResult<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|error| qid_core::error::QidError::Internal {
                    message: format!("SCIM outbound HTTP client initialization failed: {error}"),
                })?,
        })
    }
}

#[async_trait]
impl OutboundScimTransport for ReqwestOutboundScimTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        let method = request
            .method
            .to_uppercase()
            .parse::<reqwest::Method>()
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("invalid SCIM outbound method {}: {e}", request.method),
            })?;
        let mut req = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(body) = request.body {
            req = req.json(&body);
        }
        let response = req
            .send()
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("SCIM outbound request failed: {e}"),
            })?;
        let status = response.status().as_u16();
        let body: Option<serde_json::Value> = response.json().await.ok();
        Ok(OutboundScimHttpResponse { status, body })
    }
}
