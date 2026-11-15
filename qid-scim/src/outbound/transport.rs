use super::{OutboundScimHttpRequest, OutboundScimHttpResponse, remote::invalid};
use async_trait::async_trait;
use qid_core::error::QidResult;

#[async_trait]
pub trait OutboundScimTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse>;
}
pub struct ReqwestOutboundScimTransport {
    client: reqwest::Client,
    max_response_bytes: usize,
}
impl ReqwestOutboundScimTransport {
    /// Default response budget is 1 MiB; redirects never forward credentials.
    pub fn new() -> QidResult<Self> {
        Self::with_response_limit(1_048_576)
    }
    pub fn with_response_limit(max_response_bytes: usize) -> QidResult<Self> {
        if max_response_bytes == 0 {
            return Err(invalid("response limit must be positive"));
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|_| invalid("HTTP client initialization failed"))?,
            max_response_bytes,
        })
    }
}
#[async_trait]
impl OutboundScimTransport for ReqwestOutboundScimTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        let method = request
            .method
            .parse::<reqwest::Method>()
            .map_err(|_| invalid("invalid HTTP method"))?;
        let mut req = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            req = req.header(name, value);
        }
        if let Some(body) = request.body {
            req = req.json(&body);
        }
        let mut response = req
            .send()
            .await
            .map_err(|_| invalid("HTTP request failed"))?;
        let status = response.status().as_u16();
        // Do not parse, retain or expose remote error bodies.
        if !(200..300).contains(&status) {
            return Ok(OutboundScimHttpResponse { status, body: None });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("response read failed"))?
        {
            if chunk.len() > self.max_response_bytes.saturating_sub(bytes.len()) {
                return Err(invalid("response exceeds byte limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = if bytes.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&bytes).map_err(|_| invalid("invalid response JSON"))?)
        };
        Ok(OutboundScimHttpResponse { status, body })
    }
}
