use super::*;

/// Sources for screening exact prospective UTF-8 password bytes.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordScreeningConfig {
    #[serde(default)]
    pub sha256_hex: Vec<String>,
    /// HTTPS range endpoint base; the five-character prefix is appended as a path segment.
    #[serde(default)]
    pub range_url: Option<String>,
    #[serde(default)]
    pub on_unavailable: ScreeningUnavailable,
    #[serde(default = "screening_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub max_retries: u64,
    #[serde(default = "screening_retry_delay_ms")]
    pub retry_delay_ms: u64,
    #[serde(default = "screening_max_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningUnavailable {
    #[default]
    Deny,
    Allow,
}

fn screening_timeout_ms() -> u64 {
    3_000
}
fn screening_retry_delay_ms() -> u64 {
    250
}
fn screening_max_response_bytes() -> usize {
    1024 * 1024
}

impl PasswordScreeningConfig {
    pub fn validate(&self) -> QidResult<()> {
        let url_valid = self.range_url.as_ref().is_none_or(|value| {
            url::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
        });
        if (self.sha256_hex.is_empty() && self.range_url.is_none())
            || self.sha256_hex.iter().any(|digest| {
                digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || !url_valid
            || self.timeout_ms == 0
            || self.max_response_bytes == 0
        {
            return Err(QidError::Config {
                message: "invalid password screening sources or request bounds".into(),
            });
        }
        Ok(())
    }
}
