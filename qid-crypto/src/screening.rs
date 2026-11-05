use std::{collections::HashSet, time::Duration};

use qid_core::{
    config::{PasswordScreeningConfig, ScreeningUnavailable},
    error::{QidError, QidResult},
};
use sha2::{Digest, Sha256};

/// Immutable realm-local source snapshot and client; no background work or login use.
pub(crate) struct PasswordScreening {
    local: HashSet<String>,
    range: Option<(reqwest::Client, reqwest::Url)>,
    on_unavailable: ScreeningUnavailable,
    max_response_bytes: usize,
    max_retries: u64,
    retry_delay: Duration,
}

enum QueryFailure {
    Transient,
    Permanent,
}

fn transport_failure(error: reqwest::Error) -> QueryFailure {
    if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
        QueryFailure::Transient
    } else {
        QueryFailure::Permanent
    }
}

fn unavailable() -> QidError {
    QidError::Storage {
        message: "password screening unavailable".into(),
    }
}
fn not_allowed() -> QidError {
    QidError::BadRequest {
        message: "password_not_allowed".into(),
    }
}

impl PasswordScreening {
    pub(crate) fn new(config: &PasswordScreeningConfig) -> QidResult<Self> {
        config.validate()?;
        let range = config
            .range_url
            .as_ref()
            .map(|value| {
                let url = reqwest::Url::parse(value).map_err(|_| unavailable())?;
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .timeout(Duration::from_millis(config.timeout_ms))
                    .build()
                    .map_err(|_| unavailable())?;
                Ok::<_, QidError>((client, url))
            })
            .transpose()?;
        Ok(Self {
            local: config
                .sha256_hex
                .iter()
                .map(|value| value.to_ascii_uppercase())
                .collect(),
            range,
            on_unavailable: config.on_unavailable,
            max_response_bytes: config.max_response_bytes,
            max_retries: config.max_retries,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    pub(crate) async fn check(&self, plaintext: &str) -> QidResult<()> {
        if self
            .local
            .contains(&hex::encode_upper(Sha256::digest(plaintext.as_bytes())))
        {
            return Err(not_allowed());
        }
        if let Some((client, base)) = &self.range {
            match self.query(client, base, plaintext).await {
                Ok(true) => return Err(not_allowed()),
                Err(()) if self.on_unavailable == ScreeningUnavailable::Deny => {
                    return Err(unavailable());
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn query(
        &self,
        client: &reqwest::Client,
        base: &reqwest::Url,
        plaintext: &str,
    ) -> Result<bool, ()> {
        let digest = hex::encode_upper(sha1::Sha1::digest(plaintext.as_bytes()));
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|_| ())?
            .pop_if_empty()
            .push(&digest[..5]);
        let mut remaining = self.max_retries;
        loop {
            match self.attempt(client, &url, &digest[5..]).await {
                Err(QueryFailure::Transient) if remaining > 0 => {
                    remaining -= 1;
                    tokio::time::sleep(self.retry_delay).await;
                }
                result => return result.map_err(|_| ()),
            }
        }
    }

    async fn attempt(
        &self,
        client: &reqwest::Client,
        url: &reqwest::Url,
        suffix: &str,
    ) -> Result<bool, QueryFailure> {
        let mut response = client
            .get(url.clone())
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(transport_failure)?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(QueryFailure::Transient);
        }
        if !status.is_success() {
            return Err(QueryFailure::Permanent);
        }
        let mut body = Vec::new();
        // chunk() wraps interrupted body reads as decode errors; parse payloads only below.
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| QueryFailure::Transient)?
        {
            if chunk.len() > self.max_response_bytes.saturating_sub(body.len()) {
                return Err(QueryFailure::Permanent);
            }
            body.extend_from_slice(&chunk);
        }
        parse_range(&body, suffix).map_err(|_| QueryFailure::Permanent)
    }
}

fn parse_range(body: &[u8], suffix: &str) -> Result<bool, ()> {
    let mut valid = !body.is_empty();
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        let line = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(line);
        let entry = line.iter().position(|byte| *byte == b':').and_then(|at| {
            let (hash, count) = (&line[..at], &line[at + 1..]);
            if hash.len() != 35 || !hash.iter().all(u8::is_ascii_hexdigit) || count.is_empty() {
                return None;
            }
            let count = count.iter().try_fold(0u64, |count, byte| {
                byte.is_ascii_digit()
                    .then(|| count.checked_mul(10)?.checked_add(u64::from(byte - b'0')))
                    .flatten()
            })?;
            Some(count > 0 && hash.eq_ignore_ascii_case(suffix.as_bytes()))
        });
        if entry == Some(true) {
            return Ok(true);
        }
        valid &= entry.is_some();
    }
    if valid { Ok(false) } else { Err(()) }
}

#[cfg(test)]
#[path = "screening_tests.rs"]
mod tests;
