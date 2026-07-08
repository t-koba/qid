//! Shared utilities used across qid crates.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;

use crate::error::{QidError, QidResult};

/// Current wall-clock time in seconds since the Unix epoch.
///
/// Returns 0 and logs a warning if the system clock is before the Unix epoch.
pub fn now_seconds() -> u64 {
    match now_seconds_fallible() {
        Ok(secs) => secs,
        Err(e) => {
            tracing::warn!("clock before unix epoch: {e}");
            0
        }
    }
}

/// Fallible variant of [`now_seconds`] that returns a typed error.
pub fn now_seconds_fallible() -> QidResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| QidError::Internal {
            message: format!("system time before unix epoch: {e}"),
        })
}

/// Encode bytes as unpadded base64url.
pub fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 digest of `input`, encoded as unpadded base64url.
pub fn sha256_base64url(input: impl AsRef<[u8]>) -> String {
    let hash = Sha256::digest(input.as_ref());
    base64_url_encode(&hash)
}

/// HMAC-SHA-256 digest of `input`, encoded as unpadded base64url.
#[allow(clippy::expect_used)]
pub fn hmac_sha256_base64url(key: &[u8], input: impl AsRef<[u8]>) -> String {
    // HMAC accepts keys of any length; construction failure would indicate a library invariant change.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input.as_ref());
    let result = mac.finalize().into_bytes();
    base64_url_encode(&result)
}

/// Hash an OAuth client secret for repository storage.
pub fn client_secret_hash(secret: &str) -> String {
    sha256_base64url(format!("qid-client-secret-v1:{secret}"))
}

/// Compute a pairwise subject identifier per OIDC Core §8.1.
#[allow(clippy::expect_used)]
pub fn compute_pairwise_sub(public_sub: &str, sector_identifier: &str, issuer: &str) -> String {
    // HMAC accepts keys of any length; construction failure would indicate a library invariant change.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(issuer.as_bytes()).expect("HMAC accepts any key length");
    mac.update(public_sub.as_bytes());
    mac.update(b"|");
    mac.update(sector_identifier.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&result[..16])
}

/// Resolve the sector identifier for a client per OIDC Core §8.1.
///
/// Priority:
/// 1. Host from `sector_identifier_uri`
/// 2. Host from first `redirect_uri`
/// 3. `client_id`
pub fn sector_identifier_for_client(client: &crate::models::Client) -> String {
    if let Some(uri) = &client.sector_identifier_uri
        && let Ok(parsed) = url::Url::parse(uri)
        && let Some(host) = parsed.host_str()
    {
        return host.to_string();
    }
    if let Some(uri) = client.redirect_uris.first()
        && let Ok(parsed) = url::Url::parse(uri)
        && let Some(host) = parsed.host_str()
    {
        return host.to_string();
    }
    client.client_id.clone()
}

/// Constant-time equality using `subtle::ConstantTimeEq`.
///
/// Accepts any type implementing `AsRef<[u8]>` (e.g. `&str`, `String`, `&[u8]`).
pub fn constant_time_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(left: T, right: U) -> bool {
    left.as_ref().ct_eq(right.as_ref()).into()
}
