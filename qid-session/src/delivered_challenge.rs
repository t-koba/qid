//! Shared delivered-secret proof format and response protections.
use axum::{
    http::{HeaderValue, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::models::CiamVerificationChallengeRecord;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub(crate) fn random_secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn well_formed(value: &str) -> bool {
    value.len() == 43 && URL_SAFE_NO_PAD.decode(value).is_ok_and(|v| v.len() == 32)
}

// Versioned, separately domain-separated proofs; every component is length-prefixed.
// Storage checks the browser proof before spending any token attempt.
pub(crate) fn challenge_hash(
    c: &CiamVerificationChallengeRecord,
    token: &str,
    binding: &str,
) -> String {
    let sms = c.purpose == "sms_recovery";
    let digest = |domain: &str, secret: &str| {
        let mut hash = Sha256::new();
        for part in [
            domain,
            &c.id,
            &c.realm_id,
            &c.user_id,
            &c.address,
            &c.channel,
            &c.purpose,
            secret,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        if sms && domain.ends_with(":token") {
            hash.update((binding.len() as u64).to_be_bytes());
            hash.update(binding.as_bytes());
        }
        qid_core::util::hex_encode_lower(&hash.finalize())
    };
    format!(
        "{}:{}:{}",
        if sms { "sr1" } else { "ml2" },
        digest(
            if sms {
                "qid:sms-recovery:v1:binding"
            } else {
                "qid:email-magic-link:v2:binding"
            },
            binding
        ),
        digest(
            if sms {
                "qid:sms-recovery:v1:token"
            } else {
                "qid:email-magic-link:v2:token"
            },
            token
        )
    )
}

pub(crate) fn protected(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
