//! PKCE helpers.

use sha2::{Digest, Sha256};

/// Verify a PKCE code verifier against the stored code challenge.
pub fn verify_code_verifier(
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    verifier: &str,
) -> bool {
    let Some(challenge) = code_challenge else {
        return true; // PKCE not used
    };

    let method = code_challenge_method.unwrap_or("plain");
    if method != "S256" {
        return false; // reject plain and unknown methods
    }
    let hash = Sha256::digest(verifier.as_bytes());
    let computed = crate::util::base64_url_encode(&hash);

    computed == challenge
}
