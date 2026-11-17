//! PKCE helpers.

use sha2::{Digest, Sha256};

/// RFC 7636 section 4.1: `43*128unreserved`, where unreserved is ALPHA /
/// DIGIT / "-" / "." / "_" / "~".
fn is_unreserved_43_128(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// Whether a verifier satisfies the RFC 7636 ABNF.
pub fn valid_code_verifier(verifier: &str) -> bool {
    is_unreserved_43_128(verifier)
}

/// Whether an S256 challenge satisfies the RFC 7636 ABNF. Other methods are
/// left to the caller's policy; qid accepts S256 only where PKCE is used.
pub fn valid_code_challenge(method: Option<&str>, challenge: &str) -> bool {
    match method {
        Some("S256") => is_unreserved_43_128(challenge),
        _ => true,
    }
}

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
    if method != "S256"
        || !valid_code_verifier(verifier)
        || !valid_code_challenge(Some(method), challenge)
    {
        return false; // reject plain, unknown methods, and RFC-invalid material
    }
    let hash = Sha256::digest(verifier.as_bytes());
    let computed = crate::util::base64_url_encode(&hash);

    computed == challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[test]
    fn accepts_rfc_conforming_verifiers_and_challenges() {
        assert!(valid_code_verifier(VERIFIER));
        assert!(valid_code_verifier(&"a".repeat(128)));
        let challenge = crate::util::base64_url_encode(&Sha256::digest(VERIFIER.as_bytes()));
        assert!(valid_code_challenge(Some("S256"), &challenge));
        assert!(verify_code_verifier(
            Some(&challenge),
            Some("S256"),
            VERIFIER
        ));
    }

    #[test]
    fn rejects_verifiers_outside_the_rfc_abnf() {
        for verifier in [
            "short",
            &"a".repeat(42),
            &"a".repeat(129),
            &format!("{}!", "a".repeat(42)),
            "a/b+c=d",
        ] {
            assert!(!valid_code_verifier(verifier), "accepted {verifier}");
        }
        let challenge = crate::util::base64_url_encode(&Sha256::digest(b"anything"));
        assert!(!verify_code_verifier(
            Some(&challenge),
            Some("S256"),
            "short"
        ));
    }

    #[test]
    fn rejects_challenges_outside_the_rfc_abnf() {
        assert!(!valid_code_challenge(Some("S256"), "short"));
        assert!(!valid_code_challenge(Some("S256"), &"a".repeat(129)));
        assert!(!valid_code_challenge(Some("S256"), "a+b/c=d"));
        assert!(!verify_code_verifier(Some("short"), Some("S256"), VERIFIER));
    }

    #[test]
    fn absent_challenge_still_means_pkce_not_used() {
        assert!(verify_code_verifier(None, None, "short"));
    }

    #[test]
    fn plain_and_unknown_methods_remain_refused() {
        let challenge = crate::util::base64_url_encode(&Sha256::digest(VERIFIER.as_bytes()));
        assert!(!verify_code_verifier(
            Some(&challenge),
            Some("plain"),
            VERIFIER
        ));
        assert!(!verify_code_verifier(
            Some(&challenge),
            Some("S256+"),
            VERIFIER
        ));
    }
}
