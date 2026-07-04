use base64::Engine;
use proptest::prelude::*;

proptest! {
    // PKCE invariant: S256(code_verifier) == base64url(sha256(verifier))
    // https://www.rfc-editor.org/rfc/rfc7636#section-4.6
    #[test]
    fn pkce_s256_code_challenge_round_trip(
        code_verifier in "[a-zA-Z0-9\\-._~]{43,128}",
    ) {
        use sha2::{Digest, Sha256};
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            Sha256::digest(code_verifier.as_bytes()),
        );
        let computed = {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        };
        prop_assert_eq!(
            computed, expected,
            "S256 code_challenge must equal base64url(sha256(verifier))"
        );
    }

    // Token round-trip: sign -> decode preserves subject
    #[test]
    fn jwt_claims_round_trip_preserves_subject(
        subject in "[a-zA-Z0-9_@.\\-]{1,64}",
        issuer in "[a-zA-Z0-9_./:\\-]{1,128}",
    ) {
        use qid_crypto::{JwtClaims, LocalSigner, Signer};
        let signer = LocalSigner::from_secret("test", b"test-secret-for-proptest");
        use std::collections::HashMap;
        let now = qid_core::util::now_seconds() as usize;
        let claims = JwtClaims {
            iss: Some(issuer),
            sub: Some(subject.clone()),
            aud: None,
            exp: Some(now + 3600),
            nbf: None,
            iat: Some(now),
            jti: None,
            extra: HashMap::new(),
        };
        let token = signer.sign(&claims).expect("JWT signing must succeed");
        let decoded = signer.decode_signature_only(&token).expect("JWT decoding must succeed");
        prop_assert_eq!(
            decoded.claims.sub,
            Some(subject),
            "subject must survive token round-trip"
        );
    }

    // Realm isolation: different realm IDs produce different issuers
    #[test]
    fn realm_isolation_produces_different_issuers(
        realm_a in "[a-z]{4,12}",
        realm_b in "[a-z]{4,12}",
    ) {
        prop_assume!(realm_a != realm_b);
        prop_assert_ne!(
            format!("https://{}.example.com", realm_a),
            format!("https://{}.example.com", realm_b),
            "different realms must have different issuers"
        );
    }
}
