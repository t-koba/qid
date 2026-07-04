#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let parts: Vec<&str> = input.splitn(3, '\n').collect();
        if parts.len() == 3 {
            let token = parts[0];
            let alg = parts[1];
            let jwk_json = parts[2];
                if let Ok(jwk) = serde_json::from_str::<qid_crypto::Jwk>(jwk_json) {
                let _ = qid_crypto::jwt::verify_jwt_signature_with_jwk(token, &jwk, alg);
            }
        }
    }
});
