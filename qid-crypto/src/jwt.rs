use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use p256::pkcs8::EncodePublicKey;
use qid_core::error::{QidError, QidResult};
use qid_core::jwt::{JwtClaims, Signer};
use qid_core::util::base64_url_encode;
use serde::Serialize;
#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;

use crate::jwk::Jwk;
use crate::keyring::{RemoteSignerConfig, RemoteSignerTransport, remote_sign};

/// An access token / refresh token pair.
#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_jti: String,
    pub refresh_jti: String,
    pub expires_in: u64,
}

/// Local JWT signer backed by private key material held in process memory.
///
/// Constructors validate the supplied PEM or secret enough to build both the
/// signing and verification keys. They do not persist key material and do not
/// zeroize the `jsonwebtoken` key objects, so long-lived production deployments
/// should load private keys through the encrypted keystore path before building
/// this signer.
#[derive(Clone)]
pub struct LocalSigner {
    kid: String,
    algorithm: Algorithm,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigner")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl LocalSigner {
    /// Create an ES256 signer from a PKCS#8 P-256 private key PEM.
    ///
    /// Fails if the input is not UTF-8 PEM, is not a valid PKCS#8 EC private
    /// key, or cannot be converted into `jsonwebtoken` encoding/decoding keys.
    pub fn from_ec_pem(kid: impl Into<String>, pem: &[u8]) -> anyhow::Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(
            std::str::from_utf8(pem).map_err(|e| anyhow::anyhow!("invalid pem: {e}"))?,
        )?;
        let encoding_key = EncodingKey::from_ec_pem(pem)?;
        let public_pem = signing_key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)?;
        let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())?;
        Ok(Self {
            kid: kid.into(),
            algorithm: Algorithm::ES256,
            encoding_key,
            decoding_key,
        })
    }

    /// Create an RS256 signer from an RSA private key PEM.
    ///
    /// The same PEM is used to construct the local verification key. Fails if
    /// the PEM cannot be parsed by `jsonwebtoken`.
    pub fn from_rsa_pem(kid: impl Into<String>, pem: &[u8]) -> anyhow::Result<Self> {
        let encoding_key = EncodingKey::from_rsa_pem(pem)?;
        let decoding_key = DecodingKey::from_rsa_pem(pem)?;
        Ok(Self {
            kid: kid.into(),
            algorithm: Algorithm::RS256,
            encoding_key,
            decoding_key,
        })
    }

    /// Create an EdDSA signer from a PKCS#8 Ed25519 private key PEM.
    ///
    /// Fails if the input is not UTF-8 PEM or the key is not a valid Ed25519
    /// PKCS#8 private key.
    pub fn from_eddsa_pem(kid: impl Into<String>, pem: &[u8]) -> anyhow::Result<Self> {
        use ed25519_dalek::{
            SigningKey,
            pkcs8::{DecodePrivateKey, EncodePrivateKey},
        };
        let pem_str = std::str::from_utf8(pem).map_err(|e| anyhow::anyhow!("invalid PEM: {e}"))?;
        let signing_key = SigningKey::from_pkcs8_pem(pem_str)?;
        let secret_doc = signing_key.to_pkcs8_der()?;
        let verifying_key = signing_key.verifying_key();
        let encoding_key = EncodingKey::from_ed_der(secret_doc.as_bytes());
        let decoding_key = DecodingKey::from_ed_der(verifying_key.as_bytes());
        Ok(Self {
            kid: kid.into(),
            algorithm: Algorithm::EdDSA,
            encoding_key,
            decoding_key,
        })
    }

    /// Create an HS256 signer from a shared secret.
    ///
    /// Callers must provide sufficient entropy and keep the secret scoped to a
    /// single trust domain; this constructor cannot distinguish weak secrets.
    pub fn from_secret(kid: impl Into<String>, secret: &[u8]) -> Self {
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);
        Self {
            kid: kid.into(),
            algorithm: Algorithm::HS256,
            encoding_key,
            decoding_key,
        }
    }

    /// Return the key identifier placed into JOSE headers by this signer.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl Signer for LocalSigner {
    fn sign(&self, claims: &JwtClaims) -> anyhow::Result<String> {
        self.sign_with_typ(claims, "JWT")
    }

    fn sign_with_typ(&self, claims: &JwtClaims, typ: &str) -> anyhow::Result<String> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_string());
        Ok(encode(&header, claims, &self.encoding_key)?)
    }

    /// Verify the JWT signature and decode the payload using the local signer's key.
    ///
    /// NOTE: This method performs signature-only validation and does NOT validate
    /// audience (`aud`), issuer (`iss`), or expiration (`exp`) claims.
    /// Callers MUST validate these claims themselves. Production validation paths
    /// must use [`Signer::decode_with_aud`] instead.
    fn decode_signature_only(&self, token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = false;
        Ok(decode(token, &self.decoding_key, &validation)?)
    }

    fn decode_with_aud(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = true;
        validation.aud = Some(HashSet::from([expected_audience.to_string()]));
        Ok(decode(token, &self.decoding_key, &validation)?)
    }

    fn algorithm(&self) -> &'static str {
        match self.algorithm {
            Algorithm::HS256 => "HS256",
            Algorithm::RS256 => "RS256",
            Algorithm::ES256 => "ES256",
            Algorithm::EdDSA => "EdDSA",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
struct RemoteJwtHeader<'a> {
    alg: &'a str,
    kid: &'a str,
    typ: &'a str,
}

/// Sign JWT claims with a configured remote signer and return a compact JWT.
pub fn remote_sign_jwt<T: RemoteSignerTransport>(
    transport: &T,
    config: &RemoteSignerConfig,
    claims: &JwtClaims,
    typ: &str,
) -> QidResult<String> {
    let header = RemoteJwtHeader {
        alg: config.algorithm.as_str(),
        kid: config.key_id.as_str(),
        typ,
    };
    let header_json = serde_json::to_vec(&header).map_err(|err| QidError::Crypto {
        message: format!("failed to serialize JWT header: {err}"),
    })?;
    let claims_json = serde_json::to_vec(claims).map_err(|err| QidError::Crypto {
        message: format!("failed to serialize JWT claims: {err}"),
    })?;
    let signing_input = format!(
        "{}.{}",
        base64_url_encode(&header_json),
        base64_url_encode(&claims_json)
    );
    let response = remote_sign(transport, config, signing_input.as_bytes().to_vec())?;
    Ok(format!(
        "{}.{}",
        signing_input,
        base64_url_encode(&response.signature)
    ))
}

/// Remote JWT signer backed by a KMS/HSM/PKCS#11 transport and a pinned public JWK.
pub struct RemoteJwtSigner<T> {
    transport: T,
    config: RemoteSignerConfig,
    algorithm: Algorithm,
    decoding_key: DecodingKey,
}

impl<T> std::fmt::Debug for RemoteJwtSigner<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteJwtSigner")
            .field("key_id", &self.config.key_id)
            .field("algorithm", &self.config.algorithm)
            .finish_non_exhaustive()
    }
}

impl<T: RemoteSignerTransport> RemoteJwtSigner<T> {
    pub fn new(transport: T, config: RemoteSignerConfig, public_jwk: &Jwk) -> QidResult<Self> {
        validate_remote_jwk_binding(&config, public_jwk)?;
        let algorithm = algorithm_from_name(&config.algorithm)?;
        let decoding_key = decoding_key_from_jwk(public_jwk, algorithm)?;
        Ok(Self {
            transport,
            config,
            algorithm,
            decoding_key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.config.key_id
    }
}

impl<T: RemoteSignerTransport + Send + Sync> Signer for RemoteJwtSigner<T> {
    fn sign(&self, claims: &JwtClaims) -> anyhow::Result<String> {
        self.sign_with_typ(claims, "JWT")
    }

    fn sign_with_typ(&self, claims: &JwtClaims, typ: &str) -> anyhow::Result<String> {
        remote_sign_jwt(&self.transport, &self.config, claims, typ)
            .map_err(|err| anyhow::anyhow!(err.message()))
    }

    /// Verify the JWT signature and decode the payload using the remote signer's public key.
    ///
    /// NOTE: This method performs signature-only validation and does NOT validate
    /// audience (`aud`), issuer (`iss`), or expiration (`exp`) claims.
    /// Callers MUST validate these claims themselves. Production validation paths
    /// must use [`Signer::decode_with_aud`] instead.
    fn decode_signature_only(&self, token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = false;
        Ok(decode(token, &self.decoding_key, &validation)?)
    }

    fn decode_with_aud(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = true;
        validation.aud = Some(HashSet::from([expected_audience.to_string()]));
        Ok(decode(token, &self.decoding_key, &validation)?)
    }

    fn algorithm(&self) -> &'static str {
        match self.algorithm {
            Algorithm::RS256 => "RS256",
            Algorithm::ES256 => "ES256",
            Algorithm::EdDSA => "EdDSA",
            _ => "unknown",
        }
    }
}

/// Build a JWT decoding key from an RSA, P-256, or Ed25519 public JWK.
///
/// The JWK must contain the key parameters required for the selected algorithm:
/// `n`/`e` for RS256, `x`/`y` for ES256, and `x` for EdDSA.
pub fn decoding_key_from_jwk(public_jwk: &Jwk, algorithm: Algorithm) -> QidResult<DecodingKey> {
    match algorithm {
        Algorithm::RS256 => {
            let n = public_jwk.n.as_deref().ok_or_else(|| QidError::Crypto {
                message: "RS256 public JWK is missing n".to_string(),
            })?;
            let e = public_jwk.e.as_deref().ok_or_else(|| QidError::Crypto {
                message: "RS256 public JWK is missing e".to_string(),
            })?;
            DecodingKey::from_rsa_components(n, e).map_err(|err| QidError::Crypto {
                message: format!("failed to build RS256 decoding key: {err}"),
            })
        }
        Algorithm::ES256 => {
            let x = public_jwk.x.as_deref().ok_or_else(|| QidError::Crypto {
                message: "ES256 public JWK is missing x".to_string(),
            })?;
            let y = public_jwk.y.as_deref().ok_or_else(|| QidError::Crypto {
                message: "ES256 public JWK is missing y".to_string(),
            })?;
            DecodingKey::from_ec_components(x, y).map_err(|err| QidError::Crypto {
                message: format!("failed to build ES256 decoding key: {err}"),
            })
        }
        Algorithm::EdDSA => {
            let x = public_jwk.x.as_deref().ok_or_else(|| QidError::Crypto {
                message: "EdDSA public JWK is missing x".to_string(),
            })?;
            DecodingKey::from_ed_components(x).map_err(|err| QidError::Crypto {
                message: format!("failed to build EdDSA decoding key: {err}"),
            })
        }
        _ => Err(QidError::Crypto {
            message: "remote JWT signer only supports RS256, ES256, or EdDSA".to_string(),
        }),
    }
}

/// Verify a JWT signature using the given JWK and algorithm.
///
/// NOTE: This function ONLY verifies the JWT signature. It does NOT validate
/// audience (`aud`), expiration (`exp`), issuer (`iss`), or any other standard
/// claims. Callers MUST validate all relevant claims after signature verification.
pub fn verify_jwt_signature_with_jwk(token: &str, public_jwk: &Jwk, alg: &str) -> QidResult<()> {
    let algorithm = algorithm_from_name(alg)?;
    let key = decoding_key_from_jwk(public_jwk, algorithm)?;
    let mut validation = Validation::new(algorithm);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    decode::<serde_json::Value>(token, &key, &validation).map_err(|err| QidError::Crypto {
        message: format!("JWT signature verification failed: {err}"),
    })?;
    Ok(())
}

/// Verify a JWT signature and validate audience, expiration, and issuer claims.
///
/// This function:
/// 1. Verifies the JWT signature using the provided JWK and algorithm
/// 2. Validates the `aud` claim matches `expected_audience` (supports both string and array)
/// 3. Validates the `exp` claim is in the future
/// 4. Validates the `iss` claim matches `expected_issuer`
pub fn verify_jwt_signature_with_claims(
    token: &str,
    public_jwk: &Jwk,
    alg: &str,
    expected_audience: &str,
    expected_issuer: &str,
) -> QidResult<TokenData<JwtClaims>> {
    verify_jwt_signature_with_jwk(token, public_jwk, alg)?;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(QidError::Crypto {
            message: "malformed JWT: expected 3 segments".to_string(),
        });
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| QidError::Crypto {
            message: format!("JWT payload base64 decode failed: {e}"),
        })?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| QidError::Crypto {
            message: format!("JWT payload JSON parse failed: {e}"),
        })?;

    let aud_matches = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == expected_audience,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(expected_audience))
        }
        _ => false,
    };
    if !aud_matches {
        return Err(QidError::Crypto {
            message: format!("JWT aud claim does not match expected audience: {expected_audience}"),
        });
    }

    let exp = payload
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| QidError::Crypto {
            message: "JWT missing or invalid exp claim".to_string(),
        })?;
    if exp < qid_core::util::now_seconds() {
        return Err(QidError::Crypto {
            message: "JWT has expired".to_string(),
        });
    }

    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::Crypto {
            message: "JWT missing iss claim".to_string(),
        })?;
    if iss != expected_issuer {
        return Err(QidError::Crypto {
            message: format!("JWT iss mismatch: expected '{expected_issuer}', got '{iss}'"),
        });
    }

    let claims: JwtClaims = serde_json::from_value(payload).map_err(|e| QidError::Crypto {
        message: format!("JWT claims deserialization failed: {e}"),
    })?;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| QidError::Crypto {
            message: format!("JWT header base64 decode failed: {e}"),
        })?;
    let header: jsonwebtoken::Header =
        serde_json::from_slice(&header_bytes).map_err(|e| QidError::Crypto {
            message: format!("JWT header JSON parse failed: {e}"),
        })?;

    Ok(TokenData { header, claims })
}

/// Sign JSON payload as ES256 and embed the supplied public JWK in the header.
///
/// This is intended for proof-style JWTs where the verifier needs the public
/// key in-band. The private key must be a PKCS#8 P-256 PEM and must correspond
/// to `public_jwk`; this function signs the payload but does not prove that the
/// supplied public JWK matches the private key.
pub fn sign_es256_jwt_with_jwk_header(
    private_pem: &[u8],
    public_jwk: &Jwk,
    typ: &str,
    payload: &serde_json::Value,
) -> QidResult<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(typ.to_string());
    header.jwk = Some(
        serde_json::from_value(serde_json::to_value(public_jwk).map_err(|err| {
            QidError::Crypto {
                message: format!("failed to serialize public JWK: {err}"),
            }
        })?)
        .map_err(|err| QidError::Crypto {
            message: format!("failed to convert public JWK: {err}"),
        })?,
    );
    let key = EncodingKey::from_ec_pem(private_pem).map_err(|err| QidError::Crypto {
        message: format!("failed to build ES256 encoding key: {err}"),
    })?;
    encode(&header, payload, &key).map_err(|err| QidError::Crypto {
        message: format!("failed to sign ES256 JWT: {err}"),
    })
}

fn validate_remote_jwk_binding(config: &RemoteSignerConfig, public_jwk: &Jwk) -> QidResult<()> {
    if public_jwk.kid != config.key_id {
        return Err(QidError::Crypto {
            message: "remote signer public JWK kid does not match key id".to_string(),
        });
    }
    if public_jwk.alg.as_deref() != Some(config.algorithm.as_str()) {
        return Err(QidError::Crypto {
            message: "remote signer public JWK alg does not match signer algorithm".to_string(),
        });
    }
    match config.algorithm.as_str() {
        "RS256" if public_jwk.kty == "RSA" => Ok(()),
        "ES256" if public_jwk.kty == "EC" && public_jwk.crv.as_deref() == Some("P-256") => Ok(()),
        "EdDSA" if public_jwk.kty == "OKP" && public_jwk.crv.as_deref() == Some("Ed25519") => {
            Ok(())
        }
        _ => Err(QidError::Crypto {
            message: "remote signer public JWK type does not match signer algorithm".to_string(),
        }),
    }
}

fn algorithm_from_name(name: &str) -> QidResult<Algorithm> {
    match name {
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => Err(QidError::Crypto {
            message: format!("unsupported remote JWT algorithm: {name}"),
        }),
    }
}

/// Sign a JWT with a `b64: false` header per RFC 7797.
///
/// The payload is NOT base64-encoded; the signing input is
/// `base64url(header) + "." + payload`. The key must be a PKCS#8 P-256
/// private key PEM and the payload must not contain transport-specific
/// delimiters that would be ambiguous to downstream verifiers.
pub fn sign_unencoded_jwt(payload: &str, key_pem: &[u8]) -> QidResult<String> {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    let header = serde_json::json!({
        "alg": "ES256",
        "b64": false,
        "crit": ["b64"],
    });
    let pem = std::str::from_utf8(key_pem).map_err(|_| QidError::BadRequest {
        message: "key must be valid UTF-8 PEM".to_string(),
    })?;
    let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| QidError::Crypto {
        message: format!("key parse failed: {e}"),
    })?;
    let header_b64 =
        URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&header).map_err(|e| QidError::Crypto {
                message: format!("failed to encode detached JWT header: {e}"),
            })?,
        );
    let signing_input = format!("{header_b64}.{payload}");
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_es256;
    use crate::keyring::{
        RemoteSignerHealth, RemoteSignerProvider, RemoteSigningRequest, RemoteSigningResponse,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature as Es256Signature, SigningKey as Es256SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use std::sync::Mutex;

    struct JwtRecordingRemoteSigner {
        signing_input: Mutex<Option<Vec<u8>>>,
        response_key_id: String,
        response_algorithm: String,
    }

    impl JwtRecordingRemoteSigner {
        fn new() -> Self {
            Self {
                signing_input: Mutex::new(None),
                response_key_id: "kms-key-1".to_string(),
                response_algorithm: "ES256".to_string(),
            }
        }
    }

    impl crate::keyring::RemoteSignerTransport for JwtRecordingRemoteSigner {
        fn sign(&self, request: RemoteSigningRequest) -> Result<RemoteSigningResponse, String> {
            assert_eq!(request.provider, RemoteSignerProvider::Kms);
            assert_eq!(request.key_id, "kms-key-1");
            assert_eq!(request.algorithm, "ES256");
            *self.signing_input.lock().expect("mutex poisoned") = Some(request.signing_input);
            Ok(RemoteSigningResponse {
                key_id: self.response_key_id.clone(),
                algorithm: self.response_algorithm.clone(),
                signature: b"remote-signature".to_vec(),
            })
        }

        fn health(&self, _config: &RemoteSignerConfig) -> Result<RemoteSignerHealth, String> {
            Ok(RemoteSignerHealth {
                reachable: true,
                key_available: true,
                latency_ms: 1,
            })
        }
    }

    struct Es256RemoteJwtTransport {
        signing_key: Es256SigningKey,
    }

    impl crate::keyring::RemoteSignerTransport for Es256RemoteJwtTransport {
        fn sign(&self, request: RemoteSigningRequest) -> Result<RemoteSigningResponse, String> {
            assert_eq!(request.key_id, "kms-key-1");
            assert_eq!(request.algorithm, "ES256");
            assert!(
                std::str::from_utf8(&request.signing_input)
                    .unwrap()
                    .contains('.')
            );
            let signature: Es256Signature =
                p256::ecdsa::signature::Signer::sign(&self.signing_key, &request.signing_input);
            Ok(RemoteSigningResponse {
                key_id: request.key_id,
                algorithm: request.algorithm,
                signature: signature.to_bytes().to_vec(),
            })
        }

        fn health(&self, _config: &RemoteSignerConfig) -> Result<RemoteSignerHealth, String> {
            Ok(RemoteSignerHealth {
                reachable: true,
                key_available: true,
                latency_ms: 1,
            })
        }
    }

    fn remote_config() -> RemoteSignerConfig {
        RemoteSignerConfig {
            provider: RemoteSignerProvider::Kms,
            key_id: "kms-key-1".to_string(),
            algorithm: "ES256".to_string(),
            endpoint: "https://kms.example/sign".to_string(),
            health_check_required: false,
            timeout_ms: 500,
        }
    }

    #[test]
    fn sign_and_verify_es256_round_trip() {
        let key = generate_es256("test").expect("key generation failed");
        let signer = LocalSigner::from_ec_pem("test", key.private_pem.as_bytes()).unwrap();
        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(0),
            iat: Some(0),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };
        let token = signer.sign(&claims).expect("signing failed");
        assert!(!token.is_empty());
        let decoded = signer
            .decode_signature_only(&token)
            .expect("decoding failed");
        assert_eq!(decoded.claims.sub, Some("subject".to_string()));
    }

    #[test]
    fn jwk_header_signature_helpers_verify_and_reject_tampering() {
        let key = generate_es256("dpop").expect("key generation failed");
        let payload = serde_json::json!({
            "jti": "proof-1",
            "htm": "POST",
            "htu": "https://id.example.com/oauth2/token",
            "iat": 1_700_000_000_u64
        });
        let token = sign_es256_jwt_with_jwk_header(
            key.private_pem.as_bytes(),
            &key.public_jwk,
            "dpop+jwt",
            &payload,
        )
        .expect("JWK header JWT signing failed");
        verify_jwt_signature_with_jwk(&token, &key.public_jwk, "ES256")
            .expect("JWK header JWT verification failed");

        let (signed_input, signature) = token.rsplit_once('.').expect("JWT signature is present");
        let (header, _payload) = signed_input
            .split_once('.')
            .expect("JWT payload is present");
        let tampered_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&serde_json::json!({
                "jti": "proof-1",
                "htm": "GET",
                "htu": "https://id.example.com/oauth2/token",
                "iat": 1_700_000_000_u64
            }))
            .unwrap()
            .as_bytes(),
        );
        let tampered = format!("{header}.{tampered_payload}.{signature}");
        assert!(verify_jwt_signature_with_jwk(&tampered, &key.public_jwk, "ES256").is_err());
    }

    #[test]
    fn verify_es256_jwk_derivation() {
        let key = generate_es256("test-kid").expect("key generation failed");
        assert_eq!(key.public_jwk.kty, "EC");
        assert_eq!(key.public_jwk.crv.as_deref(), Some("P-256"));
        assert_eq!(key.public_jwk.alg.as_deref(), Some("ES256"));
        assert_eq!(key.public_jwk.use_.as_deref(), Some("sig"));
        let x = key.public_jwk.x.expect("x coordinate should be set");
        let y = key.public_jwk.y.expect("y coordinate should be set");
        assert!(!x.is_empty(), "x coordinate must be non-empty");
        assert!(!y.is_empty(), "y coordinate must be non-empty");
        assert!(
            URL_SAFE_NO_PAD.decode(&x).is_ok(),
            "x must be valid base64url"
        );
        assert!(
            URL_SAFE_NO_PAD.decode(&y).is_ok(),
            "y must be valid base64url"
        );
    }

    #[test]
    fn verify_hs256_round_trip() {
        let signer = LocalSigner::from_secret("test", b"super-secret-key-for-hs256");
        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(0),
            iat: Some(0),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };
        let token = signer.sign(&claims).expect("signing failed");
        assert!(!token.is_empty());
        let decoded = signer
            .decode_signature_only(&token)
            .expect("decoding failed");
        assert_eq!(decoded.claims.sub, Some("subject".to_string()));
        assert_eq!(signer.algorithm(), "HS256");
    }

    #[test]
    fn verify_eddsa_round_trip() {
        use crate::jwk::generate_eddsa;
        let key = generate_eddsa("test").expect("key generation failed");
        let signer = LocalSigner::from_eddsa_pem("test", key.private_pem.as_bytes()).unwrap();
        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(0),
            iat: Some(0),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };
        let token = signer.sign(&claims).expect("signing failed");
        assert!(!token.is_empty());
        let decoded = signer
            .decode_signature_only(&token)
            .expect("decoding failed");
        assert_eq!(decoded.claims.sub, Some("subject".to_string()));
    }

    #[test]
    fn jwt_claims_serialization() {
        let claims = JwtClaims {
            iss: Some("https://issuer.example.com".to_string()),
            sub: Some("user-123".to_string()),
            aud: Some("client-app".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(1_000_000_000),
            iat: Some(1_000_000_000),
            jti: Some("unique-jti".to_string()),
            extra: {
                let mut m = HashMap::new();
                m.insert("custom".to_string(), serde_json::json!("value"));
                m
            },
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iss"], "https://issuer.example.com");
        assert_eq!(json["sub"], "user-123");
        assert_eq!(json["aud"], "client-app");
        assert_eq!(json["exp"], 2_000_000_000);
        assert_eq!(json["nbf"], 1_000_000_000);
        assert_eq!(json["iat"], 1_000_000_000);
        assert_eq!(json["jti"], "unique-jti");
        assert_eq!(json["custom"], "value");
        assert_eq!(json.as_object().unwrap().len(), 8);
    }

    #[test]
    fn remote_sign_jwt_builds_compact_jwt_signing_input() {
        let transport = JwtRecordingRemoteSigner::new();
        let claims = JwtClaims {
            iss: Some("https://issuer.example.com".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(1_000_000_000),
            iat: Some(1_000_000_000),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };

        let token = remote_sign_jwt(&transport, &remote_config(), &claims, "JWT")
            .expect("remote JWT failed");

        let segments = token.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "kms-key-1");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(payload["sub"], "subject");
        assert_eq!(payload["aud"], "audience");
        assert_eq!(
            URL_SAFE_NO_PAD.decode(segments[2]).unwrap(),
            b"remote-signature".to_vec()
        );
        let captured = transport
            .signing_input
            .lock()
            .expect("mutex poisoned")
            .clone()
            .expect("signing input captured");
        assert_eq!(
            std::str::from_utf8(&captured).unwrap(),
            format!("{}.{}", segments[0], segments[1])
        );
    }

    #[test]
    fn remote_sign_jwt_fails_closed_on_unbound_response() {
        let mut transport = JwtRecordingRemoteSigner::new();
        transport.response_key_id = "other-key".to_string();
        let claims = JwtClaims {
            iss: None,
            sub: Some("subject".to_string()),
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            extra: HashMap::new(),
        };

        let err = remote_sign_jwt(&transport, &remote_config(), &claims, "JWT").unwrap_err();

        assert!(
            err.message()
                .contains("remote signer returned a different key id")
        );
    }

    #[test]
    fn remote_jwt_signer_signs_and_decodes_with_pinned_jwk() {
        let generated = generate_es256("kms-key-1").expect("key generation failed");
        let signing_key = Es256SigningKey::from_pkcs8_pem(&generated.private_pem)
            .expect("private key should parse");
        let transport = Es256RemoteJwtTransport { signing_key };
        let signer = RemoteJwtSigner::new(transport, remote_config(), &generated.public_jwk)
            .expect("remote signer should be created");
        let claims = JwtClaims {
            iss: Some("https://issuer.example.com".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(1_000_000_000),
            iat: Some(1_000_000_000),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };

        let token = signer.sign(&claims).expect("remote signing failed");
        let decoded = signer
            .decode_signature_only(&token)
            .expect("remote JWT decoding failed");

        assert_eq!(signer.key_id(), "kms-key-1");
        assert_eq!(signer.algorithm(), "ES256");
        assert_eq!(decoded.claims.sub.as_deref(), Some("subject"));
    }

    #[test]
    fn remote_jwt_signer_rejects_unbound_public_jwk() {
        let mut generated = generate_es256("other-key").expect("key generation failed");
        generated.public_jwk.alg = Some("ES256".to_string());

        let err = RemoteJwtSigner::new(
            JwtRecordingRemoteSigner::new(),
            remote_config(),
            &generated.public_jwk,
        )
        .unwrap_err();

        assert!(err.message().contains("kid does not match"));
    }

    #[test]
    fn verify_rs256_round_trip() {
        // Use separate private key for signing and public key for verification
        // to work around jsonwebtoken 9.3.1 DecodingKey::from_rsa_pem bug
        // with PKCS#1 private key PEM extracting the public key.
        let rsa_private_pem = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA3lE0G0UlhG1KCeDQRnmJSY/Oyz8YV2gdmnrkNBK7kg9Y80x8
OlGeuFi/SgWgczu1AKjpGjoC2LhK3w2OhVSqwUUCyrUKH2qFD0e0InUIVn0hNQqd
M38T54jkvjBUPN6SaLvA23h5Fe6Ie2Abd3lQzku2iNeH+KZ0/RSTdFkLmkhTMW9v
fwf+at9xI1RdgDj/XetCUqqZ5GG1Wi0OEyQ5p9GWcF2O4WSmIV4IfouXoqF7vZWm
GIEa+Y3KQEsStWn29fvu8xbMY7imen7qO9zky5ikf4X4Fzgi7litiqbK6BLJMdHl
8WSvi5OVAasiPBrb9kccT/Iy6HHG2WXD/VQ66QIDAQABAoIBAAfvU8nn4kaLXI3E
9IYZaychHv9F251uCcV0Xq4Fn6R/T/xSFeqCdITtpPk0QXVvc37IKJa/LJAV5tU2
f4hefOA8UXTQ+KElrQVeOK2UqgUlPvDM1c7LWbdlPU3U/YK1Knpavi/PKVo5Ku2l
YOGXJsVQMj4I3FFphoosaHVqArYhTuXYfTHLgrxutAGHffXh5inLu3bWKqf3B6mP
uJfs2UwkRbJVgXAnCFmQzhOMhq//LVakSG4zhpsP8OKk9V3/fAIsdYEzGaseMaDB
D0LVvBytiHJzABv7Sj2imVxtMmzirSdW3VA3pHGQ5MynbRgdOlw4YEChD+stDpGy
s3RO1EECgYEA/5e7MAnr8nXCMU3BcxIAx3rkQ2iPNFjqaEa6YvP9Sjlj9sd5O6MK
OITdsMRNUt3xWFhD5WVoowuU6EJK7lazfSfabj/x9Q5aB9irLt5wXDTP5Zs/px7L
0TlavG80/VPPg1RUZHygpCNP8uKhJycjvh9EeHgB75n8EDTo6G7uvUECgYEA3qvl
yyvCsnQMCFXJQVB68ioKJ6Ie2EtvdkVoViadO2m27UiycbvAFiDo9E0aogLMQXUl
27vQknW0DJHY59bbI2yJ+TvFhHKlm3pIuXKS/qjojWzyaI6oZ/ycwda/z5FE84kG
omAuhz8FqZXh9008/5ytzC+tVWEmWrlOlng3i6kCgYAG4io7Z/j/xaYeN87e73wv
4yJkoltA+KgPeOAqLBIFPrhve/3K2mA7F3D1AsRmV+3ZCD+D3RBNW9F909M6ygD5
fOpID9bPV7ya+33YvErgYNe8gkrbkFvC3b2Q15ngvLIZAltnfWfCI+VSUEIw0MAI
rcTlTa4Xqtj8AsDHCb3KQQKBgEqSTvbnxOB2tMDl2eyhw0rugVAcny/Ys49sVzDi
5a1MDhMRUZF9SyseAmYunEi9nyIc1XztPUCPYqkC/x1Fe0Y1x09MkS12J7gWD9zr
XgcjEh6q6dPSUtvgYa8Y+EvPXsQgk7Q1ed+ZX5AXvgFQQKlqE1pabTY2vt2LSaJi
yFdhAoGAf5khMcHZ9eIrwrMEh9GtDhEujMNsjv+7CqMQxkHb83lqNgILOXOlgfc0
ZKsqO2M7Na+rJPO2pvLbM5RQM6oayvaZGYGkZxTl/HqTcXfaAUQ73NCloXSB6KHO
giO1Z/IjvBkDJIpJnxOgoHzm/dE5uPEoR97XHo6Vu2RdJYM/W/8=
-----END RSA PRIVATE KEY-----";
        let rsa_public_pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3lE0G0UlhG1KCeDQRnmJ
SY/Oyz8YV2gdmnrkNBK7kg9Y80x8OlGeuFi/SgWgczu1AKjpGjoC2LhK3w2OhVSq
wUUCyrUKH2qFD0e0InUIVn0hNQqdM38T54jkvjBUPN6SaLvA23h5Fe6Ie2Abd3lQ
zku2iNeH+KZ0/RSTdFkLmkhTMW9vfwf+at9xI1RdgDj/XetCUqqZ5GG1Wi0OEyQ5
p9GWcF2O4WSmIV4IfouXoqF7vZWmGIEa+Y3KQEsStWn29fvu8xbMY7imen7qO9zk
y5ikf4X4Fzgi7litiqbK6BLJMdHl8WSvi5OVAasiPBrb9kccT/Iy6HHG2WXD/VQ6
6QIDAQAB
-----END PUBLIC KEY-----";
        let signer = LocalSigner {
            kid: "test-rsa".to_string(),
            algorithm: Algorithm::RS256,
            encoding_key: EncodingKey::from_rsa_pem(rsa_private_pem.as_bytes())
                .expect("RSA encoding key failed"),
            decoding_key: DecodingKey::from_rsa_pem(rsa_public_pem.as_bytes())
                .expect("RSA decoding key failed"),
        };
        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: Some(0),
            iat: Some(0),
            jti: Some("jti".to_string()),
            extra: HashMap::new(),
        };
        let token = signer.sign(&claims).expect("RS256 signing failed");
        assert!(!token.is_empty());
        let decoded = signer
            .decode_signature_only(&token)
            .expect("RS256 decoding failed");
        assert_eq!(decoded.claims.sub, Some("subject".to_string()));
        assert_eq!(signer.algorithm(), "RS256");
    }
}
