use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value as CborValue;
use qid_core::{
    error::{QidError, QidResult},
    models::WebAuthnCredential,
};
use serde::Deserialize;
use sha2::Digest;
use url::Url;
use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, COSE_EDDSA, COSE_ES256,
    COSE_ES384, COSE_RS256, Challenge, Credential, RelyingParty,
};

#[derive(Debug, Default)]
pub struct WebAuthnState {
    reg: Mutex<HashMap<String, Challenge>>,
    auth: Mutex<HashMap<String, Challenge>>,
    disc_auth: Mutex<HashMap<String, Challenge>>,
}

impl WebAuthnState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn insert_reg(&self, state_key: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.insert(state_key.to_string(), state);
        Ok(())
    }

    fn remove_reg(&self, state_key: &str) -> QidResult<Challenge> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.remove(state_key).ok_or_else(|| QidError::BadRequest {
            message: "no registration in progress".to_string(),
        })
    }

    fn insert_auth(&self, state_key: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.insert(state_key.to_string(), state);
        Ok(())
    }

    fn remove_auth(&self, state_key: &str) -> QidResult<Challenge> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.remove(state_key).ok_or_else(|| QidError::BadRequest {
            message: "no authentication in progress".to_string(),
        })
    }

    fn insert_disc_auth(&self, ceremony_key: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.insert(ceremony_key.to_string(), state);
        Ok(())
    }

    fn remove_disc_auth(&self, ceremony_key: &str) -> QidResult<Challenge> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.remove(ceremony_key)
            .ok_or_else(|| QidError::BadRequest {
                message: "no discoverable authentication in progress".to_string(),
            })
    }
}

pub(crate) fn webauthn_state_key(realm_id: &str, user_id: &str) -> String {
    format!("{realm_id}:{user_id}")
}

pub struct WebAuthnService {
    rp: RelyingParty,
    rp_id: String,
    rp_name: String,
}

pub struct WebAuthnAuthOutcome {
    pub credential_id: Vec<u8>,
    pub counter: u64,
}

#[derive(Debug, Deserialize)]
struct CredentialResponse<T> {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: Option<String>,
    response: T,
}

#[derive(Debug, Deserialize)]
struct RegistrationResponseFields {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

#[derive(Debug, Deserialize)]
struct AuthenticationResponseFields {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

struct ParsedRegistrationCredential {
    credential_id: Vec<u8>,
    response: AuthenticatorAttestationResponse,
}

struct ParsedAuthenticationCredential {
    credential_id: Vec<u8>,
    response: AuthenticatorAssertionResponse,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> QidResult<Self> {
        Url::parse(rp_origin).map_err(|e| QidError::BadRequest {
            message: format!("invalid rp_origin: {e}"),
        })?;
        Ok(Self {
            rp: RelyingParty::new(rp_id, rp_origin, rp_name)
                .allowed_algorithms([COSE_ES256, COSE_ES384, COSE_EDDSA, COSE_RS256]),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
        })
    }

    pub fn start_registration(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        user_unique_id: &str,
        user_name: &str,
        user_display_name: &str,
    ) -> QidResult<serde_json::Value> {
        let challenge = new_challenge()?;
        let challenge_value = challenge_json(&challenge);
        let user_handle = stable_user_handle(user_unique_id);
        webauthn_state.insert_reg(state_key, challenge)?;
        Ok(serde_json::json!({
            "rp": {
                "id": self.rp_id,
                "name": self.rp_name,
            },
            "user": {
                "id": encode_bytes(&user_handle),
                "name": user_name,
                "displayName": user_display_name,
            },
            "challenge": challenge_value,
            "pubKeyCredParams": [
                { "type": "public-key", "alg": COSE_ES256 },
                { "type": "public-key", "alg": COSE_ES384 },
                { "type": "public-key", "alg": COSE_EDDSA },
                { "type": "public-key", "alg": COSE_RS256 },
            ],
            "timeout": 300000u64,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "preferred",
                "requireResidentKey": false,
                "userVerification": "preferred",
            },
        }))
    }

    pub fn finish_registration(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        user_id: &str,
        response: serde_json::Value,
    ) -> QidResult<WebAuthnCredential> {
        let parsed = parse_registration_response(response)?;
        let challenge = webauthn_state.remove_reg(state_key)?;
        let aaguid = registration_aaguid(&parsed.response.attestation_object)?;
        let result = self
            .rp
            .verify_registration(&challenge, &parsed.response, &stable_user_handle(user_id))
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish registration: {e}"),
            })?;
        if result.credential.id != parsed.credential_id {
            return Err(QidError::Crypto {
                message: "webauthn registration credential id mismatch".to_string(),
            });
        }
        let pk_json = serde_json::to_vec(&result.credential).map_err(|e| QidError::Internal {
            message: format!("serialize webauthn credential: {e}"),
        })?;
        Ok(WebAuthnCredential {
            id: qid_core::util::base64_url_encode(&result.credential.id),
            user_id: user_id.to_string(),
            credential_id: result.credential.id,
            public_key: pk_json,
            counter: u64::from(result.credential.sign_count),
            aaguid,
            device_name: None,
            created_at: qid_core::util::now_seconds(),
        })
    }

    pub fn start_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        _user_unique_id: &str,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<serde_json::Value> {
        if credentials.is_empty() {
            return Err(QidError::NotFound {
                resource: "webauthn credentials".to_string(),
            });
        }
        let challenge = new_challenge()?;
        let options = authentication_options(&self.rp_id, &challenge, credentials);
        webauthn_state.insert_auth(state_key, challenge)?;
        Ok(options)
    }

    pub fn finish_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let parsed = parse_authentication_response(response)?;
        let challenge = webauthn_state.remove_auth(state_key)?;
        let stored = matching_credential(credentials, &parsed.credential_id)?;
        let outcome = self
            .rp
            .verify_authentication(&stored, &challenge, &parsed.response)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish authentication: {e}"),
            })?;
        Ok(WebAuthnAuthOutcome {
            credential_id: outcome.credential_id,
            counter: u64::from(outcome.new_sign_count),
        })
    }

    pub fn start_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
    ) -> QidResult<serde_json::Value> {
        let challenge = new_challenge()?;
        let options = discoverable_authentication_options(&self.rp_id, &challenge);
        webauthn_state.insert_disc_auth(ceremony_key, challenge)?;
        Ok(options)
    }

    pub fn identify_discoverable_authentication(
        &self,
        response: &serde_json::Value,
    ) -> QidResult<(uuid::Uuid, Vec<u8>)> {
        let parsed = parse_authentication_response(response.clone())?;
        let user_handle =
            parsed
                .response
                .user_handle
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "discoverable WebAuthn response is missing userHandle".to_string(),
                })?;
        let user_uuid = uuid::Uuid::from_slice(user_handle).map_err(|e| QidError::BadRequest {
            message: format!("invalid discoverable WebAuthn userHandle: {e}"),
        })?;
        Ok((user_uuid, parsed.credential_id))
    }

    pub fn finish_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let parsed = parse_authentication_response(response)?;
        let challenge = webauthn_state.remove_disc_auth(ceremony_key)?;
        let stored = matching_credential(credentials, &parsed.credential_id)?;
        let outcome = self
            .rp
            .verify_authentication(&stored, &challenge, &parsed.response)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish discoverable auth: {e}"),
            })?;
        Ok(WebAuthnAuthOutcome {
            credential_id: outcome.credential_id,
            counter: u64::from(outcome.new_sign_count),
        })
    }
}

fn new_challenge() -> QidResult<Challenge> {
    Challenge::new().map_err(|e| QidError::Crypto {
        message: format!("webauthn challenge generation failed: {e}"),
    })
}

fn stable_user_handle(user_unique_id: &str) -> Vec<u8> {
    sha2::Sha256::digest(user_unique_id.as_bytes())[..16].to_vec()
}

fn authentication_options(
    rp_id: &str,
    challenge: &Challenge,
    credentials: &[WebAuthnCredential],
) -> serde_json::Value {
    let allow_credentials: Vec<_> = credentials
        .iter()
        .map(|credential| credential_descriptor(&credential.credential_id))
        .collect();
    serde_json::json!({
        "challenge": challenge_json(challenge),
        "rpId": rp_id,
        "allowCredentials": allow_credentials,
        "timeout": 300000u64,
        "userVerification": "preferred",
    })
}

fn discoverable_authentication_options(rp_id: &str, challenge: &Challenge) -> serde_json::Value {
    serde_json::json!({
        "challenge": challenge_json(challenge),
        "rpId": rp_id,
        "timeout": 300000u64,
        "userVerification": "preferred",
    })
}

fn credential_descriptor(credential_id: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "type": "public-key",
        "id": encode_bytes(credential_id),
    })
}

fn challenge_json(challenge: &Challenge) -> String {
    encode_bytes(&challenge.bytes)
}

fn parse_registration_response(
    value: serde_json::Value,
) -> QidResult<ParsedRegistrationCredential> {
    let credential: CredentialResponse<RegistrationResponseFields> = serde_json::from_value(value)
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid registration response: {e}"),
        })?;
    let credential_id =
        decode_preferred_credential_id(&credential.id, credential.raw_id.as_deref())?;
    Ok(ParsedRegistrationCredential {
        credential_id,
        response: AuthenticatorAttestationResponse {
            client_data_json: decode_credential_bytes(&credential.response.client_data_json)?,
            attestation_object: decode_credential_bytes(&credential.response.attestation_object)?,
        },
    })
}

fn parse_authentication_response(
    value: serde_json::Value,
) -> QidResult<ParsedAuthenticationCredential> {
    let credential: CredentialResponse<AuthenticationResponseFields> =
        serde_json::from_value(value).map_err(|e| QidError::BadRequest {
            message: format!("invalid authentication response: {e}"),
        })?;
    let credential_id =
        decode_preferred_credential_id(&credential.id, credential.raw_id.as_deref())?;
    Ok(ParsedAuthenticationCredential {
        credential_id,
        response: AuthenticatorAssertionResponse {
            client_data_json: decode_credential_bytes(&credential.response.client_data_json)?,
            authenticator_data: decode_credential_bytes(&credential.response.authenticator_data)?,
            signature: decode_credential_bytes(&credential.response.signature)?,
            user_handle: credential
                .response
                .user_handle
                .as_deref()
                .map(decode_credential_bytes)
                .transpose()?,
        },
    })
}

fn decode_preferred_credential_id(id: &str, raw_id: Option<&str>) -> QidResult<Vec<u8>> {
    match raw_id {
        Some(raw_id) => decode_credential_bytes(raw_id),
        None => decode_credential_bytes(id),
    }
}

fn matching_credential(
    credentials: &[WebAuthnCredential],
    credential_id: &[u8],
) -> QidResult<Credential> {
    for credential in credentials {
        if credential.credential_id == credential_id {
            let mut stored =
                serde_json::from_slice::<Credential>(&credential.public_key).map_err(|e| {
                    QidError::Internal {
                        message: format!("stored WebAuthn credential is invalid: {e}"),
                    }
                })?;
            stored.sign_count =
                u32::try_from(credential.counter).map_err(|e| QidError::Internal {
                    message: format!("stored WebAuthn credential counter is invalid: {e}"),
                })?;
            return Ok(stored);
        }
    }
    Err(QidError::NotFound {
        resource: "matching webauthn credential".to_string(),
    })
}

fn registration_aaguid(attestation_object: &[u8]) -> QidResult<Vec<u8>> {
    let cbor: CborValue =
        ciborium::from_reader(attestation_object).map_err(|e| QidError::BadRequest {
            message: format!("invalid WebAuthn attestation object: {e}"),
        })?;
    let CborValue::Map(map) = cbor else {
        return Err(QidError::BadRequest {
            message: "invalid WebAuthn attestation object: expected map".to_string(),
        });
    };
    for (key, value) in map {
        if matches!(key, CborValue::Text(ref text) if text == "authData") {
            let CborValue::Bytes(auth_data) = value else {
                return Err(QidError::BadRequest {
                    message: "invalid WebAuthn attestation authData".to_string(),
                });
            };
            let parsed = webauthn::authenticator_data::parse_authenticator_data(&auth_data)
                .map_err(|e| QidError::BadRequest {
                    message: format!("invalid WebAuthn authenticator data: {e}"),
                })?;
            return parsed
                .attested_credential_data
                .map(|data| data.aaguid.to_vec())
                .ok_or_else(|| QidError::BadRequest {
                    message: "WebAuthn attestation is missing attested credential data".to_string(),
                });
        }
    }
    Err(QidError::BadRequest {
        message: "WebAuthn attestation object is missing authData".to_string(),
    })
}

fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_credential_bytes(value: &str) -> QidResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid base64url WebAuthn identifier: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_state_discoverable_auth_remove_nonexistent_fails() {
        let state = WebAuthnState::new();
        let ceremony_key = "realm-1:disc_0000000000000001";
        assert!(state.remove_disc_auth(ceremony_key).is_err());
    }

    #[test]
    fn webauthn_discoverable_ceremony_id_format() {
        let realm = "corp";
        let ceremony_id = format!("disc_{:016x}", 42u64);
        let ceremony_key = format!("{}:{}", realm, ceremony_id);
        assert!(ceremony_key.starts_with("corp:disc_"));
        assert!(ceremony_key.len() > 10);
    }

    #[test]
    fn webauthn_state_isolation_between_ceremony_types() {
        let state = WebAuthnState::new();

        let reg = state.reg.lock().unwrap();
        let auth = state.auth.lock().unwrap();
        drop(reg);
        drop(auth);

        let disc_map = state.disc_auth.lock().unwrap();
        assert!(disc_map.is_empty());
        drop(disc_map);
    }

    #[test]
    fn registration_options_include_rs256() {
        let service =
            WebAuthnService::new("example.com", "Example", "https://example.com").unwrap();
        let state = WebAuthnState::new();
        let options = service
            .start_registration(&state, "r:u", "user-1", "a@example.com", "Alice")
            .unwrap();
        let params = options["pubKeyCredParams"].as_array().unwrap();
        assert!(params.iter().any(|p| p["alg"] == COSE_RS256));
    }

    #[test]
    fn discoverable_user_handle_matches_stable_handle() {
        let user_id = "user-1";
        let user_handle = stable_user_handle(user_id);
        let expected = sha2::Sha256::digest(user_id.as_bytes());
        assert_eq!(user_handle, expected[..16]);
    }
}
