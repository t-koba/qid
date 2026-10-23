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
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, CHALLENGE_MAX_AGE_SECS,
    COSE_EDDSA, COSE_ES256, COSE_ES384, COSE_RS256, Challenge, Credential, RelyingParty,
};

/// Live ceremonies a realm may hold per ceremony kind.
///
/// The discoverable start route needs no credential, so the ceremony state
/// must not grow with the number of requests an unauthenticated caller
/// makes.
const MAX_CEREMONY_ENTRIES_PER_REALM: usize = 4096;

/// A live ceremony and the time it was started.
#[derive(Debug)]
struct CeremonyEntry {
    challenge: Challenge,
    created_at: u64,
}

/// The live ceremonies of one kind, grouped by realm.
///
/// A ceremony lives as long as the challenge it carries: `caden` refuses a
/// challenge older than [`CHALLENGE_MAX_AGE_SECS`] when it verifies it, so a
/// ceremony older than that can never complete.
#[derive(Debug, Default)]
struct CeremonyMap {
    realms: HashMap<String, HashMap<String, CeremonyEntry>>,
}

impl CeremonyMap {
    fn insert(&mut self, realm: &str, id: &str, challenge: Challenge, now: u64) {
        let entries = self.realms.entry(realm.to_string()).or_default();
        entries.retain(|_, entry| !expired(entry, now));
        while entries.len() >= MAX_CEREMONY_ENTRIES_PER_REALM {
            let Some(oldest) = oldest_id(entries) else {
                break;
            };
            entries.remove(&oldest);
        }
        entries.insert(
            id.to_string(),
            CeremonyEntry {
                challenge,
                created_at: now,
            },
        );
    }

    fn remove(&mut self, realm: &str, id: &str, now: u64) -> Option<Challenge> {
        let entry = self.realms.get_mut(realm)?.remove(id)?;
        if expired(&entry, now) {
            return None;
        }
        let empty = self
            .realms
            .get(realm)
            .map(|e| e.is_empty())
            .unwrap_or(false);
        if empty {
            self.realms.remove(realm);
        }
        Some(entry.challenge)
    }

    #[cfg(test)]
    fn entries(&self, realm: &str) -> usize {
        self.realms.get(realm).map(|e| e.len()).unwrap_or(0)
    }
}

fn oldest_id(entries: &HashMap<String, CeremonyEntry>) -> Option<String> {
    entries
        .iter()
        .min_by_key(|(_, entry)| entry.created_at)
        .map(|(id, _)| id.clone())
}

fn expired(entry: &CeremonyEntry, now: u64) -> bool {
    now.saturating_sub(entry.created_at) >= CHALLENGE_MAX_AGE_SECS
}

/// The live WebAuthn ceremonies of the daemon, grouped by realm and kind.
#[derive(Debug, Default)]
pub struct WebAuthnState {
    reg: Mutex<CeremonyMap>,
    auth: Mutex<CeremonyMap>,
    disc_auth: Mutex<CeremonyMap>,
}

impl WebAuthnState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn insert_reg(&self, realm: &str, id: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.insert(realm, id, state, qid_core::util::now_seconds());
        Ok(())
    }

    fn remove_reg(&self, realm: &str, id: &str) -> QidResult<Challenge> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.remove(realm, id, qid_core::util::now_seconds())
            .ok_or_else(|| QidError::BadRequest {
                message: "no registration in progress".to_string(),
            })
    }

    fn insert_auth(&self, realm: &str, id: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.insert(realm, id, state, qid_core::util::now_seconds());
        Ok(())
    }

    fn remove_auth(&self, realm: &str, id: &str) -> QidResult<Challenge> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.remove(realm, id, qid_core::util::now_seconds())
            .ok_or_else(|| QidError::BadRequest {
                message: "no authentication in progress".to_string(),
            })
    }

    fn insert_disc_auth(&self, realm: &str, id: &str, state: Challenge) -> QidResult<()> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.insert(realm, id, state, qid_core::util::now_seconds());
        Ok(())
    }

    fn remove_disc_auth(&self, realm: &str, id: &str) -> QidResult<Challenge> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.remove(realm, id, qid_core::util::now_seconds())
            .ok_or_else(|| QidError::BadRequest {
                message: "no discoverable authentication in progress".to_string(),
            })
    }
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

/// The challenge of a consumed WebAuthn ceremony.
pub struct CeremonyChallenge(Challenge);

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
        let parsed = Url::parse(rp_origin).map_err(|e| QidError::BadRequest {
            message: format!("invalid rp_origin: {e}"),
        })?;
        if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
            return Err(QidError::BadRequest {
                message: "WebAuthn RP origin must use https except localhost".to_string(),
            });
        }
        let host = parsed.host_str().ok_or_else(|| QidError::BadRequest {
            message: "WebAuthn RP origin must include a host".to_string(),
        })?;
        if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
            return Err(QidError::BadRequest {
                message: "WebAuthn RP origin host must match RP ID scope".to_string(),
            });
        }
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
        realm: &str,
        user_unique_id: &str,
        user_name: &str,
        user_display_name: &str,
    ) -> QidResult<serde_json::Value> {
        let challenge = new_challenge()?;
        let challenge_value = challenge_json(&challenge);
        let user_handle = stable_user_handle(user_unique_id);
        webauthn_state.insert_reg(realm, user_unique_id, challenge)?;
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
        realm: &str,
        user_id: &str,
        response: serde_json::Value,
    ) -> QidResult<WebAuthnCredential> {
        let parsed = parse_registration_response(response)?;
        let challenge = webauthn_state.remove_reg(realm, user_id)?;
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
        realm: &str,
        user_unique_id: &str,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<serde_json::Value> {
        if credentials.is_empty() {
            return Err(QidError::NotFound {
                resource: "webauthn credentials".to_string(),
            });
        }
        let challenge = new_challenge()?;
        let options = authentication_options(&self.rp_id, &challenge, credentials);
        webauthn_state.insert_auth(realm, user_unique_id, challenge)?;
        Ok(options)
    }

    pub fn finish_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        realm: &str,
        user_id: &str,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let parsed = parse_authentication_response(response)?;
        let challenge = webauthn_state.remove_auth(realm, user_id)?;
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
        realm: &str,
        ceremony_id: &str,
    ) -> QidResult<serde_json::Value> {
        let challenge = new_challenge()?;
        let options = discoverable_authentication_options(&self.rp_id, &challenge);
        webauthn_state.insert_disc_auth(realm, ceremony_id, challenge)?;
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

    /// Take the challenge of a live discoverable ceremony.
    ///
    /// Taking the challenge consumes the ceremony, so it is single-use and
    /// the caller that verifies it is the only one that can: a caller
    /// without a live ceremony never reaches the realm's user table.
    pub fn take_discoverable_challenge(
        &self,
        webauthn_state: &WebAuthnState,
        realm: &str,
        ceremony_id: &str,
    ) -> QidResult<CeremonyChallenge> {
        Ok(CeremonyChallenge(
            webauthn_state.remove_disc_auth(realm, ceremony_id)?,
        ))
    }

    pub fn verify_discoverable_authentication(
        &self,
        challenge: &CeremonyChallenge,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let parsed = parse_authentication_response(response)?;
        let stored = matching_credential(credentials, &parsed.credential_id)?;
        let outcome = self
            .rp
            .verify_authentication(&stored, &challenge.0, &parsed.response)
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

// Validate the original evidence before caden sees it; never resolve duplicate
// keys by choosing a value or by re-encoding the object passed to the verifier.
fn registration_aaguid(attestation_object: &[u8]) -> QidResult<Vec<u8>> {
    let mut remaining = attestation_object;
    let cbor: CborValue =
        ciborium::from_reader(&mut remaining).map_err(|e| QidError::BadRequest {
            message: format!("invalid WebAuthn attestation object: {e}"),
        })?;
    if !remaining.is_empty() {
        return Err(invalid_attestation_evidence());
    }
    let mut fields = attestation_fields(cbor)?;
    if !matches!(fields.remove("fmt"), Some(CborValue::Text(_))) {
        return Err(invalid_attestation_evidence());
    }
    attestation_fields(
        fields
            .remove("attStmt")
            .ok_or_else(invalid_attestation_evidence)?,
    )?;
    let Some(CborValue::Bytes(auth_data)) = fields.remove("authData") else {
        return Err(invalid_attestation_evidence());
    };
    let parsed =
        webauthn::authenticator_data::parse_authenticator_data(&auth_data).map_err(|e| {
            QidError::BadRequest {
                message: format!("invalid WebAuthn authenticator data: {e}"),
            }
        })?;
    parsed
        .attested_credential_data
        .map(|data| data.aaguid.to_vec())
        .ok_or_else(|| QidError::BadRequest {
            message: "WebAuthn attestation is missing attested credential data".to_string(),
        })
}

fn attestation_fields(value: CborValue) -> QidResult<HashMap<String, CborValue>> {
    let CborValue::Map(map) = value else {
        return Err(invalid_attestation_evidence());
    };
    let mut fields = HashMap::new();
    for (key, value) in map {
        let CborValue::Text(key) = key else {
            return Err(invalid_attestation_evidence());
        };
        if fields.insert(key, value).is_some() {
            return Err(invalid_attestation_evidence());
        }
    }
    Ok(fields)
}

fn invalid_attestation_evidence() -> QidError {
    QidError::BadRequest {
        message: "invalid WebAuthn attestation evidence: expected complete CBOR with unique text map keys and fmt/authData/attStmt fields".to_string(),
    }
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
        assert!(
            state
                .remove_disc_auth("realm-1", "disc_0000000000000001")
                .is_err()
        );
    }

    #[test]
    fn webauthn_discoverable_ceremony_id_format() {
        let ceremony_id = format!("disc_{:016x}", 42u64);
        assert!(ceremony_id.starts_with("disc_"));
        assert_eq!(ceremony_id.len(), "disc_".len() + 16);
    }

    #[test]
    fn webauthn_state_isolation_between_ceremony_types() {
        let state = WebAuthnState::new();

        let reg = state.reg.lock().unwrap();
        let auth = state.auth.lock().unwrap();
        drop(reg);
        drop(auth);

        let disc_map = state.disc_auth.lock().unwrap();
        assert_eq!(disc_map.entries("realm-1"), 0);
        drop(disc_map);
    }

    #[test]
    fn ceremonies_are_scoped_to_their_realm() {
        let state = WebAuthnState::new();
        let service =
            WebAuthnService::new("example.com", "Example", "https://example.com").unwrap();
        service
            .start_discoverable_authentication(&state, "realm-1", "ceremony-1")
            .unwrap();

        assert!(state.remove_disc_auth("realm-2", "ceremony-1").is_err());
        assert!(state.remove_disc_auth("realm-1", "ceremony-1").is_ok());
    }

    #[test]
    fn abandoned_ceremonies_are_bounded_per_realm() {
        let state = WebAuthnState::new();
        let service =
            WebAuthnService::new("example.com", "Example", "https://example.com").unwrap();
        for index in 0..(MAX_CEREMONY_ENTRIES_PER_REALM + 10) {
            service
                .start_discoverable_authentication(&state, "realm-1", &format!("ceremony-{index}"))
                .unwrap();
        }

        assert_eq!(
            state.disc_auth.lock().unwrap().entries("realm-1"),
            MAX_CEREMONY_ENTRIES_PER_REALM
        );
    }

    #[test]
    fn a_ceremony_older_than_the_challenge_lifetime_is_refused() {
        let now = 1_000;
        let mut map = CeremonyMap::default();
        map.insert("realm-1", "ceremony-1", Challenge::new().unwrap(), now);
        assert!(
            map.remove("realm-1", "ceremony-1", now + CHALLENGE_MAX_AGE_SECS - 1)
                .is_some()
        );

        let mut map = CeremonyMap::default();
        map.insert("realm-1", "ceremony-2", Challenge::new().unwrap(), now);
        assert!(
            map.remove("realm-1", "ceremony-2", now + CHALLENGE_MAX_AGE_SECS)
                .is_none()
        );
    }

    #[test]
    fn expired_ceremonies_are_dropped_when_a_new_one_starts() {
        let mut map = CeremonyMap::default();
        map.insert("realm-1", "old", Challenge::new().unwrap(), 1_000);
        map.insert(
            "realm-1",
            "new",
            Challenge::new().unwrap(),
            1_000 + CHALLENGE_MAX_AGE_SECS,
        );

        assert_eq!(map.entries("realm-1"), 1);
    }

    #[test]
    fn wired_service_rejects_plain_http_and_cross_site_origins() {
        assert!(WebAuthnService::new("example.com", "Example", "http://example.com").is_err());
        assert!(
            WebAuthnService::new("example.com", "Example", "https://evil.example.net").is_err()
        );
    }

    #[test]
    fn wired_service_accepts_localhost_http_and_scoped_subdomain() {
        assert!(WebAuthnService::new("localhost", "Example", "http://localhost:5173").is_ok());
        assert!(
            WebAuthnService::new("example.com", "Example", "https://login.example.com").is_ok()
        );
    }

    #[test]
    fn registration_options_include_rs256() {
        let service =
            WebAuthnService::new("example.com", "Example", "https://example.com").unwrap();
        let state = WebAuthnState::new();
        let options = service
            .start_registration(&state, "realm-1", "user-1", "a@example.com", "Alice")
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
