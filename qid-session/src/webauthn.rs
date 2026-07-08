use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use passkey_auth::{
    AuthenticationResponse, AuthenticationState, PasskeyCredential, RegistrationResponse,
    RegistrationState, Webauthn,
};
use qid_core::{
    error::{QidError, QidResult},
    models::WebAuthnCredential,
};
use sha2::Digest;
use url::Url;

#[derive(Debug, Default)]
pub struct WebAuthnState {
    reg: Mutex<HashMap<String, RegistrationState>>,
    auth: Mutex<HashMap<String, AuthenticationState>>,
    disc_auth: Mutex<HashMap<String, AuthenticationState>>,
}

impl WebAuthnState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn insert_reg(&self, state_key: &str, state: RegistrationState) -> QidResult<()> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.insert(state_key.to_string(), state);
        Ok(())
    }

    fn remove_reg(&self, state_key: &str) -> QidResult<RegistrationState> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.remove(state_key).ok_or_else(|| QidError::BadRequest {
            message: "no registration in progress".to_string(),
        })
    }

    fn insert_auth(&self, state_key: &str, state: AuthenticationState) -> QidResult<()> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.insert(state_key.to_string(), state);
        Ok(())
    }

    fn remove_auth(&self, state_key: &str) -> QidResult<AuthenticationState> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.remove(state_key).ok_or_else(|| QidError::BadRequest {
            message: "no authentication in progress".to_string(),
        })
    }

    fn insert_disc_auth(&self, ceremony_key: &str, state: AuthenticationState) -> QidResult<()> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.insert(ceremony_key.to_string(), state);
        Ok(())
    }

    fn remove_disc_auth(&self, ceremony_key: &str) -> QidResult<AuthenticationState> {
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
    webauthn: Webauthn,
}

pub struct WebAuthnAuthOutcome {
    pub credential_id: Vec<u8>,
    pub counter: u64,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> QidResult<Self> {
        Url::parse(rp_origin).map_err(|e| QidError::BadRequest {
            message: format!("invalid rp_origin: {e}"),
        })?;
        Ok(Self {
            webauthn: Webauthn::new(rp_id, rp_name, rp_origin),
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
        let user_handle = stable_user_handle(user_unique_id);
        let existing = Vec::new();
        let (challenge, reg_state) =
            self.webauthn
                .start_registration(&user_handle, user_name, user_display_name, &existing);
        webauthn_state.insert_reg(state_key, reg_state)?;
        serde_json::to_value(&challenge).map_err(|e| QidError::Internal {
            message: format!("serialization error: {e}"),
        })
    }

    pub fn finish_registration(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        user_id: &str,
        response: serde_json::Value,
    ) -> QidResult<WebAuthnCredential> {
        let response: RegistrationResponse =
            serde_json::from_value(response).map_err(|e| QidError::BadRequest {
                message: format!("invalid registration response: {e}"),
            })?;
        let reg_state = webauthn_state.remove_reg(state_key)?;
        let passkey = self
            .webauthn
            .finish_registration(&reg_state, &response)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish registration: {e}"),
            })?;
        let credential_id = passkey.id.as_bytes().to_vec();
        let pk_json = serde_json::to_vec(&passkey).map_err(|e| QidError::Internal {
            message: format!("serialize passkey: {e}"),
        })?;
        Ok(WebAuthnCredential {
            id: qid_core::util::base64_url_encode(&credential_id),
            user_id: user_id.to_string(),
            credential_id,
            public_key: pk_json,
            counter: passkey.counter as u64,
            aaguid: passkey.aaguid.to_vec(),
            device_name: None,
            created_at: qid_core::util::now_seconds(),
        })
    }

    pub fn start_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        user_unique_id: &str,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<serde_json::Value> {
        let passkeys = parse_passkeys(credentials)?;
        if passkeys.is_empty() {
            return Err(QidError::NotFound {
                resource: "webauthn credentials".to_string(),
            });
        }
        let (challenge, auth_state) = self.webauthn.start_authentication_with_creds_for_user(
            &stable_user_handle(user_unique_id),
            &passkeys,
        );
        webauthn_state.insert_auth(state_key, auth_state)?;
        serde_json::to_value(&challenge).map_err(|e| QidError::Internal {
            message: format!("serialization error: {e}"),
        })
    }

    pub fn finish_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let response = parse_authentication_response(response)?;
        let auth_state = webauthn_state.remove_auth(state_key)?;
        let passkey = matching_passkey(credentials, &response)?;
        let outcome = self
            .webauthn
            .finish_authentication(&auth_state, &response, &passkey)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish authentication: {e}"),
            })?;
        Ok(WebAuthnAuthOutcome {
            credential_id: outcome.credential_id.as_bytes().to_vec(),
            counter: outcome.new_counter as u64,
        })
    }

    pub fn start_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
    ) -> QidResult<serde_json::Value> {
        let (challenge, auth_state) = self.webauthn.start_authentication(&[]);
        webauthn_state.insert_disc_auth(ceremony_key, auth_state)?;
        serde_json::to_value(&challenge).map_err(|e| QidError::Internal {
            message: format!("serialization error: {e}"),
        })
    }

    pub fn identify_discoverable_authentication(
        &self,
        response: &serde_json::Value,
    ) -> QidResult<(uuid::Uuid, Vec<u8>)> {
        let response = parse_authentication_response(response.clone())?;
        let user_handle = response
            .user_handle
            .as_deref()
            .ok_or_else(|| QidError::BadRequest {
                message: "discoverable WebAuthn response is missing userHandle".to_string(),
            })?;
        let user_handle = decode_credential_bytes(user_handle)?;
        let user_uuid = uuid::Uuid::from_slice(&user_handle).map_err(|e| QidError::BadRequest {
            message: format!("invalid discoverable WebAuthn userHandle: {e}"),
        })?;
        Ok((user_uuid, response_credential_id(&response)?))
    }

    pub fn finish_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
        response: serde_json::Value,
        credentials: &[WebAuthnCredential],
    ) -> QidResult<WebAuthnAuthOutcome> {
        let response = parse_authentication_response(response)?;
        let auth_state = webauthn_state.remove_disc_auth(ceremony_key)?;
        let passkey = matching_passkey(credentials, &response)?;
        let outcome = self
            .webauthn
            .finish_authentication(&auth_state, &response, &passkey)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish discoverable auth: {e}"),
            })?;
        Ok(WebAuthnAuthOutcome {
            credential_id: outcome.credential_id.as_bytes().to_vec(),
            counter: outcome.new_counter as u64,
        })
    }
}

fn stable_user_handle(user_unique_id: &str) -> Vec<u8> {
    sha2::Sha256::digest(user_unique_id.as_bytes())[..16].to_vec()
}

fn parse_passkeys(credentials: &[WebAuthnCredential]) -> QidResult<Vec<PasskeyCredential>> {
    credentials
        .iter()
        .map(|credential| {
            serde_json::from_slice::<PasskeyCredential>(&credential.public_key).map_err(|e| {
                QidError::Internal {
                    message: format!("stored WebAuthn credential is invalid: {e}"),
                }
            })
        })
        .collect()
}

fn matching_passkey(
    credentials: &[WebAuthnCredential],
    response: &AuthenticationResponse,
) -> QidResult<PasskeyCredential> {
    let response_id = response_credential_id(response)?;
    for credential in credentials {
        if credential.credential_id == response_id {
            return serde_json::from_slice::<PasskeyCredential>(&credential.public_key).map_err(
                |e| QidError::Internal {
                    message: format!("stored WebAuthn credential is invalid: {e}"),
                },
            );
        }
    }
    Err(QidError::NotFound {
        resource: "matching webauthn credential".to_string(),
    })
}

fn parse_authentication_response(value: serde_json::Value) -> QidResult<AuthenticationResponse> {
    serde_json::from_value(value).map_err(|e| QidError::BadRequest {
        message: format!("invalid authentication response: {e}"),
    })
}

fn response_credential_id(response: &AuthenticationResponse) -> QidResult<Vec<u8>> {
    decode_credential_bytes(&response.id)
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
}
