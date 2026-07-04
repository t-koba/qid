use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use qid_core::{
    error::{QidError, QidResult},
    models::WebAuthnCredential,
};
use sha2::Digest;
use url::Url;
use webauthn_rs::prelude::*;

/// Injected WebAuthn in-memory state for registration and authentication
/// ceremonies.
#[derive(Debug, Default)]
pub struct WebAuthnState {
    reg: Mutex<HashMap<String, PasskeyRegistration>>,
    auth: Mutex<HashMap<String, PasskeyAuthentication>>,
    disc_auth: Mutex<HashMap<String, DiscoverableAuthentication>>,
}

impl WebAuthnState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn insert_reg(&self, user_name: &str, state: PasskeyRegistration) -> QidResult<()> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.insert(user_name.to_string(), state);
        Ok(())
    }

    fn remove_reg(&self, user_name: &str) -> QidResult<PasskeyRegistration> {
        let mut map = self.reg.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn reg lock poisoned: {e}"),
        })?;
        map.remove(user_name).ok_or_else(|| QidError::BadRequest {
            message: "no registration in progress".to_string(),
        })
    }

    fn insert_auth(&self, user_name: &str, state: PasskeyAuthentication) -> QidResult<()> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.insert(user_name.to_string(), state);
        Ok(())
    }

    fn remove_auth(&self, user_name: &str) -> QidResult<PasskeyAuthentication> {
        let mut map = self.auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn auth lock poisoned: {e}"),
        })?;
        map.remove(user_name).ok_or_else(|| QidError::BadRequest {
            message: "no authentication in progress".to_string(),
        })
    }

    fn insert_disc_auth(
        &self,
        ceremony_key: &str,
        state: DiscoverableAuthentication,
    ) -> QidResult<()> {
        let mut map = self.disc_auth.lock().map_err(|e| QidError::Internal {
            message: format!("webauthn disc auth lock poisoned: {e}"),
        })?;
        map.insert(ceremony_key.to_string(), state);
        Ok(())
    }

    fn remove_disc_auth(&self, ceremony_key: &str) -> QidResult<DiscoverableAuthentication> {
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

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> QidResult<Self> {
        let origin = Url::parse(rp_origin).map_err(|e| QidError::BadRequest {
            message: format!("invalid rp_origin: {e}"),
        })?;
        let rbuilder = WebauthnBuilder::new(rp_id, &origin).map_err(|e| QidError::Internal {
            message: format!("webauthn init: {e}"),
        })?;
        let webauthn = rbuilder
            .rp_name(rp_name)
            .build()
            .map_err(|e| QidError::Internal {
                message: format!("webauthn build: {e}"),
            })?;
        Ok(Self { webauthn })
    }

    pub fn start_registration(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        user_unique_id: &str,
        user_name: &str,
        user_display_name: &str,
    ) -> QidResult<serde_json::Value> {
        let uid = uuid::Uuid::from_slice(&sha2::Sha256::digest(user_unique_id.as_bytes())[..16])
            .map_err(|e| QidError::Internal {
                message: format!("uuid from hash: {e}"),
            })?;
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(uid, user_name, user_display_name, Some(Vec::new()))
            .map_err(|e| QidError::Internal {
                message: format!("webauthn start registration: {e}"),
            })?;
        webauthn_state.insert_reg(state_key, reg_state)?;
        serde_json::to_value(&ccr).map_err(|e| QidError::Internal {
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
        let rcr: RegisterPublicKeyCredential =
            serde_json::from_value(response).map_err(|e| QidError::BadRequest {
                message: format!("invalid registration response: {e}"),
            })?;
        let reg_state = webauthn_state.remove_reg(state_key)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&rcr, &reg_state)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish registration: {e}"),
            })?;
        let cred_id = passkey.cred_id();
        let pk_json = serde_json::to_vec(&passkey).map_err(|e| QidError::Internal {
            message: format!("serialize passkey: {e}"),
        })?;
        Ok(WebAuthnCredential {
            id: qid_core::util::base64_url_encode(cred_id.as_ref()),
            user_id: user_id.to_string(),
            credential_id: cred_id.as_ref().to_vec(),
            public_key: pk_json,
            counter: 0,
            aaguid: Vec::new(),
            device_name: None,
            created_at: qid_core::util::now_seconds(),
        })
    }

    pub fn start_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        passkeys: &[Passkey],
    ) -> QidResult<serde_json::Value> {
        if passkeys.is_empty() {
            return Err(QidError::NotFound {
                resource: "webauthn credentials".to_string(),
            });
        }
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|e| QidError::Internal {
                message: format!("webauthn start authentication: {e}"),
            })?;
        webauthn_state.insert_auth(state_key, auth_state)?;
        serde_json::to_value(&rcr).map_err(|e| QidError::Internal {
            message: format!("serialization error: {e}"),
        })
    }

    pub fn finish_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        state_key: &str,
        response: serde_json::Value,
    ) -> QidResult<AuthenticationResult> {
        let rar: PublicKeyCredential =
            serde_json::from_value(response).map_err(|e| QidError::BadRequest {
                message: format!("invalid authentication response: {e}"),
            })?;
        let auth_state = webauthn_state.remove_auth(state_key)?;
        self.webauthn
            .finish_passkey_authentication(&rar, &auth_state)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish authentication: {e}"),
            })
    }

    /// Start a discoverable (conditional UI / usernameless) authentication.
    pub fn start_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
    ) -> QidResult<serde_json::Value> {
        let (rcr, disc_state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| QidError::Internal {
                message: format!("webauthn start discoverable auth: {e}"),
            })?;
        webauthn_state.insert_disc_auth(ceremony_key, disc_state)?;
        serde_json::to_value(&rcr).map_err(|e| QidError::Internal {
            message: format!("serialization error: {e}"),
        })
    }

    /// Identify the user from a discoverable authentication response.
    pub fn identify_discoverable_authentication(
        &self,
        response: &serde_json::Value,
    ) -> QidResult<(uuid::Uuid, Vec<u8>)> {
        let rar: PublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|e| QidError::BadRequest {
                message: format!("invalid discoverable auth response: {e}"),
            })?;
        let (uid, cred_id) = self
            .webauthn
            .identify_discoverable_authentication(&rar)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn identify discoverable auth: {e}"),
            })?;
        Ok((uid, cred_id.to_vec()))
    }

    /// Finish a discoverable authentication with the identified user's passkeys.
    pub fn finish_discoverable_authentication(
        &self,
        webauthn_state: &WebAuthnState,
        ceremony_key: &str,
        response: serde_json::Value,
        passkeys: &[Passkey],
    ) -> QidResult<AuthenticationResult> {
        let rar: PublicKeyCredential =
            serde_json::from_value(response).map_err(|e| QidError::BadRequest {
                message: format!("invalid discoverable auth response: {e}"),
            })?;
        let disc_state = webauthn_state.remove_disc_auth(ceremony_key)?;
        let discoverable_keys: Vec<DiscoverableKey> =
            passkeys.iter().map(DiscoverableKey::from).collect();
        self.webauthn
            .finish_discoverable_authentication(&rar, disc_state, &discoverable_keys)
            .map_err(|e| QidError::Crypto {
                message: format!("webauthn finish discoverable auth: {e}"),
            })
    }
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
        // ceremony IDs are hex formatted with disc_ prefix
        let realm = "corp";
        let ceremony_id = format!("disc_{:016x}", 42u64);
        let ceremony_key = format!("{}:{}", realm, ceremony_id);
        assert!(ceremony_key.starts_with("corp:disc_"));
        assert!(ceremony_key.len() > 10);
    }

    #[test]
    fn webauthn_state_isolation_between_ceremony_types() {
        let state = WebAuthnState::new();

        // Each ceremony type has its own Mutex<HashMap>, verified by
        // basic lock access.
        let _reg = state.reg.lock().unwrap();
        let _auth = state.auth.lock().unwrap();
        drop(_reg);
        drop(_auth);

        let disc_map = state.disc_auth.lock().unwrap();
        assert!(disc_map.is_empty());
        drop(disc_map);
    }
}
