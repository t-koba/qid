//! Durable push-factor state. Only public keys and SHA-256 verifiers belong here.
use serde::{Deserialize, Serialize};
use std::fmt;

/// A public JWK; private and unknown parameters are rejected on deserialization.
/// Algorithm, curve and key-material validation belongs to the signature verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty", deny_unknown_fields)]
pub enum PushPublicJwk {
    EC { crv: String, x: String, y: String },
    OKP { crv: String, x: String },
    RSA { n: String, e: String },
}

/// Non-secret device display metadata bound: 1..=64 Unicode scalar values, no
/// control characters, and no leading or trailing whitespace.
pub const PUSH_DEVICE_METADATA_MAX: usize = 64;
pub fn valid_push_device_metadata(s: &str) -> bool {
    !s.is_empty()
        && s.chars().take(PUSH_DEVICE_METADATA_MAX + 1).count() <= PUSH_DEVICE_METADATA_MAX
        && s.trim() == s
        && !s.chars().any(char::is_control)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAuthenticator {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub destination: String,
    pub device_name: String,
    pub device_platform: String,
    pub public_jwk: PushPublicJwk,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

/// Pending destination/key proof. The authenticator ID is also the registration ID.
/// `nonce_verifier` is lowercase hex SHA-256, never the delivered nonce.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationChallenge {
    pub authenticator: PushAuthenticator,
    pub nonce_verifier: String,
    pub expires_at: u64,
    pub max_attempts: u32,
    pub attempt_count: u32,
}

/// One durable row per authenticator. Enrollment replaces pending proof state;
/// enrolled (including revoked) rows retain no nonce verifier or attempt state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PushAuthenticatorRecord {
    Pending(PushRegistrationChallenge),
    Enrolled(PushAuthenticator),
}

impl PushAuthenticatorRecord {
    pub fn authenticator(&self) -> &PushAuthenticator {
        match self {
            Self::Pending(c) => &c.authenticator,
            Self::Enrolled(a) => a,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushPurpose {
    PasswordLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushDecision {
    Approve,
    Deny,
}

/// Immutable login binding plus monotonic attempt/decision/redemption state.
/// `id` is both the challenge ID and the unique login-transaction ID.
/// Both verifiers are lowercase hex SHA-256, never raw nonces or browser secrets.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushLoginChallenge {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub authenticator_id: String,
    pub purpose: PushPurpose,
    pub nonce_verifier: String,
    pub browser_binding_verifier: String,
    /// Admitted resend times only; initial issuance is separate immutable storage metadata.
    /// Strictly increasing, within [created_at, expires_at), at most 600 timestamps.
    #[serde(default)]
    pub resend_admitted_at: Vec<u64>,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_attempts: u32,
    pub attempt_count: u32,
    pub decision: Option<PushDecision>,
    pub decided_at: Option<u64>,
    pub consumed_at: Option<u64>,
}

// Deliberately omit destinations, key contents and nonce/browser verifiers.
impl fmt::Debug for PushAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushAuthenticator")
            .field("id", &self.id)
            .field("realm_id", &self.realm_id)
            .field("user_id", &self.user_id)
            .field("device_name", &self.device_name)
            .field("device_platform", &self.device_platform)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for PushRegistrationChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRegistrationChallenge")
            .field("authenticator", &self.authenticator)
            .field("attempt_count", &self.attempt_count)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for PushLoginChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushLoginChallenge")
            .field("id", &self.id)
            .field("realm_id", &self.realm_id)
            .field("user_id", &self.user_id)
            .field("decision", &self.decision)
            .field("consumed_at", &self.consumed_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_metadata_limit_counts_unicode_scalar_values() {
        assert!(valid_push_device_metadata(&"é".repeat(64)));
        assert!(!valid_push_device_metadata(&"é".repeat(65)));
        assert!(!valid_push_device_metadata(&"x".repeat(65)));
        assert!(!valid_push_device_metadata(" phone"));
        assert!(!valid_push_device_metadata(
            "phone
"
        ));
    }

    #[test]
    fn push_lifecycle_rejects_mixed_or_completed_proof_state() {
        let a = serde_json::json!({
            "id": "device", "realm_id": "realm", "user_id": "owner",
            "destination": "destination", "device_name": "Phone", "device_platform": "android",
            "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "x"},
            "created_at": 100, "revoked_at": null
        });
        let pending = serde_json::json!({
            "authenticator": a, "nonce_verifier": "a".repeat(64),
            "expires_at": 200, "max_attempts": 2, "attempt_count": 0
        });
        let mut completed = pending.clone();
        completed["completed_at"] = serde_json::json!(110);
        assert!(serde_json::from_value::<PushRegistrationChallenge>(completed).is_err());
        for (state, record) in [("pending", pending), ("enrolled", a)] {
            let row = serde_json::json!({"state": state, "record": record});
            let decoded: PushAuthenticatorRecord = serde_json::from_value(row.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), row);
            let mut mixed = row.clone();
            mixed["record"]["completed_at"] = serde_json::json!(110);
            assert!(serde_json::from_value::<PushAuthenticatorRecord>(mixed).is_err());
            let mut extra = row.clone();
            extra["pending"] = serde_json::json!({"nonce_verifier": "a".repeat(64)});
            assert!(serde_json::from_value::<PushAuthenticatorRecord>(extra).is_err());
            let mut unknown = row;
            unknown["state"] = serde_json::json!("unknown");
            assert!(serde_json::from_value::<PushAuthenticatorRecord>(unknown).is_err());
        }
    }

    #[test]
    fn push_jwk_rejects_private_and_unknown_parameters() {
        for value in [
            serde_json::json!({"kty":"EC", "crv":"P-256", "x":"x", "y":"y", "d":"secret"}),
            serde_json::json!({"kty":"RSA", "n":"n", "e":"e", "p":"secret"}),
            serde_json::json!({"kty":"OKP", "crv":"Ed25519", "x":"x", "extra":"secret"}),
            serde_json::json!({"kty":"oct", "k":"secret"}),
        ] {
            assert!(serde_json::from_value::<PushPublicJwk>(value).is_err());
        }
        let key = PushPublicJwk::EC {
            crv: "P-256".into(),
            x: "x".into(),
            y: "y".into(),
        };
        assert_eq!(
            serde_json::from_value::<PushPublicJwk>(serde_json::to_value(&key).unwrap()).unwrap(),
            key
        );
        assert!(serde_json::from_str::<PushPurpose>("\"registration\"").is_err());
    }
}
