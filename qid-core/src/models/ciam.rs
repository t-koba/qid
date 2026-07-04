use serde::{Deserialize, Serialize};

use crate::error::{QidError, QidResult};

use super::validation::require_non_empty;

/// A persisted CIAM consent grant for claim release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamConsentGrant {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub client_id: String,
    pub granted_claims: Vec<String>,
    pub terms_version: Option<String>,
    pub granted_at_epoch_seconds: u64,
    pub revoked: bool,
}

impl CiamConsentGrant {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("CIAM consent id", &self.id)?;
        require_non_empty("CIAM consent realm_id", &self.realm_id)?;
        require_non_empty("CIAM consent user_id", &self.user_id)?;
        require_non_empty("CIAM consent client_id", &self.client_id)?;
        if self
            .granted_claims
            .iter()
            .any(|claim| claim.trim().is_empty())
        {
            return Err(QidError::BadRequest {
                message: "CIAM consent granted_claims must not contain empty values".to_string(),
            });
        }
        if self.granted_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "CIAM consent granted_at_epoch_seconds must be set".to_string(),
            });
        }
        Ok(())
    }
}

/// A single-use CIAM verification challenge for email or phone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamVerificationChallengeRecord {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub channel: String,
    pub address: String,
    pub purpose: String,
    pub code_hash: String,
    pub expires_at_epoch_seconds: u64,
    pub consumed_at_epoch_seconds: Option<u64>,
    pub created_at_epoch_seconds: u64,
}

impl CiamVerificationChallengeRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("CIAM verification id", &self.id)?;
        require_non_empty("CIAM verification realm_id", &self.realm_id)?;
        require_non_empty("CIAM verification user_id", &self.user_id)?;
        require_non_empty("CIAM verification address", &self.address)?;
        require_non_empty("CIAM verification purpose", &self.purpose)?;
        require_non_empty("CIAM verification code_hash", &self.code_hash)?;
        if !matches!(self.channel.as_str(), "email" | "phone") {
            return Err(QidError::BadRequest {
                message: "CIAM verification channel must be email or phone".to_string(),
            });
        }
        if self.created_at_epoch_seconds == 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message: "CIAM verification expiry must be after creation".to_string(),
            });
        }
        if self
            .consumed_at_epoch_seconds
            .is_some_and(|consumed| consumed < self.created_at_epoch_seconds)
        {
            return Err(QidError::BadRequest {
                message: "CIAM verification consumed_at must not be before creation".to_string(),
            });
        }
        Ok(())
    }
}

/// A linked external CIAM identity from a social or inbound identity provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamIdentityLink {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub provider: String,
    pub external_subject: String,
    #[serde(default)]
    pub external_email: Option<String>,
    #[serde(default)]
    pub profile_json: serde_json::Value,
    pub linked_at_epoch_seconds: u64,
    pub verified: bool,
}

impl CiamIdentityLink {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("CIAM identity link id", &self.id)?;
        require_non_empty("CIAM identity link realm_id", &self.realm_id)?;
        require_non_empty("CIAM identity link user_id", &self.user_id)?;
        require_non_empty("CIAM identity link provider", &self.provider)?;
        require_non_empty(
            "CIAM identity link external_subject",
            &self.external_subject,
        )?;
        if self
            .external_email
            .as_deref()
            .is_some_and(|email| !email.contains('@') || email.trim() != email)
        {
            return Err(QidError::BadRequest {
                message: "CIAM identity link external_email must be a normalized email".to_string(),
            });
        }
        if !self.profile_json.is_object() {
            return Err(QidError::BadRequest {
                message: "CIAM identity link profile_json must be an object".to_string(),
            });
        }
        if self.linked_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "CIAM identity link linked_at_epoch_seconds must be set".to_string(),
            });
        }
        Ok(())
    }
}

/// A persisted CIAM progressive profile with passwordless migration flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamProgressiveProfile {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub profile_json: serde_json::Value,
    pub passwordless_migrated_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// A single-use password reset token constrained by device and risk context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetToken {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub token_hash: String,
    pub device_id: Option<String>,
    pub risk_json: serde_json::Value,
    pub expires_at_epoch_seconds: u64,
    pub consumed_at_epoch_seconds: Option<u64>,
    pub created_at_epoch_seconds: u64,
}

impl PasswordResetToken {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("password reset id", &self.id)?;
        require_non_empty("password reset realm_id", &self.realm_id)?;
        require_non_empty("password reset user_id", &self.user_id)?;
        require_non_empty("password reset token_hash", &self.token_hash)?;
        if !self.risk_json.is_object() {
            return Err(QidError::BadRequest {
                message: "password reset risk_json must be an object".to_string(),
            });
        }
        if self.created_at_epoch_seconds == 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message: "password reset expiry must be after creation".to_string(),
            });
        }
        if self
            .consumed_at_epoch_seconds
            .is_some_and(|consumed| consumed < self.created_at_epoch_seconds)
        {
            return Err(QidError::BadRequest {
                message: "password reset consumed_at must not be before creation".to_string(),
            });
        }
        Ok(())
    }
}
