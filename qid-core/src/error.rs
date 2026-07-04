use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type QidResult<T> = Result<T, QidError>;

/// Stable machine-readable error codes for API responses.
///
/// These codes map to the standard error vocabularies used in OAuth 2.0
/// (RFC 6749 §5.2), OIDC, SCIM 2.0 (RFC 7644 §3), and RFC 9457
/// (Problem Details).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // OAuth / OIDC standard error codes
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    ServerError,
    TemporarilyUnavailable,
    // Resource / general codes
    NotFound,
    Conflict,
    TooManyRequests,
    ConfigError,
    CryptoError,
    StorageError,
    // OAuth extension codes
    InvalidRedirectUri,
    InvalidClientMetadata,
    SlowDown,
    AuthorizationPending,
    ExpiredToken,
    InvalidTarget,
    RequestNotSupported,
}

impl ErrorCode {
    /// Return the wire-format string (snake_case) used in JSON responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TooManyRequests => "too_many_requests",
            Self::ConfigError => "config_error",
            Self::CryptoError => "crypto_error",
            Self::StorageError => "storage_error",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::SlowDown => "slow_down",
            Self::AuthorizationPending => "authorization_pending",
            Self::ExpiredToken => "expired_token",
            Self::InvalidTarget => "invalid_target",
            Self::RequestNotSupported => "request_not_supported",
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum QidError {
    #[error("config error: {message}")]
    Config { message: String },
    #[error("crypto error: {message}")]
    Crypto { message: String },
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("{resource} not found")]
    NotFound { resource: String },
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },
    #[error("bad request: {message}")]
    BadRequest { message: String },
    #[error("internal error: {message}")]
    Internal { message: String },
    #[error("too many requests: {message}")]
    TooManyRequests { message: String },
    #[error("conflict: {message}")]
    Conflict { message: String },
}

impl QidError {
    /// Return a stable [`ErrorCode`] that is safe to expose in API responses.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            QidError::Config { .. } => ErrorCode::ConfigError,
            QidError::Crypto { .. } => ErrorCode::CryptoError,
            QidError::Storage { .. } => ErrorCode::StorageError,
            QidError::NotFound { .. } => ErrorCode::NotFound,
            QidError::Unauthorized { message } if message == "expired_token" => {
                ErrorCode::ExpiredToken
            }
            QidError::Unauthorized { message } if message == "slow_down" => ErrorCode::SlowDown,
            QidError::Unauthorized { message } if message == "authorization_pending" => {
                ErrorCode::AuthorizationPending
            }
            QidError::Unauthorized { .. } => ErrorCode::AccessDenied,
            QidError::BadRequest { .. } => ErrorCode::InvalidRequest,
            QidError::Internal { .. } => ErrorCode::ServerError,
            QidError::TooManyRequests { .. } => ErrorCode::TooManyRequests,
            QidError::Conflict { .. } => ErrorCode::Conflict,
        }
    }

    /// Deprecated string-based code; use [`Self::error_code()`] instead.
    pub fn code(&self) -> &'static str {
        self.error_code().as_str()
    }

    pub fn to_response_body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "error_description": self.message(),
        })
    }

    pub fn message(&self) -> String {
        self.to_string()
    }

    pub fn status_code(&self) -> u16 {
        match self {
            QidError::Config { .. } => 422,
            QidError::Crypto { .. } => 400,
            QidError::Storage { .. } => 503,
            QidError::NotFound { .. } => 404,
            QidError::Unauthorized { .. } => 401,
            QidError::BadRequest { .. } => 400,
            QidError::Internal { .. } => 500,
            QidError::TooManyRequests { .. } => 429,
            QidError::Conflict { .. } => 409,
        }
    }
}

impl From<anyhow::Error> for QidError {
    fn from(err: anyhow::Error) -> Self {
        QidError::Internal {
            message: err.to_string(),
        }
    }
}
