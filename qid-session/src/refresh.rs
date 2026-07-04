//! Refresh token rotation primitives.

#[derive(Debug, Clone)]
pub struct TokenFamily {
    pub id: String,
    pub current_refresh_hash: String,
    pub revoked: bool,
}
