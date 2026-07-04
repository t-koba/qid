//! RFC 9116 security.txt.

use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityTxt {
    pub contacts: Vec<String>,
    pub expires: String,
    pub preferred_languages: Option<String>,
    pub canonical: Option<String>,
    pub policy: Option<String>,
    pub hiring: Option<String>,
    pub encryption: Option<String>,
    pub acknowledgments: Option<String>,
}

impl Default for SecurityTxt {
    fn default() -> Self {
        Self::new("mailto:security@qid.example.com")
    }
}

impl SecurityTxt {
    pub fn new(contact: &str) -> Self {
        Self {
            contacts: vec![contact.to_string()],
            expires: "2027-12-31T23:59:59Z".to_string(),
            preferred_languages: Some("en".to_string()),
            canonical: None,
            policy: None,
            hiring: None,
            encryption: None,
            acknowledgments: None,
        }
    }
}

impl fmt::Display for SecurityTxt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.contacts {
            writeln!(f, "Contact: {c}")?;
        }
        writeln!(f, "Expires: {}", self.expires)?;
        if let Some(ref lang) = self.preferred_languages {
            writeln!(f, "Preferred-Languages: {lang}")?;
        }
        if let Some(ref c) = self.canonical {
            writeln!(f, "Canonical: {c}")?;
        }
        if let Some(ref p) = self.policy {
            writeln!(f, "Policy: {p}")?;
        }
        if let Some(ref h) = self.hiring {
            writeln!(f, "Hiring: {h}")?;
        }
        if let Some(ref e) = self.encryption {
            writeln!(f, "Encryption: {e}")?;
        }
        if let Some(ref a) = self.acknowledgments {
            writeln!(f, "Acknowledgments: {a}")?;
        }
        Ok(())
    }
}

pub async fn security_txt_endpoint() -> Response {
    let st = SecurityTxt::new("mailto:security@qid.example.com");
    (
        [("content-type", "text/plain; charset=utf-8")],
        st.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_txt_generates() {
        let st = SecurityTxt::new("mailto:security@example.com");
        let txt = st.to_string();
        assert!(txt.contains("Contact: mailto:security@example.com"));
        assert!(txt.contains("Expires: 2027-12-31"));
    }

    #[test]
    fn security_txt_full() {
        let st = SecurityTxt {
            contacts: vec!["https://example.com/.well-known/security".to_string()],
            expires: "2026-01-01T00:00:00Z".to_string(),
            preferred_languages: Some("en,ja".to_string()),
            canonical: Some("https://example.com/.well-known/security.txt".to_string()),
            policy: Some("https://example.com/security-policy".to_string()),
            hiring: Some("https://example.com/jobs".to_string()),
            encryption: Some("https://example.com/pgp-key.txt".to_string()),
            acknowledgments: Some("https://example.com/hall-of-fame".to_string()),
        };
        let txt = st.to_string();
        assert!(txt.contains("Canonical:"));
        assert!(txt.contains("Policy:"));
    }
}
