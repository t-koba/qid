//! Transaction-bound JWT (draft-transaction-tokens).

use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub tx: TransactionContext,
    pub cnf: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionContext {
    pub method: String,
    pub path: String,
    pub request: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
}

impl TransactionToken {
    pub fn new(iss: &str, sub: &str, aud: &str, method: &str, path: &str) -> Self {
        let now = qid_core::util::now_seconds();
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            exp: now + 300,
            iat: now,
            jti: ulid::Ulid::new().to_string(),
            tx: TransactionContext {
                method: method.to_string(),
                path: path.to_string(),
                request: None,
                resource: None,
                action: None,
            },
            cnf: None,
        }
    }

    pub fn with_cnf(mut self, cnf: serde_json::Value) -> Self {
        self.cnf = Some(cnf);
        self
    }

    pub fn encode(&self, signer: &dyn qid_core::jwt::Signer) -> QidResult<String> {
        let claims = qid_core::jwt::JwtClaims {
            iss: Some(self.iss.clone()),
            sub: Some(self.sub.clone()),
            aud: Some(self.aud.clone()),
            exp: Some(self.exp as usize),
            nbf: Some(self.iat as usize),
            iat: Some(self.iat as usize),
            jti: Some(self.jti.clone()),
            extra: std::collections::HashMap::from([(
                "tx".to_string(),
                serde_json::to_value(&self.tx).unwrap_or_default(),
            )]),
        };
        signer.sign(&claims).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_token_constructs() {
        let tt = TransactionToken::new(
            "https://as.example.com",
            "user-1",
            "api://resource",
            "POST",
            "/api/data",
        );
        assert_eq!(tt.tx.method, "POST");
        assert!(tt.jti.len() > 10);
    }

    #[test]
    fn transaction_context_serializes() {
        let ctx = TransactionContext {
            method: "GET".to_string(),
            path: "/api/resource".to_string(),
            request: None,
            resource: Some("urn:example:resource".to_string()),
            action: Some("read".to_string()),
        };
        let json = serde_json::to_value(&ctx).unwrap();
        assert_eq!(json["method"], "GET");
        assert_eq!(json["action"], "read");
    }
}
