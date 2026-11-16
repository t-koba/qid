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
        let mut extra = std::collections::HashMap::from([(
            "tx".to_string(),
            serde_json::to_value(&self.tx).unwrap_or_default(),
        )]);
        if let Some(cnf) = &self.cnf {
            extra.insert("cnf".to_string(), cnf.clone());
        }
        let claims = qid_core::jwt::JwtClaims {
            iss: Some(self.iss.clone()),
            sub: Some(self.sub.clone()),
            aud: Some(qid_core::jwt::Audience::single(self.aud.clone())),
            exp: Some(self.exp as usize),
            nbf: Some(self.iat as usize),
            iat: Some(self.iat as usize),
            jti: Some(self.jti.clone()),
            extra,
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
    fn encoded_transaction_token_preserves_optional_confirmation() {
        use qid_core::jwt::Signer;

        let key = qid_crypto::jwk::generate_es256("transaction-test").unwrap();
        let signer =
            qid_crypto::LocalSigner::from_ec_pem("transaction-test", key.private_pem.as_bytes())
                .unwrap();
        for cnf in [None, Some(serde_json::json!({"jkt": "key-thumbprint"}))] {
            let mut tt = TransactionToken::new(
                "https://as.example.com",
                "user-1",
                "api://resource",
                "POST",
                "/api/data",
            );
            if let Some(cnf) = &cnf {
                tt = tt.with_cnf(cnf.clone());
            }
            let token = tt.encode(&signer).unwrap();
            let decoded = signer.decode_with_aud(&token, &tt.aud).unwrap();
            let claims = serde_json::to_value(decoded.claims).unwrap();
            let mut expected = serde_json::json!({
                "iss": tt.iss,
                "sub": tt.sub,
                "aud": tt.aud,
                "exp": tt.exp,
                "nbf": tt.iat,
                "iat": tt.iat,
                "jti": tt.jti,
                "tx": tt.tx,
            });
            if let Some(cnf) = cnf {
                expected["cnf"] = cnf;
            } else {
                assert!(claims.get("cnf").is_none());
            }
            assert_eq!(claims, expected);
        }
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
