//! The SPIFFE ID rule the product applies to every path that names one.
//!
//! A SPIFFE ID is `spiffe://<trust_domain>/<workload_identifier>`. The
//! rule lives here so a path that registers an identity and a path that
//! issues a certificate for it accept the same identities.

use crate::error::{QidError, QidResult};

/// The trust domain a SPIFFE ID names.
///
/// The ID must carry the `spiffe://` scheme, must name a trust domain, and
/// must carry neither whitespace nor a query, so an identity the product
/// accepts is one the product can issue a certificate for.
pub fn spiffe_trust_domain(spiffe_id: &str) -> QidResult<&str> {
    let rest = spiffe_id
        .strip_prefix("spiffe://")
        .ok_or_else(|| QidError::BadRequest {
            message: format!("SPIFFE ID {spiffe_id} is missing the spiffe:// scheme"),
        })?;
    if rest.chars().any(char::is_whitespace) {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID must not contain whitespace".to_string(),
        });
    }
    if rest.contains('?') {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID must not contain query parameters".to_string(),
        });
    }
    let domain = rest.split('/').next().unwrap_or_default();
    if domain.is_empty() {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID has an empty trust domain".to_string(),
        });
    }
    Ok(domain)
}

/// The trust domain a SPIFFE ID must name.
pub fn require_spiffe_trust_domain(spiffe_id: &str, trust_domain: &str) -> QidResult<()> {
    if spiffe_trust_domain(spiffe_id)? != trust_domain {
        return Err(QidError::BadRequest {
            message: "spiffe_id trust domain does not match trust_domain".to_string(),
        });
    }
    Ok(())
}

/// Whether a SPIFFE ID is well-formed.
pub fn validate_spiffe_id(spiffe_id: &str) -> QidResult<()> {
    spiffe_trust_domain(spiffe_id).map(|_| ())
}
