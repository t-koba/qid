//! OAuth mTLS sender-constrained token helpers.

use axum::http::{HeaderMap, HeaderValue};
use qid_core::{
    error::{QidError, QidResult},
    state::SharedState,
};
use qid_storage::prelude::*;

const MTLS_ADAPTER_AUTHORIZATION_HEADER: &str = "x-qid-pep-adapter-authorization";
const MTLS_THUMBPRINT_HEADER: &str = "x-qid-mtls-x5t-s256";
const NATIVE_MTLS_THUMBPRINT_HEADER: &str = "x-qid-native-mtls-x5t-s256";
const NATIVE_MTLS_PROOF_HEADER: &str = "x-qid-native-mtls-proof";

/// Replace any caller-controlled native mTLS metadata with authenticated metadata.
///
/// This function must run at the outer HTTP boundary. The proof is bound to the
/// process-local `SharedState`, so raw headers supplied by a client cannot be
/// mistaken for a certificate authenticated by the TLS stack.
pub fn bind_native_mtls_headers<R: Repository>(
    headers: &mut HeaderMap,
    state: &SharedState<R>,
    thumbprint: Option<&str>,
) -> QidResult<()> {
    headers.remove(NATIVE_MTLS_THUMBPRINT_HEADER);
    headers.remove(NATIVE_MTLS_PROOF_HEADER);

    let Some(thumbprint) = thumbprint else {
        return Ok(());
    };
    let proof = state.native_mtls_metadata_proof(thumbprint);
    headers.insert(
        NATIVE_MTLS_THUMBPRINT_HEADER,
        HeaderValue::from_str(thumbprint).map_err(|error| QidError::Internal {
            message: format!("failed to bind native mTLS certificate thumbprint: {error}"),
        })?,
    );
    headers.insert(
        NATIVE_MTLS_PROOF_HEADER,
        HeaderValue::from_str(&proof).map_err(|error| QidError::Internal {
            message: format!("failed to bind native mTLS metadata proof: {error}"),
        })?,
    );
    Ok(())
}

pub fn extract_mtls_x5t_s256<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> QidResult<Option<String>> {
    if let Some(thumbprint) = authenticated_native_thumbprint(headers, state)? {
        return Ok(Some(thumbprint));
    }
    if !headers.contains_key(MTLS_ADAPTER_AUTHORIZATION_HEADER)
        && !headers.contains_key(MTLS_THUMBPRINT_HEADER)
    {
        return Ok(None);
    }

    let token = bearer_token_from_header(headers, MTLS_ADAPTER_AUTHORIZATION_HEADER).ok_or_else(
        || QidError::Unauthorized {
            message: "OAuth mTLS requires native peer certificate binding or authenticated PEP mTLS metadata"
                .to_string(),
        },
    )?;
    let mut authenticated_thumbprint = None;
    for adapter in state
        .config
        .realms
        .iter()
        .flat_map(|realm| realm.pep_registrations.registrations.iter())
    {
        let Some(audience) = adapter.audience.as_deref() else {
            continue;
        };
        if let Ok(decoded) = state.signer.decode_with_aud(token, audience)
            && decoded.claims.sub.as_deref() == Some(adapter.name.as_str())
        {
            authenticated_thumbprint = decoded
                .claims
                .extra
                .get("x5t#S256")
                .or_else(|| decoded.claims.extra.get("x5t_s256"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            break;
        }
    }
    let Some(bound_thumbprint) = authenticated_thumbprint else {
        return Err(QidError::Unauthorized {
            message: "invalid or unbound PEP mTLS metadata adapter authentication".to_string(),
        });
    };
    let x5t_s256 = headers
        .get(MTLS_THUMBPRINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: "authenticated PEP mTLS metadata is missing x5t#S256".to_string(),
        })?;
    if !qid_core::util::constant_time_eq(x5t_s256.as_bytes(), bound_thumbprint.as_bytes()) {
        return Err(QidError::Unauthorized {
            message: "PEP mTLS metadata thumbprint does not match adapter assertion".to_string(),
        });
    }
    Ok(Some(x5t_s256.to_string()))
}

fn authenticated_native_thumbprint<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> QidResult<Option<String>> {
    let thumbprint = headers
        .get(NATIVE_MTLS_THUMBPRINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let proof = headers
        .get(NATIVE_MTLS_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (thumbprint, proof) {
        (None, None) => Ok(None),
        (Some(thumbprint), Some(proof)) if state.verify_native_mtls_metadata(thumbprint, proof) => {
            Ok(Some(thumbprint.to_string()))
        }
        _ => Err(QidError::Unauthorized {
            message: "invalid native mTLS peer metadata".to_string(),
        }),
    }
}

fn bearer_token_from_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.contains(' ')).then_some(token)
}
