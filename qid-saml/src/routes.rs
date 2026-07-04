use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use qid_core::{models::Session, state::SharedState};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    ARTIFACT_BINDING, EMAIL_NAME_ID_FORMAT, SamlBrowserSubject, SamlPostBindingForm,
    SamlRelayStatePolicy, build_assertion_request_from_authn, build_saml_logout_post_response,
    build_saml_logout_response, build_saml_post_response, build_saml_response,
    parse_post_binding_authn_request, parse_post_binding_logout_request,
    service_provider_from_config, subject_from_browser_session, validate_authn_request_for_sp,
    validate_logout_request_for_sp,
};

pub fn saml_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/saml/:realm/metadata", get(metadata::<R>))
        .route("/saml/:realm/sso", post(sso::<R>))
        .route("/saml/:realm/slo", post(slo::<R>))
        .route("/saml/:realm/slo/initiate", get(slo_initiate::<R>))
        .route("/saml/:realm/artifact", post(artifact_resolve::<R>))
        .route("/saml/:realm/attribute-query", post(attribute_query::<R>))
}

async fn metadata<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if !realm_config.protocols.saml.enabled {
        return (StatusCode::NOT_FOUND, "saml disabled").into_response();
    }

    let entity_id = &realm_config.issuer;
    let sso_url = format!(
        "{}/saml/{}/sso",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm)
    );
    let slo_url = format!(
        "{}/saml/{}/slo",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm)
    );
    let artifact_url = format!(
        "{}/saml/{}/artifact",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm),
    );
    let metadata_id = format!("metadata-{}", ulid::Ulid::new());
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="{metadata_id}" entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
    <NameIDFormat>{EMAIL_NAME_ID_FORMAT}</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="{sso_url}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo_url}"/>
    <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="{artifact_url}" index="0"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#
    );
    if realm_config.protocols.saml.sign_metadata {
        let idp_descriptor = format!(
            r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
    <NameIDFormat>{EMAIL_NAME_ID_FORMAT}</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="{sso_url}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo_url}"/>
    <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="{artifact_url}" index="0"/>
  </IDPSSODescriptor>"#
        );
        let _ = idp_descriptor;
        let key_path = match realm_config
            .protocols
            .saml
            .idp_signing_key_pem_path
            .as_deref()
        {
            Some(path) => path,
            None => {
                return saml_config_error(
                    "SAML metadata signing requires idp_signing_key_pem_path",
                );
            }
        };
        let private_key_pem = match std::fs::read(key_path) {
            Ok(key) => key,
            Err(e) => {
                return saml_config_error(&format!(
                    "failed to read SAML metadata signing key: {e}"
                ));
            }
        };
        match crate::signature::build_saml_element_signature_with_key(
            &xml,
            "EntityDescriptor",
            &metadata_id,
            &private_key_pem,
            None,
            crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256,
        ) {
            Ok(sig) => {
                xml = xml.replace(
                    "  <IDPSSODescriptor",
                    &format!("{sig}\n  <IDPSSODescriptor"),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "metadata_signing_failed",
                        "message": e.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }
    (
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        xml,
    )
        .into_response()
}

fn saml_config_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

pub(crate) fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (cookie_name, cookie_value) = part.trim().split_once('=')?;
        (cookie_name == name).then(|| cookie_value.to_string())
    })
}

pub(crate) fn is_active_session_for_realm(session: &Session, realm: &str) -> bool {
    let now = qid_core::util::now_seconds();
    session.realm_id == realm
        && !session.revoked
        && session.idle_expires_at >= now
        && session.absolute_expires_at >= now
}

async fn sso<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SamlPostBindingForm>,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if realm_config.protocols.saml.enabled {
        let expected_destination = format!(
            "{}/saml/{}/sso",
            state.plan.public_base_url.trim_end_matches('/'),
            urlencoding::encode(&realm)
        );
        let req = match parse_post_binding_authn_request(&form, &SamlRelayStatePolicy::default()) {
            Ok(req) => req,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_saml_request",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let Some(sp_config) = realm_config
            .protocols
            .saml
            .service_providers
            .iter()
            .find(|sp| sp.entity_id == req.issuer)
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "untrusted_saml_service_provider",
                    "message": "SAML AuthnRequest issuer is not configured for this realm",
                    "request_id": req.id,
                    "issuer": req.issuer,
                })),
            )
                .into_response();
        };
        let sp = service_provider_from_config(sp_config);
        if let Err(err) = validate_authn_request_for_sp(&req, &sp, Some(&expected_destination)) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_saml_request",
                    "message": err.to_string(),
                    "request_id": req.id,
                    "issuer": req.issuer,
                })),
            )
                .into_response();
        }
        let Some(runtime_realm) = state.realm(&realm) else {
            return (StatusCode::NOT_FOUND, "realm not found").into_response();
        };
        let Some(session_id) = extract_cookie(&headers, &runtime_realm.browser_session.cookie_name)
        else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "saml_authentication_required",
                    "message": "SAML SSO requires an authenticated browser session",
                    "request_id": req.id,
                    "issuer": req.issuer,
                })),
            )
                .into_response();
        };
        let session = match state.repo.get_session(&session_id).await {
            Ok(Some(session)) if is_active_session_for_realm(&session, &realm) => session,
            Ok(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "saml_authentication_required",
                        "message": "SAML SSO session is invalid or expired",
                        "request_id": req.id,
                        "issuer": req.issuer,
                    })),
                )
                    .into_response();
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "saml_session_lookup_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let user = match state.repo.get_user_by_id(&session.user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "saml_authentication_required",
                        "message": "SAML SSO session subject no longer exists",
                        "request_id": req.id,
                        "issuer": req.issuer,
                    })),
                )
                    .into_response();
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "saml_user_lookup_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let subject = subject_from_browser_session(&SamlBrowserSubject { session, user });
        let assertion_req = match build_assertion_request_from_authn(
            &req,
            &sp,
            &realm_config.issuer,
            subject,
            qid_core::util::now_seconds(),
            300,
            Some(session_id),
        ) {
            Ok(req) => req,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_saml_request",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let issued = match build_saml_response(&assertion_req) {
            Ok(issued) => {
                metrics::counter!("qid_saml_assertions_issued_total").increment(1);
                issued
            }
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "saml_response_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let issued = if realm_config.protocols.saml.encrypt_assertions.as_deref()
            == Some("required")
            || realm_config.protocols.saml.encrypt_assertions.as_deref() == Some("optional")
        {
            if let Some(encryption_cert) = sp_config.encryption_certificates.first() {
                match crate::encryption::encrypt_saml_response(&issued, encryption_cert) {
                    Ok(encrypted) => encrypted,
                    Err(err) => {
                        if realm_config.protocols.saml.encrypt_assertions.as_deref()
                            == Some("required")
                        {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": "saml_encryption_failed",
                                    "message": err.to_string(),
                                })),
                            )
                                .into_response();
                        }
                        tracing::warn!(
                            "SAML assertion encryption failed for SP {}: {err}",
                            sp_config.entity_id
                        );
                        issued
                    }
                }
            } else {
                if realm_config.protocols.saml.encrypt_assertions.as_deref() == Some("required") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "saml_encryption_required",
                            "message": "SAML encrypted assertion requires SP encryption certificate"
                        })),
                    )
                        .into_response();
                }
                issued
            }
        } else {
            issued
        };
        let should_sign = realm_config.protocols.saml.sign_assertions || sp.want_assertions_signed;
        let issued = if should_sign {
            let signing_policy = crate::SamlSigningPolicy {
                sign_response: true,
                sign_assertion: true,
            };
            let Some(key_path) = realm_config
                .protocols
                .saml
                .idp_signing_key_pem_path
                .as_deref()
            else {
                return saml_config_error(
                    "SAML response signing requires idp_signing_key_pem_path",
                );
            };
            let private_key_pem = match std::fs::read(key_path) {
                Ok(key) => key,
                Err(err) => {
                    return saml_config_error(&format!(
                        "failed to read SAML response signing key: {err}"
                    ));
                }
            };
            let signing_result = crate::signature::sign_saml_response_with_key(
                &issued,
                &sp,
                &signing_policy,
                &private_key_pem,
                None,
                crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256,
            );
            match signing_result {
                Ok(signed) => signed,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "saml_signing_failed",
                            "message": err.to_string(),
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            issued
        };
        let uses_artifact = req.protocol_binding.as_deref() == Some(ARTIFACT_BINDING);
        if uses_artifact {
            let artifact = crate::artifact::store_artifact(&issued.xml, 300);
            let redirect = format!(
                "{}?SAMLart={}&RelayState={}",
                sp.acs_url,
                urlencoding::encode(&artifact.artifact),
                req.relay_state
                    .as_deref()
                    .map(urlencoding::encode)
                    .unwrap_or_default(),
            );
            (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, redirect.as_str())],
            )
                .into_response()
        } else {
            let post_response =
                build_saml_post_response(&issued, &sp.acs_url, req.relay_state.as_deref());
            (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                post_response.html,
            )
                .into_response()
        }
    } else {
        (StatusCode::NOT_FOUND, "saml disabled").into_response()
    }
}

async fn slo<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Form(form): Form<SamlPostBindingForm>,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if !realm_config.protocols.saml.enabled {
        return (StatusCode::NOT_FOUND, "saml disabled").into_response();
    }
    let expected_destination = format!(
        "{}/saml/{}/slo",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm)
    );
    let req = match parse_post_binding_logout_request(&form, &SamlRelayStatePolicy::default()) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_saml_logout_request",
                    "message": err.to_string(),
                })),
            )
                .into_response();
        }
    };
    let Some(sp_config) = realm_config
        .protocols
        .saml
        .service_providers
        .iter()
        .find(|sp| sp.entity_id == req.issuer)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "untrusted_saml_service_provider",
                "message": "SAML LogoutRequest issuer is not configured for this realm",
                "request_id": req.id,
                "issuer": req.issuer,
            })),
        )
            .into_response();
    };
    let sp = service_provider_from_config(sp_config);
    if let Err(err) = validate_logout_request_for_sp(&req, &sp, Some(&expected_destination)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_saml_logout_request",
                "message": err.to_string(),
                "request_id": req.id,
                "issuer": req.issuer,
            })),
        )
            .into_response();
    }
    let mut revoked_sessions = Vec::new();
    for session_index in &req.session_indexes {
        match state.repo.get_session(session_index).await {
            Ok(Some(session)) if session.realm_id == realm => {
                if let Err(err) = state.repo.revoke_session(session_index).await {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "saml_logout_failed",
                            "message": err.to_string(),
                        })),
                    )
                        .into_response();
                }
                revoked_sessions.push(session_index.clone());
            }
            Ok(_) => {}
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "saml_logout_lookup_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }
    if let Some(slo_url) = &sp.slo_url {
        let issued = match build_saml_logout_response(
            &realm_config.issuer,
            slo_url,
            &req.id,
            qid_core::util::now_seconds(),
        ) {
            Ok(issued) => issued,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "saml_logout_response_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        };
        let post_response =
            build_saml_logout_post_response(&issued, slo_url, req.relay_state.as_deref());
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            post_response.html,
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": "logout_received",
            "request_id": req.id,
            "issuer": req.issuer,
            "name_id": req.name_id,
            "revoked_sessions": revoked_sessions,
            "response": "no_sp_slo_url",
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct SloInitiateQuery {
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn slo_initiate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SloInitiateQuery>,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if !realm_config.protocols.saml.enabled {
        return (StatusCode::NOT_FOUND, "saml disabled").into_response();
    }
    let Some(runtime_realm) = state.realm(&realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    let session_id = match extract_cookie(&headers, &runtime_realm.browser_session.cookie_name) {
        Some(cookie_session_id) => cookie_session_id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "saml_logout_required",
                    "message": "SAML SLO initiation requires an authenticated browser session",
                })),
            )
                .into_response();
        }
    };
    if let Some(redirect_uri) = &query.redirect_uri {
        match state.repo.list_clients(&realm.clone().into()).await {
            Ok(clients)
                if clients.iter().any(|client| {
                    client
                        .post_logout_redirect_uris
                        .iter()
                        .any(|registered| registered == redirect_uri)
                }) => {}
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_redirect_uri",
                        "message": "post logout redirect_uri is not registered",
                    })),
                )
                    .into_response();
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "saml_client_lookup_failed",
                        "message": err.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }
    let session = match state.repo.get_session(&session_id).await {
        Ok(Some(session))
            if session.realm_id == realm
                && !session.revoked
                && session.idle_expires_at > qid_core::util::now_seconds()
                && session.absolute_expires_at > qid_core::util::now_seconds() =>
        {
            session
        }
        Ok(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "saml_logout_required",
                    "message": "session is invalid or expired",
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "saml_session_lookup_failed",
                    "message": err.to_string(),
                })),
            )
                .into_response();
        }
    };
    if let Err(err) = state.repo.revoke_session(&session.id).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "saml_logout_failed",
                "message": err.to_string(),
            })),
        )
            .into_response();
    }
    if let Some(redirect_uri) = &query.redirect_uri {
        return Redirect::to(redirect_uri).into_response();
    }
    let slo_sp = realm_config
        .protocols
        .saml
        .service_providers
        .iter()
        .find(|sp| sp.slo_url.is_some());
    if let Some(sp) = slo_sp
        && let Some(slo_url) = &sp.slo_url
    {
        return Redirect::to(slo_url).into_response();
    }
    Json(serde_json::json!({
        "result": "logged_out",
        "session_id": session.id,
        "user_id": session.user_id,
    }))
    .into_response()
}

async fn artifact_resolve<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if !realm_config.protocols.saml.enabled {
        return (StatusCode::NOT_FOUND, "saml disabled").into_response();
    }
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_utf8",
                    "message": "SOAP request body must be valid UTF-8"
                })),
            )
                .into_response();
        }
    };
    let resolve = match crate::artifact::parse_artifact_resolve(body_str) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_artifact_resolve",
                    "message": e.to_string(),
                })),
            )
                .into_response();
        }
    };
    let saml_response = match crate::artifact::resolve_artifact(&resolve.artifact) {
        Ok(response) => response,
        Err(e) => {
            let error_xml = artifact_error_soap(&resolve.id, &realm_config.issuer, e.to_string());
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                error_xml,
            )
                .into_response();
        }
    };
    let soap =
        crate::artifact::build_artifact_response(&resolve.id, &realm_config.issuer, &saml_response);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
        soap,
    )
        .into_response()
}

async fn attribute_query<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(realm_config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return (StatusCode::NOT_FOUND, "realm not found").into_response();
    };
    if !realm_config.protocols.saml.enabled {
        return (StatusCode::NOT_FOUND, "saml disabled").into_response();
    }
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_utf8",
                    "message": "SOAP request body must be valid UTF-8"
                })),
            )
                .into_response();
        }
    };
    let query = match crate::attribute_query::parse_attribute_query(body_str) {
        Ok(q) => q,
        Err(e) => {
            let error_xml = crate::attribute_query::attribute_query_error_soap(
                "unknown",
                &realm_config.issuer,
                "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
                &e.to_string(),
            );
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                error_xml,
            )
                .into_response();
        }
    };
    let sp_config = realm_config
        .protocols
        .saml
        .service_providers
        .iter()
        .find(|sp| sp.entity_id == query.issuer)
        .cloned();
    let Some(sp_config) = sp_config else {
        let error_xml = crate::attribute_query::attribute_query_error_soap(
            &query.id,
            &realm_config.issuer,
            "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            "untrusted SAML service provider",
        );
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
            error_xml,
        )
            .into_response();
    };
    let user = {
        let is_email = query.name_id_format.as_deref() == Some(crate::EMAIL_NAME_ID_FORMAT);
        if is_email {
            match state
                .repo
                .get_user_by_email(&qid_core::tenant::RealmId(realm.clone()), &query.name_id)
                .await
            {
                Ok(Some(u)) => u,
                Ok(None) => {
                    let error_xml = crate::attribute_query::attribute_query_error_soap(
                        &query.id,
                        &realm_config.issuer,
                        "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
                        "user not found",
                    );
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                        error_xml,
                    )
                        .into_response();
                }
                Err(e) => {
                    let error_xml = crate::attribute_query::attribute_query_error_soap(
                        &query.id,
                        &realm_config.issuer,
                        "urn:oasis:names:tc:SAML:2.0:status:Responder",
                        &e.to_string(),
                    );
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                        error_xml,
                    )
                        .into_response();
                }
            }
        } else {
            match state.repo.get_user_by_id(&query.name_id).await {
                Ok(Some(u)) => u,
                Ok(None) => {
                    let error_xml = crate::attribute_query::attribute_query_error_soap(
                        &query.id,
                        &realm_config.issuer,
                        "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
                        "user not found",
                    );
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                        error_xml,
                    )
                        .into_response();
                }
                Err(e) => {
                    let error_xml = crate::attribute_query::attribute_query_error_soap(
                        &query.id,
                        &realm_config.issuer,
                        "urn:oasis:names:tc:SAML:2.0:status:Responder",
                        &e.to_string(),
                    );
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
                        error_xml,
                    )
                        .into_response();
                }
            }
        }
    };
    let allowed = |name: &str| -> bool {
        sp_config.attribute_release_policy.is_empty()
            || sp_config
                .attribute_release_policy
                .contains(&name.to_string())
    };
    let mut attributes_xml = String::new();
    if let Some(email) = &user.email
        && allowed("email")
    {
        push_saml_attribute(&mut attributes_xml, "email", email);
    }
    if let Some(display_name) = &user.display_name
        && allowed("displayName")
    {
        push_saml_attribute(&mut attributes_xml, "displayName", display_name);
    }
    let soap = crate::attribute_query::build_attribute_query_response(
        &query.id,
        &realm_config.issuer,
        &attributes_xml,
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
        soap,
    )
        .into_response()
}

fn push_saml_attribute(xml: &mut String, name: &str, value: &str) {
    xml.push_str(&format!(
        r#"<saml:Attribute Name="{}"><saml:AttributeValue>{}</saml:AttributeValue></saml:Attribute>"#,
        xml_escape(name),
        xml_escape(value),
    ));
}

fn artifact_error_soap(in_response_to: &str, issuer: &str, error_message: String) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
        <samlp:StatusMessage>{}</samlp:StatusMessage>
      </samlp:Status>
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        crate::artifact::iso_now_utc(),
        in_response_to,
        issuer,
        xml_escape(&error_message),
    )
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
