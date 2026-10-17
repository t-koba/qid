//! SAML 2.0 IdP surface.
#![forbid(unsafe_code)]

use base64::Engine;
use qid_core::{
    error::{QidError, QidResult},
    models::{Session, User},
};
use serde::{Deserialize, Serialize};

mod artifact;
mod binding;
mod encryption;
mod metadata;
pub mod redirect_binding;
mod routes;
mod saml_document;
mod signature;
mod verification;
mod xml;
mod xmldsig;

pub use artifact::ARTIFACT_BINDING;
pub use encryption::{
    SamlEncryptionPlan, SamlEncryptionPolicy, apply_encrypted_assertion, decrypt_assertion_xml,
    decrypt_saml_response, encrypt_assertion_xml, encrypt_saml_response, plan_saml_encryption,
};
pub use metadata::{
    SamlMetadataAggregateImport, SamlMetadataImportRejection, SamlServiceProviderMetadata,
    import_sp_metadata, import_sp_metadata_aggregate, service_provider_from_config,
};
pub use routes::saml_routes;
pub(crate) use xml::*;

pub use signature::{
    SamlSignaturePlan, SamlSignatureTarget, SamlSigningPolicy, plan_saml_signatures,
    sign_saml_response_with_key, validate_authn_request_signature_profile,
};
pub use verification::{
    SamlSignatureInputs, SignedSamlElement, VerifiedSamlClaims, VerifiedSamlDocument,
    verify_saml_xml_signature_for,
};
pub use xmldsig::{
    SamlSigningElement, SamlXmlSignatureAlgorithm, cert_pem_to_public_key_pem_from_pem,
    sign_saml_document_with_key,
};

pub(crate) const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const EMAIL_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
pub const PERSISTENT_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const BEARER_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const PASSWORD_PROTECTED_TRANSPORT_AUTHN_CONTEXT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

pub use binding::*;

#[cfg(test)]
mod tests;
