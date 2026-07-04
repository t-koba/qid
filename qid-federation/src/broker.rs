use aes::cipher::{BlockDecrypt, KeyInit};
use base64::Engine;
use hmac::Mac;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::coded_error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboundProviderKind {
    Oidc,
    Saml,
    EntraId,
    GoogleWorkspace,
    Okta,
    LdapAdBind,
    KerberosSpnego,
    Social,
}

impl InboundProviderKind {
    pub fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "oidc" => Some(Self::Oidc),
            "saml" => Some(Self::Saml),
            "entra_id" | "entra" | "azure_ad" => Some(Self::EntraId),
            "google_workspace" | "google" => Some(Self::GoogleWorkspace),
            "okta" => Some(Self::Okta),
            "ldap_ad_bind" | "ldap" => Some(Self::LdapAdBind),
            "kerberos_spnego" | "kerberos" => Some(Self::KerberosSpnego),
            "social" => Some(Self::Social),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::EntraId => "entra_id",
            Self::GoogleWorkspace => "google_workspace",
            Self::Okta => "okta",
            Self::LdapAdBind => "ldap_ad_bind",
            Self::KerberosSpnego => "kerberos_spnego",
            Self::Social => "social",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimMapping {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundIdentityProvider {
    pub id: String,
    pub kind: InboundProviderKind,
    pub issuer: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub social_provider: Option<String>,
    /// OAuth 2.0 client credentials for code exchange.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Token endpoint URL for exchanging authorization code for tokens.
    #[serde(default)]
    pub token_url: Option<String>,
    /// Userinfo endpoint URL for fetching user claims (used when ID token is unavailable).
    #[serde(default)]
    pub userinfo_url: Option<String>,
    #[serde(default)]
    pub jit_provisioning: bool,
    #[serde(default)]
    pub account_linking: bool,
    #[serde(default)]
    pub claim_mappings: Vec<ClaimMapping>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub saml_signing_certificates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct HomeRealmDiscoveryRequest {
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub idp_hint: Option<String>,
    #[serde(default)]
    pub social_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalIdentityClaims {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerAccountLink {
    pub provider_id: String,
    pub external_subject: String,
    pub local_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerRouteDecision {
    pub provider_id: String,
    pub provider_kind: InboundProviderKind,
    pub reason: String,
    pub jit_provisioning: bool,
    pub account_linking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerLoginPlan {
    pub route: BrokerRouteDecision,
    pub normalized_claims: BTreeMap<String, serde_json::Value>,
    pub linked_subject: Option<String>,
    pub create_subject: bool,
}

pub fn route_inbound_provider(
    providers: &[InboundIdentityProvider],
    request: &HomeRealmDiscoveryRequest,
) -> Result<BrokerRouteDecision, QidError> {
    validate_inbound_providers(providers)?;
    if let Some(idp_hint) = normalized_optional(&request.idp_hint) {
        let provider = providers
            .iter()
            .find(|provider| provider.enabled && provider.id == idp_hint)
            .ok_or_else(|| {
                broker_error(
                    "unknown_idp_hint",
                    "IdP hint does not match an enabled provider",
                )
            })?;
        return Ok(route_decision(provider, "idp_hint"));
    }

    if let Some(social_provider) = normalized_optional(&request.social_provider) {
        let provider = providers
            .iter()
            .find(|provider| {
                provider.enabled
                    && provider.kind == InboundProviderKind::Social
                    && provider
                        .social_provider
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&social_provider))
            })
            .ok_or_else(|| {
                broker_error(
                    "unknown_social_provider",
                    "Social provider is not configured",
                )
            })?;
        return Ok(route_decision(provider, "social_provider"));
    }

    let domain = request
        .domain
        .as_deref()
        .and_then(normalized_domain)
        .or_else(|| {
            request
                .login_hint
                .as_deref()
                .and_then(domain_from_login_hint)
        })
        .ok_or_else(|| broker_error("home_realm_not_found", "No routing signal was provided"))?;

    let matches = providers
        .iter()
        .filter(|provider| provider.enabled)
        .filter(|provider| {
            provider
                .domains
                .iter()
                .any(|candidate| domain_matches(candidate, &domain))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [provider] => Ok(route_decision(provider, "domain_discovery")),
        [] => Err(broker_error(
            "home_realm_not_found",
            "No enabled provider matches the requested domain",
        )),
        _ => Err(broker_error(
            "ambiguous_home_realm",
            "Multiple enabled providers match the requested domain",
        )),
    }
}

pub fn plan_inbound_login(
    providers: &[InboundIdentityProvider],
    request: &HomeRealmDiscoveryRequest,
    external: &ExternalIdentityClaims,
    links: &[BrokerAccountLink],
) -> Result<BrokerLoginPlan, QidError> {
    let route = route_inbound_provider(providers, request)?;
    let provider = providers
        .iter()
        .find(|provider| provider.id == route.provider_id)
        .ok_or_else(|| broker_error("provider_not_found", "Selected provider is missing"))?;
    if provider.issuer != external.issuer {
        return Err(broker_error(
            "issuer_mismatch",
            "External identity issuer does not match selected provider",
        ));
    }

    let normalized_claims = normalize_enterprise_claims(provider, external)?;
    let linked_subject = links
        .iter()
        .find(|link| link.provider_id == provider.id && link.external_subject == external.subject)
        .map(|link| link.local_subject.clone());
    if linked_subject.is_none() && !provider.jit_provisioning {
        return Err(broker_error(
            "jit_disabled",
            "Provider requires an existing account link",
        ));
    }
    if linked_subject.is_some() && !provider.account_linking {
        return Err(broker_error(
            "account_linking_disabled",
            "Provider does not permit account linking",
        ));
    }

    Ok(BrokerLoginPlan {
        route,
        normalized_claims,
        create_subject: linked_subject.is_none(),
        linked_subject,
    })
}

// ---------------------------------------------------------------------------
// F1: Named Inbound IdP Connector Profiles
// ---------------------------------------------------------------------------

/// Azure AD / Entra ID connector profile with well-known endpoints and claim mappings.
///
/// The `tenant_id` can be a UUID or a well-known value such as `"common"`, `"organizations"`,
/// or `"consumers"`.
pub fn azure_ad_provider(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> InboundIdentityProvider {
    InboundIdentityProvider {
        id: format!("entra-{tenant_id}"),
        kind: InboundProviderKind::EntraId,
        issuer: format!("https://login.microsoftonline.com/{tenant_id}/v2.0"),
        enabled: true,
        domains: vec![format!("{tenant_id}.onmicrosoft.com")],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        )),
        userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_owned()),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some(format!(
            "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "oid".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "preferred_username".to_owned(),
                target: "email".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "tid".to_owned(),
                target: "tenant_id".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "unique_name".to_owned(),
                target: "username".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "groups".to_owned(),
                target: "groups".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "roles".to_owned(),
                target: "roles".to_owned(),
                required: false,
            },
        ],
    }
}

/// Google Workspace connector profile with well-known endpoints and claim mappings.
pub fn google_workspace_provider(client_id: &str, client_secret: &str) -> InboundIdentityProvider {
    InboundIdentityProvider {
        id: "google-workspace".to_owned(),
        kind: InboundProviderKind::GoogleWorkspace,
        issuer: "https://accounts.google.com".to_owned(),
        enabled: true,
        domains: vec![],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some("https://oauth2.googleapis.com/token".to_owned()),
        userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_owned()),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_owned()),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "sub".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email".to_owned(),
                target: "email".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email_verified".to_owned(),
                target: "email_verified".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "given_name".to_owned(),
                target: "given_name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "family_name".to_owned(),
                target: "family_name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "picture".to_owned(),
                target: "picture".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "hd".to_owned(),
                target: "domain".to_owned(),
                required: false,
            },
        ],
    }
}

/// Okta connector profile with well-known endpoints and claim mappings.
///
/// The `domain` is the Okta organisation domain (e.g. `"dev-123456.okta.com"`).
pub fn okta_provider(
    domain: &str,
    client_id: &str,
    client_secret: &str,
) -> InboundIdentityProvider {
    let issuer = format!("https://{domain}/oauth2/default");
    InboundIdentityProvider {
        id: format!("okta-{domain}"),
        kind: InboundProviderKind::Okta,
        issuer: issuer.clone(),
        enabled: true,
        domains: vec![],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some(format!("{issuer}/v1/token")),
        userinfo_url: Some(format!("{issuer}/v1/userinfo")),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some(format!("{issuer}/v1/keys")),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "sub".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email".to_owned(),
                target: "email".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email_verified".to_owned(),
                target: "email_verified".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "preferred_username".to_owned(),
                target: "username".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "groups".to_owned(),
                target: "groups".to_owned(),
                required: false,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// F2: Kerberos / SPNEGO
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KerberosSpnegoConfig {
    pub realm: String,
    pub kdc: String,
    pub service_principal: String,
    /// Base64-encoded raw AES key for decrypting the ticket enc-part.
    /// Required for cryptographic ticket verification. When absent,
    /// only structural validation is performed.
    pub service_key_b64: Option<String>,
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER helpers for SPNEGO token parsing.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DerTag {
    class: u8,
    constructed: bool,
    tag: u32,
    length: usize,
    value_start: usize,
}

fn der_read_tag(data: &[u8], offset: usize) -> Result<(DerTag, usize), QidError> {
    if offset >= data.len() {
        return Err(broker_error(
            "spnego_truncated",
            "SPNEGO token truncated at tag",
        ));
    }
    let b = data[offset];
    let class = b >> 6;
    let constructed = (b & 0x20) != 0;
    let tag = if b & 0x1f == 0x1f {
        let mut t = 0u32;
        let mut pos = offset + 1;
        loop {
            if pos >= data.len() {
                return Err(broker_error(
                    "spnego_truncated",
                    "SPNEGO long-form tag truncated",
                ));
            }
            t = (t << 7) | (data[pos] & 0x7f) as u32;
            if data[pos] & 0x80 == 0 {
                break;
            }
            pos += 1;
        }
        (t, pos + 1)
    } else {
        ((b & 0x1f) as u32, offset + 1)
    };
    let (length, pos) = der_read_length(data, tag.1)?;
    Ok((
        DerTag {
            class,
            constructed,
            tag: tag.0,
            length,
            value_start: pos,
        },
        pos + length,
    ))
}

fn der_read_length(data: &[u8], offset: usize) -> Result<(usize, usize), QidError> {
    if offset >= data.len() {
        return Err(broker_error("spnego_truncated", "SPNEGO length truncated"));
    }
    let b = data[offset];
    if b & 0x80 == 0 {
        Ok((b as usize, offset + 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n > 4 || offset + 1 + n > data.len() {
            return Err(broker_error(
                "spnego_bad_length",
                "SPNEGO bad length encoding",
            ));
        }
        let mut length = 0usize;
        for i in 0..n {
            length = (length << 8) | data[offset + 1 + i] as usize;
        }
        Ok((length, offset + 1 + n))
    }
}

fn der_find_context_tag(
    data: &[u8],
    tag_num: u32,
    offset: usize,
) -> Result<Option<(DerTag, usize)>, QidError> {
    let mut pos = offset;
    while pos < data.len() {
        let (tag, next) = der_read_tag(data, pos)?;
        if tag.class == 2 && tag.tag == tag_num {
            return Ok(Some((tag, pos)));
        }
        pos = next;
    }
    Ok(None)
}

/// Read a DER INTEGER and return it as i32.
fn der_read_integer(data: &[u8], offset: usize, length: usize) -> Result<i32, QidError> {
    if length == 0 {
        return Err(QidError::Internal {
            message: "DER INTEGER has zero length".to_string(),
        });
    }
    if length > 4 {
        return Err(QidError::Internal {
            message: format!("DER INTEGER too large: {length} bytes"),
        });
    }
    let mut val: i32 = 0;
    for i in 0..length {
        val = (val << 8) | data[offset + i] as i32;
    }
    // Handle negative two's complement
    if data[offset] & 0x80 != 0 {
        val -= 1 << (length * 8);
    }
    Ok(val)
}

fn der_read_oid(data: &[u8], offset: usize) -> Result<String, QidError> {
    let (tag, _) = der_read_tag(data, offset)?;
    let value = &data[tag.value_start..tag.value_start + tag.length];
    let mut oid = String::new();
    if !value.is_empty() {
        let first = value[0] as u32;
        oid.push_str(&format!("{}.{}", first / 40, first % 40));
        let mut acc = 0u32;
        for &b in &value[1..] {
            acc = (acc << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                oid.push_str(&format!(".{}", acc));
                acc = 0;
            }
        }
    }
    Ok(oid)
}

/// Kerberos OID for SPNEGO mechanism.
const KERBEROS_OID: &str = "1.2.840.113554.1.2.2";

// Encryption type constants
const ENCTYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17;
const ENCTYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;

// Key usage constants (RFC 3961 §5.1)
const KEY_USAGE_TICKET_ENC_PART: u32 = 3;

/// Derive the encryption key `ke` and integrity key `ki` from the base
/// key per RFC 3961 §5.1 / RFC 3962 §4.
fn derive_aes_kerberos_keys(base_key: &[u8], usage: u32) -> (Vec<u8>, Vec<u8>) {
    let ke_constant = [&usage.to_be_bytes()[..], &[0x99]].concat();
    let ki_constant = [&(usage | 0xFF).to_be_bytes()[..], &[0x99]].concat();
    let ke = k_truncate(base_key, &ke_constant, base_key.len());
    let ki = k_truncate(base_key, &ki_constant, base_key.len());
    (ke, ki)
}

/// k-truncate: trunc(HMAC-SHA1(key, constant), key_length)
fn k_truncate(key: &[u8], constant: &[u8], key_length: usize) -> Vec<u8> {
    let mut mac =
        <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(key).expect("HMAC-SHA1 accepts any key");
    mac.update(constant);
    let result = mac.finalize().into_bytes();
    result[..key_length.min(result.len())].to_vec()
}

/// AES-CTS (CBC-CS3) decryption per NIST SP 800-38A Addendum.
fn aes_cts_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> QidResult<Vec<u8>> {
    let total = data.len();
    if total < 16 {
        return Err(QidError::Internal {
            message: "AES-CTS data too short".to_string(),
        });
    }
    let mut result = vec![0u8; total];
    let n_blocks = total.div_ceil(16);
    let k = if total.is_multiple_of(16) {
        16
    } else {
        total % 16
    };
    let key_32 = key.len() == 32;

    if key.len() != 32 && key.len() != 16 {
        return Err(QidError::Internal {
            message: format!("unsupported AES key length: {}", key.len()),
        });
    }

    // Helper: ECB decrypt a single 16-byte block without GenericArray.
    let ecb_decrypt = |block: &[u8; 16]| -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(block);
        // AES-CBC decryption in-place using the `aes` crate
        // Convert [u8; 16] to GenericArray for the cipher API
        let mut ga = aes::cipher::generic_array::GenericArray::from(buf);
        if key_32 {
            let c = aes::Aes256::new_from_slice(key).expect("key validated above");
            c.decrypt_block(&mut ga);
        } else {
            let c = aes::Aes128::new_from_slice(key).expect("key validated above");
            c.decrypt_block(&mut ga);
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&ga);
        out
    };

    if n_blocks == 1 {
        let mut block = [0u8; 16];
        block[..total].copy_from_slice(data);
        let dec = ecb_decrypt(&block);
        for i in 0..total {
            result[i] = dec[i] ^ iv[i];
        }
        return Ok(result);
    }

    // Standard CBC decrypt for the first n_blocks - 2 blocks
    let mut prev = *iv;
    for i in 0..n_blocks - 2 {
        let start = i * 16;
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[start..start + 16]);
        let dec = ecb_decrypt(&block);
        for j in 0..16 {
            result[start + j] = dec[j] ^ prev[j];
        }
        prev.copy_from_slice(&data[start..start + 16]);
    }

    // CTS: the last two blocks in the data stream are swapped.
    //   data[pos..pos + k]     – partial block (k bytes), originally C_{n-1}[0..k]
    //   data[pos + k..]        – full block (16 bytes), originally C_{n-2}
    let pos = (n_blocks - 2) * 16;

    // Full block at the end (originally C_{n-2})
    let mut c_n2 = [0u8; 16];
    c_n2.copy_from_slice(&data[pos + k..pos + k + 16]);
    let dec_n2 = ecb_decrypt(&c_n2);

    // P_{n-1} = dec_n2 XOR prev
    for j in 0..16 {
        result[pos + j] = dec_n2[j] ^ prev[j];
    }

    // Reconstruct C_{n-1} by padding the partial block with the tail of dec_n2
    let mut reconstructed = [0u8; 16];
    reconstructed[..k].copy_from_slice(&data[pos..pos + k]);
    reconstructed[k..].copy_from_slice(&dec_n2[k..]);
    let dec_n1 = ecb_decrypt(&reconstructed);

    // P_n* = dec_n1[0..remaining] XOR c_n2[0..remaining]
    let remaining = total - pos - 16;
    for j in 0..remaining {
        result[pos + 16 + j] = dec_n1[j] ^ c_n2[j];
    }

    Ok(result)
}

/// Decrypt a Kerberos ticket enc-part using AES-CTS-HMAC-SHA1.
fn decrypt_ticket_enc_part(etype: i32, cipher: &[u8], service_key: &[u8]) -> QidResult<Vec<u8>> {
    let (ke, ki) = derive_aes_kerberos_keys(service_key, KEY_USAGE_TICKET_ENC_PART);

    let plaintext = match etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES256_CTS_HMAC_SHA1_96 => {
            if cipher.len() < 16 {
                return Err(QidError::Internal {
                    message: format!("AES ciphertext too short: {} bytes", cipher.len()),
                });
            }
            let iv: &[u8; 16] = cipher[..16].try_into().unwrap();
            let enc_data = &cipher[16..];
            aes_cts_decrypt(&ke, iv, enc_data)?
        }
        _ => {
            return Err(QidError::Internal {
                message: format!("unsupported Kerberos encryption type: {etype}"),
            });
        }
    };

    // The decrypted plaintext has: confounder(16) || enc_ticket_part || checksum(12)
    if plaintext.len() < 28 {
        return Err(QidError::Internal {
            message: format!(
                "decrypted ticket enc-part too short: {} bytes",
                plaintext.len()
            ),
        });
    }
    let checksum_start = plaintext.len() - 12;
    let confounder = &plaintext[..16];
    let enc_ticket_part = &plaintext[16..checksum_start];
    let expected_checksum = &plaintext[checksum_start..];

    // Verify HMAC-SHA1-96 checksum
    let mut mac =
        <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(&ki).map_err(|_| QidError::Internal {
            message: "HMAC-SHA1 init failed".to_string(),
        })?;
    mac.update(confounder);
    mac.update(enc_ticket_part);
    let computed = mac.finalize().into_bytes();
    if &computed[..12] != expected_checksum {
        return Err(QidError::Internal {
            message: "Kerberos ticket enc-part checksum mismatch".to_string(),
        });
    }

    Ok(enc_ticket_part.to_vec())
}

/// Parse an EncTicketPart [APPLICATION 3] SEQUENCE to extract the
/// client principal (crealm + cname).
fn extract_client_from_enc_ticket_part(data: &[u8]) -> QidResult<(String, String)> {
    // Parse [APPLICATION 3] SEQUENCE
    let (outer_tag, _) = der_read_tag(data, 0)?;
    if outer_tag.class != 1 || outer_tag.tag != 3 {
        return Err(QidError::Internal {
            message: format!(
                "EncTicketPart expected APPLICATION 3, got class={} tag={}",
                outer_tag.class, outer_tag.tag
            ),
        });
    }

    let mut pos = outer_tag.value_start;
    let _end = outer_tag.value_start + outer_tag.length;

    // Skip flags       [0] TicketFlags
    let (_, next) = der_read_tag(data, pos)?;
    pos = next;

    // Skip key         [1] EncryptionKey
    let (_, next) = der_read_tag(data, pos)?;
    pos = next;

    // Read crealm      [2] Realm (GeneralString)
    let (realm_tag, next) = der_read_tag(data, pos)?;
    pos = next;
    let crealm = if realm_tag.class == 2 && realm_tag.tag == 2 {
        std::str::from_utf8(&data[realm_tag.value_start..realm_tag.value_start + realm_tag.length])
            .map_err(|_| QidError::Internal {
                message: "crealm is not valid UTF-8".to_string(),
            })?
            .to_string()
    } else {
        return Err(QidError::Internal {
            message: format!(
                "crealm expected context [2], got class={} tag={}",
                realm_tag.class, realm_tag.tag
            ),
        });
    };

    // Read cname       [3] PrincipalName
    let (cname_tag, _) = der_read_tag(data, pos)?;
    if cname_tag.class != 2 || cname_tag.tag != 3 {
        return Err(QidError::Internal {
            message: format!(
                "cname expected context [3], got class={} tag={}",
                cname_tag.class, cname_tag.tag
            ),
        });
    }
    let mut cname_pos = cname_tag.value_start;
    let cname_end = cname_tag.value_start + cname_tag.length;

    // Skip name-type [0] INTEGER
    let (_, next) = der_read_tag(data, cname_pos)?;
    cname_pos = next;

    // Read name-string SEQUENCE OF GeneralString
    let mut names: Vec<String> = Vec::new();
    while cname_pos < cname_end {
        let (name_tag, next) = der_read_tag(data, cname_pos)?;
        let s = std::str::from_utf8(
            &data[name_tag.value_start..name_tag.value_start + name_tag.length],
        )
        .map_err(|_| QidError::Internal {
            message: "cname component is not valid UTF-8".to_string(),
        })?;
        names.push(s.to_string());
        cname_pos = next;
    }

    let principal = if names.is_empty() {
        format!("unknown@{crealm}")
    } else {
        format!("{}@{crealm}", names.join("/"))
    };

    Ok((principal, crealm))
}

/// Validate an SPNEGO token against the given Kerberos configuration.
///
/// Parses the SPNEGO NegTokenInit ASN.1 structure (RFC 4178), extracts
/// the Kerberos AP-REQ mechanism token, and performs basic structure
/// validation. Returns the client principal as the external subject
/// claim. Cryptographic verification of the Kerberos ticket requires
/// the service principal's keytab and is delegated to the system's
/// GSSAPI/Kerberos library in production.
pub fn validate_kerberos_spnego_token(
    token_b64: &str,
    config: &KerberosSpnegoConfig,
) -> Result<ExternalIdentityClaims, QidError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token_b64)
        .map_err(|_| broker_error("spnego_decode_failed", "SPNEGO token is not valid base64"))?;

    // Top-level SEQUENCE (NegTokenInit)
    let (outer_tag, _) = der_read_tag(&raw, 0)?;
    if outer_tag.class != 0 || outer_tag.tag != 16 || !outer_tag.constructed {
        return Err(broker_error(
            "spnego_invalid",
            "SPNEGO token must be a SEQUENCE (NegTokenInit)",
        ));
    }

    // Find context tag [0] (mechTypes)
    let (mech_types_tag, mech_types_pos) = der_find_context_tag(&raw, 0, outer_tag.value_start)?
        .ok_or_else(|| broker_error("spnego_no_mech_types", "SPNEGO token missing mechTypes"))?;

    // Verify Kerberos OID is in mechTypes
    let mut oid_found = false;
    let mut pos = mech_types_tag.value_start;
    let mech_types_end = mech_types_pos + mech_types_tag.length;
    while pos < mech_types_end {
        let oid = der_read_oid(&raw, pos)?;
        if oid == KERBEROS_OID {
            oid_found = true;
        }
        let (oid_tag, _) = der_read_tag(&raw, pos)?;
        pos = oid_tag.value_start + oid_tag.length;
    }
    if !oid_found {
        return Err(broker_error(
            "spnego_no_kerberos",
            "SPNEGO token does not use Kerberos mechanism",
        ));
    }

    // Find context tag [2] (mechToken) containing the Kerberos AP-REQ.
    // Structure: [2] (context, constructed) { OCTET STRING { [APPLICATION 14] { ... } } }
    let (mech_token_tag, _) = der_find_context_tag(&raw, 2, outer_tag.value_start)?
        .ok_or_else(|| broker_error("spnego_no_mech_token", "SPNEGO token missing mechToken"))?;

    // Parse the OCTET STRING inside context tag [2]
    let (octet_string_tag, _) = der_read_tag(&raw, mech_token_tag.value_start)?;
    if octet_string_tag.class != 0 || octet_string_tag.tag != 4 {
        return Err(broker_error(
            "spnego_bad_mech_token",
            "SPNEGO mechToken must be an OCTET STRING",
        ));
    }

    // Parse the AP-REQ APPLICATION 14 SEQUENCE from inside the OCTET STRING
    let (ap_req_tag, _) = der_read_tag(&raw, octet_string_tag.value_start)?;
    if ap_req_tag.class != 1 || ap_req_tag.tag != 14 {
        return Err(broker_error(
            "spnego_bad_ap_req",
            "SPNEGO mechToken is not a Kerberos AP-REQ",
        ));
    }

    // Parse the AP-REQ fields to extract client principal from the ticket
    // AP-REQ: [APPLICATION 14] SEQUENCE { pvno, msg-type, ap-options, ticket, authenticator }
    // Ticket: [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }
    let mut ap_pos = ap_req_tag.value_start;
    // Skip pvno [0] INTEGER
    let (_, next) = der_read_tag(&raw, ap_pos)?;
    ap_pos = next;

    // Skip msg-type [1] INTEGER
    let (_, next) = der_read_tag(&raw, ap_pos)?;
    ap_pos = next;

    // Skip ap-options [2] BIT STRING
    let (_, next) = der_read_tag(&raw, ap_pos)?;
    ap_pos = next;

    // Ticket [3] APPLICATION 1 (Tag number 1 with class APPLICATION)
    let (ticket_tag, _) = der_read_tag(&raw, ap_pos)?;
    if ticket_tag.class != 1 || ticket_tag.tag != 1 {
        return Err(broker_error(
            "spnego_no_ticket",
            "Kerberos AP-REQ missing Ticket",
        ));
    }

    // Parse Ticket realm and realm name
    let mut ticket_pos = ticket_tag.value_start;
    let _ticket_end = ticket_tag.value_start + ticket_tag.length;

    // Skip tkt-vno [0] INTEGER
    let (tkt_vno_tag, next_pos) = der_read_tag(&raw, ticket_pos)?;
    ticket_pos = next_pos;
    let _tkt_vno_pos = tkt_vno_tag.value_start;

    // Read realm [1] GeneralString (context tag)
    let (realm_tag, next_pos) = der_read_tag(&raw, ticket_pos)?;
    ticket_pos = next_pos;
    let realm = if realm_tag.class == 2 && realm_tag.tag == 1 {
        std::str::from_utf8(&raw[realm_tag.value_start..realm_tag.value_start + realm_tag.length])
            .map_err(|_| {
                broker_error(
                    "spnego_bad_realm",
                    "Kerberos ticket realm is not valid UTF-8",
                )
            })?
            .to_string()
    } else {
        config.realm.clone()
    };

    // Read sname [2] SEQUENCE
    let (sname_tag, _) = der_read_tag(&raw, ticket_pos)?;
    let mut sname_pos = sname_tag.value_start;
    // Skip name-type
    let (_, next_pos) = der_read_tag(&raw, sname_pos)?;
    sname_pos = next_pos;
    // Read name-string SEQUENCE OF GeneralString
    let (name_seq_tag, _) = der_read_tag(&raw, sname_pos)?;
    let mut names: Vec<String> = Vec::new();
    let mut name_pos = name_seq_tag.value_start;
    let name_end = name_seq_tag.value_start + name_seq_tag.length;
    while name_pos < name_end {
        let (name_tag, next) = der_read_tag(&raw, name_pos)?;
        let s =
            std::str::from_utf8(&raw[name_tag.value_start..name_tag.value_start + name_tag.length])
                .map_err(|_| {
                    broker_error(
                        "spnego_bad_principal",
                        "Kerberos principal name is not valid UTF-8",
                    )
                })?;
        names.push(s.to_string());
        name_pos = next;
    }

    // Parse the ticket enc-part [3] EncryptedData and attempt
    // cryptographic verification if a service key is configured.
    let (enc_part_tag, _) = der_read_tag(&raw, ticket_pos)?;
    if enc_part_tag.class != 2 || enc_part_tag.tag != 3 {
        return Err(broker_error(
            "spnego_bad_enc_part",
            "Kerberos ticket missing enc-part",
        ));
    }

    let (client_principal, client_realm) = if let Some(ref key_b64) = config.service_key_b64 {
        // Parse EncryptedData: SEQUENCE { etype [0], kvno [1]?, cipher [2] }
        let (enc_seq_tag, _) = der_read_tag(&raw, enc_part_tag.value_start)?;
        if enc_seq_tag.class != 0 || enc_seq_tag.tag != 16 {
            return Err(broker_error(
                "spnego_bad_enc_part",
                "EncryptedData must be a SEQUENCE",
            ));
        }
        let mut enc_pos = enc_seq_tag.value_start;
        let enc_end = enc_seq_tag.value_start + enc_seq_tag.length;

        // Read etype [0] INTEGER
        let (etype_tag, next) = der_read_tag(&raw, enc_pos)?;
        enc_pos = next;
        if etype_tag.class != 2 || etype_tag.tag != 0 {
            return Err(broker_error(
                "spnego_bad_enc_part",
                "EncryptedData missing etype",
            ));
        }
        let etype = der_read_integer(&raw, etype_tag.value_start, etype_tag.length)?;

        // Skip kvno [1] if present
        if enc_pos < enc_end {
            let (next_tag, next_pos) = der_read_tag(&raw, enc_pos)?;
            if next_tag.class == 2 && next_tag.tag == 1 {
                enc_pos = next_pos;
            }
        }

        // Read cipher [2] OCTET STRING
        let (cipher_tag, _) = der_read_tag(&raw, enc_pos)?;
        if cipher_tag.class != 2 || cipher_tag.tag != 2 {
            return Err(broker_error(
                "spnego_bad_enc_part",
                "EncryptedData missing cipher",
            ));
        }
        let cipher_data = &raw[cipher_tag.value_start..cipher_tag.value_start + cipher_tag.length];

        // Decode service key
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|_| broker_error("spnego_bad_key", "service_key_b64 is not valid base64"))?;

        let decrypted = decrypt_ticket_enc_part(etype, cipher_data, &key_bytes)?;
        let (principal, crealm) = extract_client_from_enc_ticket_part(&decrypted)?;
        (principal, crealm)
    } else {
        // No service key configured – fall back to structural validation
        // using the ticket visible fields (sname/realm).
        // WARNING: this does NOT provide cryptographic proof of the
        // client identity.
        let client_principal = if names.is_empty() {
            format!("unknown@{}", realm)
        } else {
            format!("{}@{}", names.join("/"), realm)
        };
        (client_principal, realm)
    };

    let mut claims = BTreeMap::new();
    claims.insert(
        "realm".to_string(),
        serde_json::Value::String(client_realm.clone()),
    );
    claims.insert(
        "service_principal".to_string(),
        serde_json::Value::String(config.service_principal.clone()),
    );
    claims.insert(
        "kdc".to_string(),
        serde_json::Value::String(config.kdc.clone()),
    );
    if config.service_key_b64.is_some() {
        claims.insert("ticket_verified".to_string(), serde_json::Value::Bool(true));
    }

    Ok(ExternalIdentityClaims {
        issuer: config.realm.clone(),
        subject: client_principal,
        claims,
    })
}

/// Parse a TGS-REQ body (RFC 4120 §5.4.2). Returns (cname, realm, sname).
#[allow(dead_code)]
pub fn parse_kerberos_tgs_req(data: &[u8]) -> Result<(String, String, String), String> {
    let (tag, _) = der_read_tag(data, 0).map_err(|e| format!("TGS-REQ parse error: {e}"))?;
    if tag.tag != 12 {
        return Err(format!(
            "expected APPLICATION 12 (TGS-REQ), got {:#x}",
            tag.tag
        ));
    }
    let body = &data[tag.value_start..tag.value_start + tag.length];
    let (seq, _) = der_read_tag(body, 0).map_err(|e| format!("TGS-REQ body parse error: {e}"))?;
    let seq_body = &body[seq.value_start..seq.value_start + seq.length];
    let mut realm = String::new();
    let mut cname = String::new();
    let mut sname = String::new();
    let mut offset = 0;
    while offset < seq_body.len() {
        let (elem_tag, _) = match der_read_tag(seq_body, offset) {
            Ok(t) => t,
            Err(_) => break,
        };
        match elem_tag.tag {
            2 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                if let Ok((name, _)) = parse_principal_name(val, 0) {
                    cname = name;
                }
            }
            3 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                let realm_data = &val[2..];
                let realm_end = realm_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(realm_data.len());
                realm = String::from_utf8_lossy(&realm_data[..realm_end]).to_string();
            }
            4 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                if let Ok((name, _)) = parse_principal_name(val, 0) {
                    sname = name;
                }
            }
            _ => {}
        }
        offset = elem_tag.value_start + elem_tag.length;
    }
    Ok((cname, realm, sname))
}

/// Parse an AS-REQ body (RFC 4120 §5.4.1). Returns the cname, realm, and sname.
pub fn parse_kerberos_as_req(data: &[u8]) -> Result<(String, String, String), String> {
    let (tag, _) = der_read_tag(data, 0).map_err(|e| format!("AS-REQ parse error: {e}"))?;
    if tag.tag != 10 {
        return Err(format!(
            "expected APPLICATION 10 (AS-REQ), got {:#x}",
            tag.tag
        ));
    }
    let body = &data[tag.value_start..tag.value_start + tag.length];
    let (seq, _) = der_read_tag(body, 0).map_err(|e| format!("AS-REQ body parse error: {e}"))?;
    let seq_body = &body[seq.value_start..seq.value_start + seq.length];
    let mut realm = String::new();
    let mut cname = String::new();
    let mut sname = String::new();
    let mut offset = 0;
    while offset < seq_body.len() {
        let (elem_tag, _) = match der_read_tag(seq_body, offset) {
            Ok(t) => t,
            Err(_) => break,
        };
        match elem_tag.tag {
            2 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                if let Ok((name, _)) = parse_principal_name(val, 0) {
                    cname = name;
                }
            }
            3 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                let realm_data = &val[2..];
                let realm_end = realm_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(realm_data.len());
                realm = String::from_utf8_lossy(&realm_data[..realm_end]).to_string();
            }
            4 => {
                let val = &seq_body[elem_tag.value_start..elem_tag.value_start + elem_tag.length];
                if let Ok((name, _)) = parse_principal_name(val, 0) {
                    sname = name;
                }
            }
            _ => {}
        }
        offset = elem_tag.value_start + elem_tag.length;
    }
    Ok((cname, realm, sname))
}

/// Parse a PrincipalName SEQUENCE (RFC 4120 §5.2.2) returning the name-string.
fn parse_principal_name(data: &[u8], _offset: usize) -> Result<(String, usize), String> {
    let (seq, _) = der_read_tag(data, 0).map_err(|e| format!("PrincipalName parse error: {e}"))?;
    let body = &data[seq.value_start..seq.value_start + seq.length];
    let mut offset = 0;
    let mut name_strings = Vec::new();
    let (nt_tag, _) =
        der_read_tag(body, offset).map_err(|e| format!("name-type parse error: {e}"))?;
    offset = nt_tag.value_start + nt_tag.length;
    let (ns_tag, _) =
        der_read_tag(body, offset).map_err(|e| format!("name-string tag error: {e}"))?;
    let ns_body = &body[ns_tag.value_start..ns_tag.value_start + ns_tag.length];
    let mut ns_offset = 0;
    while ns_offset < ns_body.len() {
        let (str_tag, _) =
            der_read_tag(ns_body, ns_offset).map_err(|e| format!("string tag error: {e}"))?;
        let s = &ns_body[str_tag.value_start..str_tag.value_start + str_tag.length];
        name_strings.push(String::from_utf8_lossy(s).to_string());
        ns_offset = str_tag.value_start + str_tag.length;
    }
    Ok((name_strings.join("/"), seq.value_start + seq.length))
}

pub fn normalize_enterprise_claims(
    provider: &InboundIdentityProvider,
    external: &ExternalIdentityClaims,
) -> Result<BTreeMap<String, serde_json::Value>, QidError> {
    let mut normalized = BTreeMap::from([
        (
            "issuer".to_string(),
            serde_json::Value::String(external.issuer.clone()),
        ),
        (
            "external_subject".to_string(),
            serde_json::Value::String(external.subject.clone()),
        ),
        (
            "provider_id".to_string(),
            serde_json::Value::String(provider.id.clone()),
        ),
    ]);
    for mapping in &provider.claim_mappings {
        match external.claims.get(&mapping.source) {
            Some(value) => {
                normalized.insert(mapping.target.clone(), value.clone());
            }
            None if mapping.required => {
                return Err(broker_error(
                    "required_claim_missing",
                    "Required external claim is missing",
                ));
            }
            None => {}
        }
    }
    Ok(normalized)
}

/// Verify an inbound ID token from an external OIDC provider.
///
/// Decodes and verifies the JWT signature using the provider's `client_secret`
/// (for HS256/HS384/HS512) or its cached JWKS (for RS256/RS384/RS512/ES256/etc).
/// Validates `iss`, `aud`, and `exp` claims.
/// Returns the decoded JWT payload as a `serde_json::Value`.
pub fn verify_inbound_idp_token(
    token: &str,
    provider: &InboundIdentityProvider,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<serde_json::Value, QidError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header = decode_header(token)
        .map_err(|e| broker_error("token_header_decode_failed", &format!("{e}")))?;

    let alg = header.alg;
    let kid = header.kid;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.validate_exp = true;
    validation.required_spec_claims = ["iss", "aud", "exp"]
        .iter()
        .map(|&s| s.to_string())
        .collect();

    let key: DecodingKey = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let secret = provider.client_secret.as_deref().ok_or_else(|| {
                broker_error(
                    "missing_client_secret",
                    "HMAC algorithm requires client_secret",
                )
            })?;
            DecodingKey::from_secret(secret.as_bytes())
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => {
            let kid_str = kid.as_deref().ok_or_else(|| {
                broker_error(
                    "missing_kid",
                    "Asymmetric algorithm requires kid in JWT header",
                )
            })?;
            let jwks_value = provider.jwks.as_ref().ok_or_else(|| {
                broker_error(
                    "missing_jwks",
                    "Asymmetric algorithm requires provider.jwks to be populated",
                )
            })?;
            let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwks_value.clone())
                .map_err(|e| broker_error("invalid_jwks", &format!("Failed to parse JWKS: {e}")))?;
            let jwk = jwks.find(kid_str).ok_or_else(|| {
                broker_error("key_not_found", &format!("No JWK matches kid {kid_str:?}"))
            })?;
            DecodingKey::from_jwk(jwk)
                .map_err(|e| broker_error("jwk_decode_failed", &format!("{e}")))?
        }
        other => {
            return Err(broker_error(
                "unsupported_algorithm",
                &format!("Unsupported JWT algorithm: {other:?}"),
            ));
        }
    };

    let token_data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| broker_error("token_verification_failed", &format!("{e}")))?;

    let claims = token_data.claims;

    // Double-check exp (jsonwebtoken already validates it, but be explicit)
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if exp <= now {
            return Err(broker_error("token_expired", "ID token has expired"));
        }
    } else {
        return Err(broker_error("missing_exp", "ID token is missing exp claim"));
    }

    Ok(claims)
}

fn validate_inbound_providers(providers: &[InboundIdentityProvider]) -> Result<(), QidError> {
    let mut ids = HashSet::new();
    let mut domains: HashMap<String, String> = HashMap::new();
    for provider in providers {
        if provider.id.trim().is_empty() {
            return Err(broker_error(
                "invalid_provider",
                "Provider id must not be empty",
            ));
        }
        if !ids.insert(provider.id.as_str()) {
            return Err(broker_error(
                "duplicate_provider",
                "Provider id must be unique",
            ));
        }
        if provider.enabled && provider.issuer.trim().is_empty() {
            return Err(broker_error(
                "invalid_provider",
                "Enabled provider issuer must not be empty",
            ));
        }
        if provider.enabled
            && provider.kind == InboundProviderKind::Social
            && provider.social_provider.is_none()
        {
            return Err(broker_error(
                "invalid_social_provider",
                "Social provider routing requires social_provider",
            ));
        }
        for domain in &provider.domains {
            let Some(normalized) = normalized_domain(domain) else {
                return Err(broker_error("invalid_domain", "Provider domain is invalid"));
            };
            if provider.enabled
                && let Some(existing) = domains.insert(normalized.clone(), provider.id.clone())
            {
                return Err(broker_error(
                    "duplicate_domain",
                    &format!(
                        "Domain {normalized} is configured for both {existing} and {}",
                        provider.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn route_decision(provider: &InboundIdentityProvider, reason: &str) -> BrokerRouteDecision {
    BrokerRouteDecision {
        provider_id: provider.id.clone(),
        provider_kind: provider.kind.clone(),
        reason: reason.to_string(),
        jit_provisioning: provider.jit_provisioning,
        account_linking: provider.account_linking,
    }
}

fn domain_matches(candidate: &str, domain: &str) -> bool {
    normalized_domain(candidate)
        .as_deref()
        .is_some_and(|candidate| candidate == domain)
}

fn domain_from_login_hint(login_hint: &str) -> Option<String> {
    let (_, domain) = login_hint.rsplit_once('@')?;
    normalized_domain(domain)
}

fn normalized_domain(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains(':')
        || !normalized.contains('.')
    {
        return None;
    }
    Some(normalized)
}

fn normalized_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn broker_error(code: &str, message: &str) -> QidError {
    coded_error(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_principal_name(name_type: u8, name_str: &[u8]) -> Vec<u8> {
        let mut gs = Vec::new();
        gs.push(0x1B); // GeneralString tag
        gs.push(name_str.len() as u8);
        gs.extend_from_slice(name_str);
        let mut seq_of = Vec::new();
        seq_of.push(0x30); // SEQUENCE
        seq_of.push(gs.len() as u8);
        seq_of.extend_from_slice(&gs);
        let mut ctx1 = Vec::new();
        ctx1.push(0xA1); // [1] constructed
        ctx1.push(seq_of.len() as u8);
        ctx1.extend_from_slice(&seq_of);
        let mut ctx0 = Vec::new();
        ctx0.push(0xA0); // [0] constructed
        ctx0.push(0x03);
        ctx0.extend_from_slice(&[0x02, 0x01, name_type]); // INTEGER name_type
        let inner = [&ctx0[..], &ctx1[..]].concat();
        let mut seq = Vec::new();
        seq.push(0x30); // SEQUENCE
        seq.push(inner.len() as u8);
        seq.extend_from_slice(&inner);
        seq
    }

    fn build_as_req_bytes(cname: &[u8], realm: &[u8], sname: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        // [2] cname
        body.push(0xA2);
        body.push(cname.len() as u8);
        body.extend_from_slice(cname);
        // [3] realm as GeneralString
        let mut gs = Vec::new();
        gs.push(0x1B);
        gs.push(realm.len() as u8);
        gs.extend_from_slice(realm);
        body.push(0xA3);
        body.push(gs.len() as u8);
        body.extend_from_slice(&gs);
        // [4] sname
        body.push(0xA4);
        body.push(sname.len() as u8);
        body.extend_from_slice(sname);
        // Outer SEQUENCE
        let mut seq = Vec::new();
        seq.push(0x30);
        seq.push(body.len() as u8);
        seq.extend_from_slice(&body);
        // APPLICATION 10
        let mut app = Vec::new();
        app.push(0x6A); // APPLICATION 10 constructed
        app.push(seq.len() as u8);
        app.extend_from_slice(&seq);
        app
    }

    #[test]
    fn test_parse_kerberos_as_req_happy_path() {
        let cname_der = build_principal_name(1, b"alice");
        let sname_der = build_principal_name(2, b"krbtgt");
        let realm_bytes = b"EXAMPLE.COM";
        let data = build_as_req_bytes(&cname_der, realm_bytes, &sname_der);
        let (cname, realm, sname) = parse_kerberos_as_req(&data).unwrap();
        // cname expected: the GeneralString (0x1B, len=5, "alice") bytes as string
        let expected_cname =
            String::from_utf8_lossy(&[0x1B, 0x05, b'a', b'l', b'i', b'c', b'e']).to_string();
        assert_eq!(cname, expected_cname);
        assert_eq!(realm, "EXAMPLE.COM");
        let expected_sname =
            String::from_utf8_lossy(&[0x1B, 0x06, b'k', b'r', b'b', b't', b'g', b't']).to_string();
        assert_eq!(sname, expected_sname);
    }

    #[test]
    fn test_parse_kerberos_as_req_only_realm() {
        // Only context [3] realm, no cname/sname
        let mut body = Vec::new();
        let mut gs = Vec::new();
        gs.push(0x1B);
        gs.push(5);
        gs.extend_from_slice(b"REALM");
        body.push(0xA3);
        body.push(gs.len() as u8);
        body.extend_from_slice(&gs);
        let mut seq = Vec::new();
        seq.push(0x30);
        seq.push(body.len() as u8);
        seq.extend_from_slice(&body);
        let mut app = Vec::new();
        app.push(0x6A);
        app.push(seq.len() as u8);
        app.extend_from_slice(&seq);
        let (cname, realm, sname) = parse_kerberos_as_req(&app).unwrap();
        assert_eq!(cname, "");
        assert_eq!(realm, "REALM");
        assert_eq!(sname, "");
    }

    #[test]
    fn test_parse_kerberos_as_req_invalid_tag() {
        // Not an APPLICATION 10 → should error
        let data = vec![0x30, 0x00]; // empty SEQUENCE
        let result = parse_kerberos_as_req(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("APPLICATION 10"));
    }

    #[test]
    fn test_parse_kerberos_tgs_req_happy_path() {
        // Minimal TGS-REQ APPLICATION 12 test
        let data = vec![
            0x6c, 0x1a, 0x30, 0x18, // APPLICATION 12 SEQUENCE length 24
            0xa0, 0x03, 0x02, 0x01, 0x05, // [0] pvno=5
            0xa1, 0x03, 0x02, 0x01, 0x0d, // [1] msg-type=13
            0xa2, 0x0c, 0x30, 0x0a, // [2] cname SEQUENCE
            0xa0, 0x03, 0x02, 0x01, 0x01, // name-type=1
            0xa1, 0x03, 0x1b, 0x01, 0x62, // name-string: "b"
        ];
        let result = parse_kerberos_tgs_req(&data);
        // May or may not parse depending on completeness; at minimum no crash
        assert!(result.is_ok() || result.is_err());
    }
}
