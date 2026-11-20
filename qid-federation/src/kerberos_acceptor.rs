//! Production Kerberos/SPNEGO acceptor core.
//!
//! This module validates an inbound Negotiate token against service keys from
//! the strict keytab parser and an explicitly supplied replay cache. It makes
//! no HTTP, mapping or configuration decisions: callers get an identity only
//! after cryptographic establishment and an explicit service/realm check.
//! Live-KDC interoperability remains the authority for ticket crypto and is
//! proven by the isolated MIT fixture, not by locally fabricated tickets.
//!
//! # Key lifetime and replay residual
//!
//! The strict parser holds file bytes and extracted keys in zeroizing buffers,
//! but krb5 1.0.0's `ServiceKey::new` and `Keytab::from_keys` copy those keys
//! into ordinary `Vec<u8>` storage with no wiping `Drop`. [`KerberosKeytab`]
//! keeps that storage private and exposes neither `Debug` nor `Clone`, which
//! prevents accidental disclosure through diagnostics or copies but cannot
//! wipe the bytes when the owner is dropped. Wiping them is not achievable
//! through the public krb5 1.0.0 API; it would require a maintained fork,
//! which the accepted scope and key-safety assessment decline. This is a
//! documented residual, not a claim of full key zeroization. Replay protection
//! is likewise only as durable as the caller-supplied `SharedCache`: a
//! process-local backend loses replay state on restart, while a shared durable
//! backend retains it for its configured TTL.

use crate::{
    KerberosReplayStore,
    kerberos_keytab::{KeytabError, load_keytab},
};
use krb5::{
    Keytab,
    acceptor::{AcceptOptions, EncType, ServiceKey},
    rcache::ReplayStore,
    spnego::SpnegoAcceptor,
};
use qid_core::cache::SharedCache;
use std::{fmt, io, ops::Deref, path::Path, sync::Arc};

/// The validated client and service names of an established Kerberos context.
///
/// Contains no key material: the acceptor's context, including its session and
/// base keys, is dropped before this value is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosIdentity {
    /// The ticket's client, `name@REALM`.
    pub client_principal: String,
    /// The ticket client's realm.
    pub client_realm: String,
    /// The ticket's service, `name@REALM`.
    pub service_principal: String,
}

/// Category-only acceptor failures. No variant carries key bytes or a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerberosAcceptError {
    /// The keytab could not be opened or read.
    KeytabUnavailable,
    /// The keytab failed strict parsing.
    KeytabMalformed,
    /// A parsed key uses an encryption type the acceptor cannot use.
    UnsupportedKeyType,
    /// The token was empty or not a Negotiate token.
    TokenDecode,
    /// The token failed negotiation or Kerberos verification: replay,
    /// tampering, expiry and wrong-service tickets all land here.
    NegotiationFailed,
    /// An established context named a different service or realm.
    AuthorizationMismatch,
}

impl fmt::Display for KerberosAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::KeytabUnavailable => "Kerberos acceptor keytab is unavailable",
            Self::KeytabMalformed => "Kerberos acceptor keytab is malformed",
            Self::UnsupportedKeyType => "Kerberos acceptor keytab has an unsupported key type",
            Self::TokenDecode => "Negotiate token could not be decoded",
            Self::NegotiationFailed => "Negotiate token failed Kerberos verification",
            Self::AuthorizationMismatch => {
                "established Kerberos context does not match the expected service or realm"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for KerberosAcceptError {}

/// The replay store is deliberately the caller's, never the environment's.
#[derive(Debug)]
struct QidReplay(KerberosReplayStore);

impl ReplayStore for QidReplay {
    fn insert(&self, tag: &[u8], now: i64, expires: i64) -> io::Result<bool> {
        self.0.insert(tag, now, expires)
    }
}

/// A strict-parsed service keytab owned by the acceptor.
///
/// The inner krb5 keytab has ordinary non-zeroizing key storage. This wrapper
/// implements neither `Debug` nor `Clone`; see the module docs for the exact
/// residual that this ownership boundary does not remove.
pub struct KerberosKeytab(Keytab);

impl Deref for KerberosKeytab {
    type Target = Keytab;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KerberosKeytab {
    /// Load service keys through the strict parser, with path-free errors.
    pub fn load(path: &Path) -> Result<Self, KerberosAcceptError> {
        let parsed = load_keytab(path).map_err(|error| match error {
            KeytabError::Unavailable => KerberosAcceptError::KeytabUnavailable,
            _ => KerberosAcceptError::KeytabMalformed,
        })?;
        let keys = parsed
            .keys()
            .iter()
            .map(|key| {
                let enctype = EncType::from_i32(key.enctype.rfc_number())
                    .ok_or(KerberosAcceptError::UnsupportedKeyType)?;
                Ok(ServiceKey::new(
                    key.principal.clone(),
                    key.realm.clone(),
                    key.kvno,
                    enctype,
                    key.key().to_vec(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(Keytab::from_keys(keys)))
    }
}

/// An established identity and the opaque final SPNEGO reply, when present.
///
/// The reply is the AP-REP the initiator needs to verify mutual completion.
/// Neither field carries key material, and its `Debug` reports only the reply
/// length so a token cannot be disclosed through diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct AcceptedNegotiate {
    /// The validated client and service names.
    pub identity: KerberosIdentity,
    /// The final Negotiate token, if the exchange produced one.
    pub reply: Option<Vec<u8>>,
}

impl fmt::Debug for AcceptedNegotiate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedNegotiate")
            .field("identity", &self.identity)
            .field("reply_len", &self.reply.as_ref().map(Vec::len))
            .finish()
    }
}

fn authorize_context(
    service_principal: &str,
    client_realm: &str,
    expected_service_principal: &str,
    expected_realm: &str,
) -> Result<(), KerberosAcceptError> {
    if service_principal == expected_service_principal && client_realm == expected_realm {
        Ok(())
    } else {
        Err(KerberosAcceptError::AuthorizationMismatch)
    }
}

/// Wire the acceptor's replay protection to the caller's cache.
///
/// Clock skew stays at the krb5 default; shortening it is per-request policy.
/// The environment's replay store is never selected.
pub fn build_accept_options(replay_cache: Arc<dyn SharedCache>) -> AcceptOptions {
    let mut options = AcceptOptions::default();
    options.channel_bindings = None;
    options.replay_cache = Some(Arc::new(QidReplay(KerberosReplayStore::new(replay_cache))));
    options
}

/// The one production validation sequence, reusable with explicit options.
///
/// One step is deliberate: multi-leg SPNEGO is unsupported and fails closed.
pub fn accept_with_options(
    keytab: &KerberosKeytab,
    expected_service_principal: &str,
    expected_realm: &str,
    options: AcceptOptions,
    token: &[u8],
) -> Result<AcceptedNegotiate, KerberosAcceptError> {
    if token.is_empty() {
        return Err(KerberosAcceptError::TokenDecode);
    }
    let mut acceptor = SpnegoAcceptor::with_options(keytab, options);
    let reply = acceptor
        .step(token)
        .map_err(|_| KerberosAcceptError::NegotiationFailed)?;
    // A multi-leg token is not an identity: fail closed until negotiation is
    // complete and a context actually exists.
    if !acceptor.is_established() || acceptor.context().is_none() {
        return Err(KerberosAcceptError::NegotiationFailed);
    }
    let context = acceptor
        .into_context()
        .ok_or(KerberosAcceptError::NegotiationFailed)?;
    authorize_context(
        &context.service_principal,
        &context.client_realm,
        expected_service_principal,
        expected_realm,
    )?;
    Ok(AcceptedNegotiate {
        identity: KerberosIdentity {
            client_principal: context.client_principal,
            client_realm: context.client_realm,
            service_principal: context.service_principal,
        },
        reply,
    })
}

/// Cryptographically validate one Negotiate token and return identity and reply.
///
/// `replay_cache` must be atomic and shared by every acceptor for the service;
/// its durability is whatever the backend provides. This core stays
/// independent of HTTP: callers decide how to deliver the mutual-auth reply.
pub fn accept_negotiate_token(
    keytab_path: &Path,
    expected_service_principal: &str,
    expected_realm: &str,
    replay_cache: Arc<dyn SharedCache>,
    token: &[u8],
) -> Result<AcceptedNegotiate, KerberosAcceptError> {
    let keytab = KerberosKeytab::load(keytab_path)?;
    let options = build_accept_options(replay_cache);
    accept_with_options(
        &keytab,
        expected_service_principal,
        expected_realm,
        options,
        token,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedNegotiate, KerberosAcceptError, KerberosIdentity, KerberosKeytab,
        accept_negotiate_token, accept_with_options, authorize_context, build_accept_options,
    };
    use krb5::{
        Keytab,
        acceptor::{DEFAULT_CLOCK_SKEW_SECS, EncType, ServiceKey},
    };
    use qid_core::cache::MemoryCache;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    };

    const TEST_KEY: [u8; 16] = [0xa5; 16];
    const SERVICE: &str = "HTTP/acceptor.qid.test@QID.MIT.TEST";
    const REALM: &str = "QID.MIT.TEST";

    /// Removes its synthetic keytab even if an assertion fails.
    struct KeytabFile(PathBuf);

    impl KeytabFile {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qid-kerberos-acceptor-{}.keytab",
                ulid::Ulid::new()
            ));
            let mut keytab = Keytab::new();
            keytab.add(ServiceKey::new(
                "HTTP/acceptor.qid.test",
                REALM,
                1,
                EncType::AES128CtsHmacSha196,
                TEST_KEY.to_vec(),
            ));
            fs::write(&path, keytab.to_bytes())
                .unwrap_or_else(|_| panic!("write synthetic keytab"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for KeytabFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn cache() -> Arc<MemoryCache> {
        Arc::new(MemoryCache::new())
    }

    fn assert_clean(text: &str, path: &Path) {
        let hex_key = TEST_KEY
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!text.contains(&hex_key), "Debug/Display leaked key bytes");
        assert!(!text.contains("a5"), "Debug/Display leaked key bytes");
        assert!(
            !text.contains(path.to_string_lossy().as_ref()),
            "Debug/Display leaked a keytab path"
        );
    }

    #[test]
    fn empty_and_garbage_tokens_are_rejected() {
        let keytab = KeytabFile::new();
        let empty = accept_negotiate_token(keytab.path(), SERVICE, REALM, cache(), &[]);
        assert_eq!(empty.err(), Some(KerberosAcceptError::TokenDecode));

        let garbage = accept_negotiate_token(
            keytab.path(),
            SERVICE,
            REALM,
            cache(),
            b"not a negotiate token",
        );
        assert_eq!(garbage.err(), Some(KerberosAcceptError::NegotiationFailed));

        // The layered API used by the MIT fixture rejects through the very
        // same sequence without loading a keytab from a path again.
        let owner = KerberosKeytab::load(keytab.path()).expect("load synthetic keytab");
        let direct =
            accept_with_options(&owner, SERVICE, REALM, build_accept_options(cache()), &[]);
        assert_eq!(direct.err(), Some(KerberosAcceptError::TokenDecode));
    }

    #[test]
    fn accept_options_use_the_callers_cache_and_default_skew() {
        let options = build_accept_options(cache());
        assert_eq!(options.max_skew_secs, DEFAULT_CLOCK_SKEW_SECS);
        assert!(options.channel_bindings.is_none());
        assert!(options.replay_cache.is_some());
    }

    #[test]
    fn accepted_negotiate_debug_never_exposes_key_bytes() {
        let keytab = KeytabFile::new();
        // The owner has neither Debug nor Clone; only the opaque accepted
        // value below can be formatted, and it holds no key material.
        let _owner = KerberosKeytab::load(keytab.path()).expect("load synthetic keytab");
        // Key-shaped reply bytes prove that even a token-looking value is
        // never printed by the accepted value's Debug implementation.
        let accepted = AcceptedNegotiate {
            identity: KerberosIdentity {
                client_principal: "client@QID.MIT.TEST".to_owned(),
                client_realm: REALM.to_owned(),
                service_principal: SERVICE.to_owned(),
            },
            reply: Some(TEST_KEY.to_vec()),
        };
        let debug = format!("{accepted:?}");
        assert_clean(&debug, keytab.path());
        assert!(
            !debug.contains("165"),
            "opaque reply bytes leaked via Debug"
        );
        assert_clean(&format!("{:?}", accepted.identity), keytab.path());
    }

    #[test]
    fn missing_keytab_is_reported_without_path_or_key_material() {
        let missing = std::env::temp_dir().join(format!(
            "qid-kerberos-acceptor-missing-{}",
            ulid::Ulid::new()
        ));
        let error = accept_negotiate_token(&missing, SERVICE, REALM, cache(), b"token")
            .err()
            .unwrap_or_else(|| panic!("missing keytab must be rejected"));
        assert_eq!(error, KerberosAcceptError::KeytabUnavailable);
        let display = error.to_string();
        assert_clean(&display, &missing);
        assert_clean(&format!("{error:?}"), &missing);
    }

    #[test]
    fn debug_and_display_never_expose_key_bytes() {
        let keytab = KeytabFile::new();
        let error = accept_negotiate_token(
            keytab.path(),
            SERVICE,
            REALM,
            cache(),
            b"not a negotiate token",
        )
        .err()
        .unwrap_or_else(|| panic!("garbage token must be rejected"));
        assert_clean(&error.to_string(), keytab.path());
        assert_clean(&format!("{error:?}"), keytab.path());

        for category in [
            KerberosAcceptError::KeytabUnavailable,
            KerberosAcceptError::KeytabMalformed,
            KerberosAcceptError::UnsupportedKeyType,
            KerberosAcceptError::TokenDecode,
            KerberosAcceptError::NegotiationFailed,
            KerberosAcceptError::AuthorizationMismatch,
        ] {
            assert_clean(&category.to_string(), keytab.path());
            assert_clean(&format!("{category:?}"), keytab.path());
        }

        let identity = KerberosIdentity {
            client_principal: "client@QID.MIT.TEST".to_owned(),
            client_realm: REALM.to_owned(),
            service_principal: SERVICE.to_owned(),
        };
        assert_clean(&format!("{identity:?}"), keytab.path());
    }

    #[test]
    fn established_context_authorization_checks_service_and_realm() {
        // Establishing a real context needs a KDC-issued ticket, which the MIT
        // integration fixture owns. Local tests cover only the post-establishment
        // comparison: both names must match, and either mismatch is refused.
        assert!(authorize_context(SERVICE, REALM, SERVICE, REALM).is_ok());
        assert_eq!(
            authorize_context("HTTP/other.qid.test@QID.MIT.TEST", REALM, SERVICE, REALM),
            Err(KerberosAcceptError::AuthorizationMismatch)
        );
        assert_eq!(
            authorize_context(SERVICE, "OTHER.MIT.TEST", SERVICE, REALM),
            Err(KerberosAcceptError::AuthorizationMismatch)
        );
        assert_eq!(
            authorize_context(
                "HTTP/other.qid.test@OTHER.MIT.TEST",
                "OTHER.MIT.TEST",
                SERVICE,
                REALM
            ),
            Err(KerberosAcceptError::AuthorizationMismatch)
        );
    }
}
