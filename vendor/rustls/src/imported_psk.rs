use alloc::vec::Vec;
use core::fmt;

use pki_types::SubjectPublicKeyInfoDer;
use zeroize::Zeroizing;

use crate::crypto::hash::HashAlgorithm;
use crate::error::Error;

/// An RFC 9258 imported PSK offered by a TLS 1.3 client.
#[derive(Clone)]
pub struct ClientImportedPsk {
    identity: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
    hash_algorithm: HashAlgorithm,
}

impl ClientImportedPsk {
    /// Creates an imported PSK.
    ///
    /// The identity and secret must be non-empty. Only SHA-256 and SHA-384 are
    /// accepted because those are the hash algorithms used by TLS 1.3 cipher
    /// suites supported by rustls.
    pub fn new(
        identity: Vec<u8>,
        secret: Vec<u8>,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Self, Error> {
        if identity.is_empty() {
            return Err(Error::General(
                "imported PSK identity must not be empty".into(),
            ));
        }
        if identity.len() > u16::MAX as usize {
            return Err(Error::General(
                "imported PSK identity exceeds the TLS vector limit".into(),
            ));
        }
        if secret.is_empty() {
            return Err(Error::General(
                "imported PSK secret must not be empty".into(),
            ));
        }
        if !matches!(hash_algorithm, HashAlgorithm::SHA256 | HashAlgorithm::SHA384) {
            return Err(Error::General(
                "imported PSK requires SHA-256 or SHA-384".into(),
            ));
        }

        Ok(Self {
            identity,
            secret: Zeroizing::new(secret),
            hash_algorithm,
        })
    }

    /// Returns the RFC 9258 ImportedIdentity bytes.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Returns the hash algorithm bound into the ImportedIdentity.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl fmt::Debug for ClientImportedPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientImportedPsk")
            .field("identity_len", &self.identity.len())
            .field("secret", &"[redacted]")
            .field("hash_algorithm", &self.hash_algorithm)
            .finish()
    }
}

/// An imported PSK selected by a server together with its expected client RPK.
#[derive(Clone)]
pub struct ServerImportedPsk {
    secret: Zeroizing<Vec<u8>>,
    client_raw_public_key: SubjectPublicKeyInfoDer<'static>,
}

impl ServerImportedPsk {
    /// Creates a server-side imported PSK result.
    pub fn new(
        secret: Vec<u8>,
        client_raw_public_key: SubjectPublicKeyInfoDer<'static>,
    ) -> Result<Self, Error> {
        if secret.is_empty() {
            return Err(Error::General(
                "imported PSK secret must not be empty".into(),
            ));
        }
        if client_raw_public_key.as_ref().is_empty() {
            return Err(Error::General(
                "imported PSK client raw public key must not be empty".into(),
            ));
        }

        Ok(Self {
            secret: Zeroizing::new(secret),
            client_raw_public_key,
        })
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub(crate) fn client_raw_public_key(&self) -> &SubjectPublicKeyInfoDer<'static> {
        &self.client_raw_public_key
    }
}

impl fmt::Debug for ServerImportedPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerImportedPsk")
            .field("secret", &"[redacted]")
            .field(
                "client_raw_public_key_len",
                &self.client_raw_public_key.as_ref().len(),
            )
            .finish()
    }
}

/// Resolves RFC 9258 imported identities for RFC 8773 certificate authentication.
pub trait ResolvesServerImportedPsk: fmt::Debug + Send + Sync {
    /// Resolves `identity` for the hash used by the selected TLS 1.3 suite.
    fn resolve(
        &self,
        identity: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Option<ServerImportedPsk>;
}
