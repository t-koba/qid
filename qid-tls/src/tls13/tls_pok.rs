//! RFC 9966 TLS-POK identity derivation.
//!
//! Offline derivation of the EPSK external identity from a raw public key's
//! DER `SubjectPublicKeyInfo`, plus the pinned `ImportedIdentity` context.
//! The EPSK Base Key is that same DER SPKI; no private key is handled here.

use super::external_psk::ImportedIdentity;
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

pub const CONTEXT: &[u8] = b"tls13-bsk";
pub const RAW_PUBLIC_KEY: u8 = 2;
pub const CLIENT_CERTIFICATE_TYPE_TYPE: u16 = 0x0013;
const IDENTITY_LEN: usize = 32;
const ZERO_SALT: [u8; IDENTITY_LEN] = [0; IDENTITY_LEN];
const IDENTITY_INFO: &[u8] = b"tls13-bspsk-identity";

/// An SPKI base key could not be turned into a TLS-POK identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyBaseKey,
    Derivation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyBaseKey => "TLS-POK base key is empty",
            Self::Derivation => "TLS-POK identity derivation failed",
        })
    }
}

impl std::error::Error for Error {}

/// RFC 9966 §3.1 `epskid` from a DER-encoded EC `SubjectPublicKeyInfo`.
pub fn epskid(base_key: &[u8]) -> Result<Zeroizing<[u8; IDENTITY_LEN]>, Error> {
    if base_key.is_empty() {
        return Err(Error::EmptyBaseKey);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&ZERO_SALT), base_key);
    let mut identity = Zeroizing::new([0u8; IDENTITY_LEN]);
    hkdf.expand(IDENTITY_INFO, identity.as_mut())
        .map_err(|_| Error::Derivation)?;
    Ok(identity)
}

/// RFC 9966 §3.1 `ImportedIdentity` for a TLS-POK raw public key.
pub fn imported_identity(base_key: &[u8]) -> Result<ImportedIdentity, Error> {
    let identity = epskid(base_key)?;
    ImportedIdentity::new(identity.to_vec(), CONTEXT.to_vec()).map_err(|_| Error::Derivation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::external_psk::{TARGET_KDF, TARGET_PROTOCOL};

    // RFC 9966 Appendix A base64 test vectors, converted to hex.
    const VECTORS: [(&str, &str); 4] = [
        (
            "3039301306072a8648ce3d020106082a8648ce3d0301070322000232f2f2a0eca48fcb052714a865fcda7ee544bccfa43580b1a440ba2884cb6fd8",
            "05dfa52e583f11176d61a71fcc37e1d4b8dd2f4f905894077585e84bb2434a40",
        ),
        (
            "3046301006072a8648ce3d020106052b8104002203320002c035ca435a72b5c47559b7ea3da3466974344499e28c91b57a6f192a296bc994437cd8a8abbf843eab93ea5f65691bf0",
            "c8c58adba79cde495515ec20db39ca9ed42056845c4518d6f359faefb18bfbcc",
        ),
        (
            "3058301006072a8648ce3d020106052b810400230344000300888720039774f56e23c9210a72501d3d63e77ad0467142718dc2654bf175728947d296e51541dc70d07e69284161c4cf85e781751e1720d7962128dde17abe1a833058301006072a8648ce3d020106052b810400230344000300888720039774f56e23c9210a72501d3d63e77ad0467142718dc2654bf175728947d296e51541dc70d07e69284161c4cf85e781751e1720d7962128dde17abe1a83",
            "0feb37131f3503c377e84088dc0757c01ceb397ba89d950c7618475d520d860f",
        ),
        (
            "303a301406072a8648ce3d020106092b24030302080101070322000377f2516aa257c342f43002f3c273995aa7a13feb7ae0afabc947a30b7058d399",
            "8f64cb59c5edad37a3f9fdeaec466b869e5298fdf5ba4d59076ddd7dc47ddc46",
        ),
    ];

    #[test]
    fn rfc9966_epskid_vectors() {
        for (base_hex, identity_hex) in VECTORS {
            let base = hex::decode(base_hex).unwrap();
            let identity = epskid(&base).unwrap();
            assert_eq!(hex::encode(&identity[..]), identity_hex);
            let imported = imported_identity(&base).unwrap();
            assert_eq!(
                imported.external_identity,
                hex::decode(identity_hex).unwrap()
            );
            assert_eq!(imported.context, CONTEXT);
            assert_eq!(imported.target_protocol, TARGET_PROTOCOL);
            assert_eq!(imported.target_kdf, TARGET_KDF);
        }
    }

    #[test]
    fn rejects_empty_base_key() {
        assert_eq!(epskid(&[]).unwrap_err(), Error::EmptyBaseKey);
        assert_eq!(imported_identity(&[]).unwrap_err(), Error::EmptyBaseKey);
    }
}
