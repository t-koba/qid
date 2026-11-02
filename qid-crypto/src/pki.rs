//! PKI protocol types: EST (RFC 7030), CMS (RFC 5652), CRMF (RFC 4211),
//! DC for TLS (RFC 9345) and PKCS#12 (RFC 7292).

use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmsSignedData {
    pub version: u32,
    pub digest_algorithms: Vec<String>,
    pub encap_content_info: CmsEncapsulatedContentInfo,
    pub certificates: Vec<Vec<u8>>,
    pub signer_infos: Vec<CmsSignerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmsEncapsulatedContentInfo {
    pub content_type: String,
    pub content: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmsSignerInfo {
    pub version: u32,
    pub sid: CmsSignerIdentifier,
    pub digest_algorithm: String,
    pub signed_attrs: Vec<Vec<u8>>,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CmsSignerIdentifier {
    IssuerAndSerialNumber { issuer: Vec<u8>, serial: Vec<u8> },
    SubjectKeyIdentifier(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EstRequest {
    pub csr: Vec<u8>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrmfCertRequest {
    pub cert_template: CrmfCertTemplate,
    pub controls: Vec<CrmfControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrmfCertTemplate {
    pub subject: Option<String>,
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrmfControl {
    pub control_type: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DcTlsConfig {
    pub delegated_credential: Vec<u8>,
    pub valid_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pkcs12Bundle {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub ca_certificates: Vec<Vec<u8>>,
}

pub fn parse_cms_signed_data(_data: &[u8]) -> QidResult<CmsSignedData> {
    Err(QidError::Internal {
        message: "CMS parsing requires ASN.1 decoder".to_string(),
    })
}

pub fn parse_crmf_request(_data: &[u8]) -> QidResult<CrmfCertRequest> {
    Err(QidError::Internal {
        message: "CRMF parsing requires ASN.1 decoder".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cms_signed_data_construct() {
        let cms = CmsSignedData {
            version: 1,
            digest_algorithms: vec!["SHA-256".to_string()],
            encap_content_info: CmsEncapsulatedContentInfo {
                content_type: "data".to_string(),
                content: Some(b"hello".to_vec()),
            },
            certificates: vec![],
            signer_infos: vec![CmsSignerInfo {
                version: 1,
                sid: CmsSignerIdentifier::SubjectKeyIdentifier(vec![0x01, 0x02]),
                digest_algorithm: "SHA-256".to_string(),
                signed_attrs: vec![],
                signature_algorithm: "RSA-SHA256".to_string(),
                signature: vec![0x03, 0x04],
            }],
        };
        let json = serde_json::to_string(&cms).unwrap();
        assert!(json.contains("SHA-256"));
    }

    #[test]
    fn est_request_construct() {
        let req = EstRequest {
            csr: vec![0x00, 0x01],
            auth_token: Some("token123".to_string()),
        };
        assert_eq!(req.auth_token.as_deref(), Some("token123"));
    }

    #[test]
    fn pkcs12_bundle() {
        let bundle = Pkcs12Bundle {
            certificate: vec![0x00],
            private_key: vec![0x01],
            ca_certificates: vec![vec![0x02]],
        };
        assert!(!bundle.private_key.is_empty());
    }
}
