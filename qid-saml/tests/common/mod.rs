use bergshamra_dsig::DsigContext;
use bergshamra_keys::{KeysManager, loader};

pub const TEST_SP_CERT_PEM: &str = include_str!("../data/test-sp.crt");
pub const TEST_SP_KEY_PEM: &str = include_str!("../data/test-sp.key");
pub const SIGNATURE_PLACEHOLDER: &str = "<!--SIGNATURE-->";

pub fn test_sp_cert_body() -> String {
    TEST_SP_CERT_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .trim()
        .to_string()
}

#[allow(clippy::expect_used)]
pub fn sign_saml_test_document(
    document_xml: &str,
    element_id: &str,
    key_pem: &[u8],
    cert_body: &str,
) -> String {
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{element_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let template = document_xml.replace(SIGNATURE_PLACEHOLDER, &signature);
    let mut keys = KeysManager::new();
    keys.add_key(
        loader::load_rsa_private_pem(key_pem)
            .expect("test SAML document uses a valid RSA private key"),
    );
    bergshamra_dsig::sign::sign(&DsigContext::new(keys), &template)
        .expect("test SAML document must sign in the enforced inbound profile")
}

pub fn sign_test_document(document_xml: &str, element_id: &str) -> String {
    sign_saml_test_document(
        document_xml,
        element_id,
        TEST_SP_KEY_PEM.as_bytes(),
        &test_sp_cert_body(),
    )
}
