"""Required independent EST client; no OpenSSL executable, external network or TLS bypass."""
import base64
import json
import ssl
import sys
import urllib.request

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

assert cryptography.__version__ == "46.0.3", "install tests/workload/requirements-est.txt"
fixture = json.load(sys.stdin)
context = ssl.create_default_context(cadata=fixture["tls_cert"])
# Ignore ambient proxy settings: only the ephemeral loopback TLS endpoint is permitted.
client = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
)


def operation(resource, der=None):
    headers = {"Authorization": fixture["token"]}
    data = None
    if der is not None:
        # Real MIME line folding, including the terminating CRLF.
        encoded = base64.b64encode(der)
        data = b"\r\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + b"\r\n"
        headers.update({"Content-Type": "application/pkcs10", "Content-Transfer-Encoding": "base64"})
    req = urllib.request.Request(fixture["url"] + resource, data=data, headers=headers)
    with client.open(req, timeout=5) as response:
        assert response.status == 200
        assert response.headers["Content-Type"] == "application/pkcs7-mime; smime-type=certs-only"
        assert response.headers["Content-Transfer-Encoding"] == "base64"
        body = response.read(65537)
        assert len(body) <= 65536
    assert body.endswith(b"\r\n")
    lines = body[:-2].split(b"\r\n")
    assert all(0 < len(line) <= 76 for line in lines)
    der = base64.b64decode(b"".join(lines), validate=True)
    certs = pkcs7.load_der_pkcs7_certificates(der)
    assert len(certs) == 1
    return certs[0]


ca = operation("cacerts")
assert ca.public_bytes(serialization.Encoding.PEM).decode() == fixture["ca_cert"]
ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(ca.signature_hash_algorithm))
assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
previous_key = None
for resource in ["simpleenroll", "simplereenroll"]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-workload")]))
           .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("spiffe://evil.example/admin")]), critical=False)
           .sign(key, hashes.SHA256()))
    der = csr.public_bytes(serialization.Encoding.DER)
    cert = operation(resource, der)
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    assert cert.issuer == ca.subject
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert spki == key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert spki != previous_key
    previous_key = spki
    assert cert.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fixture["spiffe"])])
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == x509.SubjectAlternativeName([x509.UniformResourceIdentifier(fixture["spiffe"])])
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_cert_sign and not usage.key_encipherment
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds() == 3600
print("independent TLS EST cacerts, enrollment and rekeyed reenrollment passed")
