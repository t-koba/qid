# XMLDSig verifier fixtures

## Independent ECDSA-SHA256 response

`vgi-saml-signed-response-ecdsa.xml` is the signed SAML Response fixture from
[Query-farm/vgi-saml](https://github.com/Query-farm/vgi-saml), source commit
[`5c14a1902c51261696f5fa81210ce62e150f3bbd`](https://github.com/Query-farm/vgi-saml/tree/5c14a1902c51261696f5fa81210ce62e150f3bbd).
Upstream licenses this fixture under the
[MIT license](https://github.com/Query-farm/vgi-saml/blob/5c14a1902c51261696f5fa81210ce62e150f3bbd/LICENSE).
Attribution: Query-farm/vgi-saml contributors. It is an offline test vector,
not live identity-provider traffic. The example identity values are fixture data.

Keep the file byte-for-byte unchanged (no trailing newline normalization):

- Raw file SHA-256:
  `9fde9a20177bfcb853b2d667a0ced457ee4ea1a2cb94834559c35d6abad45013`
- Embedded X.509 certificate DER SHA-256 fingerprint:
  `21b45f117b1a67a32300d524eefde46d111a64ba4bfacecdd75b68be0330d953`
- Signature: ECDSA-SHA256, P-256, referencing Assertion `#_a1`.

The regression test pins both hashes and consumes NameID and every
AttributeValue from the exact candidate-resolved Assertion in the original
Uppsala Document. The certificate is explicitly selected as the test's trusted
key; embedded KeyInfo is never enabled as a verifier trust source.

## RSA coverage

No independent RSA fixture is included here. Existing `tests/data/test-sp.*`
keys support local RSA-SHA256 algorithm-path smoke tests using bergshamra test
signing. `tests/signing.rs` additionally exercises the production signer with
those RSA keys and the existing local P-256 test key: inherited namespaces,
exact Reference/target binding, Assertion-before-Response sequential signing,
metadata placement/coverage with and without optional Extensions (Signature
follows Extensions and precedes role descriptors), signing policy and local key
constraints. The encryption regression uses the existing RSA test certificate/key
for Assertion-sign -> encrypt -> Response-sign -> decrypt with both signing key
types. It verifies the outer signature over the encrypted document, rejects
ciphertext tampering, confirms no plaintext Assertion remains, and verifies the
inner signature after decryption in its inherited namespace context. The
no-encryption dual-signing regression is retained. These tests exercise the
production signing/encryption APIs in SSO order, not the HTTP handler or a remote
SP. They check signatures with the backend without changing the inbound
single-signature policy. The outbound API emits no KeyInfo. A separate offline
check independently recomputed production-output digests with libxml2 C14N and
verified RSA/P-256 SignedInfo signatures with OpenSSL for Response, Assertion,
and EntityDescriptor targets. These generated documents are not third-party
fixtures and do not establish generic-SP or live-IdP interoperability, arbitrary
XMLDSig support, or an independent SAML fixture corpus. No MPL-2.0 fixture is
included.
