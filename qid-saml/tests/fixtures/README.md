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
signing. This is not independent interoperability coverage. Separate external
RSA verification experiments motivated the replacement; they do not constitute
live-IdP or arbitrary XMLDSig coverage. No MPL-2.0 fixture is included.
