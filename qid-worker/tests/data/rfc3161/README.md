# RFC 3161 conformance fixtures

`valid_bundle.json` and `valid_trusted_root.json` are copied unchanged from
`sigstore-tsa` 0.11.0 `test_data/timestamps`, which identifies them as
Sigstore conformance test data. The source crate is licensed under Apache-2.0.

The test decodes the real timestamp token, timestamped signature, and trusted
root and performs CMS, message-imprint, time-stamping EKU, and PKIX path
verification. These files are not production trust material.
