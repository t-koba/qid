# Standards Implementation Boundaries

This document records exact implementation boundaries. A helper type, parser, or configuration placeholder is not counted as wire-protocol support.

## Security and Transport RFCs

| Standard | qid status | Boundary |
| --- | --- | --- |
| [RFC 5280 X.509 PKIX](https://www.rfc-editor.org/rfc/rfc5280.html) | Supported for native HTTP client certificates | With `server.tls.client_ca`, rustls/webpki validates every presented client certificate chain, validity period, client-authentication usage, signatures, and trust anchor before OAuth receives the leaf thumbprint. Configured CRLs are enforced fail-closed. |
| [RFC 6066 OCSP stapling](https://www.rfc-editor.org/rfc/rfc6066.html) | Supported for the leaf server certificate | The first `server.tls.ocsp_responses` entry is also offered through the legacy `status_request` extension when it is non-empty. qid does not fetch or silently replace a missing response. |
| [RFC 6961 multiple certificate status](https://www.rfc-editor.org/rfc/rfc6961.html) | Supported for TLS 1.2 server handshakes | qid's vendored rustls implements `status_request_v2`, client preference processing, `ocsp_multi` CertificateStatus encoding, ordered response lists with empty per-certificate entries, RFC 6066 fallback, and strict extension-conflict checks. Clients only advertise `status_request_v2` when their certificate verifier explicitly opts in and implements complete multi-response validation. TLS 1.3 continues to use its per-certificate `status_request` mechanism. |
| [RFC 3161 Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html) | Supported for WORM audit exports with a configured compatible TSA | `qid-worker` creates a nonce-bearing SHA-256 request, requires HTTPS and `application/timestamp-reply`, limits the response size, verifies the nonce, imprint, CMS signature, time-stamping EKU, and path to configured roots, and stores the response and its digest in the evidence manifest. Failures abort the job. The current verifier accepts ECDSA TSA keys on P-256/P-384. |
| [RFC 6979 deterministic ECDSA](https://www.rfc-editor.org/rfc/rfc6979.html) | Supported for local ES256 JWT signing | All local P-256 JWT paths use the `p256` deterministic signer. Remote KMS/HSM signing nonce behavior remains the provider's responsibility. |
| [RFC 9966 TLS Proof of Knowledge](https://www.rfc-editor.org/rfc/rfc9966.html) | Supported for TLS 1.3 over TEAP | `qid-network::tls_pok` strictly validates the registered NAI and a single compressed-point EC SubjectPublicKeyInfo, derives the RFC 9258 imported PSK, and drives a TLS 1.3 handshake through TEAP fragments. The vendored rustls negotiates RFC 8773 `tls_cert_with_extern_psk`, requires `psk_dhe_ke`, generates and verifies the RFC 9258 `imp binder`, requests an RFC 7250 client Raw Public Key, and compares it in constant time with the BSK selected by the imported identity. Key material is redacted and zeroized. Corrupt binders, mismatched Raw Public Keys, unsupported hashes, resumption, 0-RTT, ECH, QUIC, and non-TLS-1.3 configurations fail closed. |
| [RFC 6614 RADIUS/TLS](https://www.rfc-editor.org/rfc/rfc6614.html) | Supported | `qid-network` implements TCP RADIUS/TLS with rustls and optional required client authentication. |
| [RFC 7360 RADIUS/DTLS](https://www.rfc-editor.org/rfc/rfc7360.html) | Not supported | There is no DTLS listener or transport. The former configuration-only placeholder was removed. |
| [RFC 9147 DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html) | Not supported | The permitted rustls backend is stream TLS and does not implement DTLS. qid does not depend on wolfSSL, GnuTLS, or GPL/commercial-only DTLS implementations, and OpenSSL does not supply DTLS 1.3. No placeholder is exposed as protocol support. |
| [RFC 9849 Encrypted ClientHello](https://www.rfc-editor.org/rfc/rfc9849.html) | Helpers only | `qid-crypto::ech` parses and validates ECH configuration data. qid does not claim ECH wire integration until the serving TLS stack exposes it. |

RFC 9966 Appendix A.3 publishes the same 90-byte secp521r1 DER SPKI twice as a 180-byte BSK. Its published `epskid` is the result of deriving from those duplicated bytes, but that input contradicts the normative requirement for one DER SubjectPublicKeyInfo. qid reproduces the published derivation vector in a regression test while rejecting the concatenated value at BSK registration.

## Verifiable Credential Drafts

[`draft-ietf-oauth-sd-jwt-vc`](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) and [`draft-ietf-oauth-status-list`](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) are active Internet-Drafts, not RFCs. qid has selective-disclosure credential primitives and a W3C Bitstring Status List implementation, but those names do not imply conformance to either OAuth draft. Draft conformance requires a versioned implementation and interoperability suite because draft wire formats can still change.

## Review Rule

When adding a standards citation, identify the exact wire behavior and add a conformance or interoperability test. Do not cite a base protocol RFC for an extension defined elsewhere, and do not keep configuration-only structures for transports that are not implemented.
