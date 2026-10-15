# qid rustls Fork

## Provenance

- Upstream project: `https://github.com/rustls/rustls`
- Upstream crate and tag: `rustls` 0.23.46, `v/0.23.46`
- Upstream tag commit: `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb` (also the published crate's `.cargo_vcs_info.json` revision)
- Upstream licenses: Apache-2.0, MIT, and ISC
- qid integration: the workspace `[patch.crates-io]` entry replaces every rustls 0.23 dependency with this source tree

The upstream base source and test assets were copied from the exact GitHub tag before applying the qid patches. Do not replace this directory with an unversioned branch snapshot.

## qid Patch Boundary

The fork adds two opt-in protocol surfaces:

1. RFC 9258 imported external PSKs and RFC 9973 (which obsoletes RFC 8773) certificate authentication with an external PSK, used by RFC 9966 TLS-POK. This includes the `imp binder`, required ClientHello `supported_groups`, mandatory `psk_dhe_ke`, TLS 1.3 and Raw Public Key restrictions, constant-time identity/key matching, and fail-closed rejection of incompatible resumption, 0-RTT, and QUIC modes. The imported-PSK client builder rejects ECH. The server does not process ECH; RFC 9849 keeps a real PSK identity inside ClientHelloInner, while the TLS-POK server requires a resolvable imported identity from the ClientHello it receives. No end-to-end ECH/TLS-POK integration is claimed. RFC 9973 §5 placement is enforced: `tls_cert_with_extern_psk` is permitted only in ClientHello and ServerHello, and produces `illegal_parameter` in HelloRetryRequest, EncryptedExtensions, CertificateRequest, NewSessionTicket, and every TLS 1.3 CertificateEntry, including decompressed certificates. HelloRetryRequest shares ServerHello's encoding, not its permitted-extension set (RFC 8446 §§4.1.4 and 4.2). Unrelated unknown-extension handling is unchanged. The inherited TLS 1.3 key schedule uses the RFC 9973-corrected `HKDF-Extract(0, external PSK)` order for the Early Secret.
2. RFC 6961 `status_request_v2` and TLS 1.2 `ocsp_multi`, including ordered response lists, legacy RFC 6066 fallback, extension-conflict rejection, and an explicit client verifier capability and validation callback.

Neither surface is enabled by an ordinary upstream rustls configuration. New behavior requires explicit use of the imported-PSK builder/resolver or the multi-OCSP builder/verifier methods.

## Update Notes (0.23.45 -> 0.23.46)

- Updated using the `xtask vendor-sync` three-way merge: published 0.23.45 crate as the base, the qid fork as the local side, and the published 0.23.46 crate as the new side. The cached upstream `v/0.23.46` ref and the new crate identify the same commit above; source and test assets were checked against that revision. The licenses are unchanged. No advisory exemptions or TLS implementation changes were made.
- Retains upstream security changes: reject ECH before enabling application traffic (`4de14a50`), enforce the HelloRetryRequest ECH decision (`ca4a9c21`), and delay caching the key-exchange hint until handshake confirmation (`f04804fa`). In `client/tls13.rs`, the new `kx_group` field is carried through every certificate, compressed-certificate, certificate-request, and Finished state alongside qid's imported-PSK authentication and extension-placement checks.
- Also retains record-confidentiality-limit checks and timely TLS 1.3 key updates for buffered/fragmented and unbuffered writes (`93636305`, `ab3ca337`, `74343e70`, `2b82b814`), protected ChangeCipherSpec rejection (`fce9c85c`), strict compressed-certificate decoding (`1aa987af`, `b10cdb0d`), secret redaction in session Debug output (`dcdb9464`, `6d0ba089`), and the other upstream 0.23.46 changes.
- Resolved the `server/tls13.rs` overlap by keeping qid's multi-OCSP response argument while projecting the upstream `(psk_index, session)` pair to the session for common extension processing. The full pair reaches the early-data decision, which now requires PSK index zero (`5ed42b32`); imported-PSK flows still reject early data and disable tickets. Kept upstream's empty client certificate-request-context check alongside qid's RFC 9973 restrictions. Test import conflicts in `client/test.rs` and `server/test.rs` retain both upstream regression tests and qid protocol tests.
- Advisory evidence limitation: the failing CI audit reported four entries but did not name them in its retained log. The available offline advisory database predates this release and lacks RUSTSEC-2026-0346 through RUSTSEC-2026-0349. The upstream fixes above were reviewed directly; the proposed advisory-to-fix mapping and a clean current-database audit must be confirmed separately, not inferred from an offline policy pass.

## Update Notes (0.23.41 -> 0.23.45)

- Includes upstream fix for GHSA-2mjx-qc3c-rqvc (RUSTSEC-2026-0285): TLS 1.3 handshake messages are now rejected when they span a key-change record boundary.
- Carries upstream RFC 9149 ticket request extensions, RFC 9846 second-ClientHello PSK rules, `supports_version` protocol check, QUIC version suitability, OCSP non-empty enforcement (`PayloadU24<NonEmpty>`), ML-DSA support, and key-log file permission hardening.
- qid protocol patches were re-applied on the 0.23.45 base: imported-PSK flows now use the `previous_hello` retry tracker, ticket counts honor both the imported-PSK policy (`send_tickets = 0`) and the client ticket request hint, and `CertificateStatus` keeps the `Ocsp`/`OcspMulti` enum with `NonEmpty` responses.

## Update Procedure

1. Verify the new upstream tag and licenses.
2. Replace the source from that exact tag without carrying generated `target` output. Use `cargo run -p xtask --locked -- vendor-sync --to <version> --dry-run` first to preview the three-way merge; it leaves the vendor tree untouched when conflicts remain.
3. Reapply the qid changes as a reviewable patch; resolve upstream protocol changes deliberately. When the dry run reports no conflicts, re-run without `--dry-run` to write the tree.
4. Run `cargo fmt --all` in this directory.
5. Run `cargo test --manifest-path vendor/rustls/Cargo.toml --lib`.
6. Run qid's RFC 9966, RFC 6961, RFC 5280, and workspace test suites with warnings denied.
7. Run `cargo deny check` and `cargo audit`; review every new transitive dependency and license.

Do not silently drop a protocol patch, substitute another TLS implementation, or add a compatibility fallback during an update.
