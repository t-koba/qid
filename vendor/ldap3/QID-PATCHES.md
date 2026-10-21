# qid ldap3 Fork

## Provenance

- Upstream project: `https://github.com/inejge/ldap3`
- Upstream crate and version: `ldap3` 0.12.1
- Upstream crate commit: `1107b192bb12783d8727025a77aeec079612afad` (the published
  crate's `.cargo_vcs_info.json` revision)
- Upstream licenses: Apache-2.0 and MIT
- qid integration: the workspace `[patch.crates-io]` entry replaces every `ldap3`
  0.12 dependency with this source tree

The upstream base source was copied from the published crates.io package of
0.12.1 before applying the qid patch. Do not replace this directory with an
unversioned branch snapshot.

## qid Patch Boundary

The fork changes one behavior: the response controls a server sends inside the
LDAPResult are read.

RFC 4511 puts the response controls in the LDAPResult:

```text
LDAPResult ::= SEQUENCE {
     resultCode        ENUMERATED { ... },
     matchedDN         LDAPDN,
     diagnosticMessage LDAPString,
     referral          [3] Referral OPTIONAL,
     controls          [0] Controls OPTIONAL }
```

Upstream 0.12.1 reads the controls of the LDAPMessage, which is where the
*request* controls live, so a control the server sends in the result is
dropped and `LdapResult.ctrls` stays empty. The RFC 2696 paging cookie is such
a control, so a paged search cannot read the cookie the server sent: the search
ends with "LDAP paged search did not return a PagedResults control" against
every directory that answers the way the standard requires.

Two places change, each marked with a `qid:` comment in the source:

1. `src/result.rs`: the LDAPResult's `controls [0]` element is parsed into
   `LdapResult.ctrls`.
2. `src/search.rs`: the message-level controls are added to the controls the
   result already carries, instead of replacing them, so a conformant response
   keeps the control it carried.

Nothing else changes. The request controls, the request and response encodings,
the TLS features, the SASL and extended-operation handling and the public API
are upstream's.

A control the parser cannot read ends the response parse the way a malformed
LDAPResult already does: the client's driver task stops and the operation
fails with an error. The process is not affected, and a directory server cannot
do more with a malformed control than it can by closing the connection.

## Update Procedure

1. Verify the new upstream version and its licenses.
2. Replace the source from the published crate of that version, without
   carrying generated `target` output.
3. Reapply the patch above. The two hunks are small; each carries a `qid:`
   comment that marks it, and the upstream base around them is unchanged since
   0.12.1.
4. Run `cargo fmt --all` in this directory.
5. Run qid's directory paging regression and the workspace test suites with
   warnings denied.
6. Run `cargo deny check` and `cargo audit`; review every new transitive
   dependency and license.

Do not silently drop the patch, replace the client with another implementation,
or add a compatibility fallback during an update.
