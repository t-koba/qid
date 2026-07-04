# qid Documentation

This directory is the documentation entry point for qid.

qid is a standalone identity and control plane. It combines IdP, OAuth/OIDC authorization server, SAML IdP, SCIM lifecycle service, PDP, policy/risk engine, governance surface, and operational tooling behind one canonical configuration model.

qid also integrates with external enforcement points. A proxy, gateway, service mesh, resource server, qpx edge, or other PEP observes traffic and applies enforcement; qid owns identity, sessions, tokens, MFA, lifecycle, risk, policy, audit, and decisions. qpx is the deepest sister-product PEP integration, and the same qid-owned surfaces also serve other PEPs and standalone deployments.

## Design Contract

- qid owns identity, sessions, tokens, MFA, SCIM lifecycle, risk, policy, audit, and PDP decisions.
- Enforcement points own traffic observation, protocol handling, routing, TLS behavior, local responses, header control, rate limiting, and effect application.
- Integration happens through canonical qid surfaces such as OIDC/OAuth, SAML, SCIM, signed PEP assertions, AuthZEN-style evaluation, and `/pep/decision/v1/evaluate`.
- PEP registration is a qid trust record for an external enforcement point: credential-bound identity, audience, replay state, capabilities, assertion settings, and fail policy.
- PEP request bodies provide claims to verify against the authenticated registration. They are not authentication truth by themselves.
- Enforcement points own data-plane behavior such as routing, TLS inspection, caching, mirroring, packet capture, HTTP/3, MASQUE, and protocol tunneling.
- Configuration is canonical and strict. Unknown keys are rejected, profile obligations are explicit, and pre-stable internal legacy aliases are not part of the product model.

## Reading Order

1. [architecture.md](architecture.md): product boundary, runtime planes, crate responsibilities, and `qidd` startup flow.
2. [configuration.md](configuration.md): canonical `QidConfig`, strict validation, profiles, and PEP registration.
3. [security.md](security.md): fail-closed boundaries, PEP trust, token/key handling, SAML/SCIM, and sensitive data rules.
4. [http-api.md](http-api.md): HTTP surfaces grouped by plane.
5. [operations.md](operations.md): startup, migrations, keys, audit, workers, backups, and network AAA.
6. [cli.md](cli.md): daemon and companion CLI commands.
7. [development.md](development.md): build, test, gates, fuzzing, and extension rules.

## References

- [../config/README.md](../config/README.md): use-case-oriented configuration samples.
- [../config/qid.example.yaml](../config/qid.example.yaml): representative configuration.
- [../fuzz/README.md](../fuzz/README.md): fuzz targets.

## Terms

| Term | Meaning |
| --- | --- |
| Realm | Issuer boundary for OIDC/OAuth, SAML entity identity, clients, users, authentication policy, protocol settings, policy bundles, and PEP registrations. |
| Profile | Deployment mode such as `oidc`, `edge-pep`, `fapi`, `enterprise`, `ciam`, `workload`, `high-assurance`, `network-aaa`, or `vc`; each profile adds validation obligations. |
| PDP | Policy Decision Point. qid evaluates identity, assurance, risk, resource, and policy context. |
| PEP | Policy Enforcement Point. A proxy, gateway, service mesh, resource server, qpx edge, or similar data-plane component that applies a decision. |
| PEP registration | qid-side trust record for a PEP identity, audience, capabilities, assertion settings, and decision fail policy. It is provider-neutral. |
| RuntimePlan | Normalized runtime view derived from `QidConfig`. |
