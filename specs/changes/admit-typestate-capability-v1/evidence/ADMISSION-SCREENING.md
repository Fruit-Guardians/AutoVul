# Typestate v1 admission screening

Status: active screening record; no candidate below is admitted as a Typestate v1 case.

This record applies the nine-item admission gate in the parent SPEC. A candidate is not
accepted merely because its description contains “use after close”, “double close”, or
“lifecycle”. It must provide a security-relevant vulnerable/fixed pair, one resource
identity, an ordered violation trace, and an Analyzer-compatible bounded completeness
boundary.

## Candidate under evaluation

### G-001 — Ghost admin-session regeneration (CVE-2026-70594)

- Upstream: `TryGhost/Ghost`, MIT; vulnerable commit
  `a8bea3a4ceec4c852b880f4885119453c3d8588e`, fixed commit
  `6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c`, scoped initially to
  `ghost/core/core/server/services/auth/session/session-service.js`.
- Security fact: the upstream advisory identifies a session-fixation vulnerability
  caused by login retaining the existing admin session. The fixed revision first
  captures the previous session, calls `req.session.regenerate`, then assigns the
  user to the newly installed session object.
- Candidate protocol: resource identity is the direct `req.session` object within
  `createSessionForUser`; states are `preauth`, `rekeyed`, and `authenticated`;
  events are `read_session`, `regenerate`, and `assign_user`; the frozen proposed
  violation form is `assign_user` while the same pre-auth session identity is
  still current.
- Why it is not MissingCheck: `regenerate` is a state-changing identity rotation,
  not a boolean guard that dominates a protected call. The security predicate
  depends on authentication being bound to a different session identity after the
  transition, not merely on the syntactic presence of a call.
- Proposed Analyzer boundary: CodeQL JavaScript with a single staged source file,
  one direct `req.session` receiver, direct local aliases only, and no callbacks,
  cross-function aliasing, reflection, or concurrent request reasoning. This is
  a proposed boundary, not an Analyzer witness.
- Remaining admission evidence: no CodeQL ordered identity witness has yet been
  run; no wrong-resource/wrong-event fixtures or model-free replay exist. The
  candidate is therefore **not admitted** and authorizes no Typestate production
  Schema or implementation.

## Rejected candidates

| Candidate | Source | Why it was considered | Gate failure | Disposition |
| --- | --- | --- | --- | --- |
| CPython Emscripten fd read regression (`800d37f`) | [commit announcement](https://www.mail-archive.com/python-checkins%40python.org/msg13444.html) | One file distinguishes a closed file descriptor before async use. | It is a regression fix rather than an established security vulnerability; native/Emscripten analysis also does not provide the proposed no-target-build, identity-backed Analyzer witness. | Rejected. |
| Node/Windows async-handle shutdown issue #64322 | [issue](https://github.com/nodejs/node/issues/64322) | Describes use-after-close during teardown. | It is an unresolved platform reliability report, includes shutdown concurrency, and has neither a fixed target nor a bounded single-resource witness. | Rejected. |
| Generic resource-leak and closed-file examples | [PEP 533 discussion](https://peps.python.org/pep-0533/) | Illustrates why operation order matters for file handles and iterators. | Design examples are not a reproducible security vulnerability or vulnerable/fixed target pair. | Rejected as admission evidence; retained only as domain background. |

## Frozen screening criteria

The next candidate MUST be rejected before implementation if any of these is absent:

1. A public source revision establishes one security-relevant vulnerable behavior and one
   fixed or equally strong safe counter-example.
2. The witness can be stated as events on one identity, for example
   `open -> close -> use`, and cannot be honestly reduced to a missing guard or a value
   propagation path.
3. The chosen Analyzer can observe the ordered events and direct identity evidence without
   relying on text order, mocked results, or event aggregation across objects.
4. The completeness boundary is finite and explicit. Unsupported aliases, callbacks,
   concurrency, reflection, or dynamic dispatch must become a capability gap rather than a
   positive verdict.
5. The target can be analyzed without executing unapproved install, build, migration,
   service, or exploit steps.

## Current outcome

No candidate satisfies the parent SPEC’s admission gate. Typestate remains `Draft`; this
file does not authorize contracts, routing, adapters, or a support claim.
