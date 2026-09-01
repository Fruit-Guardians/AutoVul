# Change: Admit Typestate Capability v1

- Change ID: `admit-typestate-capability-v1`
- Status: Accepted
- Owner: AutoVul maintainers
- Created: 2026-08-29
- Updated: 2026-09-01
- Admission gate: Satisfied by the Ghost CVE-2026-70594 evidence package
- Depends on: `establish-research-capability-architecture` and the Verified Flow v1 and MissingCheck v1 shared-runtime baselines

## Problem

Some vulnerabilities are determined by the order in which operations affect one resource: use before initialization, use after close, double release, missing finalization, unsafe reuse after validation, or an illegal protocol transition. The decisive evidence is a sequence of state transitions for a tracked object or protocol instance, not a Source-to-Sink path and not merely an absent guard.

Modeling these defects as Flow would confuse value propagation with lifecycle semantics. Modeling them as MissingCheck would lose transition order and object identity. Typestate is therefore a candidate parallel Capability, but it must be admitted by a real case and a real Analyzer witness before any production state-machine abstraction is introduced.

This Accepted change SPEC defines the admission evidence, a deliberately narrow single-resource v1 contract candidate, implementation phases, and verification gates. It does not claim that Typestate is implemented or supported.

## Host boundary

The host Agent reads code and vulnerability context, selects Typestate, proposes the tracked resource and protocol events, revises the hypothesis, and decides whether to continue or stop.

AutoVul validates the versioned protocol hypothesis, executes one bounded Analyzer operation, records transition observations, applies a deterministic Typestate Decision Policy, commits evidence, and supports replay.

AutoVul MUST NOT infer arbitrary protocols from an entire repository, invent missing events, generate a replacement protocol, automatically patch lifecycle code, or become a general program verifier.

## Relationship to existing specifications

- Root `SPEC.md` owns shared runtime, evidence, safety, and change control.
- `establish-research-capability-architecture` owns the case-gated parallel-Capability rule.
- Flow and MissingCheck semantics MUST NOT be reused as Typestate domain types.
- The real-case admission record is frozen in
  [`evidence/ghost-cve-2026-70594/README.md`](./evidence/ghost-cve-2026-70594/README.md)
  and [`evidence/ghost-cve-2026-70594/RESULTS.json`](./evidence/ghost-cve-2026-70594/RESULTS.json).
- Candidate screening and rejected-case rationale are recorded in
  [`evidence/ADMISSION-SCREENING.md`](./evidence/ADMISSION-SCREENING.md). A screening
  record is not an admission record.

## Scope

### In scope

- Define the evidence required to admit Typestate as a later Capability.
- Freeze one tracked resource, one bounded protocol, and one prohibited behavior for v1.
- Separate host-proposed protocol, Analyzer transition observations, and Core decision.
- Define structured identity, alias, missing-event, ordering, and capability-gap feedback.
- Reuse `autovul_research`, `autovul_run`, and the shared deterministic runtime.
- Require one concrete Analyzer chosen by the real admission case.
- Require vulnerable/fixed or equivalent counter-example evidence and model-free replay.
- Define an implementation sequence that begins only after acceptance.

### Non-goals

- A universal state-machine language, temporal-logic engine, symbolic executor, model checker, or theorem prover.
- Whole-repository protocol mining or automatic inference of lifecycle contracts.
- Multiple interacting resources, concurrent protocols, distributed workflows, or cross-process state in v1.
- Unbounded event alphabets, arbitrary predicates on transitions, nested automata, inheritance, or user-defined executable code in contracts.
- Recasting event order as taint Flow or a missing guard.
- Automatic repair, exploit generation, Finding prose, severity scoring, or autonomous revision loops.
- A Capability registry, generic base class, or placeholder modules for other paradigms.
- Production Typestate code or support claims are not added by this admission
  change; support remains blocked until a later implementation reaches Verified.

## Definitions

- **Tracked resource**: the single object, handle, session, request, transaction, or protocol instance whose lifecycle is analyzed.
- **Protocol event**: a bounded, selector-backed operation that changes or observes the resource state.
- **Protocol state**: a contract label used by the Typestate Decision Policy; it is not a shared runtime state.
- **Transition rule**: a declared event-driven state change for the tracked resource.
- **Violation condition**: one prohibited transition, prohibited event-in-state, or required terminal condition selected for v1.
- **Violating witness**: persisted Analyzer evidence that one identified resource follows an event sequence satisfying the declared violation condition.
- **Identity evidence**: Analyzer evidence that observed events refer to the same resource under the accepted alias boundary.
- **Completeness boundary**: the exact call graph, alias model, entry points, and event scope within which a negative result is meaningful.
- **Typestate decision**: the Core verdict `violation_observed`, `no_violation_observed`, or `unknown`.

## Admission gate — satisfied

The nine admission requirements below are satisfied by the frozen Ghost case
record. This acceptance authorizes only the narrow implementation phases in
this SPEC; it does not claim that Typestate is implemented or supported.

1. one reproducible vulnerability whose decisive fact is event order for one resource;
2. why neither Flow nor MissingCheck can represent the case honestly;
3. one fixed target or equally strong counter-example;
4. the exact resource identity, initial state, event alphabet, transitions, and violation condition;
5. one Analyzer that can persist an ordered witness and identity evidence;
6. the accepted alias and call-graph completeness boundary;
7. a vulnerable violating trace and fixed or safe counter-trace;
8. at least two wrong-hypothesis fixtures producing different field-level revisions;
9. a model-free replay artifact.

Evidence mapping and replay counts are in
[`evidence/ghost-cve-2026-70594/RESULTS.json`](./evidence/ghost-cve-2026-70594/RESULTS.json).

### Frozen admission case

- Case: Ghost admin-session fixation, CVE-2026-70594 / GHSA-7mpp-r37j-x5wh.
- Vulnerable source: commit
  `a8bea3a4ceec4c852b880f4885119453c3d8588e`.
- Fixed source: commit
  `6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c`.
- Analyzer: CodeQL JavaScript `2.26.1`, database mode `none`, one staged source
  file, no target build or install.
- Contract candidate: `autovul.typestate/1`.
- Resource: exactly one logical `login_session` request-session slot. Its
  physical identity is the concrete object held by the accepted local binding.
- States: exactly `preauth`, `rekeyed`, and `authenticated`.
- Events: exactly `session_acquired`, `regenerate_request_session`, and
  `assign_user`.
- Allowed transitions: `preauth --session_acquired--> preauth`,
  `preauth --regenerate_request_session--> rekeyed`, and
  `rekeyed --assign_user--> authenticated`.
- Sole violation: prohibited `preauth --assign_user--> authenticated` when the
  authenticated value has the same concrete identity selected by
  `session_acquired` and no direct `req.session.regenerate` event intervenes.
- Identity boundary: the same lexical local must be initialized directly by
  `await getSession(req, res)` and used as the `session` property of the direct
  `assignUserToSession` call. The fixed safe trace binds the post-regeneration
  `req.session` value directly. Cross-file aliases, indirect calls, reflection,
  arbitrary dispatch, framework callback semantics, and concurrency are outside
  the completeness boundary and cannot produce a positive witness.
- Real evidence: the vulnerable query returns one ordered identity-backed
  witness and the fixed target returns zero; the fixed safe-trace query returns
  one ordered acquire/rekey/authenticate trace; a different-resource counterexample
  returns zero under the identity-aware query and one under the call-order-only
  control query; wrong resource and wrong event hypotheses return zero with
  distinct revision paths.

This case cannot be represented honestly as Flow because its decisive fact is
ordered identity-preserving or identity-changing lifecycle behavior, not value
propagation from a source to a sink. It cannot be represented honestly as
MissingCheck because `regenerate` is not a dominating boolean guard: presence
on another object or after authentication is insufficient. Encoding either
identity and ordering relation in those capabilities would import Typestate
semantics into their domain contracts.

## Requirements

### Capability identity and isolation

- `REQ-TSTATE-001`: Typestate MUST be admitted only for a real case whose success predicate depends on ordered state transitions for one resource.
- `REQ-TSTATE-002`: The admission record MUST explain why Flow and MissingCheck cannot represent the case without losing resource identity or event-order semantics.
- `REQ-TSTATE-003`: Typestate MUST independently own its Hypothesis, Observation, Decision Policy, diagnostics, revision actions, Port, success predicates, Golden cases, and replay gates.
- `REQ-TSTATE-004`: Typestate MUST reuse shared run, budget, timeout, cancellation, locks, recovery, artifact commit, evidence references, and replay routing.
- `REQ-TSTATE-005`: Shared runtime code MUST NOT interpret resource, state, event, transition, alias, or violating-trace fields.
- `REQ-TSTATE-006`: Composition MUST use an explicit `typestate` branch and MUST NOT introduce a registry, dynamic loader, factory, or generic Capability base class.
- `REQ-TSTATE-007`: Typestate MUST use the aggregate Application and host interfaces; no `autovul_typestate` model tool may be added.
- `REQ-TSTATE-008`: The host MUST retain protocol-hypothesis generation, revision, action selection, and stopping authority.
- `REQ-TSTATE-009`: Typestate MUST NOT be documented as supported before Verified.

### Frozen hypothesis contract

- `REQ-TSTATE-010`: The accepted contract version MUST be exactly `autovul.typestate/1`.
- `REQ-TSTATE-011`: A v1 hypothesis MUST describe exactly one tracked resource, one initial state, a bounded event alphabet, a bounded transition set, one violation condition, and one completeness boundary.
- `REQ-TSTATE-012`: Resource and event selectors MUST be Typestate-owned and MUST NOT reuse FlowEndpoint or MissingCheck operation/check selectors by type alias.
- `REQ-TSTATE-013`: Protocol states and event ids MUST be stable identifiers with strict count and length bounds.
- `REQ-TSTATE-014`: Each transition MUST declare one `from_state`, one event, and one `to_state`; hidden side effects and executable expressions MUST be forbidden.
- `REQ-TSTATE-015`: v1 MUST support exactly one violation form: `prohibited_transition` with `requires_same_identity: true`.
- `REQ-TSTATE-016`: The hypothesis MUST declare the resource identity and alias boundary the Analyzer is expected to support.
- `REQ-TSTATE-017`: Target refs, Analyzer id, mode, budget, idempotency key, evidence refs, message, CWE, rationale, and presentation fields MUST remain outside the hypothesis.
- `REQ-TSTATE-018`: The hypothesis MUST NOT contain a precomputed `violating`, `confirmed`, or `vulnerable` field.
- `REQ-TSTATE-019`: v1 MUST reject multiple resources, concurrent event interleavings, recursive protocol composition, arbitrary extension properties, and unbounded state graphs.

### Phase B schema freeze

The following is the exact Phase B contract surface. The TypeBox schemas in
`packages/contracts/src/typestate.ts` are authoritative, and every object has
`additionalProperties: false` unless stated otherwise.

`TypestateHypothesis` has exactly these required fields:

```text
schema_version: "autovul.typestate/1"
hypothesis_id: identifier
language: "javascript"
resource: { id, kind, binding_name, acquisition_event, identity_model }
initial_state: state identifier
states: state identifier[2..4], unique
events: event[1..4]
transitions: transition[1..8]
violation: { kind, from_state, event, to_state, requires_same_identity }
analysis_scope: { kind, file, entry, event_scope, alias_boundary }
```

The exact nested fields and closed values are:

- `identifier` is 3–128 characters matching
  `^[a-z0-9][a-z0-9._-]{2,127}$`. JavaScript selector names, receivers,
  binding names, function names, and argument properties are 1–160 characters
  with the JavaScript identifier-compatible patterns frozen in the Contract.
- `resource.kind` is `local_binding`; `resource.identity_model` is
  `direct_lexical_binding`; `resource.binding_name` is the local binding;
  `acquisition_event` is an event id.
- An `event` has `id` and `selector`. A `direct_call` selector has `kind`,
  `name`, and optional `argument_property`. A `direct_method` selector has
  `kind`, `receiver`, and `name`. The selector kind enum is exactly
  `direct_call | direct_method`.
- A `transition` has `from_state`, `event`, and `to_state`. The sole
  `violation.kind` is `prohibited_transition`, and
  `requires_same_identity` is the literal `true`.
- `analysis_scope.kind` is `single_file_named_function`; `entry` has
  `kind: named_function` and `name`; `event_scope` is
  `named_function_including_inline_callbacks`; `alias_boundary` is
  `direct_lexical_binding`.

The exact numeric limits are frozen as follows. These are contract limits and
are separate from shared runtime budgets:

| Limit | Value |
| --- | ---: |
| `maxStates` | 4 |
| `maxEvents` | 4 |
| `maxTransitions` | 8 |
| `maxTraceEvents` | 8 |
| `maxLocationsPerItem` | 4 |
| `maxIdentityEvidence` | 8 |
| `maxCapabilityGaps` | 16 |
| `maxEvidenceRefs` | 32 |
| `maxAllowedValues` | 32 |
| `maxLimitations` | 8 |
| `maxIssueCount` | 64 |
| `maxActions` | 4 |
| `maxRevisionHints` | 8 |
| `maxCompactObservations` | 16 |
| `maxIdentifierLength` | 128 |
| `maxSelectorTextLength` | 160 |
| `maxFileLength` | 1024 |
| `maxIdempotencyKeyLength` | 256 |

`violation_step` is a zero-based index into the ordered `events` array.
Additional scalar bounds are `states >= 2`, `events >= 1`,
`transitions >= 1`, `start_line >= 1`, `end_line >= 1`, and
`violation_step` in `0..7`. State ids and completeness limitation values are
unique. The completeness limitation enum is exactly
`cross_file_aliases_excluded | indirect_calls_excluded | reflection_excluded |
dynamic_dispatch_excluded | framework_callbacks_excluded |
concurrency_excluded | helper_semantics_excluded`.

Every `location` has required `file` and `start_line`, with optional
`end_line`. A validation issue has required `code` and JSON Pointer `path`,
with optional bounded `allowed_values` (strings or booleans) and
`expected_kind`. A validation result has required `valid`, `issues`, and
`allowed_next_actions`, with an optional normalized `hypothesis` only when
`valid` is true.

The observation contract has exactly these top-level fields:

```text
schema_version, compile_accepted, resource, events, traces,
fixed_resource?, fixed_events?, fixed_traces?, completeness,
capability_gaps, evidence_refs, analyzer
```

`compile_accepted` is `true | false | not_run`. Resource and event states are
`observed | not_found | not_run`. A trace state is
`violating_witness | safe_trace | inconclusive | not_run`; every trace has
`state`, `resource_id`, `events`, `identity_evidence`, and `evidence_ref`,
with optional `violation_step`. Each trace event has `event_id`,
`from_state`, `to_state`, and optional `location`. Identity evidence has
`kind: same_binding | identity_change | direct_selector`, `resource_id`,
`event_ids`, and `locations`. Completeness has a `vulnerable` boundary and an
optional `fixed` boundary; each boundary has `status: complete | incomplete |
not_run`, `scope`, and `limitations`. Analyzer provenance is restricted to
`analyzer_id: codeql`, `evidence_kind: real_analyzer | test_double`, and the
boolean `available`, with optional bounded `version` and `adapter_version`.

The decision and compact-result contracts have these exact fields:

- `TypestateDecision`: required `capability: typestate` and
  `outcome: violation_observed | no_violation_observed | unknown`; differential
  results may additionally contain `fixed_outcome` and
  `fixed_policy_satisfied`.
- `TypestateRevisionHint`: required `action`, `path`, and `reason_code`; the
  action enum is exactly `revise_resource | revise_event |
  revise_transition | revise_violation | revise_scope`. v1 has no free-form
  constraint object; closed repair values live in validation issues.
- `TypestateCompactObservation`: required `code`, with optional `path`,
  `locations`, and `evidence_ref`.
- `TypestateExecutionResult`: required `schema_version: v2.contracts/1`,
  `run_id`, `operation_status`, `capability`, `decision`,
  `verification_level`, `observations`, `revision_hints`,
  `allowed_next_actions`, and `artifact_ref`; `budget_remaining` is optional.

The standalone Typestate request contract has required `action`, `capability`,
`hypothesis_version`, and `hypothesis`, plus optional `target`, `analyzer_id`,
`mode`, `budget`, and `idempotency_key`. `action` is `validate | execute`,
`analyzer_id` is `codeql`, and `mode` is `probe | reproduce | differential`.
It is a Contracts-only branch in Phase B; host registration remains a later
phase.

`TypestateRunArtifact` has these required fields:

```text
schema_version, capability, hypothesis_version, hypothesis, target, mode,
analyzer, operation_status, decision, verification_level, observations,
revision_hints, allowed_next_actions
```

It may additionally contain `budget`, `idempotency_key`,
`target_fingerprints`, `observation`, `decision_policy_version`, and
`budget_remaining`. The replay comparison has exactly `schema_version`,
`capability`, `status`, `recorded_decision`, optional `replay_decision`, and
`observations`; its status enum is `match | environment_blocked |
version_difference | semantic_mismatch`.

### Validation and revision

- `REQ-TSTATE-020`: Boundary input MUST be parsed from `unknown` into one normalized hypothesis or a bounded list of issues.
- `REQ-TSTATE-021`: Every issue MUST contain a stable `code` and JSON Pointer `path`, plus `allowed_values` for closed repairs.
- `REQ-TSTATE-022`: `validate` MUST be deterministic and side-effect free and MUST NOT create a run, call an Analyzer, or write artifacts.
- `REQ-TSTATE-023`: Validation MUST reject duplicate ids, unknown transition endpoints, unreachable declared states where prohibited by the frozen contract, invalid initial state, unsupported violation form, a prohibited transition declared as allowed, missing resource identity, and unknown properties.
- `REQ-TSTATE-024`: Counts MUST use the exact Phase B limits: states 2–4, events 1–4, transitions 1–8, trace events and stored traces at most 8, locations per item at most 4, identity evidence per trace at most 8, capability gaps at most 16, evidence refs at most 32, validation issues at most 64, revision hints at most 8, compact observations at most 16, and closed `allowed_values` at most 32.
- `REQ-TSTATE-025`: Envelope actions MUST remain a subset of `revise`, `execute`, `replay`, and `stop`.
- `REQ-TSTATE-026`: Revision actions MUST be exactly `revise_resource`, `revise_event`, `revise_transition`, `revise_violation`, and `revise_scope`.
- `REQ-TSTATE-027`: Every revision hint MUST contain a hypothesis JSON Pointer and stable reason code; closed repair values MUST be returned through bounded `allowed_values` or an observation/evidence reference.
- `REQ-TSTATE-028`: Core MUST NOT return or automatically apply a replacement Typestate hypothesis.
- `REQ-TSTATE-029`: Narrative protocol advice MUST NOT substitute for structured validation or revision fields.

### Analyzer observations and Decision Policy

- `REQ-TSTATE-030`: The Typestate Analyzer Port MUST return observations and capability gaps only; it MUST NOT return a decision or verification level.
- `REQ-TSTATE-031`: The observation MUST separately represent resource observation, event observations, ordered traces, identity/alias evidence, completeness boundary, capability gaps, Analyzer provenance, and evidence refs.
- `REQ-TSTATE-032`: Resource and event observation states MUST distinguish `observed`, `not_found`, and `not_run`.
- `REQ-TSTATE-033`: A violating trace MUST retain ordered event ids, bounded source locations, resource identity evidence, consecutive state continuity (`previous.to_state == next.from_state`), and the zero-based transition step at which the violation occurred.
- `REQ-TSTATE-034`: Events on different resources MUST NOT be combined into one violating witness without accepted alias evidence.
- `REQ-TSTATE-035`: Unsupported aliasing, reflection, callbacks, concurrency, framework dispatch, or incomplete call graphs MUST produce a capability gap or `unknown`.
- `REQ-TSTATE-036`: Core MUST be the sole writer of Typestate `decision` and `verification_level`.
- `REQ-TSTATE-037`: The v1 decision outcome MUST be exactly `violation_observed`, `no_violation_observed`, or `unknown`.
- `REQ-TSTATE-038`: `violation_observed` MUST require a persisted ordered witness satisfying the accepted identity and violation predicates.
- `REQ-TSTATE-039`: `no_violation_observed` MUST mean only that no violating trace was observed within the declared completeness boundary. It MUST NOT be presented as a proof of global protocol correctness.

### Evidence and verification semantics

- `REQ-TSTATE-040`: `probe` MAY observe resource and event selectors but MUST NOT establish a lifecycle violation.
- `REQ-TSTATE-041`: `reproduce` MUST require a valid violating witness on the vulnerable target.
- `REQ-TSTATE-042`: `differential` MUST require a reproduced vulnerable witness and a successfully analyzed fixed target satisfying the declared fixed policy.
- `REQ-TSTATE-043`: A fixed-side `not_run`, incomplete alias model, timeout, failure, or capability gap MUST NOT satisfy the fixed policy.
- `REQ-TSTATE-044`: A trace assembled by a model, mock, text order, or events from different identities MUST NOT raise a real verification level.
- `REQ-TSTATE-045`: `variant_validated` MUST remain unavailable unless a later accepted change defines additional cross-case protocol validation.
- `REQ-TSTATE-046`: `operation_status`, Typestate `decision`, and `verification_level` MUST remain independent.
- `REQ-TSTATE-047`: Result claims MUST identify or reference the accepted identity and completeness boundaries.
- `REQ-TSTATE-048`: Unknown and negative results MUST retain observed prefixes, missing events, capability gaps, and replay inputs without inventing the missing transition.
- `REQ-TSTATE-049`: The central real acceptance case MUST be understandable from the compact trace summary and artifact refs without raw Analyzer prose.

### Runtime, artifacts, safety, and compatibility

- `REQ-TSTATE-050`: Execute MUST create or idempotently resume one bounded shared-runtime operation and bind the idempotency key to a normalized request digest.
- `REQ-TSTATE-051`: Typestate MUST use accepted trusted-root, timeout, live cancellation, process cleanup, locking, atomic commit, and recovery behavior.
- `REQ-TSTATE-052`: A committed artifact MUST record contract version, normalized protocol, target refs and fingerprints, Analyzer provenance, alias/completeness boundaries, observations, Decision Policy version, decision, verification level, budget identity, and replay inputs.
- `REQ-TSTATE-053`: Critical traces and route metadata MUST be committed atomically before authoritative state references the result.
- `REQ-TSTATE-054`: Replay MUST revalidate targets, fingerprints, Analyzer version, and trace semantics and distinguish environment block, version difference, and semantic mismatch.
- `REQ-TSTATE-055`: Logs and artifacts MUST sanitize secrets, tokens, user data carried by events, and unrestricted environment values.
- `REQ-TSTATE-056`: The adapter MUST NOT execute target build, install, migration, network service, or exploit scripts without a separate accepted approval path.
- `REQ-TSTATE-057`: Existing Flow, CodeQL, and later MissingCheck contracts and artifacts MUST remain unchanged.
- `REQ-TSTATE-058`: Pi and CLI MUST route Typestate through the same aggregate Application API and compact result envelope.
- `REQ-TSTATE-059`: Typestate MUST remain in existing packages unless separate publication, dependencies, or size justify a new package.

## Proposed behavior

```text
Host
  -> autovul_research validate/execute
       capability: typestate
       hypothesis_version: autovul.typestate/1
       hypothesis: TypestateHypothesis
  -> Typestate Analyzer Observation
       resource + events + ordered traces + identity evidence
  -> deterministic Typestate Decision Policy
  -> compact result + durable replay artifact
```

The frozen admission shape is:

```text
TypestateHypothesis
  schema_version
  hypothesis_id
  language
  resource
  initial_state
  states[]
  events[]
  transitions[]
  violation
  analysis_scope
```

The future Core decision branch is:

```text
decision
  capability: typestate
  outcome: violation_observed | no_violation_observed | unknown
```

## Implementation plan

### Phase A — admission case and protocol freeze

- Select one vulnerable/fixed lifecycle case and record provenance.
- Freeze one resource identity, a small event alphabet, transitions, violation form, alias boundary, and completeness boundary.
- Produce the vulnerable trace, fixed/safe counter-trace, and wrong-resource/wrong-event fixtures.
- Select one Analyzer capable of ordered, identity-backed evidence.
- Preserve the exact Schema enums and Golden inputs in the admission record.

Exit gate: satisfied on 2026-09-01 by the Ghost evidence package and this
Accepted SPEC. No production code is included in Phase A.

### Phase B — contracts and pure Core policy

- Freeze the `typestate` capability discriminator and `autovul.typestate/1`.
- Add strict hypothesis, observation, decision, revision, result-branch,
  artifact, and replay Schemas with the exact fields and limits above.
- Implement deterministic structural validation and trace evaluation for the
  one-resource Ghost protocol.
- Add tests proving ordered identity, missing events, invalid transitions,
  incomplete scope, and Flow/MissingCheck domain isolation.

### Phase C — one Analyzer adapter

- Define one Port matching the frozen evidence needs.
- Implement exactly one Analyzer adapter.
- Normalize resource identity, ordered events, trace locations, incomplete analysis, timeout, cancellation, and capability gaps.
- Do not build a generic event engine or Analyzer registry.

### Phase D — shared runtime and host projection

- Add explicit research and replay branches.
- Reuse shared idempotency, budgets, cancellation, atomic commit, recovery, and artifact routing.
- Extend Pi and CLI through `autovul_research` and `autovul_run` only.

### Phase E — real verification

- Reproduce the vulnerable ordered trace.
- Verify the fixed policy on a successfully analyzed fixed target.
- Run wrong-resource, wrong-event, and safe-order negative samples.
- Replay from committed artifacts without model or host session.
- Record Analyzer version, target fingerprints, and known completeness limits.

## Contracts and artifacts

The accepted revision MUST version:

- `TypestateHypothesis`;
- validation issue/result;
- `TypestateAnalyzerObservation`;
- `TypestateDecision`;
- `TypestateRevisionHint`;
- the shared result Typestate branch;
- `TypestateRunArtifact` and replay comparison result.

Shared routing remains domain-blind. No existing artifact migration is required.

## Architecture

- Contracts own only strict data contracts.
- Core owns structural protocol validation, pure trace Decision Policy, Port, and replay comparison.
- One Analyzer/Runner owns event extraction, identity evidence, and raw trace decoding.
- Integrations only register, convert, cancel, and present aggregate calls.

Dependency direction remains unchanged. Typestate protocol state MUST never be stored as shared runtime state.

## Safety and privacy

- Validation is pure.
- Execute and replay use approved targets under trusted roots.
- Event arguments or resource labels may contain secrets; compact observations should prefer locations and stable ids, while artifacts sanitize recognized sensitive values.
- Trace, event, state, output, time, and concurrency counts are bounded.
- No build/install, live service interaction, or exploit execution is introduced.
- Cancellation terminates active Analyzer processes and preserves an honest terminal state.

## Compatibility and migration

- Addition is gated and backward compatible.
- Existing capabilities retain independent decisions and artifacts.
- The shared research request and operation-route contracts contain the
  `typestate` discriminator in Phase B; model-facing aggregate tool
  registration remains a later phase.
- Rollback disables the branch while retaining versioned artifacts for read-only inspection.
- No support claim is allowed before Verified.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-TSTATE-001` through `REQ-TSTATE-009` | Given the admission case, when reviewed, then ordered resource state—not Flow or missing-check semantics—determines success | Admission record and architecture review |
| `REQ-TSTATE-010` through `REQ-TSTATE-019` | Given protocol fixtures, when parsed, then a bounded single-resource protocol is accepted and universal/state-engine features are rejected | Schema and validator tests |
| `REQ-TSTATE-020` through `REQ-TSTATE-029` | Given malformed states, events, transitions, identity, and scope, when validated, then precise field-level repairs are returned without side effects | Validator matrix and call-count assertions |
| `REQ-TSTATE-030` through `REQ-TSTATE-039` | Given ordered, reordered, cross-resource, incomplete, and unsupported observations, when Core decides, then only an identity-backed violating trace becomes `violation_observed` | Pure Decision Policy tests |
| `REQ-TSTATE-040` through `REQ-TSTATE-049` | Given vulnerable, fixed-failed, fixed-passed, and safe-order cases, when executed, then evidence levels are never inflated | Fake adapter matrix and real vulnerable/fixed Golden |
| `REQ-TSTATE-050` through `REQ-TSTATE-059` | Given duplicate requests, cancellation, corrupt traces, untrusted paths, and replay, when operations run, then shared runtime and safety invariants hold | Failure injection and independent replay |

## Validation plan

- Focused unit tests:
  - bounded protocol Schema and graph validation;
  - deterministic trace evaluation;
  - resource identity and cross-object rejection;
  - incomplete-analysis and `not_run` matrix;
  - request digest and replay comparison.
- Failure injection:
  - missing event extraction, alias uncertainty, timeout, cancellation, Analyzer crash, corrupt trace, interrupted commit.
- Real analyzer/target:
  - one frozen vulnerable/fixed lifecycle case.
- Differential or negative sample:
  - fixed target, safe event ordering, wrong object identity, and missing selector.
- Independent replay:
  - fresh process, no model, fingerprint and Analyzer-version checks.
- Package/integration smoke:
  - one Application API and two aggregate model tools; no host logic in Core.

## Resolved admission choices

- Real case: Ghost admin-session fixation, CVE-2026-70594.
- Single violation form: prohibited transition from `preauth` to
  `authenticated` on the same concrete session identity without a direct
  `regenerate_request_session` event.
- Resource identity: one logical request-session slot, with direct lexical
  binding evidence for the concrete object.
- Completeness boundary: one named function in one staged JavaScript file,
  including a direct regeneration call in its inline callback body; unsupported
  aliases, dispatch, callbacks, reflection, and concurrency are gaps.
- Analyzer: CodeQL JavaScript `2.26.1` in database mode `none`.

These choices are frozen for the first narrow implementation. A broader
protocol or a different violation form requires a separate change SPEC.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-29 | Treat Typestate as a candidate parallel Capability | Ordered lifecycle evidence has a distinct hypothesis and success predicate. |
| 2026-08-29 | Limit v1 to one resource and one violation condition | Prevents an early universal state-machine framework. |
| 2026-08-29 | Require identity-backed ordered witnesses | Text order and events on different objects are not lifecycle evidence. |
| 2026-08-29 | Block production implementation before a real case | Required by the accepted architecture baseline. |
| 2026-08-30 | Accept Typestate as the next research direction, while retaining Draft status | Directional approval does not satisfy the real-case admission gate or the required Verified Flow runtime baseline. |
| 2026-09-01 | Accept the Ghost CVE-2026-70594 case for narrow Typestate v1 implementation | Real CodeQL evidence demonstrates an ordered identity-backed violating witness, a fixed safe trace, a different-resource counterexample, field-specific revisions, and model-free replay. |

## Delivery gate

Accepted status authorizes the narrow v1 implementation phases below. This
admission evidence itself did not add production behavior. The current Phase B
implementation is intentionally limited to the Typestate Contracts and pure
Core policy authorized by this Accepted SPEC; it does not add an Analyzer
adapter, shared-runtime route, replay executor, Pi/CLI host exposure, or
support claim.

Implementation may begin in a later change because the admission gate is
satisfied, the protocol and Analyzer choices are frozen here, and the Flow and
MissingCheck Capabilities have supplied Verified shared-runtime baselines. Those
baselines prove runtime behavior only; they do not import their domain
semantics into Typestate.

## Verification record

This is an admission verification record, not a production implementation
verification record.

- Commands and results: CodeQL `2.26.1` compiled all five case queries with
  warnings as errors. `replay.sh` created isolated vulnerable, fixed, and safe
  databases in `none` build mode and passed with counts `1/0` for the primary
  vulnerable/fixed transition, `1/0` for fixed-safe/vulnerable-safe traces,
  `0/1` for identity-aware/call-order-only safe analysis, and `0/0` for the
  wrong-resource/wrong-event queries.
- Requirement-to-evidence mapping: `REQ-TSTATE-001` through `009` map to the
  admission gate and case rationale; `010` through `019` map to the frozen
  protocol; `030` through `049` map to CodeQL observations, identity evidence,
  counterexamples, and the decision projection; `050` through `059` remain
  implementation acceptance requirements.
- Skipped or blocked checks: Production contracts, runtime routing, Analyzer
  Ports, host adapters, and support claims are intentionally not implemented in
  this change. They are authorized only for the later phases and remain
  unverified.
- Remaining limitations: the evidence is single-file and direct-binding only;
  unsupported aliasing, dynamic dispatch, framework semantics, and concurrency
  remain outside the admitted boundary.
