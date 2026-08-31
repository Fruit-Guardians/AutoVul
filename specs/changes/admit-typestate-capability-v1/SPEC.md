# Change: Admit Typestate Capability v1

- Change ID: `admit-typestate-capability-v1`
- Status: Draft
- Owner: AutoVul maintainers
- Created: 2026-08-29
- Updated: 2026-08-30
- Admission gate: Unsatisfied
- Depends on: `establish-research-capability-architecture` and one Verified shared-runtime Capability baseline (currently MissingCheck v1)

## Problem

Some vulnerabilities are determined by the order in which operations affect one resource: use before initialization, use after close, double release, missing finalization, unsafe reuse after validation, or an illegal protocol transition. The decisive evidence is a sequence of state transitions for a tracked object or protocol instance, not a Source-to-Sink path and not merely an absent guard.

Modeling these defects as Flow would confuse value propagation with lifecycle semantics. Modeling them as MissingCheck would lose transition order and object identity. Typestate is therefore a candidate parallel Capability, but it must be admitted by a real case and a real Analyzer witness before any production state-machine abstraction is introduced.

This Draft defines the admission evidence, a deliberately narrow single-resource v1 proposal, implementation phases, and verification gates. It does not claim that Typestate is implemented or supported.

## Host boundary

The host Agent reads code and vulnerability context, selects Typestate, proposes the tracked resource and protocol events, revises the hypothesis, and decides whether to continue or stop.

AutoVul validates the versioned protocol hypothesis, executes one bounded Analyzer operation, records transition observations, applies a deterministic Typestate Decision Policy, commits evidence, and supports replay.

AutoVul MUST NOT infer arbitrary protocols from an entire repository, invent missing events, generate a replacement protocol, automatically patch lifecycle code, or become a general program verifier.

## Relationship to existing specifications

- Root `SPEC.md` owns shared runtime, evidence, safety, and change control.
- `establish-research-capability-architecture` owns the case-gated parallel-Capability rule.
- Flow and MissingCheck semantics MUST NOT be reused as Typestate domain types.
- A real-case admission record MUST be added to this SPEC before acceptance.
- Candidate screening and rejected-case rationale are recorded in
  [`evidence/ADMISSION-SCREENING.md`](./evidence/ADMISSION-SCREENING.md). A screening
  record is not an admission record.

## Scope

### In scope

- Define the evidence required to admit Typestate as a later Capability.
- Propose one tracked resource, one bounded protocol, and one prohibited behavior for v1.
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
- Production Typestate code or support claims while the admission gate is unsatisfied.

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

## Admission gate

Before this SPEC may become Accepted, it MUST record:

1. one reproducible vulnerability whose decisive fact is event order for one resource;
2. why neither Flow nor MissingCheck can represent the case honestly;
3. one fixed target or equally strong counter-example;
4. the exact resource identity, initial state, event alphabet, transitions, and violation condition;
5. one Analyzer that can persist an ordered witness and identity evidence;
6. the accepted alias and call-graph completeness boundary;
7. a vulnerable violating trace and fixed or safe counter-trace;
8. at least two wrong-hypothesis fixtures producing different field-level revisions;
9. a model-free replay artifact.

No production Schema or module may be created until all nine items are satisfied.

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

### Proposed hypothesis contract

- `REQ-TSTATE-010`: The accepted contract version MUST be `autovul.typestate/1` unless review changes it before acceptance.
- `REQ-TSTATE-011`: A v1 hypothesis MUST describe exactly one tracked resource, one initial state, a bounded event alphabet, a bounded transition set, one violation condition, and one completeness boundary.
- `REQ-TSTATE-012`: Resource and event selectors MUST be Typestate-owned and MUST NOT reuse FlowEndpoint or MissingCheck operation/check selectors by type alias.
- `REQ-TSTATE-013`: Protocol states and event ids MUST be stable identifiers with strict count and length bounds.
- `REQ-TSTATE-014`: Each transition MUST declare one `from_state`, one event, and one `to_state`; hidden side effects and executable expressions MUST be forbidden.
- `REQ-TSTATE-015`: v1 MUST freeze exactly one supported violation form from the admission case: prohibited event-in-state, prohibited transition, or missing required terminal event.
- `REQ-TSTATE-016`: The hypothesis MUST declare the resource identity and alias boundary the Analyzer is expected to support.
- `REQ-TSTATE-017`: Target refs, Analyzer id, mode, budget, idempotency key, evidence refs, message, CWE, rationale, and presentation fields MUST remain outside the hypothesis.
- `REQ-TSTATE-018`: The hypothesis MUST NOT contain a precomputed `violating`, `confirmed`, or `vulnerable` field.
- `REQ-TSTATE-019`: v1 MUST reject multiple resources, concurrent event interleavings, recursive protocol composition, arbitrary extension properties, and unbounded state graphs.

### Validation and revision

- `REQ-TSTATE-020`: Boundary input MUST be parsed from `unknown` into one normalized hypothesis or a bounded list of issues.
- `REQ-TSTATE-021`: Every issue MUST contain a stable `code` and JSON Pointer `path`, plus `allowed_values` for closed repairs.
- `REQ-TSTATE-022`: `validate` MUST be deterministic and side-effect free and MUST NOT create a run, call an Analyzer, or write artifacts.
- `REQ-TSTATE-023`: Validation MUST reject duplicate ids, unknown transition endpoints, unreachable declared states where prohibited by the frozen contract, invalid initial state, unsupported violation form, missing resource identity, and unknown properties.
- `REQ-TSTATE-024`: Counts for states, events, transitions, witness length, locations, and stored traces MUST be bounded in the accepted Schema.
- `REQ-TSTATE-025`: Envelope actions MUST remain a subset of `revise`, `execute`, `replay`, and `stop`.
- `REQ-TSTATE-026`: Proposed revision actions MUST be frozen before acceptance and SHOULD distinguish `revise_resource`, `revise_event`, `revise_transition`, `revise_violation`, and `revise_scope`.
- `REQ-TSTATE-027`: Every revision hint MUST contain a hypothesis JSON Pointer, stable reason code, and optional structured constraints backed by an observation or evidence ref.
- `REQ-TSTATE-028`: Core MUST NOT return or automatically apply a replacement Typestate hypothesis.
- `REQ-TSTATE-029`: Narrative protocol advice MUST NOT substitute for structured validation or revision fields.

### Analyzer observations and Decision Policy

- `REQ-TSTATE-030`: The Typestate Analyzer Port MUST return observations and capability gaps only; it MUST NOT return a decision or verification level.
- `REQ-TSTATE-031`: The observation MUST separately represent resource observation, event observations, ordered traces, identity/alias evidence, completeness boundary, capability gaps, Analyzer provenance, and evidence refs.
- `REQ-TSTATE-032`: Resource and event observation states MUST distinguish `observed`, `not_found`, and `not_run`.
- `REQ-TSTATE-033`: A violating trace MUST retain ordered event ids, bounded source locations, resource identity evidence, and the transition step at which the violation occurred.
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

Candidate hypothesis shape, not frozen while the admission gate is open:

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
  identity_scope
  analysis_scope
```

Candidate decision:

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
- Update this Draft with exact Schema enums and Golden inputs.

Exit gate: all admission evidence is recorded and the revised SPEC is explicitly Accepted.

### Phase B — contracts and pure Core policy

- Add the `typestate` capability literal only after acceptance.
- Add strict hypothesis, observation, decision, revision, result-branch, and artifact Schemas.
- Implement deterministic structural validation and trace evaluation.
- Add tests proving Flow and MissingCheck domain types are not reused.

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
- The aggregate tools gain a new discriminated branch only after acceptance.
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

## Open questions

- Which real lifecycle vulnerability satisfies the admission gate?
- Which single violation form should v1 support?
- What resource identity and alias model can the selected Analyzer defend?
- Is the required completeness boundary intraprocedural, interprocedural, or framework-specific?
- Which Analyzer can persist a stable ordered trace across vulnerable and fixed targets?

These choices are material. This Draft MUST NOT become Accepted until they are resolved.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-29 | Treat Typestate as a candidate parallel Capability | Ordered lifecycle evidence has a distinct hypothesis and success predicate. |
| 2026-08-29 | Limit v1 to one resource and one violation condition | Prevents an early universal state-machine framework. |
| 2026-08-29 | Require identity-backed ordered witnesses | Text order and events on different objects are not lifecycle evidence. |
| 2026-08-29 | Block production implementation before a real case | Required by the accepted architecture baseline. |
| 2026-08-30 | Accept Typestate as the next research direction, while retaining Draft status | Directional approval does not satisfy the real-case admission gate or the required Verified Flow runtime baseline. |

## Delivery gate

Draft status authorizes planning and case/fixture research only. It does not authorize production Schemas, modules, routing literals, adapters, host exposure, or support claims.

Implementation may begin only after the admission gate is satisfied, the open protocol and Analyzer choices are frozen here, one Capability has supplied a Verified shared-runtime baseline, and this SPEC is explicitly Accepted. That baseline proves runtime behavior only; it does not import its domain semantics into Typestate.

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: Candidate screening performed on 2026-08-30. Public JavaScript/Python results inspected so far were either not established security cases with a vulnerable/fixed lifecycle trace, or required native/build-dependent analysis; none is admitted as evidence.
- Requirement-to-evidence mapping: Pending an admitted real case and implementation.
- Skipped or blocked checks: Production implementation remains blocked by the unsatisfied admission gate. MissingCheck v1 is the current Verified shared-runtime baseline; Flow closure remains intentionally deferred and does not block Typestate admission.
- Remaining limitations: Typestate is not implemented or supported.
