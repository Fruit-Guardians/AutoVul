# Change: Admit MissingCheck Capability v1

- Change ID: `admit-missing-check-capability-v1`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-08-29
- Updated: 2026-08-30
- Admission gate: Satisfied
- Depends on: `establish-research-capability-architecture` and the implemented shared runtime

## Problem

Flow can determine whether declared data reaches a declared endpoint. It cannot honestly represent a vulnerability whose decisive fact is that a security-relevant operation is reachable without a required check. Encoding authorization, ownership, bounds, policy, or precondition checks as fake Sources, Sanitizers, or Sinks would preserve a uniform diagram while destroying the research semantics.

MissingCheck is therefore a candidate second Research Capability. It is not admitted merely because the name is plausible. Before production contracts or modules are added, this change requires a real vulnerability case that:

- contains a security-relevant operation and a required check relationship;
- cannot be expressed as an end-to-end Flow claim without inventing taint semantics;
- has a vulnerable and fixed target, or another equally strong counter-example;
- can produce tool observations about both the operation and the check relationship;
- yields actionable field-level feedback when the hypothesis is wrong.

This accepted change defines the admission evidence, frozen v1 boundary, implementation sequence, and verification gates. It does not claim that MissingCheck is implemented or supported.

## Host boundary

The host Agent remains responsible for reading code and advisories, deciding that MissingCheck is the appropriate paradigm, proposing the protected operation and required check, revising the hypothesis, and deciding when to stop.

AutoVul owns strict MissingCheck contracts, deterministic validation, bounded Analyzer execution, structured observations, the MissingCheck Decision Policy, evidence grading, artifacts, and replay.

AutoVul MUST NOT search indefinitely for absent checks, infer an organization policy from prose, generate a replacement hypothesis, or turn MissingCheck into an autonomous audit Agent.

## Relationship to existing specifications

- Root `SPEC.md` owns the product boundary, shared runtime, evidence levels, safety, and change control.
- `establish-research-capability-architecture` owns Capability isolation and the case-gated admission rule.
- `introduce-flow-capability-v1` owns Flow. MissingCheck MUST NOT import FlowModel, FlowEndpoint, FlowDecision, or Flow diagnostic semantics.
- A real-case admission record MUST be added to this SPEC before it can become Accepted.

## Scope

### In scope

- Define the evidence required to admit MissingCheck as a second Capability.
- Propose one-operation/one-required-check MissingCheck v1 semantics.
- Define the boundary between host hypothesis, Analyzer observation, and Core decision.
- Define structured no-proof and capability-mismatch feedback.
- Reuse the aggregate `autovul_research` and `autovul_run` entries and the shared deterministic runtime.
- Require one concrete Analyzer adapter selected by the admission case.
- Require vulnerable/fixed or equivalent counter-example evidence and independent replay.
- Define a staged implementation plan that starts only after the admission gate is satisfied and this SPEC is Accepted.

### Non-goals

- A universal authorization, validation, policy, or access-control ontology.
- Rewriting MissingCheck as Flow, taint, Sanitizer, or Barrier semantics.
- A general rule engine, policy language, theorem prover, symbolic executor, or whole-program proof of security.
- Multiple protected operations, multiple required checks, policy inheritance, role hierarchies, or framework-wide policy mining in v1.
- Automatic policy discovery from natural language or configuration.
- Automatic repair, patch generation, Finding prose, severity assignment, or exploit generation.
- A Capability registry, generic Capability base class, or new workspace package solely for MissingCheck.
- A production Schema, module, support claim, or host tool before the admission and acceptance gates pass.

## Definitions

- **Protected operation**: the single security-relevant operation whose execution requires a declared check.
- **Required check**: the single check semantics the host asserts must hold before or around the protected operation.
- **Check relation**: the declared structural or control-flow relationship between the required check and operation.
- **Unchecked witness**: persisted Analyzer evidence for an execution or control-flow path on which the protected operation is reachable without the required check relation being satisfied.
- **Checked witness**: persisted Analyzer evidence that the declared check relation is satisfied for the observed operation under the analyzed scope.
- **Completeness boundary**: the exact program, entry-point, call-graph, framework, or path scope for which a negative conclusion is valid.
- **MissingCheck decision**: the Core verdict `check_missing`, `check_present`, or `unknown`.

## Admission gate

Before this SPEC may become Accepted, its decision log and fixtures MUST identify:

1. one public or internally reproducible vulnerable case that Flow cannot honestly express;
2. one fixed target or explicit counter-example;
3. the exact protected operation and required check semantics;
4. one Analyzer capable of observing the operation, check candidates, and their relation;
5. one observed unchecked witness in the vulnerable target;
6. one observed checked witness or eliminated unchecked witness in the fixed target;
7. at least two wrong-hypothesis fixtures that produce different revision actions;
8. the Analyzer completeness boundary and known blind spots;
9. an artifact that can be replayed without a model or host session.

Until all nine items are recorded, production implementation MUST NOT begin.

## Requirements

### Capability identity and isolation

- `REQ-MCHECK-001`: MissingCheck MUST be admitted only for a real case that Flow cannot represent without fake Source, Sink, Sanitizer, Barrier, or taint semantics.
- `REQ-MCHECK-002`: MissingCheck MUST independently own its Hypothesis Schema, Observation Schema, Decision Policy, diagnostic codes, revision actions, Analyzer Port, success predicates, Golden cases, and replay gates.
- `REQ-MCHECK-003`: MissingCheck MUST reuse shared run identity, idempotency, budgets, timeout, cancellation, locks, artifact commit, recovery, evidence references, and replay routing.
- `REQ-MCHECK-004`: The shared runtime MUST NOT interpret operation, check, dominance, reachability, authorization, validation, bounds, ownership, or policy fields.
- `REQ-MCHECK-005`: v1 composition MUST use one explicit `missing_check` branch. It MUST NOT introduce a Capability registry, dynamic loader, factory, or generic base class.
- `REQ-MCHECK-006`: The implementation MUST NOT add placeholder Typestate, Delta, Variant, or other future Capability code.
- `REQ-MCHECK-007`: MissingCheck MUST use the existing `autovul_research` and `autovul_run` Application methods and model-facing tools.
- `REQ-MCHECK-008`: The host MUST retain hypothesis generation, revision, action selection, and stopping authority.
- `REQ-MCHECK-009`: MissingCheck MUST NOT be documented as supported before this change is Verified.

### Proposed hypothesis contract

- `REQ-MCHECK-010`: The accepted contract version MUST be `autovul.missing-check/1` unless review changes it before acceptance.
- `REQ-MCHECK-011`: A v1 hypothesis MUST describe exactly one protected operation, one required check, one required relation, and one bounded analysis scope.
- `REQ-MCHECK-012`: The protected operation and required check MUST use MissingCheck-owned selectors. They MUST NOT reuse or alias FlowEndpoint.
- `REQ-MCHECK-013`: Check kinds MUST be a case-justified closed set. The admission case MUST prove every accepted v1 kind can be explained without framework-specific prose.
- `REQ-MCHECK-014`: Relation kinds MUST be a case-justified closed set describing what the Analyzer can observe, such as an all-path precondition, dominance-equivalent relation, or guarded branch relation.
- `REQ-MCHECK-015`: The hypothesis MUST declare its completeness boundary. A repository-wide or all-path claim MUST NOT be inferred from a local observation.
- `REQ-MCHECK-016`: Target paths, Analyzer identity, mode, budget, idempotency key, evidence refs, CWE, message, rationale, and presentation fields MUST remain outside the MissingCheck hypothesis.
- `REQ-MCHECK-017`: The hypothesis MUST NOT contain `guard_absent`, `vulnerable`, `confirmed`, or any other field that pre-decides the Analyzer observation or Core decision.
- `REQ-MCHECK-018`: v1 MUST NOT support multiple operations, multiple required checks, arbitrary boolean policy expressions, role hierarchies, or extensible property bags.
- `REQ-MCHECK-019`: The final accepted Schema MUST reject unknown properties and unsupported selector/relation combinations.

### Validation and revision

- `REQ-MCHECK-020`: Boundary input MUST be treated as `unknown` and normalized into either one valid hypothesis or a bounded list of issues.
- `REQ-MCHECK-021`: Every issue MUST contain a stable `code` and JSON Pointer `path` and MUST include `allowed_values` for closed repairs.
- `REQ-MCHECK-022`: `validate` MUST be deterministic, side-effect free, and MUST NOT create runs, call an Analyzer, or write artifacts.
- `REQ-MCHECK-023`: Validation MUST reject an operation or check without an identifying selector, an unsupported relation, an unbounded scope, contradictory location constraints, and unknown properties.
- `REQ-MCHECK-024`: Model-visible envelope actions MUST remain a subset of `revise`, `execute`, `replay`, and `stop`.
- `REQ-MCHECK-025`: Proposed v1 revision actions MUST be frozen before acceptance and SHOULD distinguish at least `revise_operation`, `revise_check`, `revise_relation`, and `revise_scope`.
- `REQ-MCHECK-026`: A revision hint MUST identify one hypothesis JSON Pointer, one stable reason code, and optional structured constraints.
- `REQ-MCHECK-027`: Core MUST NOT return or automatically apply a complete replacement MissingCheck hypothesis.
- `REQ-MCHECK-028`: A revision hint MUST be supported by a compact observation or evidence reference.
- `REQ-MCHECK-029`: Free-form recommendations MUST NOT substitute for structured issues, observations, or revision hints.

### Analyzer observation and Core decision

- `REQ-MCHECK-030`: The MissingCheck Analyzer Port MUST return observations and capability gaps only. It MUST NOT return `decision` or `verification_level`.
- `REQ-MCHECK-031`: The observation MUST separately represent operation observation, check observation, relation observation, unchecked witnesses, checked witnesses, completeness boundary, Analyzer provenance, capability gaps, and evidence refs.
- `REQ-MCHECK-032`: Operation and check observation states MUST distinguish `observed`, `not_found`, and `not_run`.
- `REQ-MCHECK-033`: Relation observation MUST distinguish an observed unchecked witness, an observed checked witness, no conclusive witness, and not run. Absence of a matched check MUST NOT by itself prove an unchecked path.
- `REQ-MCHECK-034`: Unsupported framework semantics, aliasing, indirect dispatch, incomplete control-flow scope, or missing dominance information MUST produce a capability gap or `unknown`; they MUST NOT be coerced into `check_missing`.
- `REQ-MCHECK-035`: Core MUST be the sole writer of `MissingCheckDecision` and `verification_level`.
- `REQ-MCHECK-036`: The decision outcome MUST be exactly `check_missing`, `check_present`, or `unknown` in v1.
- `REQ-MCHECK-037`: `check_missing` MUST require a persisted unchecked witness for the declared operation, check semantics, relation, and scope.
- `REQ-MCHECK-038`: `check_present` MUST require positive checked evidence or an Analyzer-supported complete proof for the declared scope. A failed search for an unchecked witness is insufficient.
- `REQ-MCHECK-039`: Timeout, cancellation, Analyzer failure, parse failure, unsupported semantics, and incomplete scope MUST remain distinct from a completed `unknown` decision.

### Evidence and verification semantics

- `REQ-MCHECK-040`: `probe` MAY observe operation and check candidates but MUST NOT establish reproduction.
- `REQ-MCHECK-041`: `reproduce` MUST require the vulnerable target to produce at least one accepted unchecked witness.
- `REQ-MCHECK-042`: `differential` MUST require a reproduced vulnerable-side unchecked witness and a successfully analyzed fixed side that satisfies the declared fixed policy.
- `REQ-MCHECK-043`: A fixed-side `not_run`, timeout, failure, or capability gap MUST NOT satisfy the differential policy even when a count defaults to zero.
- `REQ-MCHECK-044`: `variant_validated` MUST NOT be emitted by MissingCheck v1 unless a later accepted change defines additional positive/negative or cross-project validation semantics.
- `REQ-MCHECK-045`: Fake adapters, mocks, AST text search, model inference, and diagnostic wrappers MUST NOT raise a real verification level.
- `REQ-MCHECK-046`: The compact result MUST keep `operation_status`, MissingCheck `decision`, and `verification_level` as independent dimensions.
- `REQ-MCHECK-047`: Claims MUST be limited to the declared completeness boundary and recorded Analyzer version.
- `REQ-MCHECK-048`: A negative or unknown result MUST preserve the attempted scope, observations, failure category, and replay inputs.
- `REQ-MCHECK-049`: The central real acceptance case MUST be reproducible without reading raw Analyzer output or relying on host prose.

### Runtime, artifacts, safety, and compatibility

- `REQ-MCHECK-050`: Execute MUST create or idempotently resume one bounded shared-runtime operation and MUST bind the idempotency key to a normalized request digest.
- `REQ-MCHECK-051`: MissingCheck MUST use the existing trusted-root, timeout, live cancellation, lock, recovery, and process-tree cleanup behavior.
- `REQ-MCHECK-052`: A committed artifact MUST record contract version, normalized hypothesis, target refs and fingerprints, Analyzer provenance, scope, observations, Decision Policy version, decision, verification level, budget identity, and replay inputs.
- `REQ-MCHECK-053`: Critical MissingCheck evidence and route metadata MUST be committed atomically before authoritative state references the result.
- `REQ-MCHECK-054`: Replay MUST revalidate targets and fingerprints, compare Analyzer provenance, and distinguish identical result, environment block, version difference, and semantic mismatch.
- `REQ-MCHECK-055`: Logs and artifacts MUST sanitize recognized credentials, tokens, private policy values, and unrestricted environment data.
- `REQ-MCHECK-056`: The Analyzer adapter MUST NOT execute target build, install, migration, or test scripts without a separate accepted approval policy.
- `REQ-MCHECK-057`: Existing Flow and `codeql_*` contracts and artifacts MUST remain readable and behaviorally unchanged.
- `REQ-MCHECK-058`: Pi and CLI MUST route MissingCheck through the same Application API; no `autovul_missing_check` model tool may be added.
- `REQ-MCHECK-059`: Adding MissingCheck MUST NOT require a new workspace package unless a separate packaging justification is accepted.

## Proposed behavior

```text
Host
  -> autovul_research validate
       capability: missing_check
       hypothesis_version: autovul.missing-check/1
       hypothesis: MissingCheckHypothesis
  -> autovul_research execute
       target / analyzer_id / mode / budget / idempotency_key
  -> MissingCheck Analyzer Observation
  -> MissingCheck Core Decision Policy
  -> compact result + committed artifact
```

Candidate hypothesis shape, to be frozen only after the admission case:

```text
MissingCheckHypothesis
  schema_version
  hypothesis_id
  language
  operation             MissingCheck-owned selector
  required_check        MissingCheck-owned check semantics and selector
  required_relation     closed, Analyzer-observable relation
  scope                 explicit completeness boundary
```

Candidate compact decision:

```text
decision
  capability: missing_check
  outcome: check_missing | check_present | unknown
```

The Analyzer never writes this decision. It reports observed operations, checks, relation witnesses, completeness limitations, and evidence refs.

## Implementation plan

### Phase A — admission case freeze

- Select and license one vulnerable/fixed case.
- Demonstrate why Flow cannot express it honestly.
- Record operation/check/relation semantics and Analyzer feasibility.
- Produce wrong-operation and wrong-check fixtures with different revision outcomes.
- Update this SPEC with exact selectors, enums, Analyzer, and Golden inputs.

Exit gate: all admission items are recorded and the user or maintainer explicitly accepts the revised SPEC.

### Phase B — contracts and pure policy

- Add the `missing_check` literal and version only after acceptance.
- Add the strict hypothesis, validation issue, observation, decision, revision hint, compact result branch, and artifact schemas.
- Implement the pure validator and Decision Policy without live Analyzer dependencies.
- Add architecture checks preventing Flow type reuse and generic Capability abstractions.

### Phase C — one Analyzer adapter

- Define one MissingCheck execution Port around the evidence required by the frozen case.
- Implement exactly one adapter selected by the admission record.
- Preserve incomplete, failed, timed-out, and unsupported states without converting them into absence.
- Persist bounded witness locations and raw evidence references.

### Phase D — runtime and host projection

- Add an explicit Application branch to `research` and replay routing.
- Reuse shared run, cancellation, idempotency, commit, recovery, and replay facilities.
- Extend Pi and CLI schemas through the same aggregate tools.
- Keep model-visible output compact and capability-discriminated.

### Phase E — real verification

- Reproduce the vulnerable case.
- Verify the fixed policy with a successfully executed fixed target.
- Run at least one checked negative sample and one operation-selector negative sample.
- Replay from committed artifacts in a fresh process or relocated workspace where supported.
- Record Analyzer and environment versions before changing status to Verified.

## Contracts and artifacts

The exact Schema is intentionally not frozen while the admission gate is unsatisfied. The accepted revision MUST version:

- `MissingCheckHypothesis`;
- `MissingCheckValidationIssue` and result;
- `MissingCheckAnalyzerObservation`;
- `MissingCheckDecision`;
- `MissingCheckRevisionHint`;
- the `ResearchExecutionResult` MissingCheck branch;
- `MissingCheckRunArtifact` and replay comparison result.

No existing Flow artifact is migrated. Shared routing records only capability and contract version plus artifact reference.

## Architecture

- `@autovul/contracts`: versioned MissingCheck contracts after acceptance.
- `@autovul/core`: validator, Decision Policy, explicit Application branch, Port, artifact/replay policy.
- selected Analyzer/Runner package: tool invocation and MissingCheck observations.
- Pi/CLI: thin aggregate-interface projection only.

Dependency direction remains `contracts <- core <- analyzers/runners <- integrations`. MissingCheck code MUST NOT import Flow code to obtain domain semantics.

## Safety and privacy

- Validation is pure.
- Execute and replay operate only on approved target references under trusted roots.
- Check observations may expose authorization or policy identifiers; artifacts must retain only the values required for replay and must sanitize secrets.
- No target build/install or live exploit action is introduced.
- Scope, witness count, output size, time, concurrency, and stored locations are bounded.
- Cancellation must terminate the active Analyzer process rather than only changing a manifest.

## Compatibility and migration

- This is additive only after acceptance.
- Flow remains a parallel Capability with unchanged contract and decision semantics.
- Existing tools and artifacts remain readable.
- Rollback removes the MissingCheck route and host capability literal while preserving already committed versioned artifacts for read-only inspection.
- No support claim is allowed before Verified.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-MCHECK-001` through `REQ-MCHECK-009` | Given the admission case and repository graph, when reviewed, then MissingCheck is independently justified and no universal IR or registry is added | Admission record and architecture inspection |
| `REQ-MCHECK-010` through `REQ-MCHECK-019` | Given valid and invalid hypothesis fixtures, when validated, then exactly one operation/check/relation/scope is represented without Flow types | Schema fixtures and dependency checks |
| `REQ-MCHECK-020` through `REQ-MCHECK-029` | Given common model mistakes, when validate runs, then bounded code/path diagnostics and field-specific revision actions are returned without side effects | Validator unit tests and artifact call-count checks |
| `REQ-MCHECK-030` through `REQ-MCHECK-039` | Given operation/check/relation and incomplete-scope matrices, when Core decides, then only witnessed absence becomes `check_missing` and only positive/complete evidence becomes `check_present` | Pure Decision Policy matrix |
| `REQ-MCHECK-040` through `REQ-MCHECK-049` | Given probe, vulnerable, fixed-failed, fixed-passed, and negative fixtures, when executed, then verification levels never exceed real evidence | Fake-adapter tests plus real vulnerable/fixed Golden |
| `REQ-MCHECK-050` through `REQ-MCHECK-059` | Given cancellation, duplicate keys, corrupt artifacts, untrusted paths, and replay, when operations run, then shared runtime and safety invariants hold | Failure injection, cross-process replay, and integration tests |

## Validation plan

- Focused unit tests:
  - strict Schema and semantic validator;
  - issue codes, paths, and allowed values;
  - complete Decision Policy matrix, especially `not_run` and incomplete scope;
  - request-digest/idempotency conflict;
  - no Flow type imports.
- Failure injection:
  - Analyzer unavailable, timeout, cancellation, parse failure, partial evidence, commit interruption, corrupt replay artifact.
- Real analyzer/target:
  - one frozen vulnerable/fixed case using the accepted Analyzer.
- Differential or negative sample:
  - fixed target plus a checked safe sample and a wrong-operation sample.
- Independent replay:
  - fresh process, no model, target fingerprint and Analyzer-version comparison.
- Package/integration smoke:
  - Application, CLI, and Pi use the same aggregate contract; no extra model tool.

## Open questions

The frozen admission case is recorded in
[`evidence/openclaw-cve-2026-43572`](./evidence/openclaw-cve-2026-43572/):

- CVE-2026-43572 provides one public vulnerable/fixed pair under an MIT license;
- the operation selector is exactly `direct_call` named
  `handleSigninTokenExchangeInvoke`; the check selector is exactly
  `direct_call` named `isSigninInvokeAuthorized`; and the relation is exactly
  `same_callback_cfg_dominates_operation`;
- CodeQL JavaScript 2.26.1 produced one persisted vulnerable unchecked
  witness and zero fixed unchecked witnesses without executing target build,
  install, or test scripts;
- the completeness boundary is one extracted handler file and explicitly
  excludes cross-file aliasing, dynamic invocation, and helper correctness;
- fixed policy requires both a dominating checked witness for every selected
  operation and elimination of the selected unchecked witnesses.

The accepted v1 enum is deliberately narrow: `direct_call` is the only
operation and check selector kind, and `same_callback_cfg_dominates_operation`
is the only relation kind. A future generalization requires a separate
accepted change with a second real case; it MUST NOT be inferred from this
admission.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-29 | Treat MissingCheck as a candidate parallel Capability | Its success predicate concerns a required check relationship, not data flow. |
| 2026-08-29 | Require an unchecked witness | Failure to find a check is not evidence that the operation is unguarded. |
| 2026-08-29 | Limit v1 to one operation and one check | Keeps the contract LLM-revisable and avoids a general policy ontology. |
| 2026-08-29 | Block production code before a real case | Required by the accepted case-gated architecture. |
| 2026-08-29 | Use OpenClaw CVE-2026-43572 as the first admission candidate | It has a public vulnerable/fixed commit pair, a direct required sender-authorization call, and a bounded no-build CodeQL witness. |
| 2026-08-29 | Reject Arcane CVE-2026-47125 as the initial v1 Analyzer case | CodeQL Go requires a build mode, which conflicts with the Draft's no-unapproved-target-build boundary. |
| 2026-08-30 | Accept the frozen OpenClaw direct-call/dominance boundary | The user approved implementation of MissingCheck v1 with exactly one protected operation, one required check, and one local CFG relation. |
| 2026-08-30 | Do not make Flow verification a blocking dependency | The user explicitly deferred Flow closure. MissingCheck reuses the implemented shared runtime but MUST independently satisfy all of its own real Analyzer, differential, and replay gates before it is supported. |

## Delivery gate

Verified status authorizes the frozen MissingCheck v1 boundary as a supported
research capability within its declared single-file CFG completeness boundary.

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: `npm run lint`, `npm test`, and
  `npm run test:missing-check-golden-real` passed. The real Golden used
  CodeQL JavaScript 2.26.1 with only `monitor-handler.ts` staged from OpenClaw
  commits `75b4c059b8405dfbd50884b773346a9946fabd20` and
  `80b1fa17bfc3f6a668492f0326ea52f48bb89776`; it never ran target install,
  build, or test scripts. It proved vulnerable `check_missing` /
  `differential`, fixed `check_present`, a checked-safe negative,
  a wrong-operation `revise_operation` negative, and an identical fresh-process
  replay. `test/missing-check-admission-evidence.test.ts` still binds the
  admission source, commits, digests, and original wrong-hypothesis evidence.
- Requirement-to-evidence mapping: Admission items 1–9 are frozen in `evidence/openclaw-cve-2026-43572`, including query-digest-bound replay inputs and two wrong-hypothesis fixtures. The accepted selector and relation enum are intentionally limited to that evidence.
- Commands and results: The production `CodeqlMissingCheckAdapter`, used through
  `createLocalApplication`, ran against fresh CodeQL JavaScript 2.26.1
  databases created from only `monitor-handler.ts` at OpenClaw commits
  `75b4c059b8405dfbd50884b773346a9946fabd20` and
  `80b1fa17bfc3f6a668492f0326ea52f48bb89776`. The aggregate
  `autovul_research` route returned `check_missing` / `reproduced` on the
  vulnerable target and `check_present` on the fixed target, producing an
  authoritative `differential` result. A new Node process then replayed the
  committed artifact with the identical decision and verification level. No
  target build, install, or test script was executed.
- Requirement-to-evidence mapping: `REQ-MCHECK-001`–`029` are covered by
  contracts, `test/missing-check.test.ts`, and the architecture guard;
  `REQ-MCHECK-030`–`049` are covered by the pure policy matrix plus the real
  Golden; and `REQ-MCHECK-050`–`059` are covered by aggregate Application/run
  tests, fresh-process replay, artifact routing, and shared runtime checks.
- Skipped or blocked checks: none for the frozen JavaScript, direct-call,
  single-file CFG boundary.
- Remaining limitations: this support claim excludes aliases, indirect or
  dynamic invocation, cross-file analysis, helper correctness, other handlers,
  and every selector/relation not explicitly represented by v1.
