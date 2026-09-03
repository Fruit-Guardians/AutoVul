# Change: Harden Capability Execution Contracts v1

- Change ID: `harden-capability-execution-contracts-v1`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-09-03
- Updated: 2026-09-03
- Public contract: `v2.contracts/1`
- Depends on: archived `establish-research-capability-architecture`, `introduce-flow-capability-v1`, `admit-missing-check-capability-v1`, `admit-typestate-capability-v1`, `add-change-observation-analyzer-v1`

## Problem

AutoVul's product architecture defines host-independent, extensible vulnerability research capabilities over a shared deterministic runtime. However, the current implementation exhibits inconsistencies across capabilities:

1. **Unconstrained capability and version pairing**: `CapabilityResearchRequestSchema` treats `capability` and `hypothesis_version` as independent fields, permitting semantically invalid combinations (e.g. `capability: "flow"` with `hypothesis_version: "autovul.missing-check/1"`).
2. **Silent default fallback to Flow**: `Application.research()` falls back to `FlowResearchService` when an input does not explicitly match `service: "change_observation"`, `capability: "typestate"`, or `capability: "missing_check"`. Unknown capability requests or malformed payloads silently default to Flow rather than failing with structured errors.
3. **Missing `evidence_kind` gate on Flow**: MissingCheck and Typestate provenance distinguish `real_analyzer` from `test_double`, capping test-double results at `generated`. Flow's `FlowAnalyzerProvenance` lacks `evidence_kind`, allowing a fake adapter or test double to inflate verification levels to `reproduced` or `differential`.
4. **Divergent replay validation baselines**: Typestate enforces run-operation locks, cancellation begin, route validation, policy version matching, target fingerprints, and evidence immutability checks. Flow and MissingCheck replay implementations omit run locks, cancellation registration, route consistency checks, policy version verification, or evidence immutability verification.

These gaps must be hardened horizontally across existing capabilities before admitting a second analyzer.

## Host boundary

The host Agent remains responsible for selecting a research capability, forming a valid structured hypothesis, choosing targets and budgets, and deciding subsequent actions.

AutoVul owns strict contract validation, deterministic routing, explicit error emission, evidence-level integrity, and consistent model-free replay. AutoVul must never guess a capability or silently default ambiguous requests.

## Scope

### In scope

- Strict, closed discrimination between `CapabilityResearchRequest` variants (`flow`, `missing_check`, `typestate`) and explicit matching of their hypothesis versions.
- Explicit rejection of unknown capabilities, unknown services, or mismatched hypothesis versions with structured `DomainError` codes (`INVALID_INPUT`).
- Addition of `evidence_kind: "real_analyzer" | "test_double"` to `FlowAnalyzerProvenance`, with policy enforcement capping `test_double` results at `generated`.
- Harmonization of replay verification baselines across Flow, MissingCheck, and Typestate:
  - Run-operation lease and cancellation tracking;
  - Operation route matching (`route_kind`, `capability`, `hypothesis_version`);
  - Analyzer ID, analyzer version, and adapter version consistency;
  - Database portable fingerprint verification;
  - Decision policy version matching;
  - Immutable evidence snapshot checks;
  - Isolated replay output under designated replay directories.
- Preserving capability-specific semantic comparison logic and existing artifact readability.

### Non-goals

- A universal Capability base class, generic Capability registry, or dynamic plugin loader.
- A universal hypothesis IR or universal observation format.
- Admitting a new Capability or Analyzer in this change.
- Automated capability selection, automatic fallback, or multi-analyzer voting.
- Modifying the accepted JavaScript CFG boundary of MissingCheck or lexical binding boundary of Typestate.

## Definitions

- **Closed pairing**: A discriminated union where each `capability` literal strictly requires its corresponding `hypothesis_version` literal and strongly-typed hypothesis schema.
- **Evidence kind**: An explicit provenance tag (`real_analyzer` vs `test_double`) indicating whether observations originate from an authoritative tool execution or a test double.
- **Replay baseline**: The set of pre-execution invariants (route, analyzer version, adapter version, database fingerprint, decision policy version, and evidence immutability) that any replay must satisfy before running or comparing results.

## Requirements

### Capability and version pairing

- `REQ-HARDEN-PAIR-001`: `CapabilityResearchRequest` MUST be a closed discriminated union pairing each `capability` with its exact corresponding `hypothesis_version`:
  - `capability: "flow"` MUST require `hypothesis_version: "autovul.flow/1"`;
  - `capability: "missing_check"` MUST require `hypothesis_version: "autovul.missing-check/1"`;
  - `capability: "typestate"` MUST require `hypothesis_version: "autovul.typestate/1"`.
- `REQ-HARDEN-PAIR-002`: A request pairing a `capability` with a foreign or unrecognized `hypothesis_version` MUST fail schema parsing with an `INVALID_INPUT` error pointing to `/hypothesis_version`.

### Dispatch and error rejection

- `REQ-HARDEN-DISPATCH-001`: `Application.research()` MUST explicitly route only admitted capabilities (`flow`, `missing_check`, `typestate`) and admitted analyzer services (`change_observation`).
- `REQ-HARDEN-DISPATCH-002`: Any request containing an unrecognized `capability`, unrecognized `service`, or neither MUST NOT fall back to Flow. It MUST throw a `DomainError` with code `INVALID_INPUT`.

### Flow evidence integrity

- `REQ-HARDEN-FLOW-EVID-001`: `FlowAnalyzerProvenanceSchema` MUST include `evidence_kind: Type.Union([Type.Literal("real_analyzer"), Type.Literal("test_double")])`.
- `REQ-HARDEN-FLOW-EVID-002`: When `observation.analyzer.evidence_kind` is not `"real_analyzer"`, `decideFlow()` MUST cap `verificationLevel` at `"generated"`, even if path and endpoint states match an expectation.
- `REQ-HARDEN-FLOW-EVID-003`: `CodeqlFlowAdapter` MUST set `evidence_kind: "real_analyzer"` when invoking CodeQL CLI, and test fixtures/doubles MUST declare `"test_double"`.

### Replay baseline consistency

- `REQ-HARDEN-REPLAY-BASE-001`: Flow, MissingCheck, and Typestate replay services MUST acquire a per-run operation lock via `ArtifactStorePort.withRunOperation` and bind caller cancellation via `RunCancellationService.begin`.
- `REQ-HARDEN-REPLAY-BASE-002`: Replay execution MUST validate that the recorded `route` matches the executing replay service. A mismatched `route_kind`, `capability`, or `hypothesis_version` MUST result in an `environment_blocked` replay outcome with a structured code.
- `REQ-HARDEN-REPLAY-BASE-003`: Replay execution MUST verify that the recorded target database portable fingerprints match the current databases. Fingerprint absence or mismatch MUST result in an `environment_blocked` replay outcome.
- `REQ-HARDEN-REPLAY-BASE-004`: Replay execution MUST verify that the recorded Analyzer version, adapter version, and Decision Policy version match the current execution environment. An unrecorded version or version difference MUST yield a `version_difference` comparison outcome with decision set to `unknown`.
- `REQ-HARDEN-REPLAY-BASE-005`: Replay execution MUST verify that original run evidence and query artifacts are immutable prior to re-execution, ensuring replay does not overwrite or corrupt original evidence.
- `REQ-HARDEN-REPLAY-BASE-006`: Capability-specific semantic comparisons (flow path matching, missing-check dominance witnesses, typestate violation traces) MUST execute only after baseline validation passes.

### Compatibility

- `REQ-HARDEN-COMPAT-001`: Historical run artifacts created prior to this specification MUST remain loadable. If an older artifact lacks fields required by baseline replay validation (such as `evidence_kind` or `target_fingerprints`), replay MUST cleanly return an `environment_blocked` or `version_difference` result rather than crashing.

## Architecture

```text
Host Request (autovul_research)
  │
  ├─ Closed Schema Validation (Flow | MissingCheck | Typestate | ChangeObservation)
  │   └─ Mismatched pair / unknown capability -> Reject with INVALID_INPUT
  │
  ▼
Application.research()
  ├─ explicit service === "change_observation" -> ChangeObservationResearchService
  ├─ explicit capability === "flow"            -> FlowResearchService
  ├─ explicit capability === "missing_check"   -> MissingCheckResearchService
  ├─ explicit capability === "typestate"       -> TypestateResearchService
  └─ else                                      -> throw DomainError(INVALID_INPUT)
```

## Contracts and artifacts

- [`packages/contracts/src/research.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/contracts/src/research.ts):
  - Replace open `CapabilityResearchRequestSchema` with closed union of Flow, MissingCheck, and Typestate request schemas.
- [`packages/contracts/src/flow.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/contracts/src/flow.ts):
  - Add `evidence_kind` to `FlowAnalyzerProvenanceSchema`.
- [`packages/core/src/flow/decision.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/decision.ts):
  - Restrict verification level to `generated` if `evidence_kind !== "real_analyzer"`.
- [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts) and [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts):
  - Add `withRunOperation`, `RunCancellationService`, route checks, policy version checks, and evidence snapshot checks.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-HARDEN-PAIR-001` | Given `capability: "flow"` and `hypothesis_version: "autovul.missing-check/1"`, when validated, then parsing fails with `INVALID_INPUT`. | Unit test |
| `REQ-HARDEN-DISPATCH-001` | Given an input with `capability: "unknown_test"`, when passed to `Application.research()`, then it throws `INVALID_INPUT` and does not execute Flow. | Unit test |
| `REQ-HARDEN-FLOW-EVID-001` | Given a test-double Flow observation with matching path, when `decideFlow` runs, then `verificationLevel` is capped at `"generated"`. | Unit test |
| `REQ-HARDEN-REPLAY-BASE-001` | Given a Flow or MissingCheck replay call, when executed, then it runs inside `withRunOperation` and respects cancellation signals. | Unit test |
| `REQ-HARDEN-REPLAY-BASE-002` | Given a replay request with mismatched route, when executed, then it returns `environment_blocked` without invoking the analyzer. | Unit test |

## Requirement Traceability

| Requirement ID | Implementation Location | Test Verification |
| --- | --- | --- |
| `REQ-HARDEN-PAIR-001` | [`packages/contracts/src/research.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/contracts/src/research.ts) | `test/capability-execution-harden.test.ts` ("accepts valid capability and hypothesis_version pairings") |
| `REQ-HARDEN-PAIR-002` | [`packages/contracts/src/research.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/contracts/src/research.ts) | `test/capability-execution-harden.test.ts` ("rejects mismatched capability and hypothesis_version pairings") |
| `REQ-HARDEN-DISPATCH-001` | [`packages/core/src/application.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/application.ts) | `test/capability-execution-harden.test.ts` ("explicitly rejects unknown capability with DomainError(INVALID_INPUT)") |
| `REQ-HARDEN-DISPATCH-002` | [`packages/core/src/application.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/application.ts) | `test/capability-execution-harden.test.ts` ("rejects non-object input with DomainError(INVALID_INPUT)"), `test/research-architecture.test.ts` |
| `REQ-HARDEN-FLOW-EVID-001` | [`packages/contracts/src/flow.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/contracts/src/flow.ts) | `test/capability-execution-harden.test.ts` |
| `REQ-HARDEN-FLOW-EVID-002` | [`packages/core/src/flow/decision.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/decision.ts) | `test/flow-decision.test.ts` ("caps verification level at generated when evidence_kind is test_double") |
| `REQ-HARDEN-FLOW-EVID-003` | [`packages/codeql-runner/src/flow-adapter.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/codeql-runner/src/flow-adapter.ts) | `test/m2-workflow.test.ts` |
| `REQ-HARDEN-REPLAY-BASE-001` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/capability-execution-harden.test.ts`, `test/research-architecture.test.ts` |
| `REQ-HARDEN-REPLAY-BASE-002` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/capability-execution-harden.test.ts` ("blocks Flow/MissingCheck replay when route capability does not match") |
| `REQ-HARDEN-REPLAY-BASE-003` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/research-architecture.test.ts` ("downgrades replay when the Analyzer or adapter version differs") |
| `REQ-HARDEN-REPLAY-BASE-004` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/capability-execution-harden.test.ts` ("reports policy version difference when Flow replay finds mismatched policy version") |
| `REQ-HARDEN-REPLAY-BASE-005` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/research-architecture.test.ts` ("blocks replay before Analyzer execution when the target fingerprint changes") |
| `REQ-HARDEN-REPLAY-BASE-006` | [`packages/core/src/flow/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/flow/replay.ts), [`packages/core/src/missing-check/replay.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/missing-check/replay.ts) | `test/research-architecture.test.ts` ("blocks replay when committed Flow evidence is corrupted") |
| `REQ-HARDEN-COMPAT-001` | [`packages/core/src/research-operation.ts`](file:///Users/zhangboxiang/Progarm/PureAutoCodeql/v2/packages/core/src/research-operation.ts) | `test/research-architecture.test.ts` ("projects a historical capability route without rewriting its artifact") |

## Validation plan

- Unit tests for schema discrimination and invalid pair rejections (`test/capability-execution-harden.test.ts`).
- Unit tests for `decideFlow` with `test_double` vs `real_analyzer` (`test/flow-decision.test.ts`).
- Replay tests verifying cancellation, route mismatch, version difference, and fingerprint mismatch on Flow and MissingCheck (`test/capability-execution-harden.test.ts`).
- Full gate execution via `npm run check`.
