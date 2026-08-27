# Change: Stabilize architecture boundaries

- Change ID: `stabilize-architecture-boundaries`
- Status: Implemented
- Owner: PureAutoCodeQL maintainers
- Created: 2026-08-27
- Updated: 2026-08-27

## Problem

PureAutoCodeQL V2 has a working CodeQL vertical slice, but several implementation units now combine too many responsibilities:

- `packages/core/src/query-workflow.ts` owns admission, database inspection, case idempotency, probing, drafting, verification, policy evaluation, persistence and Query Pack finalization.
- Extracting a broad `query-workflow-policy.ts` helper module moved code without establishing cohesive domain ownership.
- `packages/pi-extension/src/index.ts` combines prompts, lifecycle hooks, commands, tool registration, UI state and formatting.
- `packages/codeql-runner/src/lsp/protocol-spike.ts` combines experimental protocol discovery with production package exports.
- Generic-looking run contracts contain CodeQL-specific phase values, so extending them directly would spread CodeQL assumptions into future vulnerability-research capabilities.
- The current working tree mixes specification infrastructure, lifecycle refactors, workflow changes and test-support changes, making review and rollback harder.

The immediate need is architectural stabilization without changing observable product behavior. Generalizing the product before these boundaries are stable would distribute existing complexity across every future Analyzer and host integration.

## Host boundary

This change belongs in PureAutoCodeQL because it reorganizes the deterministic vulnerability-research engine, CodeQL Analyzer and Pi integration boundary.

The host Agent continues to own:

- model access and the Agent Loop;
- session context, planning and generic tools;
- natural-language reasoning and user interaction.

This change MUST NOT introduce model providers, generic Agent runtime behavior, memory, context compression, planning or subagent orchestration.

## Scope

### In scope

- Establish a stable checkpoint for the current uncommitted V2 changes.
- Decompose CodeQL workflow orchestration by command and transaction boundary.
- Replace the broad workflow-policy helper collection with cohesive domain modules.
- Separate Pi integration registration, prompts, UI and lifecycle code.
- Separate production CodeQL LSP runtime code from protocol experiments and conformance tooling.
- Preserve existing public Application APIs, schemas, artifacts and verification semantics.
- Add architectural checks or tests that prevent the same concentration from immediately returning.

### Non-goals

- Introducing a generic Analyzer plugin SDK.
- Introducing `ResearchTarget`, `VulnerabilityHypothesis`, generic Evidence or Verification Claim contracts.
- Adding a second Analyzer.
- Adding DeepSeek Harness or MCP integrations.
- Renaming or publishing npm packages.
- Changing candidate budgets, verification levels, Source/Sink semantics or Query Pack contents.
- Changing supported language, platform or CodeQL capability claims.
- Rewriting the workflow around an Agent-style planner or generic orchestration engine.

## Requirements

### Stable baseline

- `REQ-ARCHSTAB-001`: The change MUST preserve the existing Pi and CLI Application behavior for doctor, database inspection, workflow start/status/finalize and query probe/draft/verify.
- `REQ-ARCHSTAB-002`: The change MUST preserve existing versioned schemas and artifact formats unless a separately accepted compatibility SPEC explicitly changes them.
- `REQ-ARCHSTAB-003`: The current mixed working tree SHOULD be separated into reviewable checkpoints for specification infrastructure, process/RPC lifecycle, workflow decomposition and test updates.
- `REQ-ARCHSTAB-004`: Deleted diagnostic fixtures or compatibility entry points MUST have an explicit replacement, migration note or proof that no supported command references them.

### CodeQL workflow decomposition

- `REQ-ARCHSTAB-010`: The public CodeQL workflow facade MUST delegate to focused command handlers rather than directly own every workflow stage.
- `REQ-ARCHSTAB-011`: Admission, probe, draft, verify and finalize MUST have explicit ownership boundaries.
- `REQ-ARCHSTAB-012`: Workflow state loading, migration and atomic persistence MUST have one canonical repository boundary.
- `REQ-ARCHSTAB-013`: Candidate policy, endpoint policy, case-ledger projection and state migration MUST NOT remain mixed in a generic workflow helper collection.
- `REQ-ARCHSTAB-014`: A command handler MUST perform one domain operation under one documented workflow lease and MUST NOT create partial manifest/state success when an external operation fails.
- `REQ-ARCHSTAB-015`: Candidate budget, case fingerprint, strict endpoint, probe-evidence and differential-validation semantics MUST remain unchanged.
- `REQ-ARCHSTAB-016`: The workflow facade SHOULD remain below 400 source lines after decomposition.
- `REQ-ARCHSTAB-017`: No hand-written production source file SHOULD exceed 1000 lines without an explicit exception recorded in this change's verification record.

### Pi integration decomposition

- `REQ-ARCHSTAB-020`: The Pi extension entry point MUST be limited to dependency assembly and registration.
- `REQ-ARCHSTAB-021`: Pi prompts, tool handlers, commands, lifecycle and UI formatting MUST live in focused modules with explicit imports.
- `REQ-ARCHSTAB-022`: Pi-specific prompts, types and lifecycle behavior MUST NOT move into Core.
- `REQ-ARCHSTAB-023`: The Pi extension MUST continue exposing the same three aggregate tool names and compatible command behavior.
- `REQ-ARCHSTAB-024`: The Pi extension entry point SHOULD remain below 150 source lines after decomposition.

### LSP production/lab separation

- `REQ-ARCHSTAB-030`: Production draft validation MUST depend only on the minimal LSP session/runtime modules required by the Application.
- `REQ-ARCHSTAB-031`: Protocol discovery, matrix snapshots and experimental observation types MUST be isolated from the primary production export surface.
- `REQ-ARCHSTAB-032`: LSP process startup, timeout, cancellation and process-tree cleanup MUST use one canonical lifecycle implementation.
- `REQ-ARCHSTAB-033`: Moving protocol-spike code MUST preserve the LSP conformance and snapshot commands or provide documented replacements.

### Contract discipline

- `REQ-ARCHSTAB-040`: Existing CodeQL-specific run phases MUST remain CodeQL-specific during this change; they MUST NOT be widened into untyped generic strings as a shortcut.
- `REQ-ARCHSTAB-041`: Milestone-named contract files MAY be reorganized behind compatibility exports, but public imported symbols MUST remain compatible.
- `REQ-ARCHSTAB-042`: This change MUST NOT claim that current CodeQL workflow contracts are already a generic vulnerability-research kernel.

### Maintainability gates

- `REQ-ARCHSTAB-050`: Dependency-direction checks MUST continue enforcing the contracts-to-core-to-codeql-runner-to-integrations dependency order.
- `REQ-ARCHSTAB-051`: New modules MUST have a cohesive owner and MUST NOT be pass-through wrappers that only add indirection.
- `REQ-ARCHSTAB-052`: Repeated terminal-state, timeout-option, candidate-identity and error-finalization logic SHOULD use canonical typed helpers where that removes branches without hiding state transitions.
- `REQ-ARCHSTAB-053`: Architecture checks SHOULD report oversized hand-written production files and oversized integration entry points.
- `REQ-ARCHSTAB-054`: Tests MUST cover failure and cancellation at each extracted command boundary, not only successful delegation.

## Proposed behavior

This is intended to be a behavior-preserving structural change.

The externally observable sequence remains:

```text
workflow start
  -> query probe
  -> query draft
  -> query verify
  -> workflow finalize
```

Internally, each action becomes a command boundary:

```text
Application facade
  -> CodeqlWorkflow facade
       -> Admission command
       -> Probe command
       -> Draft command
       -> Verify command
       -> Finalize command
            -> Workflow repository
            -> Case ledger
            -> CodeQL ports
            -> Artifact store
```

Each command MUST:

1. parse and validate its boundary input;
2. acquire the appropriate workflow/case lease;
3. load typed state through the repository;
4. apply one domain operation and external observation;
5. atomically persist the resulting state/artifacts;
6. return the same contract currently returned by the Application API.

The preferred module layout is illustrative rather than mandatory:

```text
packages/core/src/codeql-workflow/
├── service.ts
├── admission.ts
├── probe.ts
├── draft.ts
├── verify.ts
├── finalize.ts
├── repository.ts
├── candidate-policy.ts
├── endpoint-policy.ts
├── case-ledger.ts
└── state-migrations.ts
```

An alternative layout is acceptable only if it satisfies the ownership and size requirements without adding generic wrappers or duplicating state transitions.

## Contracts and artifacts

No public contract or artifact change is planned.

The following MUST remain compatible:

- `ApplicationApi` methods and return types;
- `VulnerabilitySpec`, `TaintQueryIntent` and `QueryCandidate` inputs;
- `RunManifest`, `QueryWorkflowState` and `CaseRunSummary` persistence;
- CodeQL tool names and discriminated action schemas;
- query, verification, evidence and Query Pack manifests;
- verification-level meanings;
- model-free relocated Query Pack replay.

Internal repository or command types MAY be introduced without exporting them from package public entry points.

## Architecture

### Target boundary for this change

```text
Pi / CLI
   -> Application
      -> CodeQL Workflow Facade
         -> focused command handlers
         -> workflow repository / case ledger
         -> CodeQL ports
            -> codeql-runner
```

This change deliberately stops before introducing a generic research-domain layer. The generic layer requires its own accepted SPEC and evidence from a second Analyzer.

### Code-judo objective

The decomposition MUST reduce the number of concepts each file owns. Merely moving the same conditional chains into a large `utils`, `policy` or `helpers` file does not satisfy this change.

The preferred simplification is to make each command responsible for one transaction and make state persistence canonical. This should delete duplicated terminal-state checks, option construction, error finalization and state-write sequences instead of redistributing them.

## Safety and privacy

- Trusted-root and canonical-path checks MUST remain in force.
- Refactoring MUST NOT broaden target filesystem or process permissions.
- Target build/install scripts remain unimplemented and unapproved.
- Cancellation MUST distinguish waiting for a lease from cancelling the current lease owner.
- Process cleanup MUST cover success, error, timeout, cancellation, application close and non-interactive host exit.
- Logs, test diagnostics and protocol snapshots MUST remain sanitized and bounded.
- Existing private target data and run artifacts MUST NOT be copied into fixtures or committed during decomposition.

## Compatibility and migration

No user migration is planned.

- Existing run artifacts MUST remain readable.
- Existing package imports MUST remain valid.
- Existing Pi commands/tools and CLI commands MUST retain their behavior.
- Internal file moves MUST use compatibility re-exports where tests or supported consumers import the old module.
- If an internal legacy state migration is changed, old-state fixtures MUST demonstrate compatibility.

Rollback is file/module-level because public contracts are unchanged. The work SHOULD be committed in reviewable checkpoints so workflow, integration and LSP changes can be reverted independently.

## Delivery plan

### Phase 0: Stabilize the current working tree

1. Inventory current modified, deleted and new files.
2. Confirm every deletion has a replacement or an explicit removal rationale.
3. Separate SPEC/infrastructure, lifecycle, workflow and test changes into reviewable checkpoints.
4. Establish the full fake/unit baseline and document missing real-tool gates.

Exit criteria:

- typecheck and unit/integration tests pass;
- `git diff --check` passes;
- SPEC validation passes;
- the working tree can be reviewed and rolled back by concern.

### Phase 1: Decompose the CodeQL workflow

1. Introduce the canonical workflow repository/state migration boundary.
2. Extract admission and case-ledger ownership.
3. Extract probe and draft command handlers.
4. Extract formal verification and evaluation.
5. Extract finalization and Query Pack creation.
6. Reduce the facade to delegation and lifecycle coordination.
7. Remove the broad helper collection after its responsibilities have canonical homes.

Exit criteria:

- requirements `REQ-ARCHSTAB-010` through `REQ-ARCHSTAB-017` pass;
- public contracts and Golden inputs are unchanged;
- concurrency, cancellation, budget and resume tests pass.

### Phase 2: Thin the Pi integration

1. Move long prompts into focused prompt modules.
2. Move each aggregate tool into its own handler module.
3. Move commands, UI state/formatting and lifecycle cleanup into focused modules.
4. Leave the entry point as application assembly and registration.

Exit criteria:

- Pi RPC smoke produces equivalent tool calls/results;
- entry-point size satisfies `REQ-ARCHSTAB-024`;
- Core has no new Pi imports or prompt content.

### Phase 3: Separate LSP product runtime from protocol lab

1. Keep process lifecycle and production session behavior in `codeql-runner`.
2. Move matrix/snapshot experimentation to test support or an explicitly non-production lab module.
3. Reduce the production export surface.
4. Run snapshot and conformance gates against the new boundary.

Exit criteria:

- LSP draft behavior remains compatible;
- snapshot and conformance commands pass;
- production package exports no longer make the protocol spike a primary runtime capability.

### Phase 4: Verify and archive

1. Run all fake/unit/integration/package checks.
2. Run real LSP conformance.
3. Run the relevant real CodeQL multi-language and replay gates.
4. Record skipped real-model gates without converting them into success.
5. Update root `SPEC.md` only if stable product requirements changed.
6. Mark this change Verified and then Archived.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-ARCHSTAB-001` | Given existing Pi and CLI inputs, when run through the decomposed Application, then compatible structured results are returned | Unit tests, CLI integration, Pi RPC smoke |
| `REQ-ARCHSTAB-002` | Given existing serialized fixtures and Query Packs, when read or replayed, then validation succeeds without migration by the user | Contract tests, Golden manifests, relocated replay |
| `REQ-ARCHSTAB-010` | Given the workflow facade, when inspected after refactoring, then each public action delegates to a focused command handler | Architecture review, source-size check |
| `REQ-ARCHSTAB-012` | Given a workflow mutation, when state is loaded or saved, then one repository owns migration and atomic persistence | Unit tests, failure injection |
| `REQ-ARCHSTAB-014` | Given external failure or cancellation during a command, when the command exits, then no partial success state is persisted | Failure and cancellation tests |
| `REQ-ARCHSTAB-015` | Given existing budget, endpoint and differential cases, when rerun, then outcomes remain unchanged | Workflow tests, real Golden/replay |
| `REQ-ARCHSTAB-016` | Given the final workflow facade, when source size is checked, then it is at most 400 lines unless an accepted exception exists | Architecture check script |
| `REQ-ARCHSTAB-017` | Given all hand-written production files, when source size is checked, then none exceeds 1000 lines without an accepted exception | Architecture check script |
| `REQ-ARCHSTAB-020` | Given the Pi entry point, when inspected, then it contains assembly and registration rather than workflow policy | Architecture review |
| `REQ-ARCHSTAB-023` | Given existing Pi commands and tools, when exercised through RPC, then names and result contracts remain compatible | Pi RPC smoke/E2E |
| `REQ-ARCHSTAB-024` | Given the final Pi entry point, when source size is checked, then it is at most 150 lines | Architecture check script |
| `REQ-ARCHSTAB-031` | Given the production package entry point, when exports are inspected, then experimental snapshot machinery is isolated | Export test/package inspection |
| `REQ-ARCHSTAB-032` | Given every LSP/process exit path, when triggered, then the canonical lifecycle implementation cleans the process tree | Failure injection, LSP conformance |
| `REQ-ARCHSTAB-040` | Given existing run manifests, when validated, then CodeQL phase semantics remain typed and compatible | Contract tests |
| `REQ-ARCHSTAB-050` | Given the final dependency graph, when the dependency check runs, then forbidden reverse/host dependencies are rejected | Dependency-direction check |

## Validation plan

- Focused unit tests:
  - command handler state transitions;
  - repository migration and atomic persistence;
  - candidate/endpoint/case policies;
  - Pi tool registration and formatting;
  - process lifecycle cleanup.
- Failure injection:
  - cancellation while waiting for a lease;
  - cancellation by the lease owner;
  - CodeQL timeout/crash;
  - LSP degraded/unavailable;
  - artifact write failure;
  - corrupt legacy state.
- Real analyzer/target:
  - relevant Python, JavaScript/TypeScript, Java/Kotlin and C/C++ Golden cases.
- Differential or negative sample:
  - vulnerable match and fixed non-match;
  - budget exhaustion;
  - strict endpoint mismatch;
  - false-positive fixed-side rejection.
- Independent replay:
  - relocated Query Pack verification without model or originating run.
- Package/integration smoke:
  - `npm run check`;
  - Pi RPC smoke;
  - LSP snapshot and conformance;
  - package dry-run and export inspection.

## Follow-up changes

The following changes are intentionally deferred and each requires its own accepted SPEC:

1. `introduce-research-domain-kernel`
   - define Research Target, Hypothesis, Evidence Envelope and Verification Claim;
   - keep CodeQL-specific query concepts specialized.
2. `add-patch-intelligence-analyzer`
   - provide a second deterministic vulnerability-research capability;
   - use it to validate which abstractions are genuinely analyzer-neutral.
3. `add-deepseek-harness-integration`
   - implement a thin DeepSeek Harness plugin over the stable Application API.
4. `add-mcp-integration`
   - expose stable vulnerability-research capabilities to additional hosts.

Physical npm package splitting or renaming SHOULD be decided only after the second Analyzer proves the common boundary.

## Open questions

- Should protocol snapshot tooling move entirely under `test/`, or remain in a separately exported lab entry point?
- Should command handlers be classes with injected dependencies or direct functions over a typed context? The implementation SHOULD choose the form with fewer wrappers and simpler tests.
- Should file-size gates be absolute or allow a small checked-in exception list for generated/fixture-heavy files?
- Which real Golden subset is the minimum required for a behavior-preserving architecture refactor before the full matrix runs?

These questions do not block accepting the direction, but they MUST be resolved before the affected phase is marked Implemented.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-27 | Stabilize CodeQL boundaries before introducing generic research contracts | Prevent current orchestration complexity from spreading into every future Analyzer and host integration |
| 2026-08-27 | Preserve public APIs and artifacts during stabilization | Keep the refactor reviewable and rollback-safe |
| 2026-08-27 | Validate generic architecture with a second Analyzer | Avoid designing an unproven plugin abstraction from CodeQL alone |
| 2026-08-27 | Keep Agent/Harness capabilities outside the project | Maintain the accepted host-extension product boundary |

## Verification record

See [VERIFICATION.md](./VERIFICATION.md) and [CHECKPOINTS.md](./CHECKPOINTS.md). The change is Implemented but not yet Verified because the real CodeQL Golden/differential/replay matrix remains pending.

Baseline observations recorded while drafting and implementation:

- TypeScript typecheck passed.
- Unit/integration suite passed: 20 test files, 98 tests.
- SPEC validation passed before this change was added: 53 baseline requirements.
- Current notable hand-written file sizes:
  - `query-workflow.ts`: approximately 1705 lines;
  - `protocol-spike.ts`: approximately 1340 lines;
  - `pi-extension/src/index.ts`: approximately 612 lines;
  - `query-workflow-policy.ts`: approximately 539 lines.
- Real CodeQL Golden and real-model gates were not run during this implementation pass; real LSP snapshot/conformance was run and passed.
- No vulnerability result is claimed from this architecture change.
