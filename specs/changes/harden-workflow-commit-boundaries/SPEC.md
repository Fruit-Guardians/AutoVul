# Change: Harden workflow commit boundaries

- Change ID: `harden-workflow-commit-boundaries`
- Status: Accepted
- Owner: PureAutoCodeQL maintainers
- Created: 2026-08-27
- Updated: 2026-08-27

## Problem

The architecture stabilization change decomposed the CodeQL workflow into focused admission, probe, draft, verify and finalize commands. Independent review and real-tool verification confirmed that the decomposition works, but also found that the persistence order does not yet provide a precise domain commit boundary.

In particular:

- verification may checkpoint the run and update the case summary before its evidence artifact and workflow state are durable;
- finalization writes a Query Pack, workflow state, completed run manifest and case ledger as separate operations;
- a failure between those writes can leave a completed-looking projection with incomplete authoritative state, or durable state with stale projections;
- cancellation behavior is not defined when cancellation arrives after the domain result has already committed;
- command-boundary tests cover important cancellation paths but do not inject failure at every persistence boundary;
- incremental TypeScript builds can leave moved files in `dist`, and the package dry-run does not currently reject those stale outputs.

These gaps prevent `stabilize-architecture-boundaries` from reaching Verified even though its fake tests, Pi RPC smoke, real LSP conformance and 20-case real CodeQL Golden suite pass.

## Host boundary

This change belongs in PureAutoCodeQL because durable evidence, deterministic workflow state, replayable Query Packs and accurate success levels are responsibilities of the vulnerability-research engine.

The host Agent or Harness continues to own:

- reasoning, planning and tool selection;
- user interaction and approval;
- model lifecycle, context and generic retry policy;
- presentation of the structured result.

This change MUST NOT add an Agent Loop, model provider, generic task system, memory system or host-specific recovery behavior to Core.

## Scope

### In scope

- Define one authoritative commit point for verification and finalization.
- Stage referenced artifacts before committing domain state.
- Treat run manifests and case summaries as recoverable projections of authoritative workflow state.
- Define cancellation behavior before and after the commit point.
- Make retries and restart recovery idempotent.
- Add deterministic failure injection for every extracted command and persistence boundary.
- Remove ambiguous direct persistence paths from the workflow context.
- Make build and package checks reject stale compiled output.
- Split the LSP lab file or record and enforce an explicit exception.
- Update the architecture stabilization verification record with independently reproduced real-tool evidence.

### Non-goals

- Changing public Application method names or tool schemas.
- Changing candidate budgets, endpoint rules or verification-level meanings.
- Adding an Analyzer, language, host integration or vulnerability class.
- Building a general distributed transaction framework.
- Providing cross-machine or multi-database transactions.
- Making run artifacts a substitute for source control or external archival storage.
- Generalizing the CodeQL workflow into a universal Agent workflow.

## Definitions

- **Authoritative workflow state**: the validated `workflow/state.json` document for a run.
- **Referenced artifact**: evidence or Query Pack content that authoritative state requires in order to substantiate its result.
- **Projection**: a run manifest or case summary derived from authoritative workflow state for status, indexing or host presentation.
- **Commit point**: the atomic replacement of authoritative workflow state after all referenced artifacts are durable.
- **Pre-commit failure**: any error or cancellation before the commit point.
- **Post-commit projection failure**: an error while updating a projection after authoritative state has committed.
- **Recovery**: deterministic reconciliation of projections and staged artifacts from authoritative workflow state and internal commit metadata.

## Requirements

### Commit protocol

- `REQ-WFCOMMIT-001`: Verification and finalization MUST each define exactly one authoritative domain commit point.
- `REQ-WFCOMMIT-002`: Every artifact referenced by the next authoritative workflow state MUST be durably written or atomically promoted before the commit point.
- `REQ-WFCOMMIT-003`: A pre-commit failure or cancellation MUST NOT persist a successful verification, completed Query Pack, successful checkpoint or completed case projection.
- `REQ-WFCOMMIT-004`: The authoritative state replacement MUST remain atomic within the trusted artifact root.
- `REQ-WFCOMMIT-005`: Run manifests and case summaries MUST be treated as projections and MUST be recoverable from authoritative workflow state.
- `REQ-WFCOMMIT-006`: A projection failure after the commit point MUST NOT change a committed domain result into a false failure or cancellation.
- `REQ-WFCOMMIT-007`: A post-commit projection failure MUST produce bounded, sanitized recovery evidence and MUST be retried during deterministic reconciliation.
- `REQ-WFCOMMIT-008`: Retrying the same operation after interruption MUST return or reconstruct the same committed result without consuming an additional candidate or draft budget.
- `REQ-WFCOMMIT-009`: Cancellation observed before the commit point MUST cancel the operation; cancellation observed after the commit point MUST NOT roll back or relabel the committed result.
- `REQ-WFCOMMIT-010`: Orphaned staging content MUST never be interpreted as successful evidence and MUST be cleaned by a bounded, trusted-root-constrained recovery policy.

### Verification semantics

- `REQ-WFCOMMIT-020`: Verification evidence and the final structured verification artifact MUST be durable before workflow state records that verification.
- `REQ-WFCOMMIT-021`: Candidate identity, candidate budget, endpoint matching and differential evaluation MUST remain unchanged.
- `REQ-WFCOMMIT-022`: A committed passing verification MUST reconcile the run manifest to `checkpointed` with the same verification level.
- `REQ-WFCOMMIT-023`: A committed failed verification MUST remain a research result without being projected as successful or completed.
- `REQ-WFCOMMIT-024`: Exhaustion MUST be derived from committed candidate state and MUST reconcile the run and case projections idempotently.

### Finalization semantics

- `REQ-WFCOMMIT-030`: Finalization MUST construct the complete Query Pack in a staging directory under the trusted artifact root.
- `REQ-WFCOMMIT-031`: The complete staged Query Pack MUST be promoted as one filesystem operation before authoritative state references it.
- `REQ-WFCOMMIT-032`: A Query Pack MUST NOT be considered finalized unless authoritative state contains the matching validated pack manifest.
- `REQ-WFCOMMIT-033`: Once authoritative state commits a Query Pack, retry or recovery MUST reconcile the run to `completed` and the case summary to the same pack id.
- `REQ-WFCOMMIT-034`: Finalization MUST be idempotent for the same verified candidate and MUST reject a conflicting pack identity.
- `REQ-WFCOMMIT-035`: Existing relocated, model-free Query Pack replay behavior MUST remain compatible.

### Persistence ownership and recovery

- `REQ-WFCOMMIT-040`: Workflow state loading, migration, commit and reconciliation MUST have one canonical repository boundary.
- `REQ-WFCOMMIT-041`: Command handlers MUST NOT bypass that boundary to mutate authoritative workflow state or success projections.
- `REQ-WFCOMMIT-042`: Raw artifact access MAY remain available for analyzer evidence, but its ownership and relationship to the commit protocol MUST be explicit and typed.
- `REQ-WFCOMMIT-043`: Recovery metadata MUST use a versioned internal schema and MUST NOT be exported as vulnerability evidence or included in a relocated Query Pack.
- `REQ-WFCOMMIT-044`: Recovery MUST be safe to run repeatedly after process crash, host restart or context loss.
- `REQ-WFCOMMIT-045`: Corrupt authoritative state or recovery metadata MUST produce a structured artifact error and MUST NOT be silently replaced with an empty or successful state.
- `REQ-WFCOMMIT-046`: Status reconciliation side effects MUST be explicit in naming and tests; a nominally read-only helper MUST NOT hide unbounded mutation.

### Failure and concurrency verification

- `REQ-WFCOMMIT-050`: Tests MUST inject failure and cancellation at admission, probe, draft, verify and finalize boundaries.
- `REQ-WFCOMMIT-051`: Verification tests MUST inject failure before evidence write, before state commit and during each post-commit projection update.
- `REQ-WFCOMMIT-052`: Finalization tests MUST inject failure during staging, promotion, state commit, run projection and case projection.
- `REQ-WFCOMMIT-053`: Crash-and-restart tests MUST demonstrate idempotent recovery from both pre-commit staging and post-commit projection-pending states.
- `REQ-WFCOMMIT-054`: Concurrency tests MUST prove that one workflow lease prevents two commits for the same run and that case locking preserves existing candidate budgets.
- `REQ-WFCOMMIT-055`: Fake or in-memory adapters MAY prove state-machine behavior, but Verified status MUST also retain the existing real CodeQL differential and replay evidence.

### Build, package and architecture hygiene

- `REQ-WFCOMMIT-060`: The canonical build used by package verification MUST remove only known package `dist` directories before compilation.
- `REQ-WFCOMMIT-061`: Package verification MUST run from clean compiled output and MUST reject stale paths that no longer have a source or approved generated owner.
- `REQ-WFCOMMIT-062`: The package dry-run MUST NOT contain both legacy `dist/lsp/protocol-spike.*` and `dist/lsp/lab/protocol-spike.*` outputs.
- `REQ-WFCOMMIT-063`: The hand-written LSP lab implementation SHOULD be split below 1000 lines; if retained above that limit, the exception MUST be explicitly justified, approved and enforced by the architecture check.
- `REQ-WFCOMMIT-064`: Experimental lab exports MUST remain isolated from the primary production runner export.

### Compatibility and lifecycle

- `REQ-WFCOMMIT-070`: Existing public Application APIs, Pi tool names, CLI commands and public schemas MUST remain compatible.
- `REQ-WFCOMMIT-071`: Existing runs without internal recovery metadata MUST remain readable and recoverable.
- `REQ-WFCOMMIT-072`: Existing completed Query Packs MUST remain replayable without migration.
- `REQ-WFCOMMIT-073`: The `stabilize-architecture-boundaries` change MUST NOT be marked Verified until all MUST requirements shared with this change have evidence or an explicitly accepted superseding decision.

## Proposed behavior

### Verification transaction

```text
acquire workflow lease
  -> load and validate authoritative state
  -> execute CodeQL and evaluate the result
  -> prepare final verification and case projection data
  -> write referenced verification evidence
  -> atomic state replacement                    [commit point]
  -> reconcile run manifest and case projection
  -> return committed verification
```

If execution, evidence writing or state replacement fails, the command exits without a successful verification in authoritative state. If a projection update fails after state replacement, the committed verification remains authoritative, recovery metadata records the pending projection, and a retry or reconciliation completes it without running CodeQL again.

### Finalization transaction

```text
acquire workflow lease
  -> load committed passing verification
  -> build complete Query Pack in staging
  -> validate staged manifest and digests
  -> atomically promote staging directory
  -> atomic state replacement with pack          [commit point]
  -> reconcile run manifest and case projection
  -> return committed Query Pack
```

An orphaned staged or promoted directory without matching authoritative state is not a finalized pack. Recovery removes or reuses it only after validating its operation id, pack id, digests and trusted-root location.

### Projection reconciliation

```text
authoritative workflow state
  ├─ derive expected run phase/status/verification level
  └─ derive expected case summary and final pack id
       -> compare persisted projections
       -> atomically repair mismatches under the required lease
       -> record bounded recovery result
```

The Application service MUST invoke an explicitly named projection reconciler before status assembly when reconciliation is required. The status-assembly helper itself remains a pure read of already reconciled state and projections.

## Contracts and artifacts

No public contract change is planned.

The implementation MAY add internal recovery metadata under a reserved run-artifact path such as:

```text
workflow/internal/commits/operation-id.json
```

Any such document MUST have a versioned schema containing, at minimum:

- schema version;
- operation id and idempotency key;
- run id and workflow phase;
- pre-commit, committed or projection-pending state;
- staged artifact paths and digests where applicable;
- bounded diagnostic codes;
- created and updated timestamps.

Internal recovery metadata MUST NOT contain model prompts, environment secrets, unrestricted command output or untrusted absolute paths. It MUST NOT be copied into Query Packs.

## Architecture

```text
Pi / CLI
  -> Application
     -> CodeQL Workflow command
        -> Workflow Commit Repository
           ├─ authoritative state
           ├─ staged evidence / Query Pack
           └─ recovery metadata
        -> Projection Reconciler
           ├─ RunStatusService
           └─ CaseLedger
        -> Analyzer Ports
           └─ codeql-runner
```

- Contracts retain public schemas and MAY define an internal versioned recovery schema only if cross-package validation requires it.
- Core owns commit rules, idempotency, projection expectations and recovery decisions.
- The artifact adapter owns trusted-root filesystem staging, atomic file replacement and atomic directory promotion.
- CodeQL runner behavior and verification truth standards remain unchanged.
- Pi and CLI remain thin adapters and MUST NOT implement recovery policy.

The repository must not become a generic transaction framework. Its API should use workflow-domain operations such as committing a verification or committing a Query Pack rather than exposing an unrestricted batch of filesystem mutations.

## Safety and privacy

- All staging and promotion paths MUST be canonical descendants of the trusted artifact root.
- Symlink escape checks MUST apply before staging, promotion, cleanup and recovery.
- Cleanup MUST target explicit operation directories; it MUST NOT recursively delete a workspace or broad parent directory.
- Existing command approval boundaries are unchanged.
- Cancellation and timeout MUST continue terminating the complete analyzer subprocess tree.
- Recovery diagnostics MUST be sanitized and size bounded.
- Recovery MUST NOT execute target build or install scripts.
- Atomic promotion MUST remain on the same filesystem; cross-filesystem fallback MUST fail safely rather than copy partial success into place.

## Compatibility and migration

- Existing state and artifact schemas remain readable.
- Runs without recovery metadata are treated as legacy-complete at their current authoritative state.
- Derived manifest or case mismatches MAY be repaired only when authoritative state validates successfully.
- Existing Query Pack paths and contents remain compatible after successful finalization.
- Internal staging and recovery paths are not compatibility surfaces.
- Rollback must leave committed legacy state readable; new internal metadata may be ignored by the previous implementation.

## Delivery plan

The executable checkpoint plan is recorded in [PLAN.md](./PLAN.md).

Implementation MUST NOT begin until this Draft is explicitly Accepted.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-WFCOMMIT-003` | Given failure at any pre-commit write, when verification or finalization exits, then no successful result is visible in authoritative state or projections | Failure-injection tests |
| `REQ-WFCOMMIT-006` | Given authoritative state has committed, when a projection write fails, then retry recovers the same result without rerunning the Analyzer | Failure-injection and call-count tests |
| `REQ-WFCOMMIT-008` | Given a crash after commit, when the same request is retried, then the same result returns without additional budget use | Restart/idempotency integration test |
| `REQ-WFCOMMIT-009` | Given cancellation before and after the commit point, when the command exits, then pre-commit is cancelled and post-commit remains committed | Deterministic cancellation tests |
| `REQ-WFCOMMIT-020` | Given a passing CodeQL result, when state commits, then its referenced verification artifact already exists and validates | Repository integration test |
| `REQ-WFCOMMIT-031` | Given a complete staged Query Pack, when promotion occurs, then observers see either no final directory or the complete validated directory | Filesystem adapter test |
| `REQ-WFCOMMIT-033` | Given a committed pack with stale projections, when recovery runs, then run and case projections converge to the same pack id | Recovery integration test |
| `REQ-WFCOMMIT-045` | Given corrupt state or metadata, when loaded, then a structured artifact error is returned and no success state is synthesized | Corruption fixtures |
| `REQ-WFCOMMIT-050` | Given all extracted command boundaries, when the failure matrix runs, then each has success, failure and cancellation evidence | Test matrix report |
| `REQ-WFCOMMIT-054` | Given concurrent operations for one run, when they attempt commit, then exactly one domain commit occurs | In-memory and cross-process tests |
| `REQ-WFCOMMIT-061` | Given a moved source file and stale prior output, when package verification runs, then stale output is absent or the gate fails | Clean-build package test |
| `REQ-WFCOMMIT-070` | Given existing Pi and CLI calls, when rerun after implementation, then compatible structured responses are returned | Unit tests and Pi RPC E2E |
| `REQ-WFCOMMIT-072` | Given existing Golden Query Packs, when relocated replay runs, then verification remains successful | Real CodeQL replay |

## Validation plan

- Focused unit tests:
  - commit-state transitions and idempotency keys;
  - projection derivation and reconciliation;
  - staging validation and cleanup selection;
  - corrupt state and recovery metadata.
- Failure injection:
  - every evidence write, state commit and projection write;
  - staging creation, file write, validation and promotion;
  - cancellation immediately before and after the commit point;
  - process crash after commit but before response.
- Real analyzer/target:
  - existing Python, JavaScript, Java and C/C++ CodeQL Golden cases.
- Differential or negative sample:
  - vulnerable match, fixed non-match, endpoint mismatch and budget exhaustion.
- Independent replay:
  - relocated Query Pack verification without model or originating run.
- Package/integration smoke:
  - `npm run check`;
  - Pi RPC smoke;
  - real LSP snapshot and conformance;
  - clean package dry-run with stale-output assertion.

## Resolved design choices

- Recovery metadata will use a reserved, versioned internal artifact schema rather than changing the public workflow-state schema. Authoritative state remains the commit point; recovery metadata records preparation and projection repair only.
- Projection reconciliation will be an explicitly named service operation invoked before status assembly when needed. The status-assembly helper remains read-only.
- `@pure-auto-codeql/codeql-runner/lab` will remain importable during this change to avoid an unrelated compatibility break. Its implementation will be split into cohesive modules and kept outside the primary runner export. Removing the subpath requires a later compatibility SPEC.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-27 | Use authoritative workflow state as the domain commit point | It is already typed, atomically replaced and required for model-free recovery. |
| 2026-08-27 | Treat run manifest and case summary as recoverable projections | A multi-file filesystem transaction is unnecessary if success has one authoritative source and projections are idempotent. |
| 2026-08-27 | Stage complete Query Packs before state commit | A committed pack must never reference incomplete replay material. |
| 2026-08-27 | Keep public Application and evidence contracts unchanged | This is reliability hardening, not a product capability expansion. |
| 2026-08-27 | Store recovery metadata outside public workflow state | This preserves public schema compatibility while keeping restart evidence versioned. |
| 2026-08-27 | Keep status assembly read-only | Reconciliation remains explicit, bounded and testable instead of hiding writes behind a read helper. |
| 2026-08-27 | Retain and split the lab subpath | The current change fixes maintainability without introducing an unrelated package compatibility break. |

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: pending implementation.
- Requirement-to-evidence mapping: pending implementation.
- Skipped or blocked checks: none recorded at Draft time.
- Remaining limitations: implementation and requirement evidence are pending acceptance.
