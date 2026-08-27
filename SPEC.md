# PureAutoCodeQL V2 Product Specification

- Status: Accepted baseline
- Version: 1.0
- Last updated: 2026-08-27

## 1. Purpose

PureAutoCodeQL V2 MUST provide host-independent, structured and verifiable vulnerability-research capabilities to mature Agent/Harness hosts such as Pi Agent and DeepSeek Harness.

PureAutoCodeQL V2 MUST NOT implement or position itself as a general Agent or general Agent Harness. The host owns model access, the Agent Loop, session context, planning, generic tools and user interaction. This project owns vulnerability-research domain contracts, deterministic analyzer execution, evidence, validation and replayable artifacts.

## 2. Scope

### 2.1 Current supported capability

- `REQ-SCOPE-001`: The system MUST accept a vulnerability description or patch description and a compatible CodeQL database.
- `REQ-SCOPE-002`: The system MUST support structured Source/Sink-oriented CodeQL query synthesis and verification for the language families represented by verified Language Packs.
- `REQ-SCOPE-003`: The system MUST expose the same deterministic Application behavior through Pi Extension and CLI adapters.
- `REQ-SCOPE-004`: The system MUST produce persisted run state and replayable Query Pack artifacts.

### 2.2 Extensible product direction

- `REQ-SCOPE-010`: New vulnerability-research capabilities MAY be added as domain contracts, Core ports, Analyzers/Runners and thin host integrations.
- `REQ-SCOPE-011`: Future capabilities MAY include patch analysis, dependency intelligence, additional static analyzers, dynamic reproduction and variant discovery.
- `REQ-SCOPE-012`: A new capability MUST define structured evidence and an observable verification gate before being presented as supported.

### 2.3 Non-goals

- `REQ-NONGOAL-001`: The project MUST NOT provide its own general model-provider framework or Agent Loop.
- `REQ-NONGOAL-002`: The project MUST NOT implement general conversation memory, context compression, planning or subagent orchestration.
- `REQ-NONGOAL-003`: The project MUST NOT duplicate generic filesystem, Shell, browser or Web tools supplied by the host unless a security-specific adapter requires deterministic policy enforcement.
- `REQ-NONGOAL-004`: The deterministic CLI MUST remain a debugging, CI and replay interface; it MUST NOT evolve into an independent general Agent.

## 3. Architecture requirements

- `REQ-ARCH-001`: Production dependencies MUST follow `contracts <- core <- analyzers/runners <- integrations`.
- `REQ-ARCH-002`: Contracts MUST NOT depend on host SDKs, UI, filesystem, processes, databases, model providers or concrete analyzers.
- `REQ-ARCH-003`: Core MUST contain deterministic domain policy, workflow state, budgets and acceptance decisions, and MUST access external capabilities through Ports.
- `REQ-ARCH-004`: Analyzers/Runners MUST own external tool protocols, process invocation and output decoding, but MUST NOT independently redefine product success.
- `REQ-ARCH-005`: Host integrations MUST remain thin and MUST use the shared Application API rather than duplicate workflow logic.
- `REQ-ARCH-006`: Host-specific prompts, UI types and lifecycle APIs MUST NOT leak into Core.

## 4. Workflow and contract requirements

- `REQ-WORKFLOW-001`: Model-provided data MUST be parsed through strict, versioned schemas before entering a deterministic workflow.
- `REQ-WORKFLOW-002`: A run MUST have a stable identifier, persisted manifest and bounded candidate/revision budget.
- `REQ-WORKFLOW-003`: Formal candidate verification MUST be serialized per case and MUST NOT allow a host to bypass the case budget by restarting an equivalent workflow.
- `REQ-WORKFLOW-004`: Long-running operations MUST support timeout and cancellation.
- `REQ-WORKFLOW-005`: A cancelled, timed-out or failed operation MUST preserve an accurate terminal or recoverable state and MUST NOT be recorded as success.
- `REQ-WORKFLOW-006`: A host session MUST NOT be the sole source of truth for workflow state.

## 5. CodeQL verification requirements

- `REQ-CODEQL-001`: Model-facing candidates SHOULD use structured query intent; language packs and renderers SHOULD own repeated QL boilerplate.
- `REQ-CODEQL-002`: Probe evidence MAY guide candidate construction but MUST NOT by itself prove end-to-end flow.
- `REQ-CODEQL-003`: LSP draft diagnostics are advisory; authoritative acceptance MUST depend on CodeQL CLI compile/analyze observations.
- `REQ-CODEQL-004`: Strict verification MUST preserve the expected Source and Sink semantics and locations.
- `REQ-CODEQL-005`: When a fixed database is supplied for differential verification, the fixed-side result MUST satisfy the declared validation policy.
- `REQ-CODEQL-006`: A finalized Query Pack MUST be independently replayable without a model and without reading mutable state from the originating run.

## 6. Evidence and result levels

- `REQ-EVIDENCE-001`: Model output MUST be treated as a hypothesis rather than evidence.
- `REQ-EVIDENCE-002`: The system MUST distinguish the following result levels:
  - `generated`: a candidate exists but has not passed execution verification.
  - `compiled`: the analyzer accepted the rule, but the target vulnerability has not been reproduced.
  - `reproduced`: the vulnerable target produced the expected result or behavior.
  - `differential`: the vulnerable target matched and the fixed target satisfied the non-match policy.
  - `variant_validated`: additional positive, negative or cross-project validation passed.
- `REQ-EVIDENCE-003`: Mocks, fake runners, diagnostic wrappers and copied reference queries MUST NOT be presented as real vulnerability evidence.
- `REQ-EVIDENCE-004`: Negative results and failures MUST retain their stage, structured diagnostic, retryability and relevant reproducible inputs.
- `REQ-EVIDENCE-005`: Claims in UI, reports and documentation MUST NOT exceed the recorded verification level.

## 7. Artifact and replay requirements

- `REQ-ARTIFACT-001`: Run manifests and critical artifacts MUST be written atomically.
- `REQ-ARTIFACT-002`: Artifacts MUST record enough version, input, diagnostic and command information to reproduce the accepted deterministic steps.
- `REQ-ARTIFACT-003`: Artifact paths intended for replay MUST be relocatable or explicitly declare non-relocatable dependencies.
- `REQ-ARTIFACT-004`: Logs and artifacts MUST NOT persist recognized credentials or unrestricted sensitive environment data.

## 8. Safety and reliability requirements

- `REQ-SAFETY-001`: Filesystem paths MUST be canonicalized and constrained to configured workspace or trusted roots.
- `REQ-SAFETY-002`: Symlink escape and unintended overwrite MUST be rejected.
- `REQ-SAFETY-003`: The system MUST NOT automatically execute target build, install or other high-risk scripts without explicit host/user approval and an accepted policy path.
- `REQ-SAFETY-004`: Spawned process trees MUST be cleaned up after success, failure, timeout, cancellation and application close.
- `REQ-SAFETY-005`: Retries MUST be limited to classified retryable failures; syntax errors, invalid hypotheses and policy rejection MUST NOT be blindly retried.
- `REQ-SAFETY-006`: Output size, execution time, candidate count, revision count and concurrency MUST be bounded.

## 9. Integration requirements

- `REQ-INTEGRATION-001`: Model-visible tools SHOULD be few, stable and domain-oriented.
- `REQ-INTEGRATION-002`: Tool inputs and outputs MUST use versioned schemas; prose MUST NOT substitute for required structured fields.
- `REQ-INTEGRATION-003`: Integrations SHOULD return compact model-consumable feedback while preserving full evidence in artifacts.
- `REQ-INTEGRATION-004`: Adding a host integration MUST NOT require changing Core domain behavior.
- `REQ-INTEGRATION-005`: Pi is the currently implemented native host integration. DeepSeek Harness and MCP are product directions, not implemented support claims until their own accepted change SPEC and verification gates pass.

## 10. Compatibility and current limitations

- `REQ-COMPAT-001`: Changes to public schemas, artifacts or Application APIs MUST document compatibility and migration behavior.
- `REQ-COMPAT-002`: Current accepted platform behavior is the tested POSIX/macOS path. Windows support MUST NOT be claimed until process-tree cleanup, paths and CI gates are implemented and verified.
- `REQ-COMPAT-003`: Current database operations are inspection and validation. Automatic database creation or execution of target build scripts MUST NOT be claimed as implemented.
- `REQ-COMPAT-004`: The Python V1 runtime is outside this isolated TypeScript workspace and MUST NOT be silently imported as a V2 dependency.

## 11. Baseline acceptance gates

The baseline is conformant only when:

1. `npm run typecheck` passes.
2. Dependency-direction checks pass.
3. Unit and integration tests pass.
4. Package dry-run succeeds.
5. Behavior-specific real CodeQL, Golden, differential and replay gates pass when a claim depends on them.
6. Skipped real-tool or real-model checks are explicitly reported and are not converted into success claims.

## 12. Change control

Material behavior changes MUST follow [specs/README.md](./specs/README.md) and use [specs/changes/TEMPLATE.md](./specs/changes/TEMPLATE.md). Once verified, stable requirements MUST be merged into this root specification without deleting the historical change record.
