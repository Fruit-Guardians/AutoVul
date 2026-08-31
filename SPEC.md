# AutoVul V2 Product Specification

- Status: Accepted baseline
- Version: 1.2
- Last updated: 2026-08-31

## 1. Purpose

AutoVul V2 MUST provide host-independent, structured and verifiable vulnerability-research capabilities to mature Agent/Harness hosts such as Pi Agent and DeepSeek Harness.

AutoVul V2 MUST NOT implement or position itself as a general Agent or general Agent Harness. The host owns model access, the Agent Loop, session context, planning, generic tools and user interaction. This project owns vulnerability-research domain contracts, deterministic analyzer execution, evidence, validation and replayable artifacts.

## 2. Scope

### 2.1 Current supported capabilities

- `REQ-SCOPE-001`: The system MUST accept a vulnerability description or patch description and a compatible CodeQL database.
- `REQ-SCOPE-002`: The system MUST support structured Source/Sink-oriented CodeQL query synthesis and verification for the language families represented by verified Language Packs.
- `REQ-SCOPE-003`: The system MUST expose the same deterministic Application behavior through Pi Extension and CLI adapters.
- `REQ-SCOPE-004`: The system MUST produce persisted run state and replayable Query Pack artifacts.
- `REQ-SCOPE-005`: The system MUST support verified MissingCheck v1 research for the frozen JavaScript direct-call/dominance case family through the aggregate research/run APIs, subject to its declared single-file named-entry completeness boundary and recorded limitations.

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

### 3.1 Research Capability architecture

- `REQ-ARCH-010`: A Research Capability MUST independently own its versioned Hypothesis Schema, Observation Schema, Decision Policy, diagnostic codes, Analyzer Port and success predicates. The shared runtime MUST NOT interpret Capability domain fields.
- `REQ-ARCH-011`: Capabilities MUST share deterministic run identity, idempotency, budget, timeout, cancellation, locks, recovery, artifacts, evidence references and replay. They MUST NOT share a universal Hypothesis IR, a large optional-field bag, or domain success predicates.
- `REQ-ARCH-012`: Before a second real Capability is accepted, composition MUST use explicit static Flow branches. The project MUST NOT introduce a Capability registry, dynamic loader, port factory, generic Capability base class or placeholder module.
- `REQ-ARCH-013`: Model content MUST remain a Hypothesis until a Capability validator accepts it. Analyzer adapters MUST return observations and capability gaps only; Core is the sole writer of the model-visible `decision` and `verification_level`.
- `REQ-ARCH-014`: Core MAY return structured, field-level revision hints. It MUST NOT generate a replacement Hypothesis, retain a host research plan, invoke a model or start an autonomous retry or revision loop.
- `REQ-ARCH-015`: A later Capability MUST have a real case Flow cannot honestly express, independent contracts and predicates, actionable diagnostics, fake-adapter failure coverage, a real-tool gate, a counter-example strategy and independently replayable artifacts before it is added or claimed as supported.

## 4. Workflow and contract requirements

- `REQ-WORKFLOW-001`: Model-provided data MUST be parsed through strict, versioned schemas before entering a deterministic workflow.
- `REQ-WORKFLOW-002`: A run MUST have a stable identifier, persisted manifest and bounded candidate/revision budget.
- `REQ-WORKFLOW-003`: Formal candidate verification MUST be serialized per case and MUST NOT allow a host to bypass the case budget by restarting an equivalent workflow.
- `REQ-WORKFLOW-004`: Long-running operations MUST support timeout and cancellation.
- `REQ-WORKFLOW-005`: A cancelled, timed-out or failed operation MUST preserve an accurate terminal or recoverable state and MUST NOT be recorded as success.
- `REQ-WORKFLOW-006`: A host session MUST NOT be the sole source of truth for workflow state.
- `REQ-WORKFLOW-007`: The aggregate research protocol MUST keep routing and execution fields separate from the opaque Capability Hypothesis. Its v1 research actions are `validate` and `execute`; its v1 run actions are `status`, `cancel` and `replay`.
- `REQ-WORKFLOW-008`: `validate` MUST be side-effect free. Invalid input MUST return bounded, structured issues with stable codes and JSON Pointer paths rather than prose-only constraints.
- `REQ-WORKFLOW-009`: A compact capability result MUST separately report `operation_status`, a Capability-discriminated `decision`, `verification_level`, bounded observations, revision hints, allowed next actions and an artifact reference. These dimensions MUST NOT be collapsed into one status.

## 5. CodeQL verification requirements

- `REQ-CODEQL-001`: Model-facing candidates SHOULD use structured query intent; language packs and renderers SHOULD own repeated QL boilerplate.
- `REQ-CODEQL-002`: Probe evidence MAY guide candidate construction but MUST NOT by itself prove end-to-end flow.
- `REQ-CODEQL-003`: LSP draft diagnostics are advisory; authoritative acceptance MUST depend on CodeQL CLI compile/analyze observations.
- `REQ-CODEQL-004`: Strict verification MUST preserve the expected Source and Sink semantics and locations.
- `REQ-CODEQL-005`: When a fixed database is supplied for differential verification, the fixed-side result MUST satisfy the declared validation policy.
- `REQ-CODEQL-006`: A finalized Query Pack MUST be independently replayable without a model and without reading mutable state from the originating run.

### 5.1 MissingCheck v1

- `REQ-MCHECK-ROOT-001`: MissingCheck v1 MUST remain an independent Research Capability for one protected direct call, one required direct check, and the closed `same_callback_cfg_dominates_operation` relation. It MUST NOT reuse Flow domain types or taint semantics.
- `REQ-MCHECK-ROOT-002`: Its hypothesis contract MUST be `autovul.missing-check/1` and MUST declare one `single_file_named_entry_cfg` scope containing a relative file and a `named_function` entry selector.
- `REQ-MCHECK-ROOT-003`: The CodeQL adapter MUST enforce both the declared file and named entry. An observation from only the same file, or from a different enclosing entry, MUST NOT satisfy the scope.
- `REQ-MCHECK-ROOT-004`: Analyzer observations MUST separately record operation/check states, relation witnesses, per-side completeness, known limitations, Analyzer/adapter provenance, evidence references, and capability gaps. The shared runtime MUST NOT interpret these fields.
- `REQ-MCHECK-ROOT-005`: Core MUST emit `check_missing` only from a persisted unchecked witness whose evidence reference resolves in the observation and whose vulnerable completeness boundary exactly equals the declared scope.
- `REQ-MCHECK-ROOT-006`: Core MUST emit `check_present` only from a persisted checked witness under the same exact completed boundary. A missing check match, empty result, incomplete analysis, or unresolved evidence reference MUST remain `unknown`.
- `REQ-MCHECK-ROOT-007`: Differential verification MUST require a reproduced vulnerable unchecked witness and a completed fixed-side checked witness under the same scope. Fixed-side `not_run`, failure, incomplete scope, capability gap, or missing evidence MUST NOT satisfy fixed policy.
- `REQ-MCHECK-ROOT-008`: Real verification levels MUST require `real_analyzer` provenance. A fake adapter, mock, diagnostic wrapper, or `test_double` observation MUST be capped at `generated` even when its synthetic decision fixture matches a higher-level policy.
- `REQ-MCHECK-ROOT-009`: A successful artifact MUST bind target references to observed portable database fingerprints, exact Analyzer and adapter versions, the Decision Policy version, and run-relative evidence references before the run becomes authoritative.
- `REQ-MCHECK-ROOT-010`: MissingCheck replay MUST revalidate portable target fingerprints and exact Analyzer/adapter versions before preserving a verification level. It MUST distinguish fingerprint absence/difference, Analyzer version absence/difference, environment block, cancellation, and semantic mismatch.
- `REQ-MCHECK-ROOT-011`: The verified Golden MUST retain immutable target revisions and source hashes, query and evidence hashes, compact ordered results, completeness boundaries, provenance, and a fresh-process model-free replay result. External dependencies MUST be explicit.
- `REQ-MCHECK-ROOT-012`: MissingCheck MUST remain reachable only through aggregate `autovul_research` and `autovul_run` APIs. The host retains capability selection, hypothesis creation/revision, and stopping authority.

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
- `REQ-ARTIFACT-005`: A committed capability artifact MUST record the Capability and contract version, normalized Hypothesis, targets, Analyzer provenance, budget/mode/idempotency identity, structured Observation, Decision Policy version, Decision, verification level and replay inputs or explicit external dependencies.
- `REQ-ARTIFACT-006`: Critical evidence MUST be durably committed before authoritative state references it. Recovery MUST use validated artifacts and commit metadata; corrupt data MUST block or fail rather than being reconstructed as success.
- `REQ-ARTIFACT-007`: Replay MUST not require a model, host session or mutable originating-run state, and MUST distinguish identical results, environment blocks, Analyzer-version differences and semantic mismatches.

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
- `REQ-INTEGRATION-006`: The target model-facing research interface MUST contain only `autovul_research` and `autovul_run`. Compatibility `codeql_*` tools MAY remain available but MUST NOT be presented as a third primary research interface.
- `REQ-INTEGRATION-007`: Pi and CLI MUST route those aggregate entries through the same Application API and remain thin registration, conversion, cancellation and presentation layers.

## 10. Compatibility and current limitations

- `REQ-COMPAT-001`: Changes to public schemas, artifacts or Application APIs MUST document compatibility and migration behavior.
- `REQ-COMPAT-002`: Current accepted platform behavior is the tested POSIX/macOS path. Windows support MUST NOT be claimed until process-tree cleanup, paths and CI gates are implemented and verified.
- `REQ-COMPAT-003`: Current database operations are inspection and validation. Automatic database creation or execution of target build scripts MUST NOT be claimed as implemented.
- `REQ-COMPAT-004`: The Python V1 runtime is outside this isolated TypeScript workspace and MUST NOT be silently imported as a V2 dependency.
- `REQ-COMPAT-005`: Flow is the first architecture Capability, but it MUST NOT be documented as supported until its own accepted change SPEC is Verified by its real Analyzer, Golden, differential and replay gates.

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
