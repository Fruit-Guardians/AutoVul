# Change: Introduce Flow Capability v1

- Change ID: `introduce-flow-capability-v1`
- Status: Implemented
- Owner: AutoVul maintainers
- Created: 2026-08-28
- Updated: 2026-08-28

## Problem

AutoVul currently exposes a verified CodeQL workflow built around `TaintQueryIntent`, CodeQL-specific tools and Query Pack artifacts. That workflow can compile and verify Source/Sink-oriented queries, but it does not yet provide the planned Agent-facing Flow capability contract:

- the hypothesis is coupled to CodeQL presentation fields and current workflow inputs;
- validation and execution are not exposed through the planned research-level aggregate entry point;
- a no-flow result does not have a stable, compact contract that distinguishes missing Source, missing Sink, observed endpoints without a path and unsupported semantics;
- Analyzer observations and the Flow decision are not modeled as separate public results;
- future research capabilities need a minimal routing envelope, but the first implementation must not create a generic Capability framework before a second real paradigm exists.

The project-level design baseline defines parallel research capabilities over one deterministic runtime. This change implements only the first member of that design: `capability: "flow"` backed by CodeQL and the existing run, evidence and replay machinery.

## Host boundary

This capability belongs in AutoVul because versioned Flow semantics, deterministic Analyzer execution, structured no-flow observations, evidence grading and replay are vulnerability-research responsibilities.

The host Agent or Harness continues to own:

- reading code, patches and vulnerability descriptions;
- choosing Flow rather than another research paradigm;
- creating and revising the Flow hypothesis;
- selecting targets and deciding whether to execute, replay, change direction or stop;
- model access, prompts, session context, planning and generic tools;
- final human-facing explanation and report composition.

AutoVul MUST NOT generate the next complete hypothesis, start an autonomous revision loop, select an open-ended research goal or write a narrative Finding.

## Scope

### In scope

- Add the minimal `capability` and `hypothesis_version` routing envelope with `flow` as the only accepted capability.
- Add `autovul_research` validation and execution behavior for Flow.
- Project Flow runs through the existing run, budget, timeout, cancellation, lock, recovery, evidence and replay infrastructure.
- Define FlowModel v1, Flow validation issues, Flow Analyzer observations, Flow decisions and revision hints.
- Keep `probe`, `reproduce` and `differential` as shared evidence-operation modes.
- Implement one Flow execution port with a CodeQL adapter and an explicit unavailable adapter.
- Preserve the Flow semantics of `TaintQueryIntent` through a lossless compatibility mapping.
- Project the existing `codeql_*` interfaces onto the same domain path without removing or changing their accepted behavior.
- Preserve existing CodeQL database inspection, Golden, differential and Query Pack replay behavior.

### Non-goals

- A Capability registry, plugin loader, port factory or generic Capability base class.
- A general Hypothesis IR or fields shared across Flow, MissingCheck, Typestate, Delta and Variant.
- Any second research paradigm, placeholder Schema or empty module for a future capability.
- Dynamic Analyzer discovery, automatic Analyzer selection or capability negotiation.
- Reworking `codeql_database`, creating CodeQL databases or running target build/install scripts.
- Removing, renaming or changing the meaning of `codeql_database`, `codeql_workflow` or `codeql_query`.
- A general Summary DSL, Model Pack inheritance, multi-label taint, multi-endpoint aggregation, Patch Delta or Variant Search.
- A Finding object, WP generator, audit report or other human-facing narrative model.
- A new run state machine, `FlowRun` persistence model or case-level Agent plan.
- A new host integration or a claim that DeepSeek Harness or MCP support is implemented.

## Definitions

- **Routing envelope**: the minimal `capability` and `hypothesis_version` fields used to select a versioned Capability contract. It contains no research semantics.
- **FlowModel**: a versioned, Analyzer-independent hypothesis describing one Source, one Sink, optional directed flow steps and optional barriers.
- **Evidence-operation mode**: one of `probe`, `reproduce` or `differential`; it describes the requested evidence strength and never carries a Flow-specific verb.
- **Flow observation**: a structured fact returned by the Flow Analyzer port, including endpoint observations, path observation and capability gaps.
- **Flow decision**: the deterministic Core result derived from Flow observations. It is stored in the shared result field `decision`; no parallel `flow_status` field exists.
- **Envelope action**: a protocol-level next action from the closed set `revise`, `execute`, `replay`, `stop`.
- **Revision hint**: a Flow-specific, evidence-backed action with a hypothesis field path, stable reason code and optional constraints. It never contains a complete replacement FlowModel.
- **Compatibility projection**: a deterministic mapping between the accepted CodeQL workflow contracts and the Flow v1 domain path that preserves existing observable behavior.

## Requirements

### Narrow architecture boundary

- `REQ-FLOWV1-001`: The new research request envelope MUST accept exactly `capability: "flow"` in v1.
- `REQ-FLOWV1-002`: The shared request envelope MUST contain only routing, contract-version and operation fields; it MUST NOT contain Source, Sink, Guard, State, Delta or other research semantics.
- `REQ-FLOWV1-003`: The implementation MUST use explicit static composition for Flow and MUST NOT add a Capability registry, dynamic plugin loader, port factory or generic Capability base class.
- `REQ-FLOWV1-004`: The implementation MUST NOT add a second Capability Schema, placeholder module or future-capability stub.
- `REQ-FLOWV1-005`: Flow MUST use the existing shared run, budget, timeout, cancellation, lock, recovery, artifact and replay infrastructure rather than a new `FlowRun` system.
- `REQ-FLOWV1-006`: The host MUST retain hypothesis generation, revision, action selection and stopping authority.
- `REQ-FLOWV1-007`: Core MUST NOT call a model, generate a replacement FlowModel, start an autonomous retry loop or persist an Agent research plan.
- `REQ-FLOWV1-008`: Contracts and Core MUST remain free of Pi, DeepSeek Harness, MCP, model-provider and UI types.
- `REQ-FLOWV1-009`: This change MUST NOT claim a second Analyzer, second research paradigm or new host integration.

### Aggregate Application interface

- `REQ-FLOWV1-010`: The target model-facing interface MUST expose Flow validation and execution through the aggregate `autovul_research` entry point.
- `REQ-FLOWV1-011`: `autovul_research` MUST accept only the actions `validate` and `execute` in v1.
- `REQ-FLOWV1-012`: `validate` MUST be side-effect free, MUST NOT create a run and MUST NOT invoke an Analyzer.
- `REQ-FLOWV1-013`: `execute` MUST create or idempotently resume exactly one bounded operation in the existing run system.
- `REQ-FLOWV1-013A`: Reusing an idempotency key with a request whose normalized Hypothesis, target, mode, expectation or budget differs from the committed operation MUST fail with the non-retryable stable error code `IDEMPOTENCY_KEY_CONFLICT`; it MUST NOT silently reuse or overwrite evidence.
- `REQ-FLOWV1-014`: Run inspection, cancellation and replay MUST remain under the aggregate `autovul_run` entry point with the actions `status`, `cancel` and `replay`.
- `REQ-FLOWV1-015`: Model-visible `allowed_next_actions` MUST be a subset of the closed envelope set `revise`, `execute`, `replay`, `stop`.
- `REQ-FLOWV1-016`: Flow-specific verbs MUST NOT be added to `allowed_next_actions`; they MAY appear only as `revision_hints[].action` values.
- `REQ-FLOWV1-017`: Every model-visible business field MUST support routing, revision, execution, evidence grading, replay or stopping; all other detail MUST be stored in artifacts.
- `REQ-FLOWV1-018`: Model-visible results MUST NOT contain a narrative Finding, report paragraph, WP section or free-form recommendation as a substitute for structured fields.
- `REQ-FLOWV1-019`: The current `codeql_database`, `codeql_workflow` and `codeql_query` tools MUST remain accessible as a compatibility surface, but a Flow-capable host profile MUST NOT present them as a third primary research interface beside `autovul_research` and `autovul_run`.

### FlowModel v1 contract

- `REQ-FLOWV1-020`: FlowModel MUST use the literal contract version `autovul.flow/1` and a stable `model_id`.
- `REQ-FLOWV1-021`: FlowModel MUST contain `language`, `flow_mode`, exactly one `source`, exactly one `sink`, optional `steps` and optional `barriers`.
- `REQ-FLOWV1-022`: `language` MUST initially use the already accepted and verified language-family set; this change MUST NOT add a language-support claim.
- `REQ-FLOWV1-023`: `flow_mode` MUST be the closed set `taint` or `value`.
- `REQ-FLOWV1-024`: FlowEndpoint v1 MUST preserve the currently accepted semantic matcher kinds: `call`, `call_argument`, `constructor`, `function`, `parameter`, `environment`, `property`, `array_index` and `array_element`.
- `REQ-FLOWV1-025`: FlowEndpoint v1 MUST preserve the current symbol, argument, keyword, property and location selectors needed for lossless `TaintQueryIntent` compatibility.
- `REQ-FLOWV1-026`: Each Flow step MUST be a directed `from`/`to` pair of Flow endpoints; each barrier MUST identify the Flow endpoint semantics it blocks.
- `REQ-FLOWV1-027`: FlowModel MUST NOT contain target paths, CodeQL database references, Analyzer ids, budgets, timeout, verification policy, CWE, message, rationale, evidence refs or host presentation fields.
- `REQ-FLOWV1-028`: Endpoint, step and barrier kinds MUST be justified by Flow research semantics and MUST NOT expose QL syntax or CodeQL SDK types.
- `REQ-FLOWV1-029`: v1 MUST NOT add multi-source, multi-sink, case aggregation, inheritance or generic extension-property semantics.

### Validation contract

- `REQ-FLOWV1-030`: Boundary input MUST be treated as `unknown` and parsed into either one normalized FlowModel or a bounded list of Flow validation issues.
- `REQ-FLOWV1-031`: The public contract MUST NOT export a separate `FlowModelDraft` domain type.
- `REQ-FLOWV1-032`: Every Flow validation issue MUST contain a stable `code` and JSON Pointer `path`.
- `REQ-FLOWV1-033`: A validation issue MUST include `allowed_values` when the repair is constrained to a closed set and MAY include a stable `expected_kind` for type mismatches.
- `REQ-FLOWV1-034`: Free-form prose MUST NOT substitute for `code`, `path`, `allowed_values` or `expected_kind`.
- `REQ-FLOWV1-035`: Validation MUST reject unknown properties, invalid discriminants, missing endpoint selectors, invalid argument positions, invalid location ranges and unsupported endpoint combinations.
- `REQ-FLOWV1-036`: A valid result MUST return the normalized FlowModel and `allowed_next_actions` drawn only from the envelope action set.
- `REQ-FLOWV1-037`: An invalid result MUST NOT create run state, Analyzer evidence or a verification level.
- `REQ-FLOWV1-038`: Validation MUST be deterministic for the same contract version and input.
- `REQ-FLOWV1-039`: FlowExpectation MUST contain bounded vulnerable-side minimum and maximum path counts and, for `differential`, bounded fixed-side minimum and maximum path counts; the vulnerable minimum MUST be at least one, each maximum MUST be greater than or equal to its minimum, and Source, Sink and location expectations MUST remain in FlowModel rather than being duplicated in the execution policy.

### Execution request and evidence modes

- `REQ-FLOWV1-040`: ExecuteFlowRequest MUST keep the FlowModel separate from `target`, `analyzer_id`, `mode`, `expectation`, `budget` and `idempotency_key`; TargetRef v1 MUST be the explicit `codeql_database` kind with a path and optional expected fingerprint.
- `REQ-FLOWV1-041`: `mode` MUST be the closed evidence-operation set `probe`, `reproduce`, `differential`.
- `REQ-FLOWV1-042`: Flow-specific actions such as revising a barrier or probing a particular declared endpoint MUST NOT extend the shared `mode` enum.
- `REQ-FLOWV1-043`: `probe` MUST inspect declared endpoint semantics and capability support without claiming end-to-end reproduction and MUST NOT require a FlowExpectation.
- `REQ-FLOWV1-044`: `reproduce` MUST execute the Flow hypothesis against one vulnerable target, MUST require a vulnerable-side FlowExpectation and MUST NOT require a fixed-side expectation.
- `REQ-FLOWV1-045`: `differential` MUST require vulnerable and fixed targets, MUST require vulnerable-side and fixed-side FlowExpectation ranges and MUST apply the declared fixed-side policy.
- `REQ-FLOWV1-046`: `analyzer_id` MUST be explicit and MUST accept only `codeql` in v1.
- `REQ-FLOWV1-047`: Missing or unavailable CodeQL MUST leave `validate` usable and MUST return a structured blocked execution without fake observations or success.
- `REQ-FLOWV1-048`: The CodeQL adapter MUST validate referenced databases as execution prerequisites and MUST return an actionable, structured blocked result when a database is unavailable, invalid, language-incompatible or outside trusted roots.
- `REQ-FLOWV1-049`: Database preflight inside `execute` MUST NOT become a new research action or replace the existing `codeql_database` compatibility tool.

### Observation and decision boundary

- `REQ-FLOWV1-050`: FlowExecutionPort MUST return observations and capability gaps only; it MUST NOT return a Flow decision or verification level.
- `REQ-FLOWV1-051`: Flow Analyzer observations MUST separately represent compile acceptance, Source observation, Sink observation, path observation, capability gaps, evidence refs and Analyzer provenance.
- `REQ-FLOWV1-052`: Source and Sink observation states MUST distinguish `observed`, `not_found` and `not_run` and MUST retain bounded location references when observed.
- `REQ-FLOWV1-053`: Path observation MUST distinguish `observed`, `not_observed` and `not_run`.
- `REQ-FLOWV1-054`: Unsupported endpoint, step or barrier semantics MUST produce `capability_mismatch`; an Adapter MUST NOT ignore, weaken or guess unsupported semantics.
- `REQ-FLOWV1-055`: Core MUST be the sole writer of the model-visible `decision` and `verification_level` fields.
- `REQ-FLOWV1-056`: Flow decision MUST be represented only under `decision` with `capability: "flow"` and `outcome: "connected" | "no_path" | "unknown"`; the result MUST NOT add `flow_status` or another parallel Flow verdict field.
- `REQ-FLOWV1-057`: A differential result MAY include the fixed-side Flow outcome and policy satisfaction inside the same Flow decision object; it MUST NOT introduce a second top-level verdict.
- `REQ-FLOWV1-058`: Core MUST derive the Flow decision deterministically from the normalized observation and declared expectation.
- `REQ-FLOWV1-059`: `operation_status` MUST be the closed set `completed`, `blocked`, `failed`, `cancelled`; failure, cancellation, timeout and capability blocking MUST remain distinct from a completed `no_path` decision.

### Actionable no-flow feedback

- `REQ-FLOWV1-060`: A completed execution without an observed path MUST let the host distinguish Source not found, Sink not found, both endpoints observed without a path and capability mismatch without opening SARIF.
- `REQ-FLOWV1-061`: Compact observations MUST use stable codes and bounded location or artifact references rather than narrative advice.
- `REQ-FLOWV1-062`: `missing_summary`, `barrier_too_wide` and `context_mismatch` MUST remain hypotheses unless an Analyzer provides explicit trace evidence for the corresponding fact.
- `REQ-FLOWV1-063`: `frontier_observed` MUST NOT be emitted without an Analyzer trace or equivalent persisted tool evidence.
- `REQ-FLOWV1-064`: Each revision hint MUST contain a Flow-specific `action`, hypothesis JSON Pointer `path`, stable `reason_code` and optional structured `constraints`.
- `REQ-FLOWV1-065`: Flow v1 revision-hint actions MUST be exactly `revise_source`, `revise_sink`, `revise_step`, `revise_barrier`, `probe_source`, `probe_sink` and MUST remain separate from envelope actions.
- `REQ-FLOWV1-066`: A revision hint MUST be supported by a returned observation or an evidence ref and MUST NOT contain a complete replacement FlowModel.
- `REQ-FLOWV1-067`: Core MUST NOT automatically apply a revision hint or execute a revised hypothesis.
- `REQ-FLOWV1-068`: Full SARIF, command output, traces and large location sets MUST remain in artifacts and MUST be reachable through `artifact_ref` or evidence refs.

### Verification semantics

- `REQ-FLOWV1-070`: Flow v1 MUST reuse the accepted verification levels `generated`, `compiled`, `reproduced`, `differential` and `variant_validated` as evidence-strength labels without redefining their baseline meaning.
- `REQ-FLOWV1-071`: `probe` MUST NOT produce `reproduced`, `differential` or `variant_validated` solely from endpoint observations.
- `REQ-FLOWV1-072`: A reproduced result MUST require an observed vulnerable-side path that satisfies the declared Source, Sink and location expectations.
- `REQ-FLOWV1-073`: Compile acceptance without a qualifying path MUST NOT exceed `compiled`.
- `REQ-FLOWV1-074`: A differential result MUST require the vulnerable-side reproduction predicate and the fixed-side policy to both pass.
- `REQ-FLOWV1-075`: A fixed-side policy failure MUST prevent `differential` and MUST remain visible as structured observation and decision data.
- `REQ-FLOWV1-076`: Failed, blocked, cancelled or timed-out execution MUST NOT raise the verification level beyond evidence actually committed before that terminal state.
- `REQ-FLOWV1-077`: Flow v1 MUST NOT newly produce `variant_validated`; that level remains readable for compatibility and future separately accepted capabilities.
- `REQ-FLOWV1-078`: Fake adapters and unit tests MAY verify state and decision mapping but MUST NOT count as real Flow reproduction evidence.

### CodeQL and legacy compatibility

- `REQ-FLOWV1-080`: The existing public `TaintQueryIntent` Schema and accepted behavior MUST remain available during this change.
- `REQ-FLOWV1-081`: The compatibility mapping MUST preserve all accepted Flow semantics from `TaintQueryIntent`, including language, flow mode, endpoint kinds and selectors, location constraints, additional flow edges and sanitizers.
- `REQ-FLOWV1-082`: Legacy `additional_flow` self-edge semantics MUST have a deterministic, lossless Flow step representation.
- `REQ-FLOWV1-083`: `cwe`, `message`, `description`, `rationale`, `evidence_refs`, presentation metadata and other non-Flow legacy fields MUST remain in the compatibility context or artifacts and MUST NOT enter FlowModel.
- `REQ-FLOWV1-084`: A legacy field that cannot be mapped without semantic loss MUST produce an explicit compatibility error; it MUST NOT be dropped, guessed or silently weakened.
- `REQ-FLOWV1-085`: Existing `codeql_*` operations MUST project onto the same Flow validation, observation and decision policies once the new path is enabled; the implementation MUST NOT retain a second conflicting success policy.
- `REQ-FLOWV1-086`: Existing Pi tool inputs, CLI commands and structured outputs MUST remain compatible unless a later accepted migration SPEC changes them.
- `REQ-FLOWV1-087`: Existing Query Packs, stable CodeQL rule ids, Golden fixtures and historical artifacts MUST remain readable and replayable without user migration.
- `REQ-FLOWV1-088`: Existing Source/Sink probes, strict endpoint checks, vulnerable/fixed policies and independent relocated replay MUST retain their accepted semantics.

### Run, artifact and safety behavior

- `REQ-FLOWV1-090`: A Flow execution MUST be a projection of the existing authoritative run and workflow state; it MUST NOT create a parallel persisted state machine.
- `REQ-FLOWV1-091`: A committed Flow artifact MUST record the capability, hypothesis version, normalized FlowModel, target refs, Analyzer provenance, mode, budget identity, observations, decision-policy version, decision, verification level and evidence refs.
- `REQ-FLOWV1-092`: Critical Flow evidence and artifacts MUST be durable before authoritative state references the corresponding decision or verification level.
- `REQ-FLOWV1-093`: Replay MUST execute without a model, host session or mutable state from the originating run.
- `REQ-FLOWV1-094`: Timeout, cancellation, idempotency, lock and recovery behavior MUST use the accepted shared workflow semantics.
- `REQ-FLOWV1-095`: Paths MUST be canonicalized and constrained to configured workspace or trusted roots, including database preflight, evidence access and replay.
- `REQ-FLOWV1-096`: The capability MUST NOT execute target build, install or other high-risk scripts.
- `REQ-FLOWV1-097`: Output size, execution time, revisions, concurrent execution and stored observation counts MUST remain bounded.
- `REQ-FLOWV1-098`: Logs and artifacts MUST sanitize recognized credentials and MUST NOT persist unrestricted environment data or model prompts.
- `REQ-FLOWV1-099`: Retry MUST remain limited to classified retryable failures and MUST NOT blindly repeat invalid hypotheses, semantic mismatches or policy failures.

## Proposed behavior

### Validation

```text
autovul_research
  action: validate
  capability: flow
  hypothesis_version: autovul.flow/1
  hypothesis: unknown
```

Valid input returns the normalized FlowModel and an allowed envelope-action subset. Invalid input returns bounded field issues and does not create a run.

```json
{
  "valid": false,
  "issues": [
    {
      "code": "FLOW_ENDPOINT_POSITION_REQUIRED",
      "path": "/sink/argument_index",
      "allowed_values": [0, 1, 2]
    }
  ],
  "allowed_next_actions": ["revise", "stop"]
}
```

### Execution

```text
autovul_research
  action: execute
  capability: flow
  hypothesis_version: autovul.flow/1
  hypothesis: FlowModel
  target:
    vulnerable: TargetRef
    fixed?: TargetRef
  analyzer_id: codeql
  mode: probe | reproduce | differential
  expectation?: FlowExpectation
  budget: OperationBudget
  idempotency_key: string
```

TargetRef v1 is deliberately Analyzer-specific and narrow:

```text
TargetRef
  kind: codeql_database
  path
  expected_fingerprint?
```

FlowExpectation contains only path-count policy:

```text
FlowExpectation
  vulnerable:
    min_paths: integer >= 1
    max_paths: bounded integer >= min_paths
  fixed?:
    min_paths: integer >= 0
    max_paths: bounded integer >= min_paths
```

`probe` omits FlowExpectation. `reproduce` requires only `vulnerable`. `differential` requires both sections. The FlowModel itself remains the Source, Sink and location expectation.

The Application validates the envelope and FlowModel, admits or resumes the operation in the existing run system, validates CodeQL and database prerequisites, calls the Flow execution port, persists observations, lets Core derive the decision and evidence level, commits the result, and returns a compact projection.

```text
ResearchExecutionResult
  schema_version
  run_id
  operation_status: completed | blocked | failed | cancelled
  capability: flow
  decision:
    capability: flow
    outcome: connected | no_path | unknown
    fixed_outcome?: connected | no_path | unknown
    fixed_policy_satisfied?: boolean
  verification_level
  observations[]
  revision_hints[]
  allowed_next_actions[]
  budget_remaining?
  artifact_ref
```

`decision` is mandatory for a completed Analyzer operation. A blocked or failed precondition returns `outcome: unknown` with a stable structured reason. `operation_status` remains the source of truth for whether the operation completed.

### No-flow result

The minimum completed no-flow observations are:

```text
SOURCE_OBSERVED | SOURCE_NOT_FOUND | SOURCE_NOT_RUN
SINK_OBSERVED   | SINK_NOT_FOUND   | SINK_NOT_RUN
PATH_OBSERVED   | PATH_NOT_OBSERVED | PATH_NOT_RUN
CAPABILITY_MISMATCH?
```

When both endpoints are observed and no path is observed, the compact result also includes `ENDPOINTS_OBSERVED_WITHOUT_PATH`. This is an observation summary, not proof that a Summary or Barrier is wrong.

### Database prerequisites

`codeql_database` remains the compatibility interface for explicit environment and database inspection. Flow `execute` independently performs the minimum CodeQL database validation required for safe deterministic execution. A failed prerequisite blocks the operation with a stable code and artifact reference; it does not add a third research action and does not create a database.

### Outer actions and Flow hints

The result envelope only exposes:

```text
revise | execute | replay | stop
```

Flow-specific actions are versioned inside revision hints:

```text
revise_source
revise_sink
revise_step
revise_barrier
probe_source
probe_sink
```

This is the complete v1 list. A hint also identifies the hypothesis path and reason code, so the host can choose whether to revise, execute a probe or stop.

## Contracts and artifacts

### New public contracts

- `ResearchAction` v1 with `validate | execute`.
- `ResearchCapability` v1 with the single literal `flow`.
- `FlowModel` at `autovul.flow/1`.
- `FlowValidationIssue` and validation result.
- `ExecuteFlowRequest`.
- `TargetRef` v1 with the literal `codeql_database` kind.
- `FlowExpectation` with bounded vulnerable/fixed path counts.
- `FlowAnalyzerObservation`.
- `FlowDecision` nested under the shared `decision` result field.
- `FlowRevisionHint`.
- `ResearchExecutionResult` for `capability: flow`.
- `RunAction` with `status | cancel | replay` where not already represented by the Application API.

These contracts form one explicitly discriminated Flow branch. They MUST NOT be implemented as an open plugin registry or an untyped payload map.

### FlowModel compatibility shape

FlowEndpoint v1 carries the accepted `TaintMatcher` semantic kinds and the selector data required to preserve current behavior. `source_location` and `sink_location` map to the corresponding endpoint location constraints. `additional_flow_steps` map to directed Flow steps. Each legacy `additional_flow` item maps to a self-edge step. `sanitizer` maps to barriers.

Legacy presentation and research-context fields remain outside FlowModel. The compatibility adapter supplies any stable Query Pack metadata required by existing CodeQL interfaces.

### Flow run artifact

Flow execution adds a versioned capability artifact under the existing trusted run artifact root. Its concrete relative path is internal, but its schema and digest are versioned. The artifact is referenced by authoritative workflow state and by the compact `artifact_ref`.

Historical Query Pack and workflow schemas are not rewritten by this change.

## Architecture

```text
Pi / CLI compatibility adapters
  └─ Application API
       ├─ autovul_research
       │    └─ explicit capability === flow branch
       │         ├─ Flow validator
       │         ├─ Flow decision policy
       │         └─ FlowExecutionPort
       │              └─ CodeQL Flow adapter / unavailable adapter
       └─ autovul_run
            └─ existing run, cancellation and replay services

Existing codeql_* adapters
  └─ compatibility projection
       └─ same Flow validator / decision policy / CodeQL adapter path
```

- `@autovul/contracts` owns versioned Flow and aggregate-interface Schemas.
- `@autovul/core` owns Flow validation, compatibility mapping, decision policy and the single Flow execution port.
- `@autovul/codeql-runner` owns database prerequisite checks, CodeQL command construction, process execution, SARIF decoding and Flow observations.
- `@autovul/pi-extension` and `@autovul/cli` remain thin registration, conversion, cancellation and presentation adapters.
- The implementation uses a direct Flow branch. A registry, service locator or generic Capability inheritance hierarchy is prohibited by this change.

No new workspace package is required. A new package requires a separate dependency and publication justification.

## Safety and privacy

- Flow validation is pure and performs no filesystem or process access.
- Execute target paths and replay paths are canonicalized under trusted roots.
- Database preflight inspects existing databases only; it does not invoke extractors, build systems or installers.
- Timeout and cancellation terminate the complete CodeQL subprocess tree.
- Analyzer output, locations and diagnostics are bounded before they enter compact results or artifacts.
- Artifacts exclude prompts, unrestricted environment data and recognized credentials.
- Invalid Flow semantics, capability mismatch and fixed-policy failure are non-retryable unless the host supplies a revised request.
- Replay executes only the committed deterministic artifact and declared Analyzer prerequisites.

## Compatibility and migration

- Existing CodeQL public Schemas, Pi tools and CLI commands remain supported.
- Existing callers do not need to migrate during Flow v1 introduction.
- New aggregate interfaces are added alongside the compatibility surface, then compatibility operations project to the same Core policy.
- Existing run ids, case budgets, workflow phases and Query Pack identities remain authoritative.
- Existing artifacts remain readable; no bulk artifact rewrite is planned.
- Existing stable CodeQL rule ids are not renamed.
- Rollback can disable the new aggregate Flow entry point while leaving existing CodeQL tools and artifacts usable.
- Removal or deprecation of any `codeql_*` tool requires a later accepted migration SPEC and is not implied by this change.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-FLOWV1-001` through `REQ-FLOWV1-009` | Given the built production graph, when architecture checks inspect it, then only an explicit Flow branch exists and no registry, base class, second Capability or host dependency is present | Architecture tests and source review |
| `REQ-FLOWV1-010` through `REQ-FLOWV1-019` | Given Pi and CLI adapters, when the aggregate contract suite runs, then validate/execute and run actions have identical Core semantics while existing `codeql_*` tools remain available | Contract tests, adapter tests and Pi RPC E2E |
| `REQ-FLOWV1-020` through `REQ-FLOWV1-029` | Given valid and invalid Flow fixtures for every endpoint kind, when parsed, then valid models normalize deterministically and invalid or extra fields are rejected | Schema fixtures and property tests |
| `REQ-FLOWV1-030` through `REQ-FLOWV1-039` | Given common LLM-shaped mistakes and bounded path expectations, when validation runs, then issues contain stable code/path and required allowed values without creating a run | Unit tests and artifact-store call-count assertions |
| `REQ-FLOWV1-040` through `REQ-FLOWV1-049` | Given each evidence mode and CodeQL/database prerequisite state, when execute runs, then mode semantics remain fixed and unavailable prerequisites return blocked without database creation | Application integration tests and fake/unavailable adapter tests |
| `REQ-FLOWV1-050` through `REQ-FLOWV1-059` | Given a matrix of compile, endpoint, path, capability and terminal observations, when Core maps them, then exactly one Flow decision is returned under `decision` and the Adapter never supplies it | Pure decision-policy tests and port type tests |
| `REQ-FLOWV1-060` through `REQ-FLOWV1-068` | Given Source-missing, Sink-missing, endpoints-without-path and capability-mismatch fixtures, when compact results are returned, then the host can identify the next hypothesis field or stop without reading SARIF | Contract snapshots, host revision fixtures and optional approved-model evaluation |
| `REQ-FLOWV1-070` through `REQ-FLOWV1-078` | Given probe, compile-only, vulnerable path, fixed match/non-match and terminal failures, when decisions commit, then verification levels follow the accepted evidence rules | Unit policy matrix plus real CodeQL differential cases |
| `REQ-FLOWV1-080` through `REQ-FLOWV1-088` | Given every accepted `TaintQueryIntent` fixture and historical Query Pack, when projected and replayed, then Flow semantics, stable ids and results remain unchanged | Round-trip fixtures, existing test suite, real Golden and relocated replay |
| `REQ-FLOWV1-090` through `REQ-FLOWV1-099` | Given interruption, cancellation, retry, invalid paths and artifact-write failure, when Flow executes or recovers, then existing commit, safety and replay invariants remain true | Failure-injection, cross-process, trusted-root and replay tests |

The central Flow acceptance case is mandatory:

> Given an Analyzer-completed execution with no observed path, when the host receives the compact result, then it can distinguish Source missing, Sink missing, both endpoints observed without a path, or unsupported semantics and can select a structured next action without reading raw SARIF.

## Validation plan

- Focused unit tests:
  - routing envelope accepts only `flow`;
  - FlowModel endpoint, step, barrier and location validation;
  - validation issue code/path/allowed-values shapes;
  - closed envelope actions and separate Flow revision actions;
  - evidence mode semantics;
  - observation-to-decision and verification-level matrix;
  - `TaintQueryIntent` compatibility round trips.
- Failure injection:
  - unavailable CodeQL;
  - missing, invalid, wrong-language and untrusted database paths;
  - cancellation and timeout before and after Analyzer execution;
  - evidence write, authoritative commit and projection recovery failures.
- Real Analyzer/target:
  - CodeQL CLI compilation for the accepted language families;
  - the existing 20-case Python, JavaScript, Java and C/C++ Golden matrix through the Flow path;
  - Source and Sink probes with strict endpoint locations.
- Differential or negative sample:
  - vulnerable path plus fixed non-match;
  - fixed-side unexpected match;
  - Source absent;
  - Sink absent;
  - both endpoints present without a path;
  - unsupported Flow semantics.
- Independent replay:
  - relocated Query Pack verification without a model or originating run;
  - replay through `autovul_run` returns the same decision and evidence level or a structured environment block.
- Package/integration smoke:
  - `npm run check`;
  - Pi RPC E2E for new and compatibility tools;
  - CLI compatibility smoke;
  - clean package dry-run.
- Agent-facing evaluation:
  - deterministic host fixtures MUST prove that each no-flow result identifies an editable field or stop condition without SARIF;
  - an approved real-model revision evaluation SHOULD be recorded when its wrapper and credentials are available;
  - an unavailable real model is reported as BLOCKED and MUST NOT be converted into a model-success claim.

## Resolved design choices

- The first implementation uses a literal Flow branch rather than a Capability registry.
- Shared `mode` is limited to evidence operations; Flow actions live in revision hints.
- Envelope next actions and Flow revision actions are separate closed enums.
- Flow verdicts exist only under `decision`; `flow_status` is not introduced.
- `codeql_database` remains a compatibility tool, while Flow execute performs its own minimum Adapter prerequisite validation.
- MissingCheck, Typestate, Delta and Variant receive no Schema, module or placeholder in this change.
- Existing `TaintQueryIntent` remains public and maps losslessly to the Flow path.
- Human-facing Finding and report models remain outside Core.

## Delivery gate

This change was Accepted on 2026-08-28 by explicit user instruction to implement. Implementation may proceed within the stated scope and non-goals.

## Open questions

No product-level open question is intentionally deferred by this Draft. Review may still require narrowing individual field names or limits before acceptance; such edits must preserve the requirements and non-goals above.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-28 | Implement Flow as the first explicit Capability branch | It delivers the first research semantics without inventing a platform framework. |
| 2026-08-28 | Share only the routing and execution envelope | Domain predicates remain Capability-owned. |
| 2026-08-28 | Keep evidence modes separate from Flow actions | Shared operation strength remains stable across future paradigms. |
| 2026-08-28 | Use one top-level `decision` field | Parallel verdict fields would create conflicting sources of truth. |
| 2026-08-28 | Retain `codeql_database` as compatibility surface | Database inspection remains useful but is not a third primary research action. |
| 2026-08-28 | Require actionable no-flow feedback | Without it, Flow v1 would only rename the existing query intent. |

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: `npm run typecheck`, `npm run lint`, focused Flow architecture/decision/Pi tests, and the baseline package checks passed during implementation. The real Flow-specific analyzer suite has not yet been run as an acceptance gate.
- Requirement-to-evidence mapping: contracts and shared routing are covered by `test/research-architecture.test.ts`, Flow policy by `test/flow-decision.test.ts`, aggregate Pi registration by `test/pi-extension.test.ts`, and legacy CodeQL-to-Flow projection by `test/m3-workflow.test.ts`; architecture constraints are asserted by `test/check-architecture.mjs`.
- Skipped or blocked checks: real Flow-path CodeQL Golden/differential/relocated replay, aggregate Pi RPC E2E, and approved-model evaluation remain pending. Historical CodeQL Golden output MUST NOT be treated as Flow-path evidence.
- Remaining limitations: Flow Capability support MUST NOT be claimed until this change is Verified.
