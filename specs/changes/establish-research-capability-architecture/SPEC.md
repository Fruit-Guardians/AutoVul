# Change: Establish Research Capability Architecture

- Change ID: `establish-research-capability-architecture`
- Status: Archived
- Owner: AutoVul maintainers
- Created: 2026-08-28
- Updated: 2026-08-28

## Problem

The accepted root `SPEC.md` still describes AutoVul primarily as a CodeQL query-synthesis and verification product. The project-level design baseline in `docs/design/RESEARCH_CAPABILITY_ARCHITECTURE.md` states a different product ontology:

- AutoVul is a host-attached vulnerability-research capability layer over a shared deterministic runtime;
- Flow, MissingCheck, Typestate and later paradigms are parallel capabilities, not one Source–Sink IR;
- Hypothesis, Observation and Decision are distinct kinds of data;
- the host retains research control; AutoVul does not become a second Agent Loop.

That design is currently non-normative. Without an accepted change SPEC:

- public Schema, Application API and support claims cannot be justified from the architecture document alone;
- later capabilities can leak domain fields into a shared “research IR”;
- Integration adapters can grow extra model tools per Analyzer action;
- Core can be asked to generate the next hypothesis or write a human Finding.

`introduce-flow-capability-v1` already defines the first Capability’s field contracts. This change does not replace that SPEC. It establishes the durable product architecture that Flow v1 and every later Capability MUST obey.

## Host boundary

This belongs in AutoVul because versioned research contracts, deterministic Analyzer execution, evidence grading, artifact commit and replay are vulnerability-research responsibilities.

The host Agent or Harness continues to own:

- model access, the Agent Loop, session context, planning and generic tools;
- reading code, patches and vulnerability descriptions;
- choosing a research paradigm and generating or revising a structured hypothesis;
- selecting targets, Analyzers and whether to validate, execute, replay, change direction or stop;
- user approval and the final human-facing explanation.

AutoVul MUST NOT generate the next complete hypothesis, start an autonomous revision loop, accept an open-ended research goal, or write a narrative Finding, WP or audit report.

## Relationship to other specifications

| Document | Role relative to this change |
| --- | --- |
| Root `SPEC.md` | Accepted baseline. Remains the product fact source until this change is Archived into it. |
| `introduce-flow-capability-v1` | Owns FlowModel, Flow observations, Flow decisions, CodeQL mapping and Flow acceptance gates. This SPEC MUST NOT redefine those field contracts. |
| `harden-workflow-commit-boundaries` | Owns authoritative commit, recovery and projection semantics for the shared run system. |
| `stabilize-architecture-boundaries` | Owns package layering and workflow decomposition already in force. |
| `docs/design/RESEARCH_CAPABILITY_ARCHITECTURE.md` | Non-normative design baseline. This SPEC is the normative counterpart. |

Conflict rule: if this SPEC and `introduce-flow-capability-v1` both constrain Flow, the Flow change SPEC wins on Flow field names, enums, mapping and Golden/replay gates. This SPEC wins on Capability/Runtime isolation, host-protocol shape, future-capability admission and the prohibition of a universal research IR.

## Scope

### In scope

- Make the Capability / Shared Runtime / Analyzer / Integration layering a product requirement.
- Define the shared routing envelope and the two aggregate host entries `autovul_research` and `autovul_run`.
- Separate Hypothesis, Observation and Decision as public data kinds.
- Keep `operation_status`, capability `decision` and `verification_level` as three distinct result dimensions.
- Define model-visible field admission and revision-hint rules.
- Define admission gates for any later Capability.
- Require shared envelopes to live outside Capability-specific Schema modules.
- Require architecture checks that forbid a Capability registry, a universal Hypothesis IR and placeholder Capability modules.
- Keep Flow as the only accepted Capability in this change, implemented through the already Accepted Flow SPEC.

### Non-goals

- A Capability registry, plugin loader, port factory or generic Capability base class.
- A universal Hypothesis IR or shared fields named Source, Sink, Guard, State, Delta or Variant.
- Any second research paradigm, including MissingCheck, Typestate, Delta or Variant, or empty modules for them.
- Dynamic Analyzer discovery, automatic Analyzer selection or capability negotiation.
- An autonomous revision loop, research planner or model-provider layer.
- A Finding object, WP generator, audit report or other human-facing narrative model.
- Removing or changing the meaning of `codeql_database`, `codeql_workflow` or `codeql_query`.
- Claiming DeepSeek Harness or MCP support.
- Claiming that Flow is a verified product capability before `introduce-flow-capability-v1` is Verified.
- Replacing the existing run state machine with a Capability-specific `FlowRun` or generic workflow engine.

## Definitions

- **Research Capability**: a versioned research paradigm with its own Hypothesis Schema, Observation Schema, Decision Policy, diagnostic codes, Analyzer Port and success predicates. Flow is the first member.
- **Shared Deterministic Runtime**: the run, budget, timeout, cancel, lock, retry, checkpoint, recovery, artifact and replay machinery. It routes and records; it does not interpret Capability domain fields.
- **Routing envelope**: the minimal `action`, `capability` and `hypothesis_version` fields used to select a versioned Capability contract. It contains no research semantics.
- **Hypothesis**: a host-submitted, versioned, schema-checked claim. Model output is always a Hypothesis.
- **Observation**: a structured fact produced by an Analyzer Adapter, including capability gaps. It is not a product success conclusion.
- **Decision**: the deterministic Core mapping from Observation plus declared expectation to a Capability-specific verdict and a verification level.
- **Evidence-operation mode**: the shared closed set `probe`, `reproduce`, `differential`. It describes requested evidence strength and MUST NOT carry Capability-specific verbs.
- **Envelope action**: a protocol-level next action from the closed set `revise`, `execute`, `replay`, `stop`.
- **Revision hint**: a Capability-specific, evidence-backed suggestion with a hypothesis field path, stable reason code and optional constraints. It is never a complete replacement Hypothesis.
- **Verification level**: the shared evidence-strength vocabulary `generated`, `compiled`, `reproduced`, `differential`, `variant_validated`.
- **Operation status**: whether a requested operation is `completed`, `blocked`, `failed` or `cancelled`.

## Requirements

### Product identity

- `REQ-RCARCH-001`: AutoVul MUST remain a host-attached vulnerability-research capability layer and deterministic execution system. It MUST NOT be implemented or documented as a general Agent or general Agent Harness.
- `REQ-RCARCH-002`: The project MUST NOT provide a model-provider framework, Agent Loop, conversation memory, context compression, general planner, task queue or subagent orchestration.
- `REQ-RCARCH-003`: The host MUST retain hypothesis generation, revision, action selection and stopping authority.
- `REQ-RCARCH-004`: AutoVul MUST own versioned research contracts, bounded Analyzer execution, structured observations, deterministic decisions, evidence commit and replay.
- `REQ-RCARCH-005`: The deterministic CLI MUST remain a debugging, CI, model-free validation and replay interface. It MUST NOT accept an open-ended research goal such as “keep looking for vulnerabilities”.
- `REQ-RCARCH-006`: Core MUST NOT generate a write-up, audit report, Finding title, risk narrative or other human-facing report body.
- `REQ-RCARCH-007`: Host-independent in this product MUST mean host-agnostic contracts, language and Analyzer extensibility, and support for multiple research paradigms. It MUST NOT mean a general coding Agent.

### Capability and runtime split

- `REQ-RCARCH-010`: Research Capabilities MUST be parallel. They MUST NOT share domain success predicates, domain types or diagnostic codes.
- `REQ-RCARCH-011`: Capabilities MUST share the existing deterministic runtime for run identity, idempotency, budget, timeout, cancellation, locks, classified retry, checkpoint, recovery, artifacts, evidence refs and replay.
- `REQ-RCARCH-012`: The shared request and run envelopes MUST contain only routing, contract-version, operation, target, Analyzer identity, budget and evidence-operation fields.
- `REQ-RCARCH-013`: The shared layer MUST NOT define generic Source, Sink, Guard, State, Delta, Variant or equivalent domain fields.
- `REQ-RCARCH-014`: The implementation MUST NOT introduce a universal research IR or a large optional-field bag that simulates paradigm differences.
- `REQ-RCARCH-015`: The shared runtime MAY record which Capability and contract version a run belongs to and where evidence is stored. It MUST NOT interpret Capability domain fields such as `path_observed`, `guard_absent` or `illegal_transition`.
- `REQ-RCARCH-016`: v1 MUST compose Capabilities with explicit static branches. The implementation MUST NOT add a Capability registry, dynamic plugin loader, port factory or generic Capability base class.
- `REQ-RCARCH-017`: This change MUST NOT add a Schema, module, empty package or test double for any Capability other than Flow.
- `REQ-RCARCH-018`: Adding a Capability MUST NOT by itself require a new workspace package. A new package requires a separate dependency, publication or size justification.
- `REQ-RCARCH-019`: The shared runtime MUST manage one requested operation. It MUST NOT store a host research plan, conversation history, next-step strategy or multi-hypothesis case aggregation.

### Hypothesis, observation and decision

- `REQ-RCARCH-020`: Model-provided content MUST be treated as a Hypothesis until a Capability validator accepts a normalized contract.
- `REQ-RCARCH-021`: An Analyzer Adapter MUST return Observations and capability gaps only. It MUST NOT return a product Decision or `verification_level`.
- `REQ-RCARCH-022`: Core MUST be the sole writer of the model-visible `decision` and `verification_level` fields.
- `REQ-RCARCH-023`: Integration adapters MUST NOT copy Capability validators, Decision Policies, budget policy or artifact commit rules.
- `REQ-RCARCH-024`: A missing Observation MUST NOT be rewritten as a stronger domain fact. In particular, “no path observed” MUST NOT be stored as “missing Summary” unless an Analyzer supplied explicit evidence for that fact.
- `REQ-RCARCH-025`: Each Capability Decision Policy MUST be a pure, deterministic function of normalized Observation plus declared expectation and MUST be unit-testable without a live Analyzer.
- `REQ-RCARCH-026`: Analyzer provenance, command records and raw tool output MUST remain evidence. They MUST NOT be promoted to product success by Integration or CLI formatting.

### Host protocol

- `REQ-RCARCH-030`: The target model-facing interface MUST expose exactly two aggregate research entries: `autovul_research` and `autovul_run`.
- `REQ-RCARCH-031`: `autovul_research` MUST accept only the actions `validate` and `execute` until a later accepted change SPEC adds another research action.
- `REQ-RCARCH-032`: `autovul_run` MUST accept only the actions `status`, `cancel` and `replay` until a later accepted change SPEC adds another run action.
- `REQ-RCARCH-033`: A new Capability MUST NOT add a separate model-visible tool per Analyzer probe, compile, analyze or decode action.
- `REQ-RCARCH-034`: The shared research request MUST include `action`, `capability` and `hypothesis_version`, and MUST pass `hypothesis` as an opaque value to the selected Capability schema.
- `REQ-RCARCH-035`: Until a second Capability is accepted, `capability` MUST be the literal `flow` and `hypothesis_version` MUST be `autovul.flow/1`.
- `REQ-RCARCH-036`: The shared envelope MUST NOT add generic `source`, `sink`, `guard`, `state`, `message` or `rationale` fields.
- `REQ-RCARCH-037`: An execute request MUST keep the Hypothesis separate from `target`, `analyzer` identity, evidence-operation `mode`, `budget` and `idempotency_key`.
- `REQ-RCARCH-038`: `validate` MUST be side-effect free. It MUST NOT create a run, write an artifact or invoke an Analyzer.
- `REQ-RCARCH-039`: Invalid input MUST return a bounded list of issues, each with a stable `code` and JSON Pointer `path`.
- `REQ-RCARCH-040`: A validation issue MUST include `allowed_values` when the repair is a closed set and MAY include `expected_kind` for a type mismatch. Free-form prose MUST NOT substitute for those fields.
- `REQ-RCARCH-041`: A compact execution result MUST include `schema_version`, `run_id`, `operation_status`, `capability`, `decision`, `verification_level`, compact `observations`, `revision_hints`, `allowed_next_actions` and `artifact_ref`. It MAY include `budget_remaining`.
- `REQ-RCARCH-042`: `decision` MUST be a Capability-discriminated object. The result MUST NOT add a parallel Capability-specific verdict field such as `flow_status`.
- `REQ-RCARCH-043`: `operation_status` MUST be the closed set `completed`, `blocked`, `failed`, `cancelled`.
- `REQ-RCARCH-044`: Model-visible `allowed_next_actions` MUST be a subset of `revise`, `execute`, `replay`, `stop`. Capability-specific verbs MUST appear only inside `revision_hints[].action`.
- `REQ-RCARCH-045`: A revision hint MUST contain `action`, hypothesis JSON Pointer `path`, stable `reason_code` and optional structured `constraints`.
- `REQ-RCARCH-046`: Core MUST NOT return a complete replacement Hypothesis and MUST NOT automatically apply a revision hint.
- `REQ-RCARCH-047`: Core MUST NOT start an autonomous retry or revision loop after a failed or negative result.
- `REQ-RCARCH-048`: Every model-visible business field MUST support at least one of: routing or recovery; deciding to continue, revise, change direction or stop; editing a specific Hypothesis field; judging current evidence strength; locating an artifact or starting replay. All other detail MUST be stored in artifacts.
- `REQ-RCARCH-049`: Analyzer logs, command lines, traces, environment dumps and large location sets MUST default to artifacts and MUST be reachable through `artifact_ref` or evidence refs.
- `REQ-RCARCH-050`: Existing `codeql_database`, `codeql_workflow` and `codeql_query` interfaces MUST remain a compatibility surface until a later accepted migration SPEC. A Flow-capable host profile MUST NOT present them as a third primary research interface beside `autovul_research` and `autovul_run`.
- `REQ-RCARCH-051`: Pi, CLI and any later host adapter MUST call the same Application API for `autovul_research` and `autovul_run`.
- `REQ-RCARCH-052`: DeepSeek Harness and MCP MUST NOT be claimed as implemented support until each has its own accepted change SPEC and verification gates.

### Verification semantics

- `REQ-RCARCH-060`: `operation_status`, Capability `decision` and `verification_level` MUST remain three distinct result dimensions and MUST NOT be collapsed into one enum.
- `REQ-RCARCH-061`: The system MUST continue to use the accepted verification levels `generated`, `compiled`, `reproduced`, `differential` and `variant_validated` as shared evidence-strength labels.
- `REQ-RCARCH-062`: Each Capability MUST define its own success predicates for `reproduced`, `differential` and any later level it is allowed to emit. Shared levels MUST NOT imply shared domain judgment.
- `REQ-RCARCH-063`: A Capability that has no compile phase MAY omit `compiled`. A Capability MUST NOT invent a parallel evidence vocabulary.
- `REQ-RCARCH-064`: Probe hits, mocks, fake adapters, model inference and diagnostic wrappers MUST NOT raise a real verification level.
- `REQ-RCARCH-065`: Negative results, environment gaps, timeouts, cancellation and parse failures MUST retain the original operation status or committed stage, a structured diagnostic and replayable inputs.
- `REQ-RCARCH-066`: A completed negative Decision, such as Flow `no_path`, MUST remain distinct from `blocked`, `failed` and `cancelled`.
- `REQ-RCARCH-067`: Claims in UI, documentation and host-visible summaries MUST NOT exceed the recorded `verification_level`.

### First Capability and later admission

- `REQ-RCARCH-070`: Flow is the first Capability. Flow field contracts, CodeQL mapping, Golden, differential and Query Pack replay gates MUST be those of `introduce-flow-capability-v1`.
- `REQ-RCARCH-071`: Flow MUST remain a parallel Capability. It MUST NOT be upgraded into a universal vulnerability IR.
- `REQ-RCARCH-072`: This change MUST NOT add a second Capability Schema, Decision Policy, Port or placeholder.
- `REQ-RCARCH-073`: A later Capability MAY enter product design only when all of the following are true: (1) a real vulnerability case that Flow cannot honestly express; (2) independent Hypothesis, Observation and success predicates; (3) structured diagnostics that can change the host’s next action; (4) fake-adapter coverage of state and failure; (5) at least one real-tool acceptance gate; (6) an explicit differential or other counter-example strategy; (7) independently replayable artifacts.
- `REQ-RCARCH-074`: MissingCheck and Typestate MAY be named as candidate paradigms in design documents. They MUST NOT receive Schema, modules or support claims in this change.
- `REQ-RCARCH-075`: Delta and Variant MUST NOT be fixed as Hypothesis types by this change. Classification of later work MUST follow inputs, observations and success gates, not noun symmetry.
- `REQ-RCARCH-076`: A Capability MUST NOT be documented as supported until its change SPEC is Verified. Draft or Implemented status MUST NOT be converted into a support claim.

### Packages, artifacts and safety

- `REQ-RCARCH-080`: Production dependencies MUST continue to follow `contracts -> core -> analyzers/runners -> integrations`.
- `REQ-RCARCH-081`: `@autovul/contracts` MUST own shared run/evidence envelopes and Capability-specific versioned Schemas. Shared envelope types MUST NOT live only inside a Flow-specific module.
- `REQ-RCARCH-082`: `@autovul/core` MUST own shared runtime policy, Capability validators, Decision Policies and Analyzer Ports.
- `REQ-RCARCH-083`: Analyzer/Runner packages MUST own tool protocol, process execution, output decoding and raw Observations. They MUST NOT independently redefine product success.
- `REQ-RCARCH-084`: Pi Extension, CLI and later host adapters MUST remain thin registration, conversion, cancellation and presentation layers.
- `REQ-RCARCH-085`: The shared runtime MUST NOT become a generic callback or untyped JSON workflow framework.
- `REQ-RCARCH-090`: A committed verifiable run artifact MUST record Capability and contract version, normalized Hypothesis, target and Analyzer provenance, budget/mode/idempotency identity, Observation, Decision Policy version, Decision, verification level, evidence refs and replay inputs or explicit external dependencies.
- `REQ-RCARCH-091`: Critical artifacts MUST be durable before authoritative state references the corresponding Decision or verification level.
- `REQ-RCARCH-092`: Recovery MUST use verified internal state and commit metadata. Corrupted state MUST NOT be silently rebuilt as success.
- `REQ-RCARCH-093`: Replay MUST execute without a model, host session or mutable temporary state from the originating run.
- `REQ-RCARCH-094`: Replay MUST distinguish identical result, environment block, Analyzer version difference and semantic mismatch. It MUST NOT coerce those cases into success.
- `REQ-RCARCH-095`: Paths MUST be canonicalized and constrained to configured workspace or trusted roots, including symlink-escape rejection.
- `REQ-RCARCH-096`: The system MUST NOT automatically execute target build, install or other high-risk scripts without explicit host/user approval and an accepted policy path.
- `REQ-RCARCH-097`: Long-running processes MUST support timeout, cancellation and complete process-tree cleanup.
- `REQ-RCARCH-098`: Retry MUST remain limited to classified retryable failures. Invalid hypotheses, semantic mismatches, policy rejection and capability mismatch MUST NOT be blindly retried.
- `REQ-RCARCH-099`: Output size, execution time, concurrency, candidate count and stored observation counts MUST be bounded. Logs and artifacts MUST NOT persist recognized credentials or unrestricted environment data.
- `REQ-RCARCH-100`: Missing Analyzer capability MUST return `blocked` or `capability_mismatch`. It MUST NOT fall back to model guessing or fake success.

## Proposed behavior

### Layering

```text
Host Agent / Harness
  └─ Integration Adapter (Pi, CLI, later hosts)
       └─ Application API
            ├─ autovul_research
            │    └─ explicit Capability branch (Flow only in this change)
            │         ├─ validator
            │         ├─ Decision Policy
            │         └─ Capability Port
            ├─ autovul_run
            │    └─ shared run, cancel, replay services
            └─ Shared Deterministic Runtime
                 └─ Analyzer Adapter (CodeQL first)
```

The Application exposes one research method and one run method. Flow is an explicit static branch. There is no registry.

### Validate

```text
autovul_research
  action: validate
  capability: flow
  hypothesis_version: autovul.flow/1
  hypothesis: unknown
```

Valid input returns the Capability-normalized Hypothesis and envelope actions such as `execute` and `stop`. Invalid input returns bounded field issues and does not create a run.

### Execute

```text
autovul_research
  action: execute
  capability: flow
  hypothesis_version: autovul.flow/1
  hypothesis: CapabilityHypothesis
  target
  analyzer
  mode: probe | reproduce | differential
  budget
  idempotency_key
```

The Application validates the envelope and Hypothesis, admits or resumes one bounded operation in the existing run system, calls the Capability Port, persists Observations, lets Core write Decision and verification level, commits artifacts, then returns the compact result.

### Run management

```text
autovul_run
  action: status | cancel | replay
  run_id
```

`status` returns the persisted run projection. `cancel` requests cancellation of a non-terminal operation and preserves an accurate terminal state. `replay` re-executes the committed deterministic artifact without a model and returns the same Decision and verification level, a structured environment block, or a structured mismatch.

### Compact result

```text
ResearchExecutionResult
  schema_version
  run_id
  operation_status: completed | blocked | failed | cancelled
  capability
  decision                 Capability-specific
  verification_level
  observations[]           compact, actionable
  revision_hints[]
  allowed_next_actions[]   revise | execute | replay | stop
  budget_remaining?
  artifact_ref
```

## Contracts and artifacts

### Shared contracts

These MUST live in a shared contracts module, not only inside Flow:

- `ResearchAction`: `validate | execute`
- `RunAction`: `status | cancel | replay`
- `EnvelopeAction`: `revise | execute | replay | stop`
- `EvidenceOperationMode`: `probe | reproduce | differential`
- `OperationStatus`: `completed | blocked | failed | cancelled`
- `OperationBudget`
- routing `ResearchRequest` with `action`, `capability`, `hypothesis_version` and opaque `hypothesis`
- `AutovulRunToolInput`

`ResearchCapability` in this change remains the literal `flow`. Adding another literal requires a later accepted Capability SPEC.

### Capability-specific contracts

FlowModel, Flow observations, Flow decisions, Flow revision hints, TargetRef v1 and Flow execute tool input remain owned by `introduce-flow-capability-v1`.

### Artifacts

Flow and later Capabilities write versioned artifacts under the existing trusted run artifact root. Historical Query Pack and workflow schemas are not rewritten by this change.

## Architecture

- `@autovul/contracts` owns shared envelopes and Capability Schemas.
- `@autovul/core` owns runtime policy, Flow validator, Flow Decision Policy and the Flow execution port.
- `@autovul/codeql-runner` owns CodeQL protocol and Flow Observations.
- `@autovul/pi-extension` and `@autovul/cli` remain thin adapters over the same Application API.
- No new workspace package is required.

Host-specific prompts, UI types and lifecycle APIs MUST NOT enter Core.

## Safety and privacy

- Validate performs no filesystem or process access.
- Execute and replay paths are canonicalized under trusted roots.
- Timeout and cancellation terminate the complete Analyzer subprocess tree.
- Artifacts exclude prompts, unrestricted environment data and recognized credentials.
- Invalid hypotheses, capability mismatch and policy failure are non-retryable unless the host supplies a revised request.
- Unavailable Analyzers block execution; they do not invent Observations.

## Compatibility and migration

- Existing CodeQL public Schemas, Pi tools and CLI commands remain supported.
- `autovul_research` and `autovul_run` are added as the target aggregate interface.
- Compatibility `codeql_*` operations MUST project onto the same Core policy once the Flow path is enabled; they MUST NOT retain a second success policy.
- Existing run ids, case budgets, workflow phases and Query Pack identities remain authoritative.
- Existing artifacts remain readable; no bulk rewrite is planned.
- Rollback can disable the new aggregate entries while leaving existing CodeQL tools and artifacts usable.
- Removal or deprecation of any `codeql_*` tool requires a later accepted migration SPEC.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-RCARCH-001` through `REQ-RCARCH-007` | Given production source and docs, when architecture and naming checks run, then AutoVul is described and implemented as a research capability layer, not an Agent | Architecture tests and source review |
| `REQ-RCARCH-010` through `REQ-RCARCH-019` | Given the built production graph, when inspectors search Core and contracts, then no Capability registry, universal Hypothesis IR, second Capability module or host research-plan state exists | Architecture tests |
| `REQ-RCARCH-020` through `REQ-RCARCH-026` | Given fake Analyzer observations, when Core maps them, then only Core writes `decision` and `verification_level` and the Adapter type cannot supply those fields | Port type tests and decision-policy unit tests |
| `REQ-RCARCH-030` through `REQ-RCARCH-052` | Given Pi and CLI adapters, when validate, execute, status, cancel and replay are invoked, then both hosts use the same Application methods and `codeql_*` remain compatibility tools | Contract tests, adapter tests, CLI tests, Pi registration tests |
| `REQ-RCARCH-038` through `REQ-RCARCH-040` | Given invalid Hypothesis input, when validate runs, then issues contain `code` and `path`, no run is created and no Analyzer is invoked | Unit tests with artifact-store call-count assertions |
| `REQ-RCARCH-060` through `REQ-RCARCH-067` | Given completed negative, blocked, failed and cancelled fixtures, when results are returned, then the three result dimensions stay distinct and verification levels are not inflated | Decision-policy matrix and Application integration tests |
| `REQ-RCARCH-070` through `REQ-RCARCH-076` | Given the repository, when source and specs are inspected, then only Flow exists as a Capability and support claims remain gated on verification | Architecture tests and SPEC check |
| `REQ-RCARCH-080` through `REQ-RCARCH-085` | Given package imports, when dependency checks run, then `contracts -> core -> runners -> integrations` holds and shared envelopes are not Flow-only | `check-dependencies` and module-layout tests |
| `REQ-RCARCH-090` through `REQ-RCARCH-100` | Given interruption, untrusted paths, unavailable Analyzer and replay, when the shared runtime is used, then commit, safety and honest-failure invariants hold | Failure-injection, trusted-root and replay tests; real Analyzer gates remain those of the Flow SPEC |

The central architecture acceptance case is:

> Given a host that needs to validate a hypothesis, execute it, inspect the run, cancel it or replay it, when it uses AutoVul, then it does so through `autovul_research` and `autovul_run`, receives structured observations and a Core decision, and never receives a generated next Hypothesis or a human Finding from Core.

Flow-specific no-path diagnostics, Golden, differential and Query Pack replay remain acceptance gates of `introduce-flow-capability-v1`.

## Validation plan

- Focused unit tests:
  - shared envelope rejects unknown capabilities and extra domain fields;
  - validate is pure;
  - Decision Policy does not run inside the Analyzer adapter;
  - envelope actions stay separate from Capability revision actions;
  - `operation_status`, `decision` and `verification_level` stay independent.
- Architecture tests:
  - no registry / plugin loader / Capability base class;
  - no MissingCheck, Typestate, Delta or Variant Schema or module;
  - no universal Hypothesis type with mixed Source/Guard/State fields;
  - shared envelope module exists outside `flow.ts`;
  - production dependency direction holds.
- Failure injection:
  - unavailable Analyzer;
  - cancellation and timeout;
  - artifact write failure before authoritative commit;
  - untrusted paths.
- Real analyzer/target:
  - not newly required by this architecture change;
  - Flow real CodeQL, Golden, differential and replay remain the Flow SPEC’s gates.
- Package/integration smoke:
  - `npm run check` or the focused typecheck/test/lint subset;
  - Pi tool registration includes `autovul_research` and `autovul_run`;
  - CLI exposes the same two aggregate commands;
  - clean package dry-run when claiming a release.

## Open questions

No product-level open question is deferred by this Draft. Review may still narrow shared module filenames or CLI command spelling (`run` versus `autovul_run`) before acceptance; such edits MUST preserve the requirements and non-goals above.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-28 | Make the architecture design a change SPEC rather than editing root `SPEC.md` in place | Public behavior changes need Draft to Archived history. |
| 2026-08-28 | Keep Flow field contracts in `introduce-flow-capability-v1` | Avoid two sources of truth for Flow enums and Golden gates. |
| 2026-08-28 | Share runtime and routing only | Domain predicates stay Capability-owned. |
| 2026-08-28 | Forbid a Capability registry and universal IR in v1 | A second real paradigm does not yet exist. |
| 2026-08-28 | Two aggregate host entries | New Capabilities must not explode the model tool surface. |
| 2026-08-28 | Keep `codeql_*` as compatibility | Existing verified CodeQL behavior must remain usable during migration. |
| 2026-08-28 | Core returns revision hints, never a replacement Hypothesis | Prevent AutoVul from becoming a second Agent Loop. |

## Delivery gate

This change was Accepted on 2026-08-28 by explicit user instruction to implement the architecture constraints. Implementation MAY proceed within the stated scope and non-goals.

This acceptance does not authorize a second Capability, a registry, Finding narrative, or a verified Flow support claim. Flow field contracts, Golden, differential and Query Pack replay remain governed by `introduce-flow-capability-v1`.

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: `npm run typecheck`, `npm test` (25 files, 137 tests), `npm run lint`, and `npm run pack:check` passed on 2026-08-29.
- Requirement-to-evidence mapping: shared-envelope, decision-policy, Application, CLI, Pi registration and architecture coverage is in `test/research-architecture.test.ts`, `test/flow-decision.test.ts`, `test/pi-extension.test.ts` and `test/check-architecture.mjs`. The architecture test injects pre-promote failure, post-promote interruption and corrupted Flow evidence; the Flow result and shared route are promoted as one `research/` artifact bundle. Existing runtime failure, locking and artifact tests cover the shared runtime boundaries.
- Skipped or blocked checks: real CodeQL Golden, differential, Pi RPC E2E and independent replay remain owned by `introduce-flow-capability-v1` and MUST be reported as BLOCKED if unavailable.
- Verification conclusion: the architecture requirements are Verified by the listed deterministic tests and package checks. They are merged into root `SPEC.md` version 1.1 and this change is Archived. At this change's archival date Flow remained `Implemented`; Flow was subsequently verified and archived on 2026-09-01 under `introduce-flow-capability-v1`, with stable behavior merged into root `SPEC.md` version 1.4.
