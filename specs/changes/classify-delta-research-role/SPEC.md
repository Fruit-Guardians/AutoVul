# Change: Classify Delta Research Role

- Change ID: `classify-delta-research-role`
- Status: Accepted
- Owner: AutoVul maintainers
- Created: 2026-08-29
- Updated: 2026-08-31
- Classification gate: `analyzer_service` explicitly accepted; production implementation remains unauthorized
- Depends on: `establish-research-capability-architecture`

## Problem

“Delta” can describe several materially different operations:

1. execute the same Capability hypothesis against vulnerable and fixed targets and compare decisions;
2. inspect a patch or commit and return structured code-change observations;
3. hypothesize that a security property changed and decide whether the change is security-relevant;
4. let the host compare two arbitrary artifacts or summaries.

Only the third form is a plausible independent Research Capability. The first is already the shared `differential` evidence mode. The second is more likely an Analyzer or evidence service. The fourth belongs to host reasoning unless AutoVul can define a deterministic vulnerability-research contract and success predicate.

Creating `DeltaHypothesis` before resolving this distinction would either duplicate `differential`, leak patch concepts into every Capability, or create a noun-shaped module with no independent decision semantics.

This change classifies Delta using real cases and produces the implementation boundary for a later change. It does not add `capability: delta` or claim Delta support.

## Host boundary

The host selects commits, patches, versions, and research questions; reads surrounding code; chooses whether change evidence should revise a Flow, MissingCheck, Typestate, or other hypothesis; and decides the next research action.

AutoVul may own deterministic patch parsing, normalized change observations, target comparison, evidence commit, and replay when those operations are security-research-specific and bounded.

AutoVul MUST NOT become a general Git client, code-review Agent, commit summarizer, patch narrator, or autonomous history-mining loop.

## Scope

### In scope

- Build a representative Delta case set.
- Evaluate Delta against a closed role-classification matrix.
- Distinguish shared `differential` mode from patch/change observations and an independent Delta success predicate.
- Specify the minimum evidence required for any later implementation.
- Define conditional implementation paths for each classification outcome.
- Produce a normative classification decision and follow-up SPEC requirement.

### Non-goals

- Adding `delta` to `ResearchCapability` in this change.
- Defining `DeltaHypothesis`, `DeltaDecision`, or a Delta runtime artifact before classification.
- Changing the existing `probe | reproduce | differential` mode set.
- General-purpose diff rendering, merge conflict resolution, blame, repository search, changelog generation, or patch explanation.
- Automatic vulnerability inference from textual diff alone.
- Feeding patch hunks directly into a model and treating its response as evidence.
- A universal change IR shared by all Capabilities.
- Production Analyzer adapters, model tools, or support claims.

## Definitions

- **Target differential**: executing one Capability hypothesis against two targets and applying that Capability’s fixed-side policy.
- **Change observation**: a structured fact about files, symbols, syntax, calls, control flow, data flow, dependencies, or configuration changed between two revisions.
- **Security-change hypothesis**: a claim that a particular change introduces, removes, or modifies a declared security property.
- **Role classification**: one of `existing_mode`, `analyzer_service`, `research_capability`, `host_strategy`, or `reject`.
- **Discriminating case**: a real case whose required inputs, observations, and success predicate separate at least two classifications.

## Classification rules

Delta MUST be classified as:

- `existing_mode` when it only runs an existing Capability against vulnerable/fixed targets and compares that Capability’s decisions;
- `analyzer_service` when it produces reusable structured change observations but has no independent vulnerability success predicate;
- `research_capability` only when it has its own versioned hypothesis, observations, deterministic decision, actionable revisions, real-tool gate, counter-example policy, and replay artifact;
- `host_strategy` when the value lies primarily in choosing commits, interpreting intent, correlating unrelated evidence, or deciding which Capability to invoke;
- `reject` when the proposed behavior is unbounded, narrative-only, non-replayable, or duplicates existing functionality without improving research action.

## Requirements

### Classification evidence

- `REQ-DELTA-001`: Classification MUST use at least three real cases covering target differential, patch/change observation, and a claimed security-property change.
- `REQ-DELTA-002`: At least one case MUST already be expressible by an existing Capability’s `differential` mode and MUST demonstrate why it does not require Delta as a Capability.
- `REQ-DELTA-003`: At least one case MUST require structured patch or revision observations that are useful before any vulnerability decision.
- `REQ-DELTA-004`: A `research_capability` outcome MUST include one case with a success predicate that cannot be owned by Flow, MissingCheck, Typestate, or shared differential semantics.
- `REQ-DELTA-005`: Every case MUST record target provenance, expected observations, counter-example, required Analyzer, completeness boundary, and replay dependencies.
- `REQ-DELTA-006`: Model prose, advisory wording, commit messages, and diff summaries MUST NOT count as tool evidence.
- `REQ-DELTA-007`: The classification record MUST state which fields change the host’s next action and which data remains artifact-only.
- `REQ-DELTA-008`: Unresolved cases MUST remain `unknown`; they MUST NOT be assigned to a role for roadmap symmetry.

### Architectural classification

- `REQ-DELTA-010`: Delta MUST NOT be added to the shared Hypothesis or result envelope.
- `REQ-DELTA-011`: Delta MUST NOT be represented as a generic optional field inside Flow, MissingCheck, Typestate, or future hypotheses.
- `REQ-DELTA-012`: Existing vulnerable/fixed execution MUST remain the owning Capability’s `differential` mode and decision policy.
- `REQ-DELTA-013`: A change-observation implementation MUST expose Analyzer observations through a Capability-specific Port or a separately specified evidence service; it MUST NOT decide another Capability’s verdict.
- `REQ-DELTA-014`: A `research_capability` decision MUST prove an independent Hypothesis/Observation/Decision split and MUST require a separate accepted implementation SPEC.
- `REQ-DELTA-015`: A `host_strategy` decision MUST result in no Core planner, history-mining loop, or new model-facing AutoVul tool.
- `REQ-DELTA-016`: Classification MUST NOT introduce a Capability registry, generic comparison engine, universal change IR, or new workspace package.
- `REQ-DELTA-017`: The outcome MUST preserve the two aggregate host entries and shared runtime/domain separation.

### Candidate observation boundary

- `REQ-DELTA-020`: Any AutoVul-owned change observation MUST be derived by a deterministic tool or parser and MUST identify both compared revisions.
- `REQ-DELTA-021`: Observations MUST distinguish syntactic change, semantic/tool-derived change, unavailable analysis, parse failure, and unsupported language or artifact type.
- `REQ-DELTA-022`: Absence of a changed line or matched pattern MUST NOT prove that a security property is unchanged.
- `REQ-DELTA-023`: Renames, generated files, vendored code, formatting-only changes, and incomplete history MUST be explicit observations or capability gaps rather than silently normalized away.
- `REQ-DELTA-024`: A change observation MUST retain bounded file/symbol/location references and evidence refs; large patches and raw histories belong in artifacts.
- `REQ-DELTA-025`: Any comparison scope MUST be explicit and replayable, including repository identity, base/head revisions, path filters, submodules, and dirty-tree policy.
- `REQ-DELTA-026`: A later Decision Policy MUST be owned by the domain hypothesis it judges; a patch parser MUST NOT emit `vulnerable`, `fixed`, or `verification_level`.

### Safety, evidence, and follow-up

- `REQ-DELTA-030`: Classification research MUST use read-only repository operations and MUST NOT checkout, reset, clean, merge, rebase, or modify user branches.
- `REQ-DELTA-031`: Private repository paths, author data, commit messages, secrets, and patch contents MUST be minimized and sanitized in portable artifacts.
- `REQ-DELTA-032`: Repository size, revision count, patch size, parser output, execution time, and concurrency MUST be bounded.
- `REQ-DELTA-033`: Network history fetches, submodule initialization, build scripts, and package installation MUST require a separately accepted policy and host approval.
- `REQ-DELTA-034`: The final classification MUST be replayable from recorded immutable revisions or explicitly declare unavailable external dependencies.
- `REQ-DELTA-035`: Classification tests and prototypes MUST NOT produce a product support claim or real verification level.
- `REQ-DELTA-036`: The final record MUST name exactly one primary role, list rejected alternatives, and identify the next SPEC or the decision to add no production code.
- `REQ-DELTA-037`: No production implementation may begin under this SPEC unless a later explicitly accepted implementation SPEC defines its contracts and acceptance gates.

## Proposed behavior

This change produces a classification record rather than a model-facing tool:

```text
Delta case set
  -> classify inputs
  -> classify observations
  -> classify success predicate
  -> classify next-action semantics
  -> select one primary role

existing_mode | analyzer_service | research_capability | host_strategy | reject
```

### Decision matrix

| Question | Yes | No |
| --- | --- | --- |
| Is the operation only vulnerable/fixed execution of an existing hypothesis? | `existing_mode` | continue |
| Are outputs deterministic change facts without an independent vulnerability verdict? | `analyzer_service` | continue |
| Are hypothesis, observations, decision, revisions, real gate, and replay all independent? | `research_capability` candidate | continue |
| Does value primarily depend on open-ended interpretation and orchestration? | `host_strategy` | `reject` |

## Conditional implementation plan

### Phase A — case corpus

- Select three or more licensed/reproducible revision pairs.
- Include an existing Flow differential, a structural patch observation, and a claimed security-property change.
- Record immutable revisions, path scope, expected facts, counter-examples, and blind spots.

### Phase B — evidence spike

- Use read-only Git and selected parsers/analyzers in a non-production research harness.
- Measure determinism, output bounds, rename behavior, language coverage, and replay dependencies.
- Separate raw patch facts from model or human interpretation.

### Phase C — classification review

- Apply every requirement and the decision matrix.
- Select one primary role and reject alternatives with evidence.
- Update this SPEC’s decision log, open questions, and verification record.

### Phase D — follow-up by outcome

- `existing_mode`: improve the owning Capability’s differential SPEC only; add no Delta module.
- `analyzer_service`: write a new change SPEC for a versioned change-observation Port, artifact, and consumers.
- `research_capability`: write `introduce-delta-capability-v1` with independent contracts and real gates.
- `host_strategy`: document host guidance or skill behavior; add no Core workflow.
- `reject`: archive the decision with no implementation.

## Contracts and artifacts

This classification defines no public product Schema. Classification evidence SHOULD record:

- case id and provenance;
- repository identity and immutable base/head revisions;
- scope and filters;
- expected and observed change facts;
- Analyzer/parser provenance;
- candidate role and rejected roles;
- counter-example outcome;
- replay dependencies and result.

If the outcome is not `research_capability`, no `DeltaHypothesis` or `DeltaDecision` may be introduced.

## Architecture

No production package or dependency change is authorized. Read-only spikes remain outside the production dependency graph. Any later implementation must preserve `contracts <- core <- analyzers/runners <- integrations` and the two aggregate host entries.

## Safety and privacy

- Use immutable revision references and read-only Git commands.
- Never modify the user’s checkout to obtain a comparison.
- Prefer temporary worktrees/direct object reads when a real tool requires materialized revisions, under a separately reviewed implementation.
- Sanitize credentials and minimize author/message content.
- Bound patch size, file count, history depth, output, time, and concurrency.
- Do not execute code from compared revisions.

## Compatibility and migration

This classification change has no public compatibility impact. Any selected implementation path requires its own migration analysis. Existing `differential` behavior remains unchanged unless a later accepted Capability SPEC modifies it.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-DELTA-001` through `REQ-DELTA-008` | Given the case corpus, when reviewed, then target comparison, change observation, and independent security judgment are empirically distinguishable | Case records and replayable evidence |
| `REQ-DELTA-010` through `REQ-DELTA-017` | Given the classification, when architecture is reviewed, then no universal IR, duplicate differential mode, registry, or host planner is introduced | Architecture decision record |
| `REQ-DELTA-020` through `REQ-DELTA-026` | Given parser/analyzer spikes, when revisions are compared, then structured facts retain scope and failure semantics without becoming vulnerability decisions | Deterministic spike outputs and counter-examples |
| `REQ-DELTA-030` through `REQ-DELTA-037` | Given private/large repositories and replay, when classification research runs, then it is read-only, bounded, sanitized, and produces exactly one follow-up role | Safety review and final classification record |

## Validation plan

- Focused unit tests: none required before an implementation role is selected; deterministic parser spikes MAY add isolated fixtures.
- Failure injection: missing revision, shallow history, rename ambiguity, binary patch, generated file, unavailable parser, oversized diff.
- Real analyzer/target: at least three real revision pairs.
- Differential or negative sample: one pair whose change is non-security-relevant and one existing Capability differential.
- Independent replay: reconstruct observations from immutable revisions without a model.
- Package/integration smoke: not applicable until a follow-up implementation SPEC.

## Open questions

- The completed corpus in [`evidence/CASE-CORPUS.md`](./evidence/CASE-CORPUS.md)
  selects `analyzer_service` as Delta’s primary role; it does not authorize an
  implementation.
- Which bounded change facts have at least two concrete Capability consumers and
  therefore justify a public service contract rather than an Analyzer-internal
  facility?
- What immutable revision and dirty-tree policy is required for a later replay
  contract?

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-29 | Do not predeclare Delta as a Capability | The term currently mixes execution mode, evidence service, and host reasoning. |
| 2026-08-29 | Keep existing vulnerable/fixed comparison under `differential` | The owning Capability must retain its domain success predicate. |
| 2026-08-29 | Require one primary classification outcome | Prevents a vague subsystem that mixes responsibilities. |
| 2026-08-29 | Record a partial three-role case corpus without classifying Delta | Two public patch pairs show deterministic observations; the required real Flow differential baseline remains intentionally incomplete. |
| 2026-08-30 | Replace the paused Flow dependency with MissingCheck’s Verified differential evidence | The classification rule requires an existing Capability differential, not Flow semantics; MissingCheck supplies the completed real baseline. |
| 2026-08-30 | Reject Arcane D-003 as current classification evidence | Its public commit view did not reproduce the recorded path or middleware fact; it remains an unverified candidate rather than a deterministic observation. |
| 2026-08-30 | Use kohya_ss D-003 as the second verified patch-observation case | Its immutable raw patch records a bounded `shell=True` argument removal while leaving Flow’s security predicate with Flow. |
| 2026-08-30 | Recommend `analyzer_service` as Delta’s primary role | D-002/D-003 provide bounded reusable change facts, while D-001 remains owning-Capability `differential`; no independent Delta predicate exists. |
| 2026-08-31 | Accept `analyzer_service` as Delta’s primary role without authorizing implementation | The user explicitly accepted the evidence-backed classification and retained the requirement for a separate implementation SPEC. |

## Delivery gate

Accepted status records the classification decision only. It does not authorize public Schemas, production modules, capability literals, tools, or support claims.

After the case corpus and classification evidence are complete, this SPEC may be Accepted and Verified as a classification decision. Production work still requires the follow-up change SPEC named by the selected role.

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: `evidence/CASE-CORPUS.md` records three discriminating research operations over immutable public revisions: a completed MissingCheck differential, an OpenClaw authorization-patch observation, and a kohya_ss shell-argument patch observation. It contains no Delta product implementation.
- Requirement-to-evidence mapping: D-001 satisfies `REQ-DELTA-001` and `REQ-DELTA-002` as an existing Capability differential; D-002 and D-003 satisfy the patch-observation and claimed-security-change portions of the corpus. The conclusion maps D-001 to `existing_mode` and selects `analyzer_service` as the sole primary Delta role, rejecting the other closed alternatives.
- Skipped or blocked checks: Production implementation checks are intentionally out of scope.
- Remaining limitations: Delta is accepted only as an `analyzer_service` role; it has no accepted implementation SPEC, public contract, module, or support claim.
