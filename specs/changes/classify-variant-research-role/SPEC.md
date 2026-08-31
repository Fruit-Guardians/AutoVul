# Change: Classify Variant Research Role

- Change ID: `classify-variant-research-role`
- Status: Draft
- Owner: AutoVul maintainers
- Created: 2026-08-29
- Updated: 2026-08-30
- Classification gate: Open
- Depends on: `establish-research-capability-architecture` and at least one Verified seed Capability result

## Problem

“Variant” can mean:

1. a host strategy that generalizes a verified vulnerability and chooses new targets;
2. a bounded search service that applies deterministic transformations or matchers to an explicit corpus;
3. a validation stage that proves additional positive, negative, sibling, fork, or cross-project cases for an existing Capability;
4. an independent Capability with its own hypothesis, observations, decision, and success predicate.

The existing verification level `variant_validated` does not imply that Variant is itself a Capability. A search candidate is not a vulnerability, and an LLM-suggested similarity is not evidence. If AutoVul absorbs open-ended target discovery, iterative planning, web search, and semantic judgment, it becomes an Agent. If it exposes only deterministic, bounded candidate generation and validation, the behavior may belong as an Analyzer/search service consumed by existing Capabilities.

This change classifies Variant before production implementation. It defines seed quality, corpus boundaries, candidate evidence, validation ownership, stopping rules, and conditional implementation paths. It does not add `capability: variant` or claim variant discovery support.

## Host boundary

The host Agent selects the research goal, chooses a verified seed, identifies or approves a target corpus, decides which search strategy to try, interprets candidate relevance, selects candidates for validation, revises hypotheses, and stops.

AutoVul may own deterministic seed extraction, bounded search execution, stable candidate observations, deduplication, evidence commit, replay, and validation through the owning Capability.

AutoVul MUST NOT perform unbounded web/repository discovery, autonomously expand the corpus, create a self-directed hunt loop, publish findings, or treat similarity as confirmation.

## Scope

### In scope

- Build real variant case families from verified seed evidence.
- Classify Variant as `host_strategy`, `search_service`, `research_capability`, or `reject`.
- Define the minimum verified seed and explicit corpus requirements.
- Separate candidate generation, candidate screening, and capability-owned validation.
- Define deterministic budgets, deduplication identity, provenance, stopping, and replay requirements.
- Define conditional implementation plans for each classification outcome.
- Protect the meaning of `variant_validated` from candidate or similarity inflation.

### Non-goals

- Adding `variant` to `ResearchCapability` in this change.
- Defining a universal vulnerability pattern, semantic embedding ontology, or cross-language IR.
- Autonomous package/repository discovery, web crawling, advisory monitoring, or target prioritization.
- An open-ended loop that mutates patterns and keeps searching without host actions.
- Treating code similarity, text matches, embeddings, model judgments, or cloned functions as vulnerability evidence.
- General-purpose code search, package intelligence, deduplication, CVE reporting, or disclosure workflow.
- A new model-facing tool per search strategy.
- Production adapters, public Schemas, or support claims before classification and a follow-up SPEC.

## Definitions

- **Verified seed**: a committed AutoVul artifact with a real `reproduced` or stronger result, complete Capability contract version, target provenance, and replayable evidence.
- **Variant family**: a bounded set of known related vulnerable and safe cases used to evaluate search and validation behavior.
- **Search pattern**: a versioned, deterministic transformation or matcher derived from explicit seed fields and accepted tool evidence.
- **Search corpus**: an explicit, immutable or fingerprinted set of repositories, packages, revisions, files, or databases approved by the host.
- **Candidate**: a search observation that may deserve validation; it is not a vulnerability decision.
- **Candidate identity**: a stable digest over corpus identity, target revision, location, strategy version, and seed identity used for deduplication.
- **Owning Capability**: Flow, MissingCheck, Typestate, or another Verified Capability whose hypothesis and success predicate validate a candidate.
- **Role classification**: `host_strategy`, `search_service`, `research_capability`, or `reject`.

## Classification rules

Variant MUST be classified as:

- `host_strategy` when most value comes from choosing target populations, inventing semantic analogies, changing search direction, or prioritizing candidates;
- `search_service` when AutoVul can accept a verified seed and explicit corpus, run a deterministic bounded search, and return structured candidates for an owning Capability to validate;
- `research_capability` only when Variant has an independent hypothesis, observation semantics, deterministic decision, revision actions, real-tool success gate, counter-examples, and replay that are not reducible to search plus another Capability’s validation;
- `reject` when the proposal is open-ended, narrative-only, non-replayable, evidence-inflating, or duplicates host/general search functionality.

## Requirements

### Seed and case-family evidence

- `REQ-VARIANT-001`: Classification MUST use at least two real variant families with a total of at least two vulnerable members and two safe or fixed counter-examples.
- `REQ-VARIANT-002`: Every seed MUST be a committed `reproduced` or stronger AutoVul result from an owning Capability; model-only, fake, or generated seeds are forbidden.
- `REQ-VARIANT-003`: Each family MUST record why members are variants, which properties are shared, which properties differ, and which owning Capability validates them.
- `REQ-VARIANT-004`: At least one family MUST contain a high-similarity safe case to measure false-positive discrimination.
- `REQ-VARIANT-005`: At least one family SHOULD contain a lower-similarity vulnerable case to measure whether the strategy is more useful than textual clone search.
- `REQ-VARIANT-006`: Case provenance, license, immutable revision, corpus membership, expected candidate identity, and validation outcome MUST be recorded.
- `REQ-VARIANT-007`: Classification MUST state which decisions require host reasoning and which operations are deterministic enough for AutoVul.
- `REQ-VARIANT-008`: An unavailable or unverified seed MUST block search rather than silently downgrade the seed requirement.

### Architectural classification

- `REQ-VARIANT-010`: Variant MUST NOT be added to the shared Hypothesis envelope or as optional fields in existing Capability hypotheses.
- `REQ-VARIANT-011`: The `variant_validated` evidence level MUST remain a result strength, not evidence that Variant is an independent Capability.
- `REQ-VARIANT-012`: Candidate validation MUST be owned by the Capability whose domain predicate is being tested.
- `REQ-VARIANT-013`: A search service MUST return candidate observations, scores/components, provenance, and evidence refs only; it MUST NOT return another Capability’s decision or verification level.
- `REQ-VARIANT-014`: A `research_capability` classification MUST prove an independent success predicate that is not “another Capability validated one of the candidates.”
- `REQ-VARIANT-015`: A `host_strategy` classification MUST not add a Core planner, target queue, model loop, memory system, or new AutoVul search Agent.
- `REQ-VARIANT-016`: Classification MUST NOT introduce a registry, universal pattern IR, embedding abstraction, or new workspace package.
- `REQ-VARIANT-017`: Any future implementation MUST preserve the two aggregate host entries and explicit static Capability composition.

### Candidate search semantics

- `REQ-VARIANT-020`: Any AutoVul-owned search MUST require an explicit verified seed, explicit strategy version, explicit corpus identity, and explicit budget.
- `REQ-VARIANT-021`: AutoVul MUST NOT autonomously add repositories, packages, branches, revisions, or network results to the corpus.
- `REQ-VARIANT-022`: Candidate identity MUST be deterministic and MUST support exact deduplication across retries and replay.
- `REQ-VARIANT-023`: Candidate output MUST distinguish `matched`, `not_matched`, `not_run`, `unsupported`, and operational failure without converting them into vulnerability decisions.
- `REQ-VARIANT-024`: Ranking MUST expose bounded structured score components or match facts. An opaque model score or unexplained embedding distance MUST NOT be the sole model-visible basis for action.
- `REQ-VARIANT-025`: Large snippets, indexes, embeddings, raw search output, and corpus metadata MUST remain in artifacts; compact output contains only actionable candidate summaries and refs.
- `REQ-VARIANT-026`: Search strategies MUST be deterministic for fixed seed, corpus, strategy version, Analyzer version, and budget, or must record the source of nondeterminism.
- `REQ-VARIANT-027`: A candidate MUST retain the mapping needed to construct or revise the owning Capability hypothesis without containing a precomputed vulnerability verdict.
- `REQ-VARIANT-028`: Search MUST stop at the declared candidate, target, time, output, and concurrency budgets and return an accurate partial result.
- `REQ-VARIANT-029`: Core MUST NOT automatically validate every candidate or revise and rerun the search; each follow-up operation remains host-selected.

### Validation and evidence strength

- `REQ-VARIANT-030`: Candidate generation, screening, reproduction, differential confirmation, and family validation MUST remain distinct stages.
- `REQ-VARIANT-031`: Similarity, structural match, copied code, shared dependency, common author, or model agreement MUST NOT raise a real verification level.
- `REQ-VARIANT-032`: A candidate becomes `reproduced` or `differential` only through the owning Capability’s accepted real evidence gates.
- `REQ-VARIANT-033`: `variant_validated` MUST require a later accepted policy specifying the minimum additional positive cases, negative cases, diversity dimensions, and per-case verification level.
- `REQ-VARIANT-034`: A safe high-similarity counter-example MUST remain negative even if it ranks above vulnerable candidates.
- `REQ-VARIANT-035`: Failed, timed-out, unavailable, or unsupported candidate validation MUST remain unknown or blocked and MUST NOT count as a negative sample.
- `REQ-VARIANT-036`: Family-level conclusions MUST reference every included candidate result and MUST not exceed the weakest required evidence gate.
- `REQ-VARIANT-037`: The host MUST be able to stop after any batch and resume from seed, corpus, strategy, cursor, and committed artifacts without model memory.

### Safety, privacy, and follow-up

- `REQ-VARIANT-040`: Classification research and any later search service MUST be read-only with respect to target repositories and package sources.
- `REQ-VARIANT-041`: Network search, cloning, fetching, registry enumeration, or package download MUST require explicit host scope and a separately accepted security/data-retention policy.
- `REQ-VARIANT-042`: Private source, repository names, package metadata, embeddings, and candidate snippets MUST be minimized, access-controlled by the host environment, and sanitized in portable artifacts.
- `REQ-VARIANT-043`: Search MUST NOT execute target build, install, test, proof-of-concept, or service commands without a separate accepted approval path.
- `REQ-VARIANT-044`: Corpus size, file count, candidate count, result size, time, concurrency, and retained snippets MUST be bounded.
- `REQ-VARIANT-045`: Replay MUST verify seed identity, corpus fingerprint, target revisions, strategy version, Analyzer provenance, budget, and candidate identities.
- `REQ-VARIANT-046`: Classification prototypes and candidate lists MUST NOT be presented as implemented support or real vulnerability findings.
- `REQ-VARIANT-047`: The final classification MUST select one primary role, reject alternatives with evidence, and name a follow-up implementation SPEC or the decision to add no Core code.
- `REQ-VARIANT-048`: Production implementation MUST NOT begin under this classification SPEC.

## Proposed behavior

This change produces a classification record:

```text
Verified seed artifact
  + explicit corpus
  + real variant families
  -> bounded strategy spike
  -> candidate observations
  -> owning Capability validation
  -> role classification

host_strategy | search_service | research_capability | reject
```

### Preferred hypothesis to test

The initial design hypothesis is that Variant will become a bounded `search_service`, not a Capability:

```text
Host chooses seed, corpus, strategy, and next candidate
  -> AutoVul deterministically searches and commits candidates
  -> Host selects a candidate and constructs/revises an owning Capability hypothesis
  -> Owning Capability validates it
```

This preference is not a conclusion. The case-family evidence may classify it differently.

## Conditional implementation plan

### Phase A — verified seeds and family corpus

- Select two or more licensed variant families.
- Produce or reference Verified seed artifacts.
- Freeze explicit corpora and immutable revisions.
- Include safe high-similarity and vulnerable lower-similarity cases.

### Phase B — bounded strategy spikes

- Evaluate at least one structural/tool-derived strategy and one conservative baseline such as exact/textual matching.
- Run spikes outside production code with fixed seeds, corpora, budgets, and versions.
- Record candidates, false positives, misses, determinism, resource cost, and required host choices.

### Phase C — owning Capability validation

- Convert selected candidates into the owning Capability’s hypotheses.
- Run real reproduction/differential gates.
- Record whether search observations are actionable without embedding another Capability’s decision.

### Phase D — classification review

- Select one role using the requirements and evidence.
- Record rejected roles and the boundary between host and AutoVul.
- Freeze stopping, replay, provenance, and privacy requirements.

### Phase E — follow-up by outcome

- `host_strategy`: add host guidance/skill behavior only; no new Core workflow.
- `search_service`: write `introduce-variant-search-service-v1` defining request, candidate observations, cursor/budget, artifacts, and owning-Capability handoff.
- `research_capability`: write `introduce-variant-capability-v1` only if an independent decision predicate is proven.
- `reject`: archive with no implementation.

Any later `variant_validated` policy requires its own accepted SPEC even if a search service is implemented.

## Contracts and artifacts

No public product contract is introduced here. Classification records SHOULD include:

- seed artifact identity and verification level;
- owning Capability and contract version;
- corpus fingerprint and immutable members;
- strategy name/version/configuration and budget;
- deterministic candidate identities and structured match facts;
- expected and observed validation outcomes;
- false-positive/false-negative accounting;
- Analyzer provenance and replay result;
- selected role and rejected alternatives.

No `VariantHypothesis` or `VariantDecision` may be created unless the final role is `research_capability` and a later SPEC is accepted.

## Architecture

No production package or dependency change is authorized. Spikes remain outside the production graph. A later search service would belong behind a narrow Core Port with implementation in an Analyzer/Runner, while host target selection and candidate prioritization remain outside Core.

## Safety and privacy

- Use read-only, explicitly scoped corpora.
- Do not fetch or expand targets without host approval and policy.
- Never execute candidate projects during search.
- Sanitize credentials and minimize private source/snippets.
- Bound all search and retention dimensions.
- Preserve stop/resume without relying on host conversation memory.

## Compatibility and migration

This classification has no public compatibility impact. Existing verification levels and Capabilities remain unchanged. A later implementation SPEC must define artifact/version migration and rollout independently.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-VARIANT-001` through `REQ-VARIANT-008` | Given verified seeds and real families, when classification begins, then candidate search is grounded in reproducible positive and safe counter-examples | Seed artifacts, family manifests, and owning-Capability results |
| `REQ-VARIANT-010` through `REQ-VARIANT-017` | Given the candidate roles, when architecture is reviewed, then Variant does not become a universal IR, duplicate verdict, registry, or Agent loop | Architecture decision record |
| `REQ-VARIANT-020` through `REQ-VARIANT-029` | Given fixed seed/corpus/strategy/budget, when spikes run, then candidate observations are deterministic, bounded, deduplicated, and non-conclusive | Strategy spike artifacts and replay |
| `REQ-VARIANT-030` through `REQ-VARIANT-037` | Given matched, safe, vulnerable, failed, and unsupported candidates, when validated, then only owning-Capability evidence raises verification levels | Real validation matrix |
| `REQ-VARIANT-040` through `REQ-VARIANT-048` | Given private and large corpora, when research runs, then scope, privacy, execution, replay, and follow-up boundaries remain enforced | Safety review and final role record |

## Validation plan

- Focused unit tests: none required before role selection; deterministic strategy spikes MAY use isolated fixtures.
- Failure injection: missing seed artifact, stale corpus fingerprint, unavailable target revision, duplicate candidates, oversized corpus, timeout, unsupported language.
- Real analyzer/target: at least two real variant families validated by owning Capabilities.
- Differential or negative sample: fixed/safe high-similarity cases and at least one vulnerable family member beyond the seed.
- Independent replay: reproduce candidate identities and ordering from the same seed/corpus/strategy without a model.
- Package/integration smoke: deferred to the follow-up implementation SPEC.

## Open questions

- The seed audit in [`evidence/SEED-AUDIT.md`](./evidence/SEED-AUDIT.md) confirms
  one replayed MissingCheck `differential` run as a currently available seed.
  Its temporary artifact root remains an explicit external dependency until a
  retention/privacy decision makes it durable.
- Can deterministic search produce useful candidates beyond exact clone matching without opaque model judgment?
- Which owning Capability and seed artifact should anchor the first family?
- What corpus is explicit and bounded enough for replay while still representative?
- Does any real case require an independent Variant decision, or is search plus owning-Capability validation sufficient?
- What future policy, if any, should permit `variant_validated`?

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-29 | Do not predeclare Variant as a Capability | Search, orchestration, and evidence strength are currently mixed under one name. |
| 2026-08-29 | Require a Verified seed | Variant search must start from evidence, not model speculation. |
| 2026-08-29 | Keep candidate validation with the owning Capability | Similarity is not a domain success predicate. |
| 2026-08-29 | Test `search_service` as the preferred role | It fits deterministic bounded execution while leaving target choice and iteration to the host. |

## Delivery gate

Draft status authorizes seed/family collection and bounded read-only strategy spikes only. It does not authorize public contracts, production modules, capability literals, network discovery, model tools, or support claims.

After real family evidence selects and verifies one role, a separate accepted implementation SPEC is mandatory for production work.

## Verification record

Complete this section before changing the status to Verified.

- Commands and results: Seed audit reviewed the MissingCheck v1 Verified Golden,
  its admission evidence, committed temporary run artifact, and a fresh
  Application-instance replay. The replay returned the original
  `missing_check` `differential` result.
- Requirement-to-evidence mapping: `REQ-VARIANT-002` is satisfied for one
  temporary, path-dependent seed. `REQ-VARIANT-001` and all family/search
  requirements remain blocked by the missing second family and validation corpus.
- Skipped or blocked checks: Family collection, search spikes, production
  implementation, and `variant_validated` policy remain out of scope until the
  corpus gate is satisfied.
- Remaining limitations: Variant has no classified product role and is not implemented or supported.
