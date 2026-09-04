# Change: Introduce Variant Search Service v1

- Change ID: `introduce-variant-search-service-v1`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-09-03
- Updated: 2026-09-04
- Public contract: `autovul.variant-search/1`
- Depends on: verified `classify-variant-research-role`, verified `harden-capability-execution-contracts-v1`, and an archived owning Capability with a real `reproduced` or stronger seed
- Implementation checkpoint: contracts, Core service/Port/replay, Git adapter, aggregate routing, host projections, two real family manifests, real MissingCheck validation of non-seed candidates, and independent replay are implemented and verified in test/variant-search-family-verification.test.ts and VERIFICATION.md

## Problem

An Agent can generalize a known vulnerability and choose where to search, but repeatedly scanning an explicit corpus for deterministic structural matches is bounded tool work. AutoVul needs a service that starts from a verified Capability result, searches only host-approved immutable Git targets, and returns reproducible candidate facts.

Candidate generation has no independent vulnerability success predicate. Variant Search is therefore an Analyzer Service beside Change Observation. It is not a fourth Research Capability, does not create a `VariantHypothesis` or `VariantDecision`, and cannot raise a candidate to `reproduced`, `differential`, or `variant_validated`.

## Responsibility boundary

The host Agent MUST:

- choose a committed seed run;
- approve the exact corpus, strategy, budget, and next batch;
- decide which candidates are relevant;
- construct or revise the owning Capability hypothesis;
- execute candidate validation and decide when to stop.

AutoVul MUST:

- validate seed strength and provenance;
- derive only the pattern facts defined by this version;
- inspect explicit immutable Git objects without executing target code;
- enforce target, file, candidate, output, and time budgets;
- persist deterministic candidate facts and evidence atomically;
- replay the service without a model or originating host session.

AutoVul MUST NOT discover repositories, fetch network content, prioritize an open-ended hunt, formulate the next hypothesis, validate every candidate automatically, or report a vulnerability verdict from similarity.

## V1 scope

### In scope

- One public Analyzer Service branch: `service: "variant_search"` and `service_version: "autovul.variant-search/1"`.
- A committed real seed whose owning Capability result is at least `reproduced`.
- Explicit local Git repositories and immutable full commit identities under configured `trustedRoots`.
- JavaScript and TypeScript syntax supported by the fixed parser profile.
- Versioned deterministic match strategies accepted by the v1 schema.
- Bounded candidate observations, match facts, provenance, gaps, and run-relative evidence references.
- A static Application/replay branch under `autovul_research` and `autovul_run`.
- Thin Pi, DeepSeek function-calling, and CLI projections over the shared Application API.

### Out of scope

- A `variant` Capability, universal vulnerability-pattern IR, embedding platform, similarity ontology, search registry, or dynamic service loader.
- Remote Git operations, package-registry enumeration, web crawling, cloning, or corpus expansion.
- LLM calls, semantic ranking, autonomous target selection, or an iterative hunt loop inside AutoVul.
- Target builds, installs, tests, proof-of-concept execution, or service startup.
- A `variant_validated` policy. That evidence level requires a separate accepted policy SPEC.
- Cross-language normalization beyond the explicitly accepted v1 parser and strategy pairings.

## Contract

The model-visible request MUST stay compact:

```text
action: execute
service: variant_search
service_version: autovul.variant-search/1
input:
  seed_run_id
  corpus[]: immutable Git target
  strategy + strategy version
  optional bounded budget
```

The model-visible result MUST contain only fields that can change a host action:

```text
operation_status
run_id
service + service_version
observation:
  seed/corpus/strategy identity
  completeness + analysis_gaps
  bounded candidate summaries and match facts
  inspected counts + budget state
  analyzer provenance + evidence refs
diagnostics
allowed_next_actions
artifact_ref
```

Raw source, large snippets, parser output, Git stderr, and full corpus metadata belong in artifacts, subject to privacy limits. Candidate summaries MUST NOT contain a vulnerability verdict or an owning Capability decision.

## Requirements

### Role and routing

- `REQ-VARSEARCH-001`: Variant Search MUST be an Analyzer Service and MUST NOT appear in the Capability discriminator, shared Hypothesis envelope, Capability Decision union, or verification-level policy.
- `REQ-VARSEARCH-002`: The service MUST use one explicit static Application branch under `autovul_research`; replay MUST use one explicit static branch under `autovul_run`. No third model-facing tool, registry, loader, or generic Analyzer-Service framework may be introduced.
- `REQ-VARSEARCH-003`: Pi, DeepSeek, and CLI adapters MUST delegate to the same Application API and MUST NOT copy seed, search, evidence, or replay policy.

### Seed admission

- `REQ-VARSEARCH-010`: The request MUST identify a committed seed run. Missing, non-terminal, failed, cancelled, `generated`, `compiled`, fake, or structurally invalid seeds MUST be rejected with a stable structured diagnostic.
- `REQ-VARSEARCH-011`: A seed MUST be parsed through its owning Capability's versioned artifact schema. Duck-typing arbitrary JSON fields or accepting a completed manifest without checking the recorded verification level and Analyzer provenance is forbidden.
- `REQ-VARSEARCH-012`: V1 MUST declare the exact owning Capabilities and artifact versions from which it can derive pattern facts. An unsupported Capability or historical artifact version MUST return `unsupported` or `blocked`; it MUST NOT guess selectors.
- `REQ-VARSEARCH-013`: The committed service artifact MUST bind the seed run id, owning Capability/version, verification level, result-artifact digest, evidence identity, and normalized derived pattern facts.

### Corpus and strategy identity

- `REQ-VARSEARCH-020`: Every corpus member MUST be an explicit local Git target with a canonical trusted repository, immutable full commit OID, and optional expected fingerprint. Worktree/index state, symbolic moving refs, network results, and automatically added targets are forbidden.
- `REQ-VARSEARCH-021`: Strategy name and version MUST be explicit and closed by the public schema. Fixed seed, corpus, strategy version, Analyzer version, and budget MUST produce the same normalized observation or a classified gap.
- `REQ-VARSEARCH-022`: Candidate identity MUST bind seed identity, corpus member identity, immutable revision, normalized location, strategy/version, and relevant match facts. It MUST remain stable across a relocated trusted root and MUST NOT depend on a private canonical repository path.
- `REQ-VARSEARCH-023`: Candidate ordering and deduplication MUST be deterministic. Equal observations from retry or replay MUST not create duplicate candidate identities.

### Bounded observation

- `REQ-VARSEARCH-030`: The observation MUST distinguish complete and partial analysis and MUST record bounded structured gaps for file truncation, candidate truncation, timeout, unsupported syntax/language, parser failure, unreadable objects, and unavailable revisions.
- `REQ-VARSEARCH-031`: A non-match, unsupported file, not-run target, and operational failure MUST remain distinguishable. Absence of candidates MUST NOT be presented as a complete negative unless every declared boundary completed.
- `REQ-VARSEARCH-032`: Target count, files per target, candidate count, output bytes, elapsed time, concurrency, evidence references, and retained source material MUST be bounded by the contract or fixed adapter limits.
- `REQ-VARSEARCH-033`: Reaching any budget MUST stop the affected work, preserve already committed facts, set an accurate partial/budget state, and return a stable diagnostic rather than silently slicing data.
- `REQ-VARSEARCH-034`: Candidate output MUST include bounded, structured match facts sufficient for the host to construct or revise an owning Capability hypothesis. Opaque model scores and unexplained embedding distances are forbidden.
- `REQ-VARSEARCH-035`: Analyzer failures, cancellation, environment blocks, and invalid input MUST use stable codes, optional field paths, retryability, and allowed next actions. Model-visible prose MUST NOT be the only distinction.

### Artifacts and replay

- `REQ-VARSEARCH-040`: The route, result, candidate evidence, provenance, resolved budget, and their digests MUST be staged and promoted as one validated atomic bundle before the run becomes authoritative.
- `REQ-VARSEARCH-041`: Portable artifacts MUST minimize private repository names and source. Any non-relocatable dependency MUST be explicit; credentials, unrestricted environment data, Git configuration, stderr, and unrelated metadata MUST NOT be persisted.
- `REQ-VARSEARCH-042`: Replay MUST run under the shared per-run lease and cancellation chain without a model or host session.
- `REQ-VARSEARCH-043`: Before search, replay MUST validate route/service version, seed identity and evidence digest, corpus target identity/fingerprint, strategy/version, Analyzer/adapter version, parser version, and resolved budget.
- `REQ-VARSEARCH-044`: Replay MUST compare the full normalized observation: completeness, gaps, inspected counts, budget state, candidates, ordering, match facts, provenance, and normalized evidence references. Candidate count/id comparison alone is insufficient.
- `REQ-VARSEARCH-045`: Replay MUST prove the original route, result, and candidate evidence are unchanged before and after re-execution and MUST write replay output only below a dedicated replay namespace.
- `REQ-VARSEARCH-046`: Replay outcomes MUST distinguish match, environment block, version difference, semantic mismatch, evidence mutation, cancellation, and operational failure through structured codes.

### Evidence strength and real verification

- `REQ-VARSEARCH-050`: A completed search result is an Analyzer observation only. It MUST NOT contain a Capability decision or raise any vulnerability verification level.
- `REQ-VARSEARCH-051`: Candidate validation MUST be a separate host-selected execution of the owning Capability. Failed, timed-out, unsupported, or skipped validation remains unknown and cannot count as a safe case.
- `REQ-VARSEARCH-052`: Verified status MUST include at least two licensed real variant families, at least two vulnerable members, at least two safe/fixed counter-examples, and at least one high-similarity safe case.
- `REQ-VARSEARCH-053`: The real matrix MUST compare the accepted structural strategy with a conservative exact/text baseline and record candidates, false positives, misses, budgets, provenance, and required host choices.
- `REQ-VARSEARCH-054`: At least one non-seed candidate MUST be validated by its owning Capability through real `reproduced` or `differential` evidence. Search output alone cannot satisfy this requirement.
- `REQ-VARSEARCH-055`: The verified matrix MUST replay from a fresh process with a relocated runs root or explicit non-relocatable corpus overrides, preserve original artifact digests, and reproduce candidate identity and ordering.

## Failure semantics

| Condition | Required result |
| --- | --- |
| Missing or weak seed | `failed` or `blocked` with seed-specific code; Analyzer not invoked |
| Unsupported seed Capability/version | `blocked` with allowed versions; no guessed pattern facts |
| Untrusted repository or fingerprint mismatch | `blocked`; no source read outside policy |
| File/candidate/time/output budget reached | partial observation with exact gap and retryable revision path where applicable |
| Parser unsupported or failed | target/file gap; no invented match or negative result |
| Cancellation | `cancelled`; process tree and lease released; no success commit |
| Artifact commit failure | failed/recoverable run; no authoritative completed state |
| Replay version or environment difference | classified comparison; original evidence strength not preserved silently |
| Candidate match | `generated` search fact only; host may execute the owning Capability |

## Implementation plan

### Phase A — accepted contract and static routing

- Freeze the service request, strategy/version, budget, observation, diagnostic, artifact, and replay schemas.
- Add explicit Application, Pi, DeepSeek, and CLI branches without a registry.
- Status gate: remain `Accepted` until every normative contract field is implemented.

### Phase B — seed and Git adapter hardening

- Parse allowed seed artifacts through their real schemas and enforce verification/provenance/evidence gates.
- Bind portable seed/corpus/strategy identities and remove local paths from candidate digests.
- Return exact completeness and gaps for every truncation or unsupported boundary.

### Phase C — atomic evidence and replay

- Commit route, result, and candidate evidence as one staged bundle.
- Add preflight identity/version/digest checks, full semantic comparison, evidence immutability, and replay namespace isolation.
- Mark `Implemented` only after all requirements have code and deterministic failure coverage.

### Phase D — real family matrix

- Freeze two family manifests with immutable revisions, licenses, expected members, safe/fixed counter-examples, and strategy baselines.
- Validate selected candidates through the owning Capabilities.
- Run fresh-process replay and aggregate Pi/DeepSeek/CLI acceptance.
- Write `VERIFICATION.md` with one row per requirement before changing status to `Verified`.

### Phase E — archival

- Merge only the verified stable behavior into root `SPEC.md`.
- Keep this change and its evidence for traceability; do not convert search candidates into findings or `variant_validated` claims.

## Requirement traceability

| Requirement range | Current implementation | Verification state |
| --- | --- | --- |
| `REQ-VARSEARCH-001`–`003` | Contracts and explicit Application/host branches exist in the working tree | Verified: `test/research-architecture.test.ts`, `test/cli.test.ts`, `test/pi-extension.test.ts` |
| `REQ-VARSEARCH-010`–`013` | Seed extraction via `MissingCheckRunArtifactSchema` and verification gate | Verified: `test/variant-search-service.test.ts` |
| `REQ-VARSEARCH-020`–`023` | Trusted-root Git adapter, immutable revisions, portable candidate IDs, and deterministic sorting | Verified: `test/variant-search-git-adapter.test.ts` |
| `REQ-VARSEARCH-030`–`035` | Completeness, structured gaps, candidate/file/timeout budgets, and structured diagnostics | Verified: `test/variant-search-git-adapter.test.ts`, `test/variant-search-service.test.ts` |
| `REQ-VARSEARCH-040`–`046` | Atomic staged bundle, preflight checks, full comparison, immutability, and replay namespace | Verified: `test/variant-search-service.test.ts`, `test/variant-search-family-verification.test.ts` |
| `REQ-VARSEARCH-050`–`055` | Two real families, safe counter-examples, owning MissingCheck validation, and fresh replay | Verified: `test/variant-search-family-verification.test.ts`, `VERIFICATION.md` |

## Acceptance criteria

| Gate | Given / When / Then | Evidence |
| --- | --- | --- |
| Seed admission | Given weak, fake, corrupt, unsupported, and valid real seeds, when search is requested, then only the valid supported seed reaches the Analyzer | Contract tests and real seed artifacts (`test/variant-search-service.test.ts`) |
| Determinism | Given fixed seed, corpus, strategy/version, Analyzer version, and budget, when run twice and relocated, then normalized candidate identity and order match | Portable clone test and replay artifact (`test/variant-search-git-adapter.test.ts`) |
| Honest partial result | Given each budget, parser, target, timeout, and cancellation boundary, when it is reached, then the exact gap and operation state are preserved | Failure-injection tests (`test/variant-search-git-adapter.test.ts`) |
| Atomic evidence | Given failure at each write/promote boundary, when recovery runs, then no completed state references missing or mutable evidence | Artifact staging tests (`test/variant-search-service.test.ts`) |
| No verdict inflation | Given matching and high-similarity safe candidates, when search completes, then no Capability decision or verification level is emitted | Schema tests and safe case (`test/variant-search-family-verification.test.ts`) |
| Owning validation | Given a selected non-seed candidate, when its Capability executes, then only that Capability's accepted real gate may produce `reproduced` or `differential` | Real MissingCheck validation (`test/variant-search-family-verification.test.ts`) |
| Host independence | Given Pi, DeepSeek, and CLI, when the same request/status/replay sequence runs, then every adapter delegates to one Application behavior | Aggregate acceptance tests (`test/cli.test.ts`, `test/pi-extension.test.ts`) |

## Compatibility and migration

The service is not part of the archived product baseline. Its schemas and artifacts may change while this SPEC is Accepted, but every breaking change MUST update this SPEC, tests, and any existing development artifact reader together. Historical development artifacts that lack required replay identity MUST fail with a classified compatibility result rather than crash or inherit their previous evidence strength.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-09-03 | Use an Analyzer Service, not a Capability | Similarity creates candidates; the owning Capability supplies the vulnerability predicate. |
| 2026-09-03 | Keep one aggregate research/run surface | A strategy-specific tool set would expand the model surface and duplicate routing. |
| 2026-09-03 | Use explicit immutable local Git corpora in v1 | This keeps search read-only, bounded, and replayable without network policy. |
| 2026-09-04 | Return the SPEC to Accepted | Production code and repository tests exist, but the parent classification evidence, replay invariants, and real two-family gate are incomplete. |
| 2026-09-04 | Promote SPEC to Verified | Verified seed schema gate, canonical portable candidate IDs, atomic bundles, two real families, high-similarity safe counter-examples, owning MissingCheck validation, and replay invariants verified. |

## Verification record

- Repository implementation: contract, Port, service, replay, Git adapter, aggregate routes, host projections, two real family manifests, and comprehensive test suites implemented.
- `VERIFICATION.md` and real family evidence manifests (`evidence/manifests/openclaw-msteams-family.json`, `evidence/manifests/webhook-auth-family.json`) committed.
- Both real families verified with real Git revisions, vulnerable members, fixed counter-examples, and high-similarity safe counter-examples in `test/variant-search-family-verification.test.ts`.
- Non-seed candidates validated by MissingCheck (`javascript_cfg` adapter) reaching real `differential` verification level.
- High-similarity safe counter-examples verified by MissingCheck to confirm `check_present` and prevent false-positive inflation.
- Clean replay under `research/replay/{ordinal}` verifying candidate identity, ordering, and evidence digest immutability.
- Verification conclusion: Verified; ready for archival consideration into root SPEC when appropriate.
