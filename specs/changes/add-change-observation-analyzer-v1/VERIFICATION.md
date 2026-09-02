# Change Observation Analyzer v1 requirement verification

- Lifecycle: `Accepted` → `Implemented` → `Verified` → `Archived` on 2026-09-02
- Contract: `autovul.change-observation/1`
- Real adapter: fixed local Git object profile with `typescript@5.9.3`
- Stable behavior: root [`SPEC.md`](../../../SPEC.md) §§2.1, 3.2, 4, and 5.4
- Real-case record: [`evidence/real-git-matrix/RESULTS.json`](./evidence/real-git-matrix/RESULTS.json)

`Covered` means the named focused test or real evidence completed. The real
matrix establishes only deterministic revision facts. It does not claim that
either patch is a vulnerability fix or that either owning Capability has a
decision.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-CHANGEOBS-001` | Covered | Static contracts and `test/change-observation-contract.test.ts` keep the service out of `ResearchCapability`. |
| `REQ-CHANGEOBS-002` | Covered | Literal discriminator/version tests, Pi/CLI labels, and architecture/naming checks exclude `delta`. |
| `REQ-CHANGEOBS-003` | Covered | Contract, Application, Pi, and CLI service-route tests use the exact `autovul_research` branch. |
| `REQ-CHANGEOBS-004` | Covered | Strict tagged-union contract fixtures reject Capability/service hybrids and unknown service values. |
| `REQ-CHANGEOBS-005` | Covered | `ResearchRunService`, `application.ts`, and service tests use explicit static execute/status/cancel/replay routes. |
| `REQ-CHANGEOBS-006` | Covered | Execution-result contract and real script assert operation data only, with no Capability verdict fields. |
| `REQ-CHANGEOBS-007` | Covered | Core contains no Decision Policy or Capability action; real record retains structural facts only. |
| `REQ-CHANGEOBS-008` | Covered | Existing capability tests and architecture checks pass without semantic changes to their differential policies. |
| `REQ-CHANGEOBS-009` | Covered | Pi and CLI tests retain only `autovul_research` and `autovul_run`. |
| `REQ-CHANGEOBS-010` | Covered | Strict input Schema tests reject non-protocol input fields. |
| `REQ-CHANGEOBS-011` | Covered | Trusted-root, canonical-path, and real bare-repository adapter tests cover accepted and rejected repositories. |
| `REQ-CHANGEOBS-012` | Covered | Contract and adapter tests freeze full OIDs and report a missing immutable object structurally. |
| `REQ-CHANGEOBS-013` | Covered | Contract/Core tests reject escaping/glob filters and normalize sorted literal filters. |
| `REQ-CHANGEOBS-014` | Covered | Contract tests cover strict partial budgets, defaults, and each upper bound. |
| `REQ-CHANGEOBS-015` | Covered | `CHANGE_OBSERVATION_LIMITS` contract/Core fixtures cover the complete closed numeric table. |
| `REQ-CHANGEOBS-016` | Covered | Real Git adapter fixture proves an untracked worktree file is not observed. |
| `REQ-CHANGEOBS-017` | Covered | Core normalization/equal-object fixtures return the deterministic empty complete observation. |
| `REQ-CHANGEOBS-018` | Covered | Missing-OID and shallow-history failure fixtures preserve structured diagnostics without fetch/deepen. |
| `REQ-CHANGEOBS-019` | Covered | Contract error-code matrix and adapter/service failure tests use the closed diagnostic set. |
| `REQ-CHANGEOBS-020` | Covered | Observation Schema and Core normalization fixture require every completed structural field. |
| `REQ-CHANGEOBS-021` | Covered | Contract/Core tests retain detected object format, commit/tree OIDs, normalized scope, and resolved budgets. |
| `REQ-CHANGEOBS-022` | Covered | Adapter fixtures cover sorted statuses, confirmed rename, binary/unavailable kinds, and bounded files. |
| `REQ-CHANGEOBS-023` | Covered | Core digest canonicalization and adapter hunk fixtures retain only ranges/counts/digests. |
| `REQ-CHANGEOBS-024` | Covered | Core truncation and adapter binary/oversized fixtures emit structured hunk/diff gaps rather than raw text. |
| `REQ-CHANGEOBS-025` | Covered | Adapter fixtures cover JavaScript/TypeScript declarations and unavailable-parser gaps. |
| `REQ-CHANGEOBS-026` | Covered | Adapter and Core fixtures cover bounded direct-call selector and argument-change facts. |
| `REQ-CHANGEOBS-027` | Covered | Real matrix and adapter fixtures record syntax-only direct-call event facts with bounded locations. |
| `REQ-CHANGEOBS-028` | Covered | Normalization fixtures distinguish complete, partial, and blocked observations. |
| `REQ-CHANGEOBS-029` | Covered | Binary, rename, parser, truncation, and no-filter-match fixtures use structured gap codes only. |
| `REQ-CHANGEOBS-030` | Covered | Real record captures the fixed command profile, Git version, used parser version, and both fingerprints. |
| `REQ-CHANGEOBS-031` | Covered | `test/change-observation-core.test.ts` proves deterministic sort/order, bounds, gaps, and fingerprints. |
| `REQ-CHANGEOBS-032` | Covered | Core owns validation/normalization/fingerprints; architecture check and tests show no Decision Policy. |
| `REQ-CHANGEOBS-033` | Covered | Fixed adapter profile test rejects unsafe Git verbs and target execution; parser is the pinned runtime dependency. |
| `REQ-CHANGEOBS-034` | Covered | Adapter tests cover canonical trusted roots, filter rejection, argument vectors, and disabled external diff/text conversion. |
| `REQ-CHANGEOBS-035` | Covered | Service tests cover idempotency, atomic commit, caller/run/Application cancellation; process and timeout suites cover cleanup/bounds. |
| `REQ-CHANGEOBS-036` | Covered | Service test serializes two concurrent replays for one run. |
| `REQ-CHANGEOBS-037` | Covered | Compact contracts and real evidence retain only structural hashes/relative locations; source stdout is bounded in memory for parsing and never artifacted. |
| `REQ-CHANGEOBS-040` | Covered | Service tests verify atomic `change-observation/` result and explicit route bundle promotion. |
| `REQ-CHANGEOBS-041` | Covered | `research-operation.ts` route schemas/tests retain explicit `analyzer_service` and backwards-readable Capability routes. |
| `REQ-CHANGEOBS-042` | Covered | Fresh-process real replay revalidated both immutable pairs, versions, request/observation fingerprints, and complete normalized semantics. |
| `REQ-CHANGEOBS-043` | Covered | Service replay tests and the relocated real root prove the original result SHA-256 is unchanged; replay writes only below `change-observation-replay/`. |
| `REQ-CHANGEOBS-044` | Covered | Replay tests separately cover revision, request, version, semantic, evidence-mutation, cancellation, and blocked outcomes. |
| `REQ-CHANGEOBS-045` | Covered | Real OpenClaw record captures the bounded added authorization-call fact without a MissingCheck decision. |
| `REQ-CHANGEOBS-046` | Covered | Real Ghost record captures the bounded added session-regeneration call against the resolved parent without a Typestate decision. |
| `REQ-CHANGEOBS-047` | Covered | Both real records assert that Capability, hypothesis, decision, verification-level, and security-conclusion fields are absent. |
| `REQ-CHANGEOBS-048` | Covered | Real cases replayed in a fresh Node process from a relocated root; focused lifecycle tests cover timeout/cancellation/serialized replay and mutation outcomes. |

## Final gates

Passed on 2026-09-02:

```text
npm run check
AUTOVUL_RUN_REAL=1 ... npm run test:change-observation-real
AUTOVUL_RUN_REAL=1 ... AUTOVUL_CHANGEOBS_MODE=replay node test/change-observation-real.mjs
```

The real execute gate used only pre-fetched immutable local objects for the
OpenClaw TypeScript authorization revision pair and Ghost JavaScript
session-fixation repair pair. The separate replay process used a copied runs
root. Both comparisons returned `match`; the two original result artifacts
retained their recorded SHA-256 digests before and after replay. The full
details, including OIDs and structural facts, are in `RESULTS.json`.

No requirement mapping or verification gate is pending. The supported boundary
is the static Change Observation service described in root `SPEC.md`, not a
Delta Capability, generic Git facility, generic Analyzer framework, or Variant
search feature.
