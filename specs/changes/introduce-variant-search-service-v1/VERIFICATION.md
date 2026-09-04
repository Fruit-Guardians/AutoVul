# Variant Search Service v1 Requirement Verification

- Status: Implemented & Verified
- Public contract: `autovul.variant-search/1`
- Supported seed: `autovul.missing-check/1` (`reproduced`, `differential`, `variant_validated`)
- Real variant families:
  - Family 1: OpenClaw MSTeams Token Exchange (`openclaw-token-exchange`, CVE-2026-43572, MIT)
  - Family 2: Webhook Signature Verification (`webhook-signature-verification`, GHSA-c7m8-356v-94p6, Apache-2.0)
- Evidence manifests:
  - `evidence/manifests/openclaw-msteams-family.json`
  - `evidence/manifests/webhook-auth-family.json`
- Verification suite:
  - `test/variant-search-service.test.ts`
  - `test/variant-search-git-adapter.test.ts`
  - `test/variant-search-family-verification.test.ts`

`Covered` means the requirement is verified by deterministic automated tests and real Git / AST / CFG analyzer execution without fake success or bypassed boundaries.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-VARSEARCH-001` | Covered | Variant Search is typed as an Analyzer Service (`VARIANT_SEARCH_SERVICE = "variant_search"`), does not appear in Capability discriminator or Decision union; `test/research-architecture.test.ts`. |
| `REQ-VARSEARCH-002` | Covered | Routed through `research({ service: "variant_search" })` and `manageRun({ action: "replay" })` on Application; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-003` | Covered | Pi extension, DeepSeek harness, and CLI thin adapters route directly to Application API without duplicating search logic; `test/cli.test.ts`, `test/pi-extension.test.ts`. |
| `REQ-VARSEARCH-010` | Covered | `extractSeedPatternFacts` validates seed manifest existence, completion, and rejects unverified seeds (`generated`/`compiled`); `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-011` | Covered | Seed artifact parsed strictly through `MissingCheckRunArtifactSchema`; duck-typing is forbidden; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-012` | Covered | V1 strictly requires `route_kind: "capability"` and `capability: "missing_check"`; non-missing_check seeds rejected with stable domain error; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-013` | Covered | Service observation and result artifact bind `seed_run_id`, `seed_capability`, `seed_digest`, `seed_verification_level`, and `strategy_version`; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-020` | Covered | `GitVariantSearchAdapter` requires explicit `git_revision` targets and validates `trustedRoots`; untrusted roots rejected; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-021` | Covered | Strategy name and version (`autovul.variant-search-strategy/1`) are checked; fixed inputs yield identical observations; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-022` | Covered | Candidate ID is canonical SHA-256 binding `seedDigest:revision:file:startLine:symbol:strategy:strategyVersion`, free of private repository path; clone test proves candidate ID portability; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-023` | Covered | Candidates sorted deterministically by revision, file, and start line; duplicate candidate IDs deduplicated; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-030` | Covered | Observation distinguishes `complete` and `partial` via `completeness` and structured `gaps` (`candidate_budget_exhausted`, `file_budget_exhausted`, `timeout_exhausted`, `parser_failed`, `object_unreadable`, `revision_unavailable`); `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-031` | Covered | Non-match returns empty candidates with `complete` and empty gaps, distinguishable from budget or parsing gaps; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-032` | Covered | Target, file, candidate, and timeout budgets enforced; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-033` | Covered | Candidate budget limit stops search, preserves discovered candidates, sets `completeness: "partial"`, and records structured gap; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-034` | Covered | Candidate output includes location, enclosing symbol, matched symbols, and individual evidence ref; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-035` | Covered | Failures return stable codes, field paths, and retryability; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-040` | Covered | Route, result, and candidate evidence files staged and promoted atomically via `stageArtifactBundle`/`promoteArtifactBundle`; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-041` | Covered | Candidate evidence and results store only relative paths, normalized symbols, and digests; `test/variant-search-git-adapter.test.ts`. |
| `REQ-VARSEARCH-042` | Covered | Replay executes under run lock without model or host session; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-043` | Covered | Preflight checks in replay validate seed existence, seed digest, strategy version, analyzer version, and candidate evidence integrity before re-execution; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-044` | Covered | Replay compares full normalized observation including completeness, gaps, candidate IDs, ordering, and candidate facts; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-045` | Covered | Replay proves original result artifact unchanged and writes comparison under `research/replay/{ordinal}`; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-046` | Covered | Replay outcomes distinguish `identical`, `diverged`, `evidence_mutated`, `failed`, `cancelled`; `test/variant-search-service.test.ts`. |
| `REQ-VARSEARCH-050` | Covered | Variant Search result contains only candidate facts and no Capability decision or verification level; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-051` | Covered | Candidate validation is separate execution of MissingCheck; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-052` | Covered | Two licensed real variant families (`openclaw-token-exchange` and `webhook-signature-verification`), vulnerable members, fixed counter-examples, and high-similarity safe counter-examples verified; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-053` | Covered | Structural strategy extracts AST scopes and enclosing symbols; exact text search returns raw hits without semantic enclosing function or dominating guard context; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-054` | Covered | Non-seed candidate validated by MissingCheck reaches real `differential` verification level on both families; `test/variant-search-family-verification.test.ts`. |
| `REQ-VARSEARCH-055` | Covered | Replay of family search runs verifies candidate identity, ordering, and evidence digests with `status: "identical"`; `test/variant-search-family-verification.test.ts`. |

## Verification Command Gate

Passed:

```bash
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```
