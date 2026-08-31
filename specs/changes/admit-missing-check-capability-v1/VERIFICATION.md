# MissingCheck v1 requirement verification

- Status: Archived after re-verification on 2026-08-31
- Contract: `autovul.missing-check/1`
- Real case: OpenClaw CVE-2026-43572
- Portable evidence: `evidence/openclaw-cve-2026-43572/PORTABLE-GOLDEN.json`

`Covered` means the implementation and named check or artifact passed the final
command gate and the real Analyzer gate.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-MCHECK-001` | Covered | Admission record and `test/missing-check-admission-evidence.test.ts` distinguish the check relation from Flow. |
| `REQ-MCHECK-002` | Covered | Independent contracts, `core/src/missing-check`, adapter, Golden and replay branches; architecture check forbids Flow domain reuse. |
| `REQ-MCHECK-003` | Covered | `MissingCheckResearchService`, shared status/artifact/cancellation services, and aggregate replay tests. |
| `REQ-MCHECK-004` | Covered | `research-operation.ts` stores only the explicit route; capability fields remain in the MissingCheck artifact. |
| `REQ-MCHECK-005` | Covered | Static `missing_check` branches in Application and run routing; `test/research-architecture.test.ts`. |
| `REQ-MCHECK-006` | Covered | Architecture check and repository inspection show no production Typestate, Delta, or Variant module. |
| `REQ-MCHECK-007` | Covered | Pi/CLI expose only aggregate `autovul_research` and `autovul_run`. |
| `REQ-MCHECK-008` | Covered | Service validates or executes only the supplied hypothesis and returns bounded revision hints. |
| `REQ-MCHECK-009` | Covered | The change passed implementation and real verification gates before archival; root SPEC v1.3 now owns stable behavior. |
| `REQ-MCHECK-010` | Covered | `MISSING_CHECK_HYPOTHESIS_VERSION` and strict literal Schema. |
| `REQ-MCHECK-011` | Covered | `MissingCheckHypothesisSchema` owns exactly one operation, check, relation, and scope. |
| `REQ-MCHECK-012` | Covered | `MissingCheckSelectorSchema`; architecture import check prevents Flow endpoint aliasing. |
| `REQ-MCHECK-013` | Covered | Closed `direct_call` selector plus admission case and validator tests. |
| `REQ-MCHECK-014` | Covered | Closed `same_callback_cfg_dominates_operation` relation plus real CodeQL witness. |
| `REQ-MCHECK-015` | Covered | `single_file_named_entry_cfg` is enforced in generated CodeQL and echoed in completeness evidence; mismatch tests return `unknown`. |
| `REQ-MCHECK-016` | Covered | Target/analyzer/mode/budget/idempotency remain in the research envelope, not the hypothesis. |
| `REQ-MCHECK-017` | Covered | Strict hypothesis Schema rejects pre-decided result properties. |
| `REQ-MCHECK-018` | Covered | Strict singular fields and `additionalProperties: false`. |
| `REQ-MCHECK-019` | Covered | TypeBox Schema and semantic validator reject unknown properties and closed-set violations. |
| `REQ-MCHECK-020` | Covered | `validateMissingCheckHypothesis(input: unknown)` returns normalized hypothesis or bounded issues. |
| `REQ-MCHECK-021` | Covered | Validator tests assert stable codes, JSON Pointer paths, and `allowed_values`. |
| `REQ-MCHECK-022` | Covered | Pure validator has no ports; architecture tests assert validation does not execute. |
| `REQ-MCHECK-023` | Covered | Validator rejects missing selectors, old/unbounded scope forms, unsupported relation, and unknown fields. |
| `REQ-MCHECK-024` | Covered | Envelope action Schema is closed; successful `check_missing` results expose only `replay/stop` and carry no contradictory revision hint. |
| `REQ-MCHECK-025` | Covered | Closed revision actions include operation, check, relation, and scope. |
| `REQ-MCHECK-026` | Covered | Revision hint Schema requires action, JSON Pointer path, and reason code. |
| `REQ-MCHECK-027` | Covered | No Core result contains or applies a replacement hypothesis. |
| `REQ-MCHECK-028` | Covered | Decision tests bind every hint to an observation and assert that hints are empty when revision is not an allowed next action. |
| `REQ-MCHECK-029` | Covered | Model-visible diagnostics are structured; no prose recommendation substitutes for them. |
| `REQ-MCHECK-030` | Covered | `MissingCheckExecutionPort` returns observations only; Decision Policy is Core-owned. |
| `REQ-MCHECK-031` | Covered | Observation Schema separately records subjects, relations, per-side completeness, provenance, gaps, and evidence refs. |
| `REQ-MCHECK-032` | Covered | Closed `observed`, `not_found`, `not_run` subject states and policy tests. |
| `REQ-MCHECK-033` | Covered | Closed relation states; inconclusive and missing-selector tests do not become absence proof. |
| `REQ-MCHECK-034` | Covered | Capability gaps and incomplete/scope-mismatch completeness force `unknown`. |
| `REQ-MCHECK-035` | Covered | Adapter does not import or emit decision/verification fields; Core Decision Policy writes both. |
| `REQ-MCHECK-036` | Covered | Closed `check_missing`, `check_present`, `unknown` outcome Schema. |
| `REQ-MCHECK-037` | Covered | `check_missing` requires an unchecked witness whose evidence ref resolves in `evidence_refs`. |
| `REQ-MCHECK-038` | Covered | `check_present` requires a checked witness plus exact completed scope. |
| `REQ-MCHECK-039` | Covered | Timeout, cancellation, unavailable Analyzer, SARIF parse failure, incomplete scope, and completed unknown have distinct statuses/codes; unreadable SARIF cannot report complete. |
| `REQ-MCHECK-040` | Covered | Probe mode remains `generated` and cannot establish reproduction. |
| `REQ-MCHECK-041` | Covered | Reproduce raises only from a complete, persisted vulnerable unchecked witness. |
| `REQ-MCHECK-042` | Covered | Real Golden records vulnerable unchecked and fixed checked witnesses before `differential`. |
| `REQ-MCHECK-043` | Covered | Fixed `not_run`/incomplete/missing scope tests cannot satisfy fixed policy. |
| `REQ-MCHECK-044` | Covered | Decision Policy never emits `variant_validated`. |
| `REQ-MCHECK-045` | Covered | Provenance distinguishes `real_analyzer` from `test_double`; test doubles are capped at `generated`, and real observations without exact CLI/adapter versions are blocked. |
| `REQ-MCHECK-046` | Covered | Compact result independently stores operation status, decision, and verification level. |
| `REQ-MCHECK-047` | Covered | Portable evidence binds exact completeness boundary and Analyzer/adapter versions; adapter and Core gates prevent a versionless success artifact. |
| `REQ-MCHECK-048` | Covered | Failure artifacts retain hypothesis scope, status/code, target input, and replay route. |
| `REQ-MCHECK-049` | Covered | Portable Golden contains compact witnesses, decisions, hashes, and replay result without requiring raw Analyzer prose. |
| `REQ-MCHECK-050` | Covered | Stable request digest/idempotency run id and conflict test. |
| `REQ-MCHECK-051` | Covered | Shared trusted-root, timeout, live cancellation, lock, recovery, and process-tree services are reused. |
| `REQ-MCHECK-052` | Covered | Artifact Schema records protocol, targets, portable fingerprints, provenance, scope, observations, policy, result, budget, and replay inputs. |
| `REQ-MCHECK-053` | Covered | Route and result are staged and promoted as one artifact bundle before run completion. |
| `REQ-MCHECK-054` | Covered | Replay distinguishes missing/unavailable/different fingerprint, unavailable/different Analyzer version, environment block, and semantic mismatch. |
| `REQ-MCHECK-055` | Covered | Adapter persists bounded locations/refs and sanitized version output, not arguments, environment, or raw process logs. |
| `REQ-MCHECK-056` | Covered | Real Golden uses CodeQL build-mode none on staged source; adapter invokes no target scripts. |
| `REQ-MCHECK-057` | Covered | Flow contracts/artifacts remain unchanged; portable fingerprint is additive and MissingCheck-specific in policy. |
| `REQ-MCHECK-058` | Covered | Pi/CLI use aggregate Application APIs and add no MissingCheck-specific tool. |
| `REQ-MCHECK-059` | Covered | Implementation remains in existing contracts/core/codeql-runner/integration packages. |

## Final command gate

Passed on 2026-08-31:

```text
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
npm run test:missing-check-golden-real
```

The original unit/integration suite passed 27 files and 154 tests. The real Golden used
CodeQL 2.26.1, returned `differential`, and reproduced the same result in a fresh
Node process without a model or target build/install/test script.

## Archived boundary re-verification

The 2026-08-31 narrow repair added explicit regression coverage for unreadable
SARIF, unavailable Analyzer version provenance, hint/action consistency, Pi
validation terminal rendering, and composed-signal listener cleanup. After the
repair:

- `npm run lint && npm test && npm run pack:check` passed with 28 test files and
  160 tests; all 5 package outputs were clean.
- `npm run test:missing-check-golden-real` passed with CodeQL 2.26.1,
  vulnerable `check_missing`, fixed `check_present`, `differential`, and an
  identical fresh-process replay.
- The Golden source loader fell back from rate-limited GitHub raw content to the
  official Contents API while retaining immutable commit and SHA-256 checks.

No requirement mapping is pending. MissingCheck v1 remains `Archived`; root
`SPEC.md` v1.3 remains the normative supported-behavior source.
