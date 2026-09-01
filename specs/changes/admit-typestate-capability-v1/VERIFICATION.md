# Typestate v1 requirement verification

- Lifecycle: `Implemented` → `Verified` → `Archived` on 2026-09-01
- Contract: `autovul.typestate/1`
- Real case: Ghost admin session fixation, CVE-2026-70594
- Real Analyzer: CodeQL JavaScript 2.26.1, `--build-mode=none`
- Stable behavior: root [`SPEC.md`](../../../SPEC.md) §5.3

`Covered` means the named implementation and test or real evidence ran. The
real Golden is the only source for real vulnerability claims; pure and fake
adapter tests cover policy and failure behavior only.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-TSTATE-001` | Covered | Frozen Ghost admission case and `test/typestate-golden-real.mjs`. |
| `REQ-TSTATE-002` | Covered | Admission README/RESULTS distinguish Typestate from Flow and MissingCheck. |
| `REQ-TSTATE-003` | Covered | Independent contracts, `core/src/typestate`, CodeQL adapter, Golden, and replay service. |
| `REQ-TSTATE-004` | Covered | Research/replay services reuse shared status, cancellation, artifact, and operation lease ports. |
| `REQ-TSTATE-005` | Covered | `ResearchRunService` stores only explicit routes; Typestate semantic fields stay capability-owned. |
| `REQ-TSTATE-006` | Covered | Static `typestate` branches in Application/run routing; architecture check rejects a registry. |
| `REQ-TSTATE-007` | Covered | Pi/CLI real Golden routes only through aggregate `autovul_research` and `autovul_run`. |
| `REQ-TSTATE-008` | Covered | The Pi provider supplies validation, execute, and replay actions; Core returns only structured hints/actions. |
| `REQ-TSTATE-009` | Covered | Verification and root-spec merge occurred before archival; no earlier support claim is retained. |
| `REQ-TSTATE-010` | Covered | Literal schema/version tests in `test/typestate.test.ts`. |
| `REQ-TSTATE-011` | Covered | Strict `TypestateHypothesisSchema` and validator matrix. |
| `REQ-TSTATE-012` | Covered | Typestate selector schemas are independent of Flow/MissingCheck imports. |
| `REQ-TSTATE-013` | Covered | TypeBox identifier/count bounds and validation tests. |
| `REQ-TSTATE-014` | Covered | Transition schema and unknown-endpoint validator tests. |
| `REQ-TSTATE-015` | Covered | Closed `prohibited_transition`/same-identity schema and policy tests. |
| `REQ-TSTATE-016` | Covered | Resource identity/alias fields and direct-binding adapter predicates. |
| `REQ-TSTATE-017` | Covered | Strict hypothesis excludes execution, evidence, presentation, and target fields. |
| `REQ-TSTATE-018` | Covered | Additional-properties validation rejects precomputed conclusion fields. |
| `REQ-TSTATE-019` | Covered | Bounded schema/validator rejects unbounded and unsupported protocol forms. |
| `REQ-TSTATE-020` | Covered | `validateTypestateHypothesis(input: unknown)` returns normalized input or bounded issues. |
| `REQ-TSTATE-021` | Covered | Validator tests assert stable codes, JSON Pointers, and closed repair values. |
| `REQ-TSTATE-022` | Covered | Pure validation tests assert no run, artifact, or Analyzer call. |
| `REQ-TSTATE-023` | Covered | Duplicate, endpoint, initial-state, prohibited-allowed, identity, and unknown-field tests. |
| `REQ-TSTATE-024` | Covered | `TYPESTATE_LIMITS` and schema-bound tests cover every frozen bound. |
| `REQ-TSTATE-025` | Covered | Result/action schemas and decision snapshots restrict the envelope set. |
| `REQ-TSTATE-026` | Covered | Closed revision-action schema and decision fixtures. |
| `REQ-TSTATE-027` | Covered | Hints carry a path/reason and are tied to observations or evidence. |
| `REQ-TSTATE-028` | Covered | Core contains no replacement-hypothesis or auto-revision path. |
| `REQ-TSTATE-029` | Covered | Model-facing validator/decision results are structured, bounded fields. |
| `REQ-TSTATE-030` | Covered | `TypestateExecutionPort` returns observation only; adapter has no decision logic. |
| `REQ-TSTATE-031` | Covered | Observation schema separates resource, events, traces, identity, completeness, gaps, provenance, and refs. |
| `REQ-TSTATE-032` | Covered | Closed subject states and adapter/policy test matrix. |
| `REQ-TSTATE-033` | Covered | Trace validation tests state continuity and zero-based `violation_step`; real witness retains locations. |
| `REQ-TSTATE-034` | Covered | Different-identity real fixture yields zero violating traces; policy rejects cross-resource evidence. |
| `REQ-TSTATE-035` | Covered | Unsupported/incomplete policy fixtures return gaps or `unknown`; no positive result is raised. |
| `REQ-TSTATE-036` | Covered | `decideTypestate` is Core-owned; adapter tests assert observations only. |
| `REQ-TSTATE-037` | Covered | Closed outcome schema and decision tests. |
| `REQ-TSTATE-038` | Covered | Identity-backed ordered Ghost witness is required for real `violation_observed`. |
| `REQ-TSTATE-039` | Covered | Negative outcomes retain the declared completeness boundary and are not global correctness claims. |
| `REQ-TSTATE-040` | Covered | Probe policy tests stay `generated`; adapter controls trace execution by mode. |
| `REQ-TSTATE-041` | Covered | Reproduce policy tests and real vulnerable witness. |
| `REQ-TSTATE-042` | Covered | Real Ghost vulnerable/fixed execution returns `differential` only with a fixed safe trace. |
| `REQ-TSTATE-043` | Covered | Fixed incomplete/not-run/failure policy fixtures cannot satisfy fixed policy. |
| `REQ-TSTATE-044` | Covered | Fake/test-double cap tests and different-identity real counterexample. |
| `REQ-TSTATE-045` | Covered | Decision Policy has no `variant_validated` output. |
| `REQ-TSTATE-046` | Covered | Compact execution results separately retain operation status, decision, and verification level. |
| `REQ-TSTATE-047` | Covered | Artifact and Golden record identity/completeness boundaries and Analyzer provenance. |
| `REQ-TSTATE-048` | Covered | Wrong resource/event, pre-rekey, incomplete, and capability-gap tests retain bounded diagnostics. |
| `REQ-TSTATE-049` | Covered | Golden compact observation/artifact refs identify the central witness without Analyzer prose. |
| `REQ-TSTATE-050` | Covered | Idempotency run id/digest and committed-result reuse tests. |
| `REQ-TSTATE-051` | Covered | Shared trusted roots, timeout, cancellation, process cleanup, operation lease, atomic commit, and recovery tests. |
| `REQ-TSTATE-052` | Covered | `TypestateRunArtifactSchema` and real artifact include protocol, target fingerprints, provenance, policy, observation, and replay inputs. |
| `REQ-TSTATE-053` | Covered | Research route/result bundle promotion is atomic before run completion. |
| `REQ-TSTATE-054` | Covered | Focused replay tests cover lease serialization, caller/run/shutdown cancellation, raw semantic differences, namespace normalization, and evidence mutation; real Golden covers relocated fresh-process replay and fingerprint/version/policy/trace differences. |
| `REQ-TSTATE-055` | Covered | Adapter stores bounded locations/refs and sanitized Analyzer output, not event arguments, environments, or raw target output. |
| `REQ-TSTATE-056` | Covered | Real scripts create CodeQL databases with `--build-mode=none` from staged source and invoke no target scripts. |
| `REQ-TSTATE-057` | Covered | Full 32-file/194-test suite and package checks preserve Flow, MissingCheck, and existing CodeQL behavior. |
| `REQ-TSTATE-058` | Covered | Real Pi E2E and real CLI validate/idempotent-execute/replay paths use the aggregate Application API. |
| `REQ-TSTATE-059` | Covered | Implementation stays in existing contracts/core/codeql-runner/Pi/CLI packages; no Typestate package was added. |

## Final gates

Passed on 2026-09-01:

```text
npm run lint
npm test                         # 32 files, 194 tests
npm run pack:check               # 5 package outputs
CODEQL_PATH=/Users/zhangboxiang/tools/codeql/codeql npm run test:typestate-adapter-real
CODEQL_PATH=/Users/zhangboxiang/tools/codeql/codeql npm run test:typestate-golden-real
CODEQL_PATH=/Users/zhangboxiang/tools/codeql/codeql npm run test:typestate-pi-e2e
```

The real Golden recorded Ghost vulnerable `violation_observed`, fixed
`no_violation_observed`, final `differential`, pre-rekey safe trace count `0`,
different-identity violation count `0`, `revise_resource`, `revise_event`, and
an incomplete-scope Core result of `unknown`. It also replayed from a fresh
Node process after moving the run root and rebuilding both target databases;
the recorded primary QL/SARIF hashes remained unchanged. Deliberate target
fingerprint, Analyzer version, Decision Policy, and trace mutations produced
their respective environment, version, version, and semantic distinctions.

No requirement mapping or real gate is pending. The accepted Ghost selectors
remain Golden evidence only; root `SPEC.md` defines the narrow product boundary
without making them universal Typestate selectors.
