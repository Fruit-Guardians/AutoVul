# Change: Add MissingCheck JavaScript CFG Analyzer v1

- Change ID: `add-missing-check-javascript-cfg-analyzer-v1`
- Status: Implemented
- Owner: AutoVul maintainers
- Created: 2026-09-03
- Updated: 2026-09-03
- Public contract: `v2.contracts/1`
- Depends on: archived `admit-missing-check-capability-v1`, `harden-capability-execution-contracts-v1`

## Problem

AutoVul V2's core architecture decouples research semantics (`flow`, `missing_check`, `typestate`) from concrete execution engines. However, the initial MissingCheck implementation was coupled to CodeQL, hardcoding CodeQL as the sole analyzer and runner.

To realize the multi-analyzer vision, MissingCheck requires an independent, dedicated static analysis adapter: a **JavaScript Control Flow Graph (CFG) Dominator Analyzer** (`javascript_cfg`). This proves that AutoVul research capabilities can execute against heterogeneous analyzers while preserving identical hypothesis schemas, compact observations, decision policies, and verification levels.

## Host boundary

The host Agent continues to select the capability (`missing_check`), formulate the hypothesis (operation, required check, relation, scope), and choose the target and analyzer.

AutoVul Core owns dispatching to the configured MissingCheck execution port based on `analyzer_id`, recording structured observations, managing budgets and cancellation, and verifying replay.

## Scope

### In scope

- Support Git-backed object inspection for JavaScript source files.
- Extend `MissingCheckResearchToolInputSchema` to support closed pairing with `analyzer_id: "javascript_cfg"` requiring `GitRevisionTargetPairSchema`.
- Implement `JavascriptCfgMissingCheckAdapter` in `@autovul/codeql-runner`:
  - Reads source files directly from Git object database within `trustedRoots`;
  - Parses JavaScript source files using TypeScript AST (`ts.createSourceFile`);
  - Resolves entry function in scope (`named_function` / `single_file_named_entry_cfg`);
  - Identifies direct call invocations of `operation` and `required_check`;
  - Performs intra-procedural dominator CFG analysis with guard polarity for `same_callback_cfg_dominates_operation`;
  - Emits `MissingCheckAnalyzerObservation` with `evidence_kind: "real_analyzer"`;
  - Reports `completeness: { status: "incomplete" }` with stable gap codes for unsupported constructs;
  - Writes structural witness evidence files under isolated namespaces (`missing-check` vs `missing-check-replay`);
  - Supports differential analysis between vulnerable and fixed Git revisions.
- Register `javascript_cfg` analyzer in `Application` / `ApplicationFactory`.
- Clean-process differential verification and replay tests proving CodeQL-independent execution.

### Non-goals

- Universal JavaScript static analysis platform, inter-procedural dataflow, or cross-file alias tracking.
- Modifying Flow or Typestate analyzers in this change.
- Automated analyzer fallback, dynamic analyzer routing, or analyzer selection voting.

## Requirements

- `REQ-MCHECK-JS-001`: MissingCheck research input MUST pair `analyzer_id: "javascript_cfg"` with immutable `GitRevisionTargetPairSchema` (`kind: "git_revision"` with `repository`, `revision`, and optional `expected_fingerprint`).
- `REQ-MCHECK-JS-002`: MissingCheck requests and analyzer provenance MUST admit `analyzer_id: "javascript_cfg"` alongside `"codeql"`.
- `REQ-MCHECK-JS-003`: `JavascriptCfgMissingCheckAdapter` MUST read JavaScript source files directly from the Git object database within canonicalized `trustedRoots` without invoking CodeQL CLI or requiring a CodeQL database.
- `REQ-MCHECK-JS-004`: `JavascriptCfgMissingCheckAdapter` MUST emit `evidence_kind: "real_analyzer"` with authoritative AST/CFG locations and evidence references.
- `REQ-MCHECK-JS-005`: When `required_check` dominates all control paths to `operation`, accounting for condition polarity (`check()` vs `!check()`), the adapter MUST report `state: "checked_witness"`; when an unhedged path to `operation` exists, it MUST report `state: "unchecked_witness"`. Unsupported control-flow constructs MUST return `completeness: { status: "incomplete" }` with stable gap codes.
- `REQ-MCHECK-JS-006`: In `mode: "differential"`, the adapter MUST execute analysis against both vulnerable and fixed Git revisions and allow Core to reach `differential` verification level.
- `REQ-MCHECK-JS-007`: Replay with `analyzer_id: "javascript_cfg"` MUST execute in an isolated workspace namespace (`missing-check-replay/`), verify Git commit fingerprints, and assert SHA-256 evidence immutability of the original run.

## Requirement Traceability

| Requirement ID | Implementation Location | Test Verification |
| --- | --- | --- |
| `REQ-MCHECK-JS-001` | `packages/contracts/src/research-tool.ts`, `packages/contracts/src/research.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-002` | `packages/contracts/src/research-tool.ts`, `packages/contracts/src/missing-check.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-003` | `packages/codeql-runner/src/javascript-cfg-adapter.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-004` | `packages/codeql-runner/src/javascript-cfg-adapter.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-005` | `packages/codeql-runner/src/javascript-cfg-adapter.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-006` | `packages/codeql-runner/src/javascript-cfg-adapter.ts`, `packages/core/src/missing-check/service.ts` | `test/missing-check-javascript-cfg.test.ts` |
| `REQ-MCHECK-JS-007` | `packages/core/src/missing-check/replay.ts`, `packages/codeql-runner/src/javascript-cfg-adapter.ts` | `test/missing-check-javascript-cfg.test.ts` |

## Validation plan

- Unit tests for AST parsing and dominance CFG evaluation in vulnerable and fixed variants.
- End-to-end integration test with `Application.research()` using `analyzer_id: "javascript_cfg"` in `differential` mode.
- Clean-process replay test ensuring exact outcome reproduction and fingerprint mismatch detection.
- `npm run check` across the workspace.
