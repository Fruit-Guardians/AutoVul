# Change: Add MissingCheck JavaScript CFG Analyzer v1

- Change ID: `add-missing-check-javascript-cfg-analyzer-v1`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-09-03
- Updated: 2026-09-03
- Public contract: `v2.contracts/1`
- Depends on: archived `admit-missing-check-capability-v1`, `harden-capability-execution-contracts-v1`

## Problem

AutoVul's MissingCheck capability currently only supports `analyzer_id: "codeql"`, which requires a pre-built CodeQL database, extractor installation, and CodeQL CLI execution. This binds MissingCheck to CodeQL even though the hypothesis scope for v1 (`single_file_named_entry_cfg` with `direct_call`) is an intra-procedural CFG property that can be deterministically analyzed directly from JavaScript/TypeScript source code without CodeQL.

To demonstrate that AutoVul is a true multi-analyzer capability layer rather than a CodeQL wrapper, MissingCheck must admit a lightweight, deterministic `javascript_cfg` production analyzer that operates on source trees and produces authoritative `real_analyzer` observations and replayable evidence.

## Host boundary

The host Agent continues to select the capability (`missing_check`), formulate the hypothesis (operation, required check, relation, scope), and choose the target and analyzer (`javascript_cfg`).

AutoVul Core owns dispatching to the configured MissingCheck execution port based on `analyzer_id`, recording structured observations, managing budgets and cancellation, and verifying replay.

## Scope

### In scope

- Expand `TargetRefSchema` to admit `kind: "source_directory"` alongside `kind: "codeql_database"`.
- Expand `MissingCheckHypothesis` / `MissingCheckAnalyzerProvenanceSchema` / request schemas to admit `analyzer_id: "codeql" | "javascript_cfg"`.
- Implement `JavascriptCfgMissingCheckAdapter` in `packages/codeql-runner`:
  - Parses JavaScript/TypeScript source files using TypeScript AST (`ts.createSourceFile`);
  - Resolves entry function in scope (`named_function` / `single_file_named_entry_cfg`);
  - Identifies direct call invocations of `operation` and `required_check`;
  - Performs intra-procedural dominator CFG analysis for `same_callback_cfg_dominates_operation`;
  - Emits `MissingCheckAnalyzerObservation` with `evidence_kind: "real_analyzer"`;
  - Generates structural witness evidence files under the run artifact directory;
  - Supports differential analysis between vulnerable and fixed source directories.
- Register `javascript_cfg` analyzer in `Application` / `ApplicationFactory`.
- Clean-process differential verification and replay tests proving CodeQL-independent execution.

### Non-goals

- Universal JavaScript static analysis platform, inter-procedural dataflow, or cross-file alias tracking.
- Modifying Flow or Typestate analyzers in this change.
- Automated analyzer fallback, dynamic analyzer routing, or analyzer selection voting.

## Requirements

- `REQ-MCHECK-JS-001`: `TargetRefSchema` MUST admit `kind: "source_directory"` with `path` and optional `expected_fingerprint`.
- `REQ-MCHECK-JS-002`: MissingCheck requests and analyzer provenance MUST admit `analyzer_id: "javascript_cfg"` alongside `"codeql"`.
- `REQ-MCHECK-JS-003`: `JavascriptCfgMissingCheckAdapter` MUST analyze single-file named entry CFGs without invoking CodeQL CLI or requiring a CodeQL database.
- `REQ-MCHECK-JS-004`: `JavascriptCfgMissingCheckAdapter` MUST emit `evidence_kind: "real_analyzer"` with authoritative AST/CFG locations and evidence references.
- `REQ-MCHECK-JS-005`: When `required_check` dominates all control paths to `operation`, the adapter MUST report `state: "checked_witness"`; when an unhedged path to `operation` exists, it MUST report `state: "unchecked_witness"`.
- `REQ-MCHECK-JS-006`: In `mode: "differential"`, the adapter MUST execute analysis against both vulnerable and fixed source directories and allow Core to reach `differential` verification level.
- `REQ-MCHECK-JS-007`: Replay with `analyzer_id: "javascript_cfg"` MUST verify source directory fingerprints and produce deterministic identical outcomes without contacting any LLM.

## Requirement Traceability

| Requirement ID | Implementation Location | Test Verification |
| --- | --- | --- |
| `REQ-MCHECK-JS-001` | `packages/contracts/src/research.ts` (`TargetRefSchema`) | `test/missing-check-javascript-cfg.test.ts` |
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
