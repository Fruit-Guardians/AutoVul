# Stabilization checkpoints

This change is being implemented on top of a pre-existing dirty working tree. No commit was created so unrelated user changes are not captured or rewritten. The reviewable checkpoint boundaries are recorded here for selective review or later commits.

## Checkpoint A: specification and validation infrastructure

- `SPEC.md`, `specs/README.md`, the change SPEC, `test/check-specs.mjs`, and repository metadata.
- The baseline gates are `npm run typecheck`, `npm run spec:check`, and `git diff --check`.

## Checkpoint B: process/RPC lifecycle

- `packages/codeql-runner/src/lsp/process-lifecycle.ts` is the shared timeout, cancellation, process-group termination, and sanitization implementation.
- `packages/codeql-runner/src/node-process.ts` and the production LSP session use that implementation.

## Checkpoint C: CodeQL workflow decomposition

- `packages/core/src/codeql-workflow/` owns admission, probe, draft, verify, finalize, repository state, policies, migrations, and case projection.
- `packages/core/src/query-workflow.ts` remains a compatibility export and the Application API is unchanged.

## Checkpoint D: Pi integration decomposition

- `packages/pi-extension/src/index.ts` only assembles the local Application and registers `lifecycle`, `commands`, and `tools`.
- Prompts, UI state/formatting, and aggregate tool handlers have focused modules.

## Checkpoint E: LSP production/lab split

- `lsp/session.ts` is the minimal production draft runtime.
- Protocol discovery and matrix snapshot code moved to `lsp/lab/protocol-spike.ts` and the explicit `@pure-auto-codeql/codeql-runner/lab` export.
- The deleted `test/l0-lsp-protocol-spike.mjs` entry point is replaced by `test/l0-lsp-matrix.mjs`, which is still used by `test:l0-lsp:snapshot` and conformance.

## Explicit removals

- `test/m4-diagnostic-repair-wrapper.mjs` and `test/m4-diagnostic-cli-repair-wrapper.mjs` had no supported command or test references after the current M4 diagnostic flow; their supported replacement is the direct CLI/LSP workflow and `test/m4-diagnostic-wrapper.mjs`.
