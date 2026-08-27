# PureAutoCodeQL V2 M0/M3/M4

This workspace contains the isolated TypeScript M0 foundation for V2. The Python V1 remains the repository's existing runtime and is not imported by these packages.

## Packages

- `@pure-auto-codeql/contracts`: versioned TypeBox schemas and static types.
- `@pure-auto-codeql/core`: ports, deterministic run state, database workflow, query verification and Query Pack finalization.
- `@pure-auto-codeql/codeql-runner`: Node adapters for safe CodeQL inspection, query compile/analyze and SARIF summaries.
- `@pure-auto-codeql/pi-extension`: thin Pi commands plus `codeql_database`, `codeql_workflow` and `codeql_query` tools.
- `@pure-auto-codeql/cli`: deterministic local CLI entry point, including model-free candidate replay.

## Development

```bash
npm install
npm run typecheck
npm test
npm run pack:check
```

The local extension can be loaded temporarily without changing `~/.pi`:

```bash
pi -e ./v2/packages/pi-extension/dist/index.js
```

The CLI is available after building through its workspace binary:

```bash
npm run build
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 doctor --json
```

M0 intentionally does not create CodeQL databases or run target-project build scripts. `database inspect` and `database validate` are read-only.

## M2 Python query workflow

M2 is limited to Python and keeps query generation in the host Pi Agent Loop. Core never starts a second Agent; it receives a structured `VulnerabilitySpec` and `QueryCandidate`, then deterministically compiles, analyzes, diagnoses, checkpoints and finalizes a complete Query Pack.

For the Python path, Pi should submit a `PythonPathQueryDraft` containing only source/sink predicate bodies and the result message. Core owns the QLDoc metadata, `@kind path-problem`, query id, Python DataFlow imports, module/Flow/PathGraph/select envelope and the case-level three-candidate budget. Raw QL remains available to the CLI for compatibility, but it must pass the same metadata preflight and staged compile before any database analysis.

```bash
npm run build
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 workflow start --spec ./spec.json --json
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 query draft <run-id> --candidate ./candidate.json --json
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 query verify <run-id> --candidate ./candidate.json --json
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 workflow finalize <run-id> --json
npx --workspace @pure-auto-codeql/cli pure-auto-codeql-v2 query-pack verify ./query-pack --vulnerable-db /path/to/vulnerable --fixed-db /path/to/fixed --json
```

When the Query Pack and the supplied databases share a non-root directory, the CLI infers that directory as the trusted workspace. Use `--workspace-root <path>` when they are stored in separate locations.

The final artifact contains relative-root `query.ql`, `candidate.json`, `qlpack.yml`, `spec.json`, `verification.json`, `evidence.json`, `REPRODUCE.md` and `query-pack-manifest.json`. On the accepted POSIX path, `query-pack verify` checks artifact digests, re-runs compile/analyze from the relocated pack, and never calls a model or reads the original run. A run with only a vulnerable database is reported as `reproduced`; `differential` is reserved for a verified fixed database. User-provided cases still require exact Source/Sink file and line locations before workflow start; omitting the fixed database only skips the additional fixed=0 comparison.

### M4 evidence-driven chain

For a real user case, `VulnerabilitySpec.project_root` identifies the supplied source root; the host Pi reads that source and the vulnerability description/patch, proposes Source/Sink, and calls `codeql_query action=probe`. It then calls `codeql_query action=draft` before `verify`. Draft reports live under `drafts/<candidate-id>/report.json`, carry LSP file/line/column diagnostics and symbol observations, and do not use the formal three-candidate budget. Draft revisions have an independent default budget of 6 and a hard maximum of 10. A draft with LSP errors is rejected by `verify`; an unavailable/degraded LSP falls back to the authoritative CodeQL CLI. The CLI result, optional fixed-database zero-result check, and model-free Query Pack replay are the success gates.

### M3 language-neutral intent

M3 adds a structured `TaintQueryIntent` for Python, JavaScript/TypeScript, Java/Kotlin and C/C++. The intent contains Source/Sink matchers and flow semantics; the selected Language Pack owns the imports, AST/data-flow node types, metadata, Flow/PathGraph envelope and qlpack dependency. The current renderer compile gate can be run with:

```bash
npm run test:m3-compile
```

This command creates and removes all four compile fixtures under the system temporary directory. For the real vulnerable/fixed Golden gate, use:

```bash
npm run test:m3-golden-real
```

That gate creates temporary databases and runs all 20 cases in the authoritative manifest for Python, JavaScript, Java and C/C++ Language Packs. It checks renderer compile, Source/Sink probes, vulnerable flow, fixed zero-result policy, strict endpoint locations and model-free CLI replay of the relocated Query Pack. It is the deterministic 20-case differential gate; it does not measure LLM first-candidate/three-candidate generation rate or variant/hard-negative validation. Set `M3_GOLDEN_CASE=<case-id>` to run one case while diagnosing a fixture.

### M3 L0/L0.1 CodeQL Language Server protocol matrix

The real headless protocol snapshot is available through:

```bash
npm run test:l0-lsp:snapshot
```

It records negative observations as data and always completes the discovery run. L0.1 covers async/synchronous execution, active-only/all visible files, initial versus one-by-one dynamic workspace folders, C/C++ order and cache temperature, three search-path layouts, actual definition locations, and qlpack graph updates. The snapshot is written to `../plan/l0-codeql-lsp-capability-snapshot.json`.

The production draft adapter keeps one lazy CodeQL Language Server session per Application. It initializes four stable scratch pack workspaces up front, routes each draft through a unique `URI + revision`, serializes overlapping draft requests, updates qlpack files through watched-file notifications, and closes the whole process group from `Application.close()`. LSP health failures degrade to the CLI path; they never decide compile/analyze acceptance. The real 20-case harness reuses one Application across all four language families to exercise this shared-session lifecycle.

The product gate is separate:

```bash
npm run test:lsp:conformance
```

It reruns the snapshot and returns non-zero when the current product requirements are not met. `test:l0-lsp` remains a compatibility alias for the non-gating snapshot command.

### Native Pi UX

Load the extension in the workspace that contains the allowed source/database paths:

```bash
npm run build
pi -e ./packages/pi-extension/dist/index.js
```

Then type a normal-language request: CodeQL/vulnerability requests are automatically guided into the host Pi Agent Loop, without requiring `/codeql-generate`. The command remains available as an explicit force-start path or multi-line case editor: `/codeql-generate` opens the editor when no description is supplied. The extension does not start a second Agent or require hand-written JSON. `/codeql` shows the native help, `/codeql doctor` runs the environment check, and `/codeql-status [run-id]` shows the current persisted run. The footer stays compact (`CodeQL ready` or the final verification summary); the widget appears only during active tool execution and briefly when a pack is ready, with at most two lines, and disappears when the agent settles. Status/doctor commands show human-readable summaries by default; append `--json` for the raw structured result. The tool transcript retains the full structured JSON result; `Ctrl+O` expands it when the result is collapsed.

The five-run real Golden evaluator is opt-in and never falls back to fake success. Set `PURE_AUTO_CODEQL_M2_GENERATOR` to an approved no-shell model-wrapper executable, optionally set `PURE_AUTO_CODEQL_M2_GENERATOR_ARGS` to a JSON argument array, and use `PURE_AUTO_CODEQL_M2_GENERATOR_MODE=counted` plus the approved-run gate. The wrapper must return `candidate` and complete `metadata` (`provider`, `model`, `adapter_version`, scalar `parameters`, and input/output/total token usage). Ordinary external wrappers remain diagnostic and cannot enter the 4/5 count. The generator receives sanitized input with no reference query content; the evaluator performs exact-copy leak detection only after the wrapper exits. Set `PURE_AUTO_CODEQL_M2_REPORT=/tmp/m2-golden-report.json` to persist the versioned report without raw model output or secrets. Without the wrapper/key, the command exits with an explicit `BLOCKED` result.

The evaluator also accepts an external real-project case and prebuilt databases. Set `PURE_AUTO_CODEQL_M2_CASE_FILE`, `PURE_AUTO_CODEQL_M2_VULNERABLE_DB`, `PURE_AUTO_CODEQL_M2_FIXED_DB` and `PURE_AUTO_CODEQL_M2_WORKSPACE_ROOT`; the workspace root must contain both database paths. `test/m2-real-kohya.case.json` is a reproducible Python example for `bmaltais/kohya_ss` and uses `--build-mode=none` database creation. The OpenAI-compatible adapter is `test/m2-openai-compatible-wrapper.mjs`.

For the accepted M4 path, `test:m4-golden-real` can invoke the host Pi CLI directly through `test/m4-pi-host-wrapper.mjs`; this is an adapter around Pi's JSONL output, not a model SDK. The evaluator gives the wrapper only a bounded, deterministic vulnerable-source context plus the vulnerability/patch description and prior diagnostics. It never sends reference query/intent, fixed source, or database contents to the model and never accepts raw `ql_text` as a counted candidate. Example configuration (provider/model may be omitted to use Pi's configured default):

```bash
PURE_AUTO_CODEQL_M4_GENERATOR="$PWD/test/m4-pi-host-wrapper.mjs" \
PURE_AUTO_CODEQL_M4_GENERATOR_MODE=counted \
PURE_AUTO_CODEQL_M4_GENERATOR_APPROVED=true \
PURE_AUTO_CODEQL_M4_PI_PROVIDER=openai-codex \
PURE_AUTO_CODEQL_M4_PI_MODEL=gpt-5.6-luna \
PURE_AUTO_CODEQL_M4_PI_NO_EXTENSIONS=true \
npm run test:m4-golden-real
```

The wrapper receives only an allowlisted provider environment (`ANTHROPIC_*`, `OPENAI_*`, `PI_CODING_AGENT_DIR`, and `PURE_AUTO_CODEQL_M4_*`); secrets are not written into reports. `PURE_AUTO_CODEQL_M4_PI_NO_EXTENSIONS=true` is useful for built-in providers such as `openai-codex` when an unrelated piagent extension is unavailable; extension-backed providers should leave it unset. A provider transport failure is recorded as blocked and cannot count toward the 4/5 Gate D threshold. Set `M4_GOLDEN_SKIP_FIXED=true` to verify the non-blocking single-database/reproduced path.

`npm run test:m4-pi-e2e` runs a diagnostic real-Pi RPC path against temporary Python databases. It verifies the host extension's inspect → start → probe → draft → verify → finalize sequence and model-free relocated replay; it is infrastructure evidence, not a real-model Gate D count.

For a model-free smoke of that non-blocking path, use the diagnostic-only source-pattern wrapper (it is never counted):

```bash
PURE_AUTO_CODEQL_M4_GENERATOR=node \
PURE_AUTO_CODEQL_M4_GENERATOR_ARGS='["'$PWD'/test/m4-diagnostic-wrapper.mjs"]' \
M4_GOLDEN_SKIP_FIXED=true \
node test/m4-golden-real.mjs
```

## Platform support

M0 lock and process-cleanup validation currently covers the POSIX/macOS path used by this repository. Windows is not an accepted support target in this milestone: Windows process-tree cleanup and Windows CI have not been implemented or validated. The project must not be treated as cross-platform complete until those gates are added.

The run lock uses an atomically created directory with a unique owner-token file. Stale recovery renames only the exact observed owner entry and then uses non-recursive `rmdir`; release validates the owner token before removing anything, so a previous owner cannot remove a replacement owner’s state.
