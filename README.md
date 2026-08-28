# AutoVul

AutoVul is a host-independent vulnerability-research extension and deterministic analysis engine.

It runs under mature Agent/Harness hosts such as Pi Agent. The host understands the request, reads code, forms a vulnerability hypothesis and decides what to do next. AutoVul validates structured research inputs, executes analyzers, persists evidence and verifies results.

> The host Agent owns understanding, reasoning and orchestration. AutoVul owns vulnerability-research capabilities, deterministic execution, evidence and verification.

AutoVul does not implement a general Agent, model provider, Agent Loop, conversation memory, planning system or subagent framework.

## Current capability

The current TypeScript V2 implementation provides a verified CodeQL query workflow:

- structured Source/Sink-oriented query intent;
- Language Packs for Python, JavaScript/TypeScript, Java/Kotlin and C/C++;
- Source and Sink probes;
- advisory CodeQL Language Server draft diagnostics;
- authoritative CodeQL CLI compile and analyze execution;
- vulnerable/fixed differential verification;
- persisted run state, bounded candidate budgets and crash recovery;
- relocatable Query Packs with model-free replay;
- thin Pi and CLI integrations sharing the same Application API.

CodeQL databases must already exist. AutoVul currently inspects and validates them but does not create databases or execute target-project build/install scripts.

The accepted result levels are:

- `generated`: a candidate exists but has not passed execution verification;
- `compiled`: the analyzer accepted the rule;
- `reproduced`: the vulnerable target matched the expected behavior or location;
- `differential`: the vulnerable target matched and the fixed target satisfied the non-match policy;
- `variant_validated`: additional positive, negative or cross-project validation passed.

Probe results, model reasoning, mocks and diagnostic wrappers are not vulnerability confirmation.

## Flow-Based direction

AutoVul is evolving toward a Flow-Based vulnerability-research capability layer designed for Agent and LLM consumption:

```text
Host Agent / LLM
  -> FlowModel
  -> ExecuteFlowRequest
       -> AutoVul Flow Core
       -> FlowExecutionPort
            └─ CodeQL Adapter
  -> FlowExecutionResult
```

The planned Flow Model describes Source, Sink, explicit propagation steps and barriers. Target references, analyzer selection, budgets and verification policy belong to the execution request. CodeQL becomes an optional execution backend rather than part of the Flow Model.

This Flow API is a design direction and is not implemented or accepted product behavior yet. The existing CodeQL interfaces remain the supported compatibility surface.

See:

- [Flow-Based design direction](./docs/design/FLOW_BASED_DIRECTION.md)
- [Flow-Based implementation plan](./docs/design/FLOW_BASED_PLAN.md)
- [Product specification](./SPEC.md)
- [Project charter](./AGENTS.md)
- [SPEC workflow](./specs/README.md)

## Architecture

```text
Host Agent / Harness
  -> Integration Adapter
       -> Application API
            -> Core domain policy and workflow
                 -> Analyzer Ports
                      -> CodeQL Runner
```

Production dependencies follow:

```text
contracts <- core <- codeql-runner <- pi-extension / cli
```

The packages are:

- `@autovul/contracts`: versioned TypeBox schemas and stable protocols;
- `@autovul/core`: deterministic policy, workflow state, budgets and verification decisions;
- `@autovul/codeql-runner`: CodeQL CLI/LSP, filesystem, process and SARIF adapters;
- `@autovul/pi-extension`: thin Pi registration, commands, lifecycle and presentation;
- `@autovul/cli`: deterministic debugging, CI and model-free replay interface.

## Development

Requirements:

- Node.js and npm;
- CodeQL CLI for real analyzer tests and normal CodeQL execution;
- prebuilt vulnerable/fixed CodeQL databases for differential research.

Install and run the standard checks:

```bash
npm install
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```

`npm run check` runs the main build, architecture, specification, unit/integration and package gates. Real CodeQL, real-model and Golden commands remain separate when they require external tools or credentials.

## CLI workflow

Build the workspace, inspect the environment and execute a query workflow:

```bash
npm run build
npx --workspace @autovul/cli autovul doctor --json
npx --workspace @autovul/cli autovul workflow start --spec ./spec.json --json
npx --workspace @autovul/cli autovul query draft <run-id> --candidate ./candidate.json --json
npx --workspace @autovul/cli autovul query verify <run-id> --candidate ./candidate.json --json
npx --workspace @autovul/cli autovul workflow finalize <run-id> --json
```

Replay a finalized Query Pack without a model or the originating run:

```bash
npx --workspace @autovul/cli autovul query-pack verify ./query-pack \
  --vulnerable-db /path/to/vulnerable \
  --fixed-db /path/to/fixed \
  --workspace-root /trusted/root \
  --json
```

The finalized pack contains the rendered query, candidate, vulnerability specification, qlpack metadata, verification result, evidence, reproduction instructions and a digest manifest.

## Pi integration

Load the built extension from the project workspace:

```bash
npm run build
pi -e ./packages/pi-extension/dist/index.js
```

The extension exposes the current aggregate tools:

- `codeql_database`
- `codeql_workflow`
- `codeql_query`

Pi remains the Agent. The extension converts tool input, calls the shared Application API, handles cancellation and presents compact results. It does not start another Agent Loop.

Useful commands include `/codeql`, `/codeql doctor`, `/codeql-status [run-id]` and `/codeql-generate`.

## Real verification gates

Run these gates only when their external dependencies are available:

```bash
npm run test:m3-compile
npm run test:m3-golden-real
npm run test:l0-lsp:snapshot
npm run test:lsp:conformance
npm run test:m4-pi-e2e
npm run test:m4-golden-real
```

The M3 real Golden gate covers 20 Python, JavaScript, Java and C/C++ vulnerable/fixed cases, strict endpoint checks and relocated replay. LSP results remain advisory; authoritative acceptance comes from CodeQL CLI execution. Model-backed evaluation must use an approved wrapper and reports blocked when the model, credentials or analyzer environment is unavailable. It never falls back to fake success.

## Safety and platform status

- Paths are canonicalized and constrained to configured workspace or trusted roots.
- Long-running operations support timeout and cancellation and clean up subprocess trees.
- Critical state and artifacts use atomic persistence and deterministic recovery.
- Output, execution time, candidate count, revisions and concurrency are bounded.
- Target build and install scripts are not executed automatically.
- Recognized secrets and unrestricted environment data must not be persisted.

The accepted platform path is POSIX/macOS. Windows process-tree cleanup and Windows CI have not been implemented or verified, so Windows support is not currently claimed.

## Compatibility

During the pre-1.0 migration window, `pure-auto-codeql-v2` remains a CLI alias. Deprecated `PURE_AUTO_CODEQL_*` environment variables continue to work where documented, while matching `AUTOVUL_*` values take precedence. Stable historical CodeQL rule IDs retain their former namespace where changing them would break replay or compatibility.

The Python V1 runtime is outside this isolated TypeScript workspace and is not imported as a V2 dependency.
