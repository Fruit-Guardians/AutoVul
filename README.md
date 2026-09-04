# AutoVul

AutoVul is a host-independent vulnerability-research capability layer and deterministic execution system.

It is designed to run under mature Agent/Harness hosts. The host owns model access, reasoning, planning, tool selection, hypothesis revision, and user interaction. AutoVul owns versioned research contracts, bounded analyzer execution, structured evidence, deterministic decisions, and model-free replay.

AutoVul does not implement a general Agent, an Agent loop, a model-provider framework, conversation memory, planning, or subagent orchestration.

The host does not need AutoVul to finish every audit. It may inspect code with its native tools and model reasoning and deliver a semantic finding directly. AutoVul is invoked when a selected hypothesis benefits from stricter structure, lightweight or deep analysis, differential verification, durable evidence, recovery, or replay. CodeQL is one optional deep backend, not the default entry point.

## Project status

The verified baseline contains three independent Research Capabilities and one supporting Analyzer Service:

| Area | Contract | Current status | Verified boundary |
| --- | --- | --- | --- |
| Flow | `autovul.flow/1` | Archived | Real CodeQL differential and relocated replay across the accepted Python, JavaScript, Java, and C/C++ matrix |
| MissingCheck | `autovul.missing-check/1` | Archived | Real CodeQL differential and fresh-process replay for the frozen JavaScript direct-call/dominance case |
| Typestate | `autovul.typestate/1` | Archived | Identity-sensitive Ghost differential, negative cases, and relocated replay for the frozen single-resource protocol |
| Change Observation | `autovul.change-observation/1` | Archived | Read-only immutable Git observations and relocated replay for the accepted OpenClaw/Ghost matrix |

The following work exists but is not part of the verified support baseline:

| Workstream | Lifecycle state | Remaining gate |
| --- | --- | --- |
| JavaScript CFG MissingCheck analyzer | Implemented | Real OpenClaw clean-process Golden, full evidence mapping, and independent replay |
| DeepSeek Harness adapter | Implemented | Real external-harness acceptance, cancellation, replay, and shutdown verification |
| Variant role classification | Accepted | Two recorded real families, safe counter-examples, strategy comparison, and owning-Capability validation |
| Variant Search service | Accepted; implementation in progress | Contract hardening, accurate partial results, atomic evidence, full replay invariants, and a real two-family matrix |

See [PROJECT_PROGRESS.md](./PROJECT_PROGRESS.md) for the complete task ledger, change-SPEC matrix, and ordered next steps. A lifecycle label is evidence-sensitive: `Implemented` does not mean `Verified`, and only archived behavior belongs in the stable root baseline.

## Architecture

Research semantics are parallel. They share a runtime, not a universal vulnerability model.

```text
Host Agent / Harness
  -> two aggregate tools: autovul_research | autovul_run
  -> explicit domain branch
       Research Capability
         Flow | MissingCheck | Typestate
       Analyzer Service
         Change Observation | Variant Search (in progress)
  -> shared deterministic runtime
       run identity | budget | timeout | cancellation | lease
       atomic artifacts | evidence | recovery | replay
  -> capability/service-specific Analyzer Port
       CodeQL | JavaScript CFG | Git object inspection
```

Each Research Capability owns its Hypothesis, Observation, Decision Policy, diagnostics, and success predicate. Analyzer Services return bounded facts or candidates and never emit another Capability's vulnerability verdict. CodeQL is an optional deep-analysis backend, not the product boundary.

The intended escalation path is:

```text
host-native semantic audit
  -> Git / patch / AST / CFG observation (optional)
  -> Capability validation and execution (optional)
  -> CodeQL deep analysis (optional)
  -> dynamic reproduction or differential evidence (optional)
```

The host may stop at any stage. A host assessment is useful research output, but it must not be presented as an AutoVul verification level unless the relevant deterministic contract has run.

## Semantic audit playbooks

To put "Agent-native audit first, AutoVul on-demand escalation" into operational practice, four canonical playbooks guide the host Agent:

- [**Patch-Guided**](./playbooks/patch-guided.md): Trace vulnerabilities backwards from Git commits, PRs, or security patches, validating fixes with `differential` verification.
- [**Sink-Guided**](./playbooks/sink-guided.md): Trace backwards from sensitive operations (exec, eval, SQL, SSRF) through multi-procedure call chains using CodeQL data-flow evidence.
- [**Protocol-Guided**](./playbooks/protocol-guided.md): Validate state-machine and lifecycle ordering violations on identity-sensitive resources using Typestate analysis.
- [**Variant-Guided**](./playbooks/variant-guided.md): Discover and filter cross-repository or cross-module variants from a verified seed vulnerability using Variant Search and owning-Capability confirmation.

See [playbooks/README.md](./playbooks/README.md) for the complete guide and host-autonomous boundary definitions.

Production dependencies follow one direction:

```text
@autovul/contracts
  <- @autovul/core
  <- @autovul/codeql-runner
  <- @autovul/pi-extension | @autovul/deepseek-harness | @autovul/cli
```

| Package | Responsibility |
| --- | --- |
| [`@autovul/contracts`](./packages/contracts) | Versioned TypeBox schemas, tool envelopes, artifacts, and domain errors |
| [`@autovul/core`](./packages/core) | Domain validation and decisions, lifecycle, budgets, evidence commit, recovery, and replay |
| [`@autovul/codeql-runner`](./packages/codeql-runner) | CodeQL, JavaScript CFG, Git, filesystem, and process adapters |
| [`@autovul/pi-extension`](./packages/pi-extension) | Thin Pi registration, lifecycle binding, and compact presentation |
| [`@autovul/deepseek-harness`](./packages/deepseek-harness) | Thin function-calling adapter; external-harness verification is still pending |
| [`@autovul/cli`](./packages/cli) | Deterministic debugging, CI, status, cancellation, and model-free replay interface |

## Evidence levels

- `generated`: a candidate exists but has not passed execution verification.
- `compiled`: the analyzer accepted the rule, but the target behavior is not yet reproduced.
- `reproduced`: the vulnerable target produced the expected result or witness.
- `differential`: the vulnerable target matched and the fixed target satisfied the Capability-specific fixed policy.
- `variant_validated`: an accepted later policy has validated additional positive, negative, or cross-project cases.

Model reasoning, probes, mocks, fake adapters, text similarity, and search candidates do not confirm a vulnerability.

## Requirements

- Node.js `>=22.19.0`
- npm
- Git for Git-backed Analyzer Services
- CodeQL CLI and prebuilt databases only for CodeQL-backed execution and real CodeQL gates

AutoVul does not create CodeQL databases or execute target-project build/install scripts automatically.

## Development

```bash
npm install
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```

`npm run check` runs the main build, architecture, specification, unit/integration, and package gates. Real CodeQL, real-host, and Golden commands remain separate when they require external tools, fixtures, or credentials. A skipped external gate must stay skipped or blocked; it cannot be replaced by a fake success.

## Aggregate research interface

The host-facing research surface contains two primary tools:

- `autovul_research`: validate or execute one versioned Capability hypothesis or Analyzer Service request.
- `autovul_run`: inspect status, cancel an active operation, or replay a committed run.

The CLI exposes the same Application API:

```bash
autovul research validate --request ./request.json --json
autovul research execute --request ./request.json --json
autovul run status <run-id> --json
autovul run cancel <run-id> --json
autovul run replay <run-id> --json
```

Compatibility `workflow`, `query`, `query-pack`, and `codeql_*` entries remain available for the historical CodeQL workflow. They are not a third primary research interface.

### Pi Agent

After building the workspace, load the extension from the repository:

```bash
pi -e ./packages/pi-extension/dist/index.js
```

Pi remains the Agent. The extension registers tools, converts inputs, forwards cancellation, and renders compact results.

### DeepSeek Harness

The package currently exposes an OpenAI-compatible function-calling adapter over `ApplicationApi`:

```typescript
import { createDeepSeekHarnessPlugin } from "@autovul/deepseek-harness";
import { createLocalApplication } from "@autovul/codeql-runner";

const application = createLocalApplication({ workspaceRoot: process.cwd() });
const plugin = createDeepSeekHarnessPlugin({ application });

const tools = plugin.tools;
const instructions = plugin.prompts.systemInstructions;
const result = await plugin.execute("autovul_research", request);
```

This adapter is implemented and covered by repository tests. It is not yet claimed as a verified native DeepSeek Harness integration until the real external-host gate is recorded.

## Safety boundary

- Paths are canonicalized and constrained to configured workspace or trusted roots.
- Long-running operations have explicit timeout and cancellation paths and clean up owned subprocesses.
- Critical artifacts use atomic persistence and deterministic recovery rules.
- Output size, execution time, candidate count, revisions, and concurrency are bounded by the owning contract.
- Target build, install, test, proof-of-concept, and service commands are not executed automatically.
- Git-backed services use explicit local repositories and immutable revisions; they do not clone, fetch, checkout, or expand the corpus on their own.
- Recognized credentials and unrestricted environment data must not be persisted.

The accepted platform is POSIX/macOS. Windows support is not claimed until its process, path, and CI gates are implemented and verified.

## Specifications

- [Project charter](./AGENTS.md)
- [Stable product specification](./SPEC.md)
- [Task ledger and progress table](./PROJECT_PROGRESS.md)
- [SPEC lifecycle](./specs/README.md)
- [Flow v1 history](./specs/changes/introduce-flow-capability-v1/SPEC.md)
- [MissingCheck v1 history](./specs/changes/admit-missing-check-capability-v1/SPEC.md)
- [Typestate v1 history](./specs/changes/admit-typestate-capability-v1/SPEC.md)
- [Change Observation v1 history](./specs/changes/add-change-observation-analyzer-v1/SPEC.md)
- [Variant classification](./specs/changes/classify-variant-research-role/SPEC.md)
- [Variant Search implementation SPEC](./specs/changes/introduce-variant-search-service-v1/SPEC.md)

During the pre-1.0 compatibility window, `pure-auto-codeql-v2` remains a CLI alias. Deprecated `PURE_AUTO_CODEQL_*` environment variables remain accepted where documented, with matching `AUTOVUL_*` values taking precedence.
