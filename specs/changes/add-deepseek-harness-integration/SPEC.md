# Change: Add DeepSeek Harness Integration

- Change ID: `add-deepseek-harness-integration`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-09-03
- Updated: 2026-09-03
- Public contract: `v2.contracts/1`
- Depends on: `harden-capability-execution-contracts-v1`, `add-missing-check-javascript-cfg-analyzer-v1`

## Problem

AutoVul V2's core positioning is a host-independent vulnerability-research capability layer. It does not implement a Coding Agent or an Agent loop; instead, it provides deterministic, verifiable research capabilities to mature hosts.

Currently, `@autovul/pi-extension` is the sole native host integration adapter. To fulfill `REQ-INTEGRATION-005` and prove that AutoVul is truly host-independent rather than a Pi-specific extension, AutoVul must provide a thin, first-class adapter package for **DeepSeek Harness** (`@autovul/deepseek-harness`).

The adapter must expose the unified research tools (`autovul_research` and `autovul_run`) in standard function-calling / tool format, route all operations strictly through the stable `ApplicationApi`, provide host prompt guidance, and ensure clean resource lifecycle management.

## Host boundary

### Host (DeepSeek Harness) owns:
- Model provider configuration, API keys, and context window management.
- Reasoning, planning, selecting capabilities, and revising research hypotheses.
- Invoking tools and handling multi-turn agent loops.

### Integration Adapter (`@autovul/deepseek-harness`) owns:
- Exposing OpenAI/JSON-Schema-compatible tool definitions for `autovul_research` and `autovul_run`.
- Translating harness tool invocations into typed calls to `ApplicationApi.research()` and `ApplicationApi.manageRun()`.
- Formatting structured execution results and normalizing errors into stable domain records.
- Providing research prompt snippets instructing the LLM on hypothesis construction across Flow, MissingCheck, Typestate, and Change Observation.
- Managing application lifecycle and cleanly releasing file locks and runner sessions upon `close()`.

### Core (`@autovul/core`) owns:
- All vulnerability research semantics, deterministic rules, state transitions, evidence storage, and replay verification.
- Core remains 100% free of DeepSeek Harness types or concepts.

## Scope

### In scope

- New package `packages/deepseek-harness` (`@autovul/deepseek-harness`) in workspace.
- Plugin factory `createDeepSeekHarnessPlugin(options?: DeepSeekHarnessPluginOptions)` returning:
  - `tools`: readonly array of tool definitions with standard JSON schema specifications.
  - `execute(name: string, input: unknown, context?: { signal?: AbortSignal })`: typed tool execution handler.
  - `prompts`: research guidance and system instructions for the host agent.
  - `close()`: cleanly releases application resources.
- Support all four capabilities/services:
  - `flow`: taint tracking on CodeQL databases.
  - `missing_check`: dominance CFG on CodeQL databases or JavaScript source trees.
  - `typestate`: state machine verification on CodeQL databases.
  - `change_observation`: static Git hunk inspection service.
- Support all run actions:
  - `replay`: zero-model deterministic verification.
  - `status`: run lifecycle inspection.
  - `cancel`: active operation cancellation.
- Integration test suite `test/deepseek-harness.test.ts`.
- Workspace boundary and pack validation.

### Non-goals

- Implementing an Agent loop or interacting with LLM APIs directly.
- Adding duplicate workflow methods or bypassing `ApplicationApi`.
- Leaking harness-specific types into `contracts` or `core`.

## Requirements

- `REQ-DSEEK-001`: The package `@autovul/deepseek-harness` MUST be a thin integration adapter depending only on `@autovul/contracts`, `@autovul/core`, and `@autovul/codeql-runner`.
- `REQ-DSEEK-002`: `createDeepSeekHarnessPlugin` MUST expose `autovul_research` with parameters conforming to `AutovulResearchToolInputSchema`.
- `REQ-DSEEK-003`: `createDeepSeekHarnessPlugin` MUST expose `autovul_run` with parameters conforming to `AutovulRunToolInputSchema`.
- `REQ-DSEEK-004`: Tool definitions MUST be emitted in standard function-calling shape (`{ type: "function", function: { name, description, parameters } }`).
- `REQ-DSEEK-005`: Invocations of `autovul_research` and `autovul_run` MUST delegate exclusively to `ApplicationApi.research()` and `ApplicationApi.manageRun()`.
- `REQ-DSEEK-006`: Adapter tool execution MUST catch and normalize domain errors into structured failure records without unhandled process crashes.
- `REQ-DSEEK-007`: The plugin MUST provide system prompt snippets guiding the host model on capability selection, hypothesis formulation, and evidence-backed verification.
- `REQ-DSEEK-008`: Calling `plugin.close()` MUST cleanly invoke `ApplicationApi.close()`.

## Requirement Traceability

| Requirement ID | Implementation Location | Test Verification |
| --- | --- | --- |
| `REQ-DSEEK-001` | `packages/deepseek-harness/package.json`, `test/check-dependencies.mjs` | `test/check-dependencies.mjs` |
| `REQ-DSEEK-002` | `packages/deepseek-harness/src/tools.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-003` | `packages/deepseek-harness/src/tools.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-004` | `packages/deepseek-harness/src/tools.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-005` | `packages/deepseek-harness/src/tools.ts`, `packages/deepseek-harness/src/index.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-006` | `packages/deepseek-harness/src/tools.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-007` | `packages/deepseek-harness/src/prompts.ts` | `test/deepseek-harness.test.ts` |
| `REQ-DSEEK-008` | `packages/deepseek-harness/src/index.ts` | `test/deepseek-harness.test.ts` |

## Validation plan

- Unit tests verifying JSON schema export, tool definitions, and prompt generation.
- Integration tests executing `autovul_research` across Flow, MissingCheck (both CodeQL and JS CFG), Typestate, and Change Observation.
- Replay test executing `autovul_run` to achieve deterministic model-free verification.
- Error handling tests validating `INVALID_INPUT` and cancellation handling.
- Full workspace verification: `npm run check`.
