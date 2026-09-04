# Change: Prototype Controlled Dynamic Reproduction Port

- Change ID: `prototype-controlled-dynamic-reproduction-port`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-09-04
- Updated: 2026-09-04
- Public contract: `v2.contracts/1`, `autovul.dynamic-reproduction/1`
- Depends on: `establish-research-capability-architecture`, `harden-capability-execution-contracts-v1`

## Problem

Static vulnerability analysis (CodeQL queries, intra-procedural AST/CFG dominance) can prove data-flow paths and check placement, but cannot empirically observe runtime exploit dynamics, side effects, or execution behavior in dynamic runtimes (e.g. Node.js evaluation, argument injection, state transitions, prototype mutations, or protocol handshakes).

In AutoVul V2's research escalation ladder:
1. Agent native code audit
2. Git / Patch / AST / CFG light observation (optional)
3. Capability structured verification (optional)
4. CodeQL deep interprocedural analysis (optional)
5. Dynamic reproduction and differential check (optional)
Dynamic reproduction represents the highest empirical validation tier, but it also carries the highest execution hazards:
1. Unconstrained command execution and shell injection.
2. Accidental host escape or filesystem damage.
3. Secret exfiltration through inherited environment variables.
4. Process hangs and resource exhaustion from uncontrolled child processes.
5. Non-deterministic, unreplayable execution that cannot be verified offline.

AutoVul requires a **Controlled Dynamic Reproduction Port** (`DynamicReproductionPort`) that provides bounded, isolated, and deterministic execution semantics with immutable evidence collection and replay verification.

## Host boundary

### Host Agent owns:
- Reading target source code, patch diffs, and security advisories.
- Deciding whether dynamic reproduction is required and formulating the concrete reproduction hypothesis: target repository, revision, reproduction script or test command, arguments, and expected witness indicators.
- Evaluating whether the structured reproduction observation confirms or disproves the audit conclusion.

### AutoVul Core owns:
- Defining the formal Port contract `DynamicReproductionPort` in `@autovul/core`.
- Validating reproduction input schemas, strict budgets, and safety policies.
- Enforcing `trustedRoots` containment and directory canonicalization.
- Sanitizing execution environments against loader injection (`LD_PRELOAD`, `NODE_OPTIONS`) and credential leakage.
- Enforcing hard execution deadlines and process-tree termination (`SIGTERM` followed by `SIGKILL`).
- Collecting bounded stdout/stderr with secret redaction and capturing witness files with immutable SHA-256 digests.
- Guaranteeing deterministic replay verification without a model or host session.

## Scope

### In scope

- Formal port definition `DynamicReproductionPort` in `@autovul/core`.
- Versioned request, observation, and witness artifact schemas in `@autovul/contracts` (`autovul.dynamic-reproduction/1`).
- Domain error codes:
  - `DYN_UNTRUSTED_ROOT`: working directory or script escapes `trustedRoots`.
  - `DYN_UNSAFE_ENVIRONMENT`: disallowed environment variables or loader injection detected.
  - `DYN_TIMEOUT_EXCEEDED`: execution exceeded budgeted deadline.
  - `DYN_WITNESS_ESCAPE`: declared witness file path escapes target directory.
  - `DYN_WITNESS_TOO_LARGE`: witness file exceeds byte limit.
  - `DYN_REPLAY_DIGEST_MISMATCH`: replay evidence does not match recorded digest.
- Production adapter `ControlledDynamicReproductionAdapter` in `@autovul/codeql-runner`:
  - Enforces `trustedRoots` and disallows shell execution (`shell: false`).
  - Environment sanitization: strips dangerous environment variables and passes only an explicit safe allowlist.
  - Detached process-tree lifecycle management with hard timeout watchdogs.
  - Output stream capture with byte caps and regex-based secret redaction.
  - Witness file capture with path confinement and SHA-256 digest calculation.
- Evidence bundling under `reproduction/{hypothesis_id}/witnesses.json` and artifact store integration.
- Deterministic model-free replay validator verifying evidence digests and tamper resistance.
- Unit and integration tests demonstrating:
  - Strict security boundary enforcement (untrusted roots, shell evasion, unsafe env vars).
  - Timeout and cancellation process-tree termination.
  - Witness collection and SHA-256 verification.
  - End-to-end differential reproduction against a real vulnerability reproduction fixture.

### Non-goals

- An autonomous Agent that invents arbitrary build commands or installs unknown package dependencies.
- A general-purpose remote execution daemon or cloud container orchestrator.
- Bypassing the host Agent's reasoning: AutoVul executes the host's specified reproduction command within strict bounds, it does not synthesize arbitrary dynamic exploits from scratch.
- Merging dynamic reproduction into CodeQL workflows.

## Requirements

- `REQ-DYNPORT-001`: The port interface `DynamicReproductionPort` MUST be defined in `@autovul/core` without dependencies on concrete runner implementations or host environments.
- `REQ-DYNPORT-002`: Every execution request MUST specify a target working directory (`cwd`), executable, arguments, budget (`timeoutMs`, `maxOutputBytes`, optional `maxWitnessBytes`), and optional declared `witnessFilePaths`.
- `REQ-DYNPORT-003`: The working directory and executable MUST reside strictly within canonicalized `trustedRoots`. Paths attempting traversal outside `trustedRoots` MUST be rejected with `DYN_UNTRUSTED_ROOT`.
- `REQ-DYNPORT-004`: Command execution MUST NOT invoke a shell (`shell: false`). Executable invocation MUST be restricted to binaries located within `trustedRoots` or an approved safe executable allowlist (e.g. `node`, `python3`, `git`).
- `REQ-DYNPORT-005`: The execution environment MUST be sanitized; loader injection variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PERL5OPT`, `PYTHONPATH`) and sensitive secrets (tokens, API keys) MUST be stripped or rejected with `DYN_UNSAFE_ENVIRONMENT`.
- `REQ-DYNPORT-006`: The adapter MUST enforce a hard execution deadline (`timeoutMs`). Upon timeout or `AbortSignal`, the adapter MUST terminate the entire child process tree and return a structured observation with `timedOut: true` or `cancelled: true` without leaking zombie processes.
- `REQ-DYNPORT-007`: Stdout and stderr streams MUST be bounded by `maxOutputBytes` with truncation flags, and recognized secrets MUST be redacted via deterministic sanitization.
- `REQ-DYNPORT-008`: Declared witness files MUST be verified within `cwd` or `artifactRoot`, capped at `maxWitnessBytes`, read, and hashed with SHA-256. Paths attempting traversal outside the allowed boundary MUST be rejected with `DYN_WITNESS_ESCAPE`.
- `REQ-DYNPORT-009`: Execution observations MUST include exit code, signal, elapsed time, stdout, stderr, truncation status, witness artifacts (with relative paths, size, and SHA-256), environment digest, and an immutable `evidenceRef`.
- `REQ-DYNPORT-010`: Replay MUST be model-free, validating that recorded witness files and execution evidence match the original SHA-256 digests. Any mutation or divergence MUST be detected and rejected.

## Proposed behavior

1. **Request Formulation**:
   The host Agent formulates a `DynamicReproductionExecutionRequest` specifying the reproduction script/executable, target working directory, explicit safe arguments, timeout, and expected witness files.
2. **Boundary Validation**:
   The port adapter canonicalizes paths, verifies membership within `trustedRoots`, validates the executable, strips dangerous environment variables, and computes a SHA-256 `environmentDigest`.
3. **Controlled Execution**:
   The adapter spawns the process with `shell: false`, detached process group, and strict timeout watchdog. Stdout and stderr are captured up to `maxOutputBytes`.
4. **Evidence Collection**:
   Upon process termination, the adapter collects exit code, signal, execution time, sanitized outputs, and declared witness files. Witness files are hashed with SHA-256. All facts are saved as an atomic artifact bundle.
5. **Observation Return**:
   The adapter returns `DynamicReproductionExecutionObservation` containing verifiable facts.
6. **Model-free Replay**:
   `DynamicReproductionReplayService` checks the original evidence bundle against recorded SHA-256 hashes, confirming tamper-free determinism.

## Contracts and artifacts

- Schema: `packages/contracts/src/dynamic-reproduction.ts` (`autovul.dynamic-reproduction/1`).
- Artifacts:
  - `reproduction/{hypothesis_id}/observation.json`: structured execution record.
  - `reproduction/{hypothesis_id}/witnesses.json`: array of captured witness paths, sizes, and SHA-256 digests.
  - `reproduction/{hypothesis_id}/witnesses/{file}`: raw witness artifacts preserved for offline inspection.

## Architecture

- Layering strictly maintained:
  `contracts` (schemas/errors) is consumed by `core` (port interface, replay validator), which is consumed by `codeql-runner` (controlled adapter, process management), which is consumed by `pi-extension` / `deepseek-harness` / `cli` (thin consumers).
- No host concepts or LLM SDKs leak into `core`.

## Safety and privacy

- All executions constrained to `trustedRoots`.
- Shell invocation disallowed.
- Environment variables stripped of loader injection vectors and API keys.
- Process trees killed with `SIGTERM` followed by `SIGKILL` on timeout or cancellation.
- Secrets redacted in stdout/stderr.

## Compatibility and migration

- Additive Analyzer Port prototype.
- Does not modify existing CodeQL, MissingCheck, or Change Observation contracts.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-DYNPORT-001` | Given `DynamicReproductionPort`, when compiled, then no runner or host types are imported. | `test/check-dependencies.mjs` |
| `REQ-DYNPORT-002` | Given valid execution request, when executed, then structured observation is returned. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-003` | Given `cwd` outside `trustedRoots`, when invoked, then rejects with `DYN_UNTRUSTED_ROOT`. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-004` | Given disallowed binary or shell invocation, when invoked, then rejects with `INVALID_INPUT`. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-005` | Given `NODE_OPTIONS` or `LD_PRELOAD`, when invoked, then strips or rejects with `DYN_UNSAFE_ENVIRONMENT`. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-006` | Given hanging process, when `timeoutMs` expires, then process tree is killed within budget. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-007` | Given output containing API keys, when captured, then secrets are redacted and bounded. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-008` | Given witness file path with `../`, when collected, then rejects with `DYN_WITNESS_ESCAPE`. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-009` | Given successful run, when observation emitted, then contains exitCode, hashes, and evidenceRef. | `test/dynamic-reproduction-port.test.ts` |
| `REQ-DYNPORT-010` | Given mutated evidence file, when replay runs, then rejects with `DYN_REPLAY_DIGEST_MISMATCH`. | `test/dynamic-reproduction-port.test.ts` |

## Validation plan

- Unit tests for adapter command parsing, trusted roots check, and environment sanitization.
- Process tree kill test verifying that child processes (e.g. spawned background workers) are fully terminated on timeout.
- Witness artifact collection and digest verification test.
- Replay test asserting detection of modified evidence files.
- Command gate: `npm run build`, `npm run typecheck`, `npm test`, `npm run lint`, `npm run pack:check`.

## Open questions

- None.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-09-04 | Model as an Analyzer Port rather than a full Capability | Dynamic reproduction is an execution mechanism; different capabilities or hosts may define different success criteria. Keeping it as a port preserves modularity and avoids forcing all dynamic bugs into a single hypothesis shape. |

## Implementation and verification record

- Port definition `DynamicReproductionPort` implemented in `@autovul/core/src/dynamic-reproduction/port.ts`.
- Adapter `ControlledDynamicReproductionAdapter` implemented in `@autovul/codeql-runner/src/dynamic-reproduction-adapter.ts`.
- Replay service `DynamicReproductionReplayService` implemented in `@autovul/core/src/dynamic-reproduction/replay.ts`.
- Automated tests in `test/dynamic-reproduction-port.test.ts` verify all 10 requirements covering sandbox boundaries, environment sanitization, process-tree killing, secret redaction, witness SHA-256 capture, differential execution, and model-free replay verification.
- Verified status documented in `specs/changes/prototype-controlled-dynamic-reproduction-port/VERIFICATION.md`.
