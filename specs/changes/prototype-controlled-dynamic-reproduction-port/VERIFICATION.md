# Controlled Dynamic Reproduction Port Requirement Verification

- Status: Implemented & Verified
- Public contract: `v2.contracts/1`, `autovul.dynamic-reproduction/1`
- Analyzer Port: `DynamicReproductionPort` (`@autovul/core`), `ControlledDynamicReproductionAdapter` (`@autovul/codeql-runner`)
- Replay Service: `DynamicReproductionReplayService` (`@autovul/core`)
- Verification suite:
  - `test/dynamic-reproduction-port.test.ts`
  - `test/check-dependencies.mjs`

`Covered` means the requirement is verified by deterministic automated tests, process-tree lifecycle assertions, environment sanitization checks, witness SHA-256 artifact verification, and model-free replay without fake runner fallback.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-DYNPORT-001` | Covered | `DynamicReproductionPort` defined in `@autovul/core/src/dynamic-reproduction/port.ts` without runner/host dependencies; architectural boundaries verified by `test/check-dependencies.mjs` and `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-002` | Covered | Valid execution request executed, returning structured observation with exit code, stdout/stderr, elapsed time, environment digest, and evidence ref; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-003` | Covered | Rejects working directory or executable paths outside canonicalized `trustedRoots` with `DYN_UNTRUSTED_ROOT`; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-004` | Covered | Restricts executable invocation to binaries in `trustedRoots` or safe allowlist (`node`, `python3`, `python`, `git`), rejects unapproved binaries, executes with `shell: false`; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-005` | Covered | Validates and sanitizes environment, rejecting loader injection variables (`LD_PRELOAD`, `NODE_OPTIONS`, etc.) and credentials with `DYN_UNSAFE_ENVIRONMENT`; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-006` | Covered | Enforces timeout watchdog with process group termination (`SIGTERM` followed by `SIGKILL`), terminating spawned worker trees within budget and supporting clean `AbortSignal` cancellation; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-007` | Covered | Stdout and stderr bounded by `max_output_bytes` with truncation indicators; detected secret patterns are redacted via `sanitizeOutput`; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-008` | Covered | Captures declared witness files, validates path confinement, hashes contents with SHA-256, stores artifacts in `runsDir`, rejects path traversal with `DYN_WITNESS_ESCAPE`, and rejects oversized files with `DYN_WITNESS_TOO_LARGE`; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-009` | Covered | Execution observation schema `DynamicReproductionExecutionObservationSchema` validated against real execution outputs; verified by `test/dynamic-reproduction-port.test.ts`. |
| `REQ-DYNPORT-010` | Covered | `DynamicReproductionReplayService` performs model-free verification of witness digests; verified identical when untouched, and flags `evidence_mutated` when artifacts are tampered with; verified by `test/dynamic-reproduction-port.test.ts`. |

## Verification Command Gate

Passed:

```bash
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```
