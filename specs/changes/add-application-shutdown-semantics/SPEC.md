# Change: Add Application Shutdown Semantics

- Change ID: `add-application-shutdown-semantics`
- Status: Verified
- Owner: AutoVul maintainers
- Created: 2026-08-31
- Updated: 2026-08-31
- Approval: Explicitly requested by the user on 2026-08-31
- Depends on: `establish-research-capability-architecture`

## Problem

The shared runtime supports per-run cancellation, but `Application.close()` only closes the query-draft resource. A host shutdown can therefore leave active Analyzer or database operations alive, and the Application can accept new work after shutdown has started.

## Scope

- Define one Application lifecycle shared by Flow, MissingCheck, compatibility workflows, and database operations.
- Propagate shutdown cancellation into every operation that accepts an `AbortSignal`.
- Wait for admitted operations and owned resources to settle before close completes.
- Reject operations admitted after shutdown begins.

## Non-goals

- No process-global shutdown manager or host Agent lifecycle framework.
- No new run action beyond `status | cancel | replay`.
- No Typestate, Variant, or Delta implementation.
- No rollback of a domain result already committed before cancellation is observed.

## Requirements

- `REQ-SHUTDOWN-001`: `Application.close()` MUST atomically transition the Application from `open` to `closing`; calls admitted after that transition MUST fail with a stable structured state error.
- `REQ-SHUTDOWN-002`: Closing MUST abort every active Application operation, including Capability execution/replay, database operations, and compatibility workflow operations.
- `REQ-SHUTDOWN-003`: The shutdown signal MUST compose with, and MUST NOT replace, a caller-provided cancellation signal.
- `REQ-SHUTDOWN-004`: Closing MUST request cancellation for every live shared-runtime run in the current process.
- `REQ-SHUTDOWN-005`: `close()` MUST wait for all operations admitted before closing and all Application-owned closeable resources to settle before resolving.
- `REQ-SHUTDOWN-006`: Repeated or concurrent `close()` calls MUST be idempotent and await the same shutdown outcome.
- `REQ-SHUTDOWN-007`: Cancellation observed before a domain commit point MUST remain cancelled and replayable; closing MUST NOT relabel a committed result.
- `REQ-SHUTDOWN-008`: Shutdown MUST NOT delete persisted runs or evidence and MUST NOT infer success from interrupted work.
- `REQ-SHUTDOWN-009`: Application-level lifecycle state MUST stay inside Core; Pi, CLI, and future integrations MUST only invoke `close()` from their host lifecycle.

## Failure and compatibility behavior

- A call admitted after closing starts fails with `INVALID_STATE_TRANSITION`, category `state`, and `details.applicationState = "closing" | "closed"`.
- An in-flight operation cancelled by close continues to use its existing `PROCESS_CANCELLED` or Capability-specific cancelled observation and persisted status.
- Existing public method signatures and run contracts remain unchanged.

## Acceptance

- Given an active Flow Adapter, when `close()` is called, then its signal is aborted, the result is cancelled, and close waits for settlement.
- Given an active database inspection, when `close()` is called, then it rejects as `PROCESS_CANCELLED` and its run is persisted as cancelled.
- Given a caller signal and the Application shutdown signal, when either aborts, then the operation observes cancellation.
- Given concurrent close calls, when shutdown finishes, then the owned closeable resource is closed exactly once.
- Given a call after closing begins, when it is invoked, then no adapter runs and a structured state error is returned.

## Delivery record

- Implementation: `packages/core/src/application.ts` owns lifecycle admission, shutdown-signal composition, active-operation settlement and idempotent resource close; `packages/core/src/run-cancellation.ts` cancels all live Capability runs.
- Verification: `test/application-shutdown.test.ts` covers active Flow cancellation, caller and shutdown cancellation of database operations, close settlement, resource-close idempotency and structured rejection after close.
- Full gates: `npm run lint && npm test && npm run pack:check` passed on 2026-08-31; 28 test files and 156 tests passed, and pack output was clean for all 5 packages.
- Root merge: stable behavior is recorded in `REQ-WORKFLOW-010`, `REQ-WORKFLOW-011`, and `REQ-INTEGRATION-008` of root `SPEC.md` v1.3.
