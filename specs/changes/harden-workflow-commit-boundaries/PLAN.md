# Workflow commit hardening plan

This plan implements `harden-workflow-commit-boundaries` after the change SPEC is explicitly Accepted. It does not authorize work while the SPEC remains Draft.

## Current baseline

- `stabilize-architecture-boundaries` is Implemented but not Verified.
- `npm run check` passes with 21 test files and 102 tests.
- Pi RPC E2E passes.
- Real CodeQL LSP snapshot and conformance pass for 13 scenarios.
- Real CodeQL multi-language Golden, differential and replay pass for 20 cases.
- Known blockers are persistence ordering, incomplete failure injection, stale compiled output and the unrecorded LSP lab size exception.

## Target outcome

At completion:

1. verification and finalization each have one documented commit point;
2. pre-commit failures expose no successful state;
3. post-commit projection failures recover without rerunning CodeQL or consuming budget;
4. Query Packs are promoted only when complete and validated;
5. all command boundaries have success, failure and cancellation tests;
6. package checks start from clean output and contain no stale LSP artifacts;
7. both this change and `stabilize-architecture-boundaries` have requirement-to-evidence records suitable for Verified review.

## Checkpoint 0: Accept the protocol

Work:

- Review the resolved choices for separate internal recovery metadata, explicit reconciliation and retained `./lab` compatibility.
- Confirm the authoritative-state commit model and post-commit return semantics.
- Change the SPEC status from Draft to Accepted only after explicit maintainer approval.

Exit criteria:

- no unresolved choice can materially change persisted recovery behavior;
- requirement IDs and acceptance evidence are stable;
- no implementation code has changed before acceptance.

## Checkpoint 1: Build the failure-injection baseline

Likely files:

- `test/workflow-command-boundaries.test.ts`
- new focused persistence/recovery test support under `test/support/`
- in-memory and filesystem ArtifactStore test doubles.

Work:

- Add named failpoints for evidence write, state replacement, pack staging/promotion, run projection and case projection.
- Encode the existing behavior as tests that demonstrate the two known partial-success defects.
- Add Analyzer call counters and budget assertions so recovery cannot silently rerun work.
- Build a command matrix for admission, probe, draft, verify and finalize: success, domain failure, infrastructure failure and cancellation.

Exit criteria:

- tests fail for the known verify/finalize ordering defects;
- each failpoint has an expected authoritative state and projection state;
- no production behavior has been changed yet.

## Checkpoint 2: Introduce the canonical commit and recovery boundary

Likely files:

- `packages/core/src/codeql-workflow/repository.ts`
- a focused commit/recovery module under `packages/core/src/codeql-workflow/`
- `packages/core/src/codeql-workflow/context.ts`
- `packages/core/src/ports.ts`
- filesystem implementation in `packages/codeql-runner/src/artifact-store.ts`.

Work:

- Define workflow-domain commit operations instead of a generic filesystem batch abstraction.
- Add trusted-root staging and same-filesystem atomic promotion primitives to the ArtifactStore port if required.
- Make authoritative state the explicit commit point.
- Add versioned internal recovery metadata if the accepted decision requires it.
- Remove direct authoritative-state/projection mutation paths from command context.
- Keep evidence-artifact access separate and explicitly non-authoritative.

Exit criteria:

- one repository owns state validation, migration, commit and reconciliation;
- corrupt state and metadata fail closed;
- pre-existing runs load without migration by the user;
- repository and adapter tests pass on the local filesystem.

## Checkpoint 3: Migrate verification

Likely files:

- `packages/core/src/codeql-workflow/verify.ts`
- `packages/core/src/codeql-workflow/verification-policy.ts`
- `packages/core/src/codeql-workflow/case-ledger.ts`
- verification failure-injection tests.

Work:

- Evaluate CodeQL results without mutating success projections.
- Persist referenced evidence before committing state.
- Commit candidate and verification exactly once.
- Reconcile run and case projections after commit.
- Define late cancellation as committed success with recorded reconciliation evidence.
- Make retries return the committed verification without another Analyzer call or budget use.

Exit criteria:

- every verification failpoint satisfies `REQ-WFCOMMIT-003` or `REQ-WFCOMMIT-006` as appropriate;
- cancellation tests cover both sides of the commit point;
- candidate budgets and endpoint/differential semantics remain unchanged.

## Checkpoint 4: Migrate finalization

Likely files:

- `packages/core/src/codeql-workflow/finalize.ts`
- Query Pack filesystem adapter support;
- finalization and relocated replay tests.

Work:

- Generate the whole Query Pack in a run-scoped staging directory.
- Validate required files, schemas and digests before promotion.
- Atomically promote the complete directory.
- Commit workflow state with the pack identity.
- Reconcile completed run and case projections.
- Recover idempotently from promoted-but-uncommitted and committed-but-unprojected states.

Exit criteria:

- no failpoint exposes an incomplete finalized pack;
- repeated finalization returns the same pack id;
- conflicting finalization is rejected deterministically;
- existing relocated replay remains compatible.

## Checkpoint 5: Make reconciliation explicit

Likely files:

- `packages/core/src/codeql-workflow/status.ts`
- `packages/core/src/codeql-workflow/admission.ts`
- recovery service and tests.

Work:

- Separate status assembly from mutating reconciliation, or name the combined operation explicitly according to the accepted decision.
- Reconcile stale active-case summaries from authoritative state.
- Bound cleanup and projection retries.
- Ensure admission cannot start a duplicate case because of a stale projection.

Exit criteria:

- repeated recovery is idempotent;
- status and admission return consistent results after simulated restart;
- no nominal read helper hides unbounded persistence work.

## Checkpoint 6: Clean package and lab boundaries

Likely files:

- root and workspace `package.json` scripts;
- `test/check-architecture.mjs`;
- package inspection test;
- `packages/codeql-runner/src/lsp/lab/`.

Work:

- Add an explicit clean-build command targeting only known workspace `dist` directories.
- Run package verification from clean output.
- Reject compiled files without a current source or approved generated owner.
- Remove legacy `dist/lsp/protocol-spike.*` from the pack result.
- Split the LSP lab into cohesive scenario, transport, observation and snapshot modules, or enforce an accepted size exception.

Exit criteria:

- clean package dry-run contains only current compiled paths;
- primary runner exports remain free of protocol-lab types;
- architecture checks do not silently exempt an oversized file.

## Checkpoint 7: Full verification and lifecycle closeout

Commands:

```bash
npm run check
npm run test:e2e
npm run test:lsp:conformance
npm run test:m3-golden-real
git diff --check
```

Additional evidence:

- failure matrix with a requirement-to-test mapping;
- clean package file-list assertion;
- restart/recovery trace showing no repeated Analyzer execution;
- relocated Query Pack replay;
- explicit record of any real-model gate not run, without treating it as success.

Exit criteria:

- every MUST requirement in the change SPEC has evidence;
- no skipped required check is reported as passing;
- `VERIFICATION.md` for `stabilize-architecture-boundaries` records the reproduced 13-scenario LSP and 20-case Golden results;
- this change moves to Verified;
- shared requirements in `stabilize-architecture-boundaries` are reviewed for Verified status;
- stable behavior is merged into root `SPEC.md` before either change is Archived.

## Recommended review checkpoints

Keep the implementation reviewable by concern:

1. failure-injection tests;
2. repository/adapter commit primitives;
3. verification migration;
4. finalization migration;
5. reconciliation cleanup;
6. build/package/lab hygiene;
7. verification records and lifecycle updates.

Do not combine public contract changes, new Analyzer support or new host integrations into these checkpoints. Those require separate accepted change specifications.
