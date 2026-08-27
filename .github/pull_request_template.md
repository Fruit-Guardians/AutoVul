## Purpose

<!-- What vulnerability-research capability, defect or infrastructure problem does this change address? -->

## Architecture boundary

- [ ] This change strengthens the vulnerability-research extension and does not duplicate host Agent/Harness capabilities.
- [ ] Domain policy is in Contracts/Core, tool implementation is in an Analyzer/Runner, and host-specific code remains in an Integration.
- [ ] Any contract or artifact compatibility impact is described below.
- [ ] The change conforms to `SPEC.md`; material behavior changes reference an accepted `specs/changes/<change-id>/SPEC.md`.

## Evidence and validation

<!-- Include exact commands and concise results. Distinguish fake tests from real analyzer/model/Golden evidence. -->

- [ ] Focused tests
- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run pack:check`
- [ ] Real analyzer or Golden/replay check, when behavior requires it

## Security and operational impact

- [ ] No secrets, private target source, databases or generated run artifacts are committed.
- [ ] New process/file operations preserve timeout, cancellation, trusted-root and cleanup behavior.
- [ ] Security claims use the correct verification level.

## Not validated / follow-up

<!-- State skipped checks, blocked external dependencies and remaining risks explicitly. -->
