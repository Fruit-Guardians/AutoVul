# Change: <short title>

- Change ID: `<lowercase-kebab-case>`
- Status: Draft
- Owner: <name or role>
- Created: YYYY-MM-DD
- Updated: YYYY-MM-DD

## Problem

Describe the vulnerability-research problem and the evidence that the current behavior is insufficient.

## Host boundary

Explain why this belongs in AutoVul instead of the host Agent/Harness. Identify which responsibilities remain with the host.

## Scope

### In scope

- ...

### Non-goals

- ...

## Requirements

- `REQ-<CHANGE>-001`: The system MUST ...
- `REQ-<CHANGE>-002`: The system MUST NOT ...
- `REQ-<CHANGE>-003`: The integration SHOULD ...

## Proposed behavior

Describe the observable workflow, inputs, outputs, state transitions and failure behavior.

## Contracts and artifacts

List affected schemas, APIs, tool inputs/outputs, manifests, evidence and replay formats. State versioning and migration behavior.

## Architecture

Describe changes to Contracts, Core, Ports, Analyzer/Runner and Integration. Confirm that host-specific dependencies do not enter Core.

## Safety and privacy

Cover permissions, approval, trusted roots, command execution, secrets, logs, target data, timeout, cancellation, cleanup and abuse considerations.

## Compatibility and migration

Describe backward compatibility, rollout, existing run/artifact behavior and rollback.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-<CHANGE>-001` | Given ..., when ..., then ... | Unit/integration/real analyzer/Golden/replay |

## Validation plan

- Focused unit tests:
- Failure injection:
- Real analyzer/target:
- Differential or negative sample:
- Independent replay:
- Package/integration smoke:

## Open questions

- ...

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| YYYY-MM-DD | ... | ... |

## Verification record

Complete this section before changing the status to Verified.

- Commands and results:
- Requirement-to-evidence mapping:
- Skipped or blocked checks:
- Remaining limitations:
