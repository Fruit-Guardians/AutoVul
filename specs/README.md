# SPEC workflow

This directory records material changes to the accepted product specification.

## When a change SPEC is required

Create `specs/changes/<change-id>/SPEC.md` before implementation when a change affects observable behavior, public contracts, workflow state, artifacts, security boundaries, analyzer support, host integrations or support claims.

Use a short lowercase kebab-case change id, for example:

```text
specs/changes/add-deepseek-integration/SPEC.md
specs/changes/generalize-evidence-contract/SPEC.md
```

Small documentation corrections, tests that only encode already-specified behavior and behavior-preserving refactors do not require a separate change SPEC.

## Lifecycle

```text
Draft -> Accepted -> Implemented -> Verified -> Archived
```

- **Draft**: open design; not authorization to expand implementation scope.
- **Accepted**: explicitly approved by the user or maintainer.
- **Implemented**: code is complete, but verification may remain.
- **Verified**: every requirement has corresponding evidence.
- **Archived**: stable requirements are reflected in the root `SPEC.md`; the change file remains for traceability.

Lifecycle status describes the whole change, not the presence of some code. If a newly added requirement, real-tool gate, replay invariant, or migration step is still open, the change cannot be `Implemented`. A repository unit test cannot replace a real Analyzer, real host, Golden, differential, or independent-replay gate required by the change.

## Review rules

- A change SPEC must explain why the capability belongs in this vulnerability-research extension rather than the host Agent/Harness.
- Requirements use stable IDs and normative `MUST`, `MUST NOT`, `SHOULD` or `MAY` language.
- Acceptance criteria are observable and identify whether they require fake infrastructure, real analyzers, real models, Golden cases, differential targets or replay.
- Implementation must not begin while material product choices remain unresolved.
- If implementation contradicts an accepted requirement, update and re-accept the SPEC instead of silently weakening tests or validation.

## Status transition checklist

Before changing a lifecycle status:

1. `Draft -> Accepted`: record who approved the scope and resolve every implementation-blocking product choice.
2. `Accepted -> Implemented`: map every normative requirement to code or migration output and record all compatibility handling.
3. `Implemented -> Verified`: add a requirement-by-requirement `VERIFICATION.md`; record the exact commands, real fixtures, immutable evidence, skipped checks, and limitations.
4. `Verified -> Archived`: merge only the stable verified behavior into root `SPEC.md`, then update `README.md` and `PROJECT_PROGRESS.md` without expanding the claim.

If a later audit finds that required evidence never existed, return the change to the last defensible status and name the missing gate. Do not preserve an inaccurate status for cosmetic progress.

Copy [changes/TEMPLATE.md](./changes/TEMPLATE.md) to start a proposal.
