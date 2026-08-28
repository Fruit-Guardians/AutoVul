# Change: Rename the project to AutoVul

- Change ID: `rename-project-to-autovul`
- Status: Implemented
- Owner: AutoVul maintainers
- Created: 2026-08-27
- Updated: 2026-08-27

## Problem

The name `PureAutoCodeQL` describes the first implementation path but now constrains the product identity to CodeQL. The accepted product boundary is broader: the project is a host-independent vulnerability-research extension that runs under mature Agent/Harness hosts, and the recorded long-term direction is a Flow-Based vulnerability-research engine with CodeQL as its first Analyzer.

The proposed project name is `AutoVul`.

The old name is already present in several kinds of interface:

- human-facing documentation, Pi UI, prompts and help text;
- npm workspace package names and TypeScript imports;
- the CLI binary;
- environment variables used by local applications and Golden harnesses;
- generated qlpack names, CodeQL rule ids and provenance strings;
- temporary directory and internal UI keys;
- historical specifications and verification records.

A global string replacement would break package resolution, scripts, existing Query Packs, SARIF rule identity, environment-based integrations and historical traceability. The rename therefore needs an explicit compatibility policy.

## Host boundary

This change renames the vulnerability-research capability layer. It does not change the division of responsibility between the project and its host.

The host Agent/Harness continues to own model access, reasoning, planning, session context, generic tools and user interaction. AutoVul continues to own structured vulnerability-research capabilities, Analyzer execution, workflow state, validation and replayable artifacts.

The rename MUST NOT reposition AutoVul as an Agent, general Agent Harness or autonomous security product.

## Naming decision

The canonical human-facing name is:

```text
AutoVul
```

The canonical short description remains:

```text
A host-independent vulnerability-research extension and deterministic analysis engine.
```

The Flow-Based direction is a non-normative design direction until separately accepted. The rename MUST NOT claim that Flow Model Core or additional Analyzers already exist.

## Scope

### In scope

- Rename current human-facing branding to AutoVul.
- Rename private workspace packages to an AutoVul namespace.
- Add `autovul` as the canonical CLI binary.
- Introduce canonical `AUTOVUL_*` environment variables with compatibility fallback.
- Rename new temporary paths, UI keys, generated qlpack names and provenance strings where compatibility permits.
- Preserve existing runs, Query Packs, SARIF identity and replay behavior.
- Preserve historical specifications while making the old-name context explicit.
- Add automated checks that prevent accidental reintroduction of the old brand outside approved compatibility and historical locations.

### Non-goals

- Changing public Application method names or structured vulnerability schemas.
- Renaming CodeQL-specific tools such as `codeql_database`, `codeql_workflow` and `codeql_query` merely for branding.
- Renaming `/codeql` commands that identify the current Analyzer capability.
- Implementing Flow Model Core, a new Analyzer or a new host integration.
- Publishing npm packages or claiming ownership of the public `@autovul` npm scope.
- Renaming the local checkout directory automatically.
- Renaming a remote Git repository, organization, domain or social account without separate explicit authorization.
- Rewriting immutable historical records to pretend the former name never existed.

## Requirements

### Human-facing identity

- `REQ-RENAME-001`: Current user-facing documentation, Pi UI, help text and prompts MUST use `AutoVul` as the project name.
- `REQ-RENAME-002`: Current project charters and accepted root specifications MUST describe AutoVul with the same non-Agent host boundary currently accepted for PureAutoCodeQL.
- `REQ-RENAME-003`: The rename MUST NOT expand supported Analyzer, language, platform, host or vulnerability-research capability claims.
- `REQ-RENAME-004`: Historical change specifications and verification records MAY retain the old name where it identifies the project at the time of the recorded decision.
- `REQ-RENAME-005`: Historical documents that retain the old name SHOULD include a concise note linking it to the current AutoVul name when ambiguity is likely.

### Package and source identity

- `REQ-RENAME-010`: Private workspace packages MUST use the canonical internal namespace `@autovul/*` after migration.
- `REQ-RENAME-011`: All first-party TypeScript imports and package scripts MUST resolve through the canonical `@autovul/*` workspace names.
- `REQ-RENAME-012`: The root workspace package name MUST become `autovul` or an equally unambiguous private workspace name accepted before implementation.
- `REQ-RENAME-013`: The package lock MUST be regenerated through the package manager and MUST NOT be edited as an unvalidated text replacement.
- `REQ-RENAME-014`: Public npm publication MUST remain disabled until ownership and availability of the intended namespace are verified separately.
- `REQ-RENAME-015`: Package dependency-direction checks MUST continue enforcing contracts-to-core-to-runner-to-integration boundaries after the namespace migration.

### CLI and environment compatibility

- `REQ-RENAME-020`: `autovul` MUST become the canonical CLI binary.
- `REQ-RENAME-021`: `pure-auto-codeql-v2` MUST remain as a compatibility CLI alias for at least the current pre-1.0 compatibility window.
- `REQ-RENAME-022`: New documented configuration MUST use `AUTOVUL_*` environment variables.
- `REQ-RENAME-023`: Existing externally documented `PURE_AUTO_CODEQL_*` variables MUST remain accepted as deprecated fallbacks during the compatibility window.
- `REQ-RENAME-024`: When both canonical and deprecated variables are set, the canonical `AUTOVUL_*` variable MUST take precedence deterministically.
- `REQ-RENAME-025`: Environment compatibility resolution MUST use one typed helper rather than scattered per-command fallback branches.
- `REQ-RENAME-026`: Test-only environment variables MAY migrate without long-term aliases when they are not documented or consumed outside the repository, but the decision MUST be recorded in the verification mapping.

### Tools and host integration

- `REQ-RENAME-030`: CodeQL-specific aggregate tool names MUST remain `codeql_database`, `codeql_workflow` and `codeql_query` during this change.
- `REQ-RENAME-031`: CodeQL-specific Pi commands MAY retain `/codeql`, `/codeql-generate` and `/codeql-status` because they name a capability rather than the project brand.
- `REQ-RENAME-032`: Pi UI keys and lifecycle identifiers MAY change to `autovul` only if reload, cleanup and stale-state behavior remain compatible.
- `REQ-RENAME-033`: Host prompts MUST identify AutoVul as an extension inside the host Agent Loop and MUST NOT imply that AutoVul starts its own Agent.

### Artifacts and stable identifiers

- `REQ-RENAME-040`: Existing run manifests, workflow state, case summaries, Query Packs and recovery metadata MUST remain readable without user migration.
- `REQ-RENAME-041`: Existing Query Packs MUST remain independently replayable after the rename.
- `REQ-RENAME-042`: Existing CodeQL rule ids beginning with `pure-auto-codeql/` MUST remain accepted and MUST NOT be rewritten inside historical artifacts.
- `REQ-RENAME-043`: A rule whose semantics are unchanged SHOULD retain its existing rule id so SARIF identity and deduplication are not reset solely by branding.
- `REQ-RENAME-044`: New generated qlpack names, temporary workspace names and producer/provenance display strings SHOULD use `autovul` or `AutoVul` where those values are not stable semantic identities.
- `REQ-RENAME-045`: Readers and replay validators MUST distinguish stable identifiers from display branding and MUST NOT reject an artifact solely because it carries the former brand.
- `REQ-RENAME-046`: Schema-version strings MUST change only when their schema semantics change; branding alone MUST NOT create a new schema version.

### Source, tests and generated output

- `REQ-RENAME-050`: First-party source identifiers SHOULD use `autoVul` or `autovul` naming after migration unless a compatibility export requires the former name.
- `REQ-RENAME-051`: Temporary paths created after migration SHOULD use an `autovul-` prefix.
- `REQ-RENAME-052`: Golden fixtures MUST preserve old identifiers when they exercise compatibility and use new branding only when they represent newly generated output.
- `REQ-RENAME-053`: A repository naming check MUST reject unapproved occurrences of the former brand in current source, current documentation and new generated output.
- `REQ-RENAME-054`: The naming check MUST use an explicit allowlist for compatibility aliases, historical specifications, legacy fixtures and stable rule ids; it MUST NOT hide arbitrary directories from inspection.
- `REQ-RENAME-055`: Clean build and package verification MUST contain the canonical package namespace and both approved CLI entries, without stale packages from the former workspace namespace.

### Lifecycle and dependency ordering

- `REQ-RENAME-060`: Implementation SHOULD begin only after `harden-workflow-commit-boundaries` reaches a stable review checkpoint, so the rename does not obscure persistence-hardening changes.
- `REQ-RENAME-061`: The rename MUST be reviewable in checkpoints separating documentation, package namespace, CLI/environment compatibility, host UI and artifact compatibility.
- `REQ-RENAME-062`: The old project name MUST NOT be removed from compatibility surfaces until their deprecation window is explicitly closed by a later accepted SPEC.

## Proposed behavior

### Human-facing behavior

After migration, current UI and documentation present:

```text
AutoVul
A host-independent vulnerability-research extension and deterministic analysis engine.
```

The accepted boundary remains:

```text
Host Agent / Harness
  -> AutoVul Integration Adapter
     -> Vulnerability Research Core
        -> Analyzer Ports
           -> CodeQL
```

### CLI behavior

Both commands invoke the same CLI implementation during the compatibility window:

```bash
autovul doctor --json
pure-auto-codeql-v2 doctor --json
```

Documentation uses `autovul`. The old binary is an alias, not a second implementation.

### Environment behavior

Canonical and deprecated variables resolve through one precedence rule:

```text
AUTOVUL_* value
  -> otherwise matching PURE_AUTO_CODEQL_* value
  -> otherwise default
```

Examples of intended migration include:

```text
PURE_AUTO_CODEQL_V2_RUNS_DIR -> AUTOVUL_RUNS_DIR
PURE_AUTO_CODEQL_TIMEOUT_MS  -> AUTOVUL_TIMEOUT_MS
PURE_AUTO_CODEQL_M4_*        -> AUTOVUL_M4_*
```

The exact mapping MUST be recorded in the implementation verification record before deprecated names are removed from documentation.

### Artifact behavior

An existing Query Pack may continue to contain:

```text
pure-auto-codeql/python-command-injection
```

and remains valid. AutoVul display text and new non-semantic qlpack names do not require rewriting the historical pack. Rule identity changes require a semantic rule migration, not a brand migration.

## Contracts and artifacts

No public schema shape or schema version change is planned.

Affected compatibility surfaces include:

- npm package names and imports;
- CLI binary names;
- environment-variable names;
- Pi display strings and UI keys;
- qlpack names and LSP client display names;
- CodeQL rule ids and fixture expectations;
- provenance display text;
- documentation and project charters.

Historical persisted artifacts remain valid under the existing schemas. No artifact rewrite command is planned.

## Architecture

The rename does not change dependency direction:

```text
@autovul/contracts
  <- @autovul/core
     <- @autovul/codeql-runner
        <- @autovul/pi-extension / @autovul/cli
```

Compatibility belongs at external boundaries:

- CLI aliases in package metadata;
- environment-name resolution at application construction;
- artifact acceptance in readers and replay validation;
- historical-name allowlists in repository checks.

Core domain logic MUST NOT carry duplicate old-name and new-name branches throughout the workflow.

## Safety and privacy

- The rename MUST NOT broaden trusted roots, filesystem permissions or command execution.
- Existing run directories MUST NOT be moved or deleted automatically.
- Environment-variable migration MUST NOT log secret values.
- Package-lock regeneration MUST use the existing dependency set and MUST NOT silently upgrade unrelated dependencies.
- Renaming temporary paths and UI keys MUST preserve process cleanup and stale-state recovery.
- Repository, npm organization, domain and account renames are external operations and require explicit authorization at execution time.

## Compatibility and migration

The rename uses additive compatibility before removal:

1. AutoVul becomes the canonical display name.
2. Canonical package imports migrate together in one buildable checkpoint.
3. `autovul` is added while the old CLI binary remains an alias.
4. `AUTOVUL_*` variables are introduced while documented old variables remain fallbacks.
5. New non-semantic generated names use AutoVul.
6. Stable historical rule ids and artifacts remain unchanged.
7. A later accepted SPEC may remove deprecated aliases after an explicit compatibility window.

No automatic filesystem migration is required for existing run artifacts.

## Delivery plan

The executable migration sequence is recorded in [PLAN.md](./PLAN.md).

Implementation MUST NOT begin while this change remains Draft.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-RENAME-001` | Given current documentation and Pi UI, when inspected after migration, then the project is presented as AutoVul | Naming check and Pi snapshot tests |
| `REQ-RENAME-010` | Given the workspace graph, when installed and built, then all first-party packages resolve through `@autovul/*` | Clean install, build and dependency check |
| `REQ-RENAME-020` | Given a clean package build, when `autovul doctor --json` runs, then the canonical CLI succeeds | CLI integration test |
| `REQ-RENAME-021` | Given the same build, when the former CLI entry runs, then it delegates to the same implementation and returns a compatible result | Compatibility CLI test |
| `REQ-RENAME-024` | Given both new and old environment variables, when configuration is resolved, then the new value wins | Unit test |
| `REQ-RENAME-030` | Given the Pi extension, when registered, then the existing CodeQL aggregate tool names remain available | Pi RPC smoke |
| `REQ-RENAME-040` | Given a pre-rename run fixture, when loaded, then workflow status is returned without migration by the user | Legacy artifact test |
| `REQ-RENAME-041` | Given a pre-rename relocated Query Pack, when replayed, then validation remains successful | Real CodeQL replay |
| `REQ-RENAME-043` | Given an unchanged existing rule, when a new run is generated after branding migration, then its stable rule id remains compatible | Golden/SARIF assertion |
| `REQ-RENAME-053` | Given current source and documentation, when the naming check runs, then only explicitly allowlisted historical and compatibility occurrences remain | Repository naming check |
| `REQ-RENAME-055` | Given stale old build output, when clean package verification runs, then no former workspace package is included | Clean pack inspection |

## Validation plan

- Focused unit tests:
  - environment-name precedence and fallback;
  - display branding and UI-key cleanup;
  - legacy artifact acceptance;
  - naming-check allowlist behavior.
- Integration tests:
  - clean workspace install and TypeScript build;
  - canonical and compatibility CLI entries;
  - Pi registration and RPC smoke;
  - package dry-run.
- Real analyzer/target:
  - existing CodeQL LSP conformance;
  - existing multi-language Golden gate.
- Differential or negative sample:
  - unchanged vulnerable/fixed behavior;
  - new-name/old-name environment conflicts;
  - unapproved old-brand occurrence rejected by the naming check.
- Independent replay:
  - pre-rename Query Pack and newly generated Query Pack.

## Resolved design choices

- `AutoVul` is the canonical human-facing brand.
- Private workspace packages migrate to `@autovul/*`; public publication remains out of scope.
- `autovul` becomes canonical CLI and the former binary remains an alias during the compatibility window.
- `AUTOVUL_*` variables take precedence over deprecated `PURE_AUTO_CODEQL_*` fallbacks.
- CodeQL-specific tool and command names remain capability-oriented.
- Existing semantic rule ids and historical artifacts are not rewritten for branding.
- Historical specifications remain historically accurate rather than receiving an indiscriminate replacement.

## Open questions

- Should the remote Git repository slug eventually become `AutoVul`, and on which hosting account or organization?
- What release or milestone will close the pre-1.0 compatibility window for the former CLI and environment variables?

These external naming and future-removal decisions do not block accepting the additive migration defined in this SPEC.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-27 | Adopt AutoVul as the canonical brand | It describes a broader vulnerability-research capability layer without binding the identity to CodeQL. |
| 2026-08-27 | Separate display branding from stable identifiers | A brand change must not invalidate SARIF identity, historical artifacts or replay. |
| 2026-08-27 | Keep CodeQL tool names | They identify the current Analyzer capability and remain accurate under the broader project brand. |
| 2026-08-27 | Use an additive compatibility window | Existing scripts and host configurations should continue working while documentation moves to the new name. |

## Verification record

Implementation checkpoint recorded on 2026-08-28. This change is not yet Verified.

- Commands and results:
  - `npm run check`: passed; 23 test files and 116 tests passed, architecture/SPEC/naming checks passed, and package output was clean for all five workspaces.
  - `npm run test:e2e`: passed; Pi RPC tool calls, workflow, cancellation, reload, exit recovery and structured errors passed.
  - `npx --workspace @autovul/cli autovul --help`: passed.
  - `npx --workspace @autovul/cli pure-auto-codeql-v2 --help`: passed.
  - `git diff --check`: passed.
- Requirement-to-evidence mapping:
  - `REQ-RENAME-001` through `REQ-RENAME-005`: current documentation, Pi text and the explicit historical allowlist; enforced by `naming:check`.
  - `REQ-RENAME-010` through `REQ-RENAME-015`: workspace manifests, regenerated lockfile, dependency check, TypeScript build and clean package inspection.
  - `REQ-RENAME-020` through `REQ-RENAME-026`: dual CLI entries, the typed environment resolver and `test/rename-compat.test.ts`.
  - `REQ-RENAME-030` through `REQ-RENAME-033`: Pi extension tests and Pi RPC E2E.
  - `REQ-RENAME-040` through `REQ-RENAME-046`: unchanged schemas and rule ids, existing artifact/workflow tests and compatibility assertions; real pre-rename CodeQL replay remains pending.
  - `REQ-RENAME-050` through `REQ-RENAME-055`: source migration, naming governance, clean build and package-output checks.
  - `REQ-RENAME-060` through `REQ-RENAME-062`: rename implemented after the workflow-hardening commit, with compatibility names retained and reported by the allowlist.
- Skipped or blocked checks:
  - real CodeQL LSP conformance and multi-language Golden/differential replay were not run in this checkpoint;
  - public npm namespace ownership remains outside this change;
  - remote repository naming was already configured externally and was not changed by this implementation.
- Remaining limitations: compatibility aliases remain until a later accepted removal SPEC; Verified status requires the pending real CodeQL evidence.
