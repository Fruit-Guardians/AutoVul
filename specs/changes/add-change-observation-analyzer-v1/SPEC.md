# Change: Add Change Observation Analyzer v1

- Change ID: `add-change-observation-analyzer-v1`
- Status: Archived
- Owner: AutoVul maintainers
- Created: 2026-09-02
- Updated: 2026-09-02
- Public contract: `autovul.change-observation/1`
- Depends on: archived `classify-delta-research-role`, `establish-research-capability-architecture`, and the existing aggregate Application/runtime contracts

## Problem

The archived Delta classification established that deterministic revision facts
are useful to more than one vulnerability-research Capability, while those
facts have no independent vulnerability success predicate. The OpenClaw
authorization patch can guide a MissingCheck revision and the Ghost
session-fixation patch can guide a Typestate revision, but neither patch diff
can decide `check_present`, `violation_observed`, or `differential`.

AutoVul therefore needs one narrow, replayable service that answers only
“what changed between two immutable revisions?” The public name is **Change
Observation Analyzer v1**. “Delta” remains only the archived classification
term and is not a product Capability or contract name.

## Host boundary

The host chooses the trusted repository, immutable revisions, optional path
scope, and research question. It reads code, interprets the observations,
selects or revises an owning Capability hypothesis, and decides whether to
stop or make another request.

AutoVul owns strict request validation, bounded read-only Git/object and
parser execution, normalized structural observations, deterministic
fingerprinting, artifacts, cancellation, and model-free replay. It does not
infer security intent, narrate a patch, select Flow/MissingCheck/Typestate,
construct a hypothesis, or decide a verification result.

## Scope

### In scope

- One Analyzer Service with public version `autovul.change-observation/1`.
- A trusted local Git repository, two immutable Git commit OIDs, optional
  literal repository-relative path-prefix filters, and an explicit bounded
  observation budget.
- File status, confirmed rename, normalized text-hunk, declaration, direct
  call/argument, and direct-call event observations.
- JavaScript and TypeScript structural parsing in v1; unsupported parsers and
  languages are structured gaps rather than silent omissions.
- Deterministic ordering, truncation, request/observation fingerprints,
  provenance, atomic artifacts, cancellation, per-run serialization, and
  fresh-process replay through the existing two aggregate host tools.
- Real OpenClaw and Ghost patch cases as two separate Capability consumers.

### Non-goals

- A fourth `ResearchCapability`, `capability: delta`, `DeltaHypothesis`, or
  `DeltaDecision`.
- Vulnerability classification, fixed/vulnerable claims, source/sink/check/state
  inference, a Decision Policy, revision hints, or any verification level.
- Automatic Capability selection, automatic hypothesis revision, or automatic
  execution of another Capability.
- A generic Git client, history miner, commit browser, blame engine, merge
  resolver, code-review Agent, patch-summary generator, or natural-language
  patch narrative.
- Cross-repository search, Variant discovery, remote fetch/clone, checkout,
  reset, build, install, test, or execution of target code.
- A generic Analyzer registry, universal observation/comparison type, new
  workspace package, or third model-facing tool.

## Definitions

- **Analyzer Service**: a non-Capability operation that returns deterministic
  tool facts but no domain verdict.
- **Immutable revision**: a complete lower-case 40- or 64-hex Git commit OID
  resolved from the local object database. Ref names, abbreviated OIDs, worktree
  contents, index contents, and staged changes are not revisions in this v1.
- **Revision identity**: the detected Git object format plus the resolved base
  and head commit and tree OIDs used to reconstruct exactly one comparison.
- **Normalized hunk**: a text-diff range and digests of its normalized added and
  removed text, never an unbounded raw patch payload.
- **Direct-call event**: a syntax-level direct invocation selector, such as the
  member chain `req.session.regenerate`. It is not a Typestate event or a claim
  about security meaning.
- **Analysis gap**: a bounded declaration that requested scope could not be
  completely observed. A gap is neither an empty result nor a vulnerability
  conclusion.

## Requirements

### Role and aggregate routing

- `REQ-CHANGEOBS-001`: Change Observation Analyzer v1 MUST be an Analyzer
  Service and MUST NOT be added to `ResearchCapability` or any Capability
  hypothesis/result union.
- `REQ-CHANGEOBS-002`: The only public service identity is
  `service: "change_observation"` with
  `service_version: "autovul.change-observation/1"`. `delta` MUST NOT be an
  accepted service, capability, version, artifact route, or user-facing label.
- `REQ-CHANGEOBS-003`: `autovul_research` MUST accept the service only through
  this exact static request branch:

  ```json
  {
    "action": "execute",
    "service": "change_observation",
    "service_version": "autovul.change-observation/1",
    "input": {
      "repository": {"kind": "trusted_local_git_repository", "path": "/trusted/repository"},
      "base_revision": "75b4c059b8405dfbd50884b773346a9946fabd20",
      "head_revision": "80b1fa17bfc3f6a668492f0326ea52f48bb89776"
    }
  }
  ```

- `REQ-CHANGEOBS-004`: The aggregate research request MUST be a strict tagged
  union of the existing Capability branch and the exact Analyzer Service branch.
  The service branch MUST NOT accept `capability`, `hypothesis`,
  `hypothesis_version`, evidence-operation `mode`, or unknown `service` values.
- `REQ-CHANGEOBS-005`: `autovul_run` MUST retain its existing `status`,
  `cancel`, and `replay` actions. Its persisted route MUST select the explicit
  `change_observation` branch without a registry, dynamic loader, or generic
  Analyzer dispatch.
- `REQ-CHANGEOBS-006`: The service compact result MUST contain
  `operation_status`, optional `observation`, structured diagnostics, allowed
  next actions, `artifact_ref`, and `replay_ref`. It MUST NOT contain
  `decision`, `verification_level`, capability revision hints, or a generated
  next hypothesis.
- `REQ-CHANGEOBS-007`: The service MUST NOT classify a change as vulnerable,
  fixed, secure, exploitable, relevant, irrelevant, reproduced, or differential.
  It MUST NOT select, execute, or modify an owning Capability.
- `REQ-CHANGEOBS-008`: Existing Flow, MissingCheck, and Typestate request and
  result semantics MUST remain unchanged. Their `differential` mode and
  fixed-side policies remain Capability-owned.
- `REQ-CHANGEOBS-009`: This change MUST preserve exactly two aggregate
  model-facing interfaces, `autovul_research` and `autovul_run`; Pi and CLI
  MUST use the same Application API and MUST NOT register a service-specific
  tool.

### Input schema and fixed budgets

- `REQ-CHANGEOBS-010`: The service input MUST contain exactly `repository`,
  `base_revision`, `head_revision`, optional `path_filters`, and optional
  `budget`; no working-tree, branch, remote, patch-text, analyzer-command, or
  parser-command field is permitted.
- `REQ-CHANGEOBS-011`: `repository` MUST be
  `{ kind: "trusted_local_git_repository", path: string }`, where `path` has
  1–4096 UTF-8 characters, resolves through the configured trusted-root policy,
  is a local Git worktree or bare repository, and is never read outside the
  resolved repository/object database boundary.
- `REQ-CHANGEOBS-012`: `base_revision` and `head_revision` MUST each match
  `^(?:[0-9a-f]{40}|[0-9a-f]{64})$`, resolve locally to commit objects of the
  repository's detected object format, and be persisted as their resolved full
  OIDs. Symbolic refs, short hashes, `HEAD`, parent expressions, and revision
  ranges MUST be rejected at validation.
- `REQ-CHANGEOBS-013`: `path_filters`, when present, MUST be an array of 1–32
  distinct literal repository-relative path prefixes, each 1–1024 characters.
  A filter MUST use `/`, MUST NOT be absolute, contain NUL, backslash, `.` or
  `..` path components, glob syntax, or a trailing slash. The normalized unique
  filters are sorted by UTF-8 byte order before fingerprinting.
- `REQ-CHANGEOBS-014`: `budget`, when omitted, MUST resolve to the fixed
  defaults in the contract table. The request's `budget` is a strict partial
  override whose present numeric fields MUST be integers within the corresponding
  inclusive range; the persisted `resolved_budget` contains every field. Values
  above a maximum MUST be rejected rather than clamped.
- `REQ-CHANGEOBS-015`: The service MUST use this closed `ChangeObservationBudget`
  schema and resolved defaults:

  | Field | Inclusive range | Default / hard default |
  | --- | ---: | ---: |
  | `timeout_ms` | 1–600000 | 600000 |
  | `max_changed_files` | 1–512 | 512 |
  | `max_diff_bytes` | 1024–4194304 | 4194304 |
  | `max_hunks` | 1–2048 | 2048 |
  | `max_hunk_lines` | 1–256 | 256 |
  | `max_symbols` | 1–4096 | 4096 |
  | `max_call_changes` | 1–4096 | 4096 |
  | `max_event_changes` | 1–4096 | 4096 |

- `REQ-CHANGEOBS-016`: The service MUST compare Git objects only. It MUST NOT
  read the worktree, index, staged content, untracked files, or dirty status;
  its recorded dirty-worktree policy is the literal `"not_inspected"`.
- `REQ-CHANGEOBS-017`: Equal resolved base/head commit OIDs MUST complete with
  an empty complete observation, not a gap or an inferred absence of a security
  property.
- `REQ-CHANGEOBS-018`: A missing revision object MUST yield the structured
  `REVISION_OBJECT_MISSING` diagnostic. A shallow repository or missing history
  needed to resolve the requested commits MUST yield `SHALLOW_HISTORY` or
  `REVISION_OBJECT_MISSING` as applicable; the service MUST NOT fetch, deepen,
  or otherwise alter the repository.
- `REQ-CHANGEOBS-019`: Service diagnostics MUST use only
  `CHANGE_OBSERVATION_INVALID_REQUEST`,
  `CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED`,
  `CHANGE_OBSERVATION_REPOSITORY_INVALID`, `REVISION_OBJECT_MISSING`,
  `SHALLOW_HISTORY`, `CHANGE_OBSERVATION_PATH_FILTER_INVALID`,
  `CHANGE_OBSERVATION_GIT_FAILED`, `CHANGE_OBSERVATION_TIMEOUT`,
  `CHANGE_OBSERVATION_CANCELLED`, `CHANGE_OBSERVATION_ARTIFACT_MISSING`,
  `CHANGE_OBSERVATION_ARTIFACT_INVALID`,
  `CHANGE_OBSERVATION_ROUTE_UNSUPPORTED`, or
  `CHANGE_OBSERVATION_APPLICATION_CLOSING`. Every diagnostic MUST contain its
  code, retryability, and only the optional bounded path/count fields.

### ChangeObservation.v1 output

- `REQ-CHANGEOBS-020`: A completed or partial observation MUST have
  `schema_version: "autovul.change-observation/1"`, `revision_identity`,
  `scope`, `resolved_budget`, `completeness`, `changed_files`,
  `normalized_hunks`, `symbols`, `call_changes`, `event_changes`,
  `analysis_gaps`, `provenance`, `request_fingerprint`, and
  `observation_fingerprint`.
- `REQ-CHANGEOBS-021`: `revision_identity` MUST contain the closed
  `object_format: "sha1" | "sha256"` enum and exact `base_oid`, `head_oid`,
  `base_tree_oid`, and `head_tree_oid`. `scope` MUST contain normalized
  `path_filters`, `submodules: "not_included"`, and
  `dirty_worktree: "not_inspected"`.
- `REQ-CHANGEOBS-022`: Each `changed_files` item MUST contain a normalized
  repository-relative `path`, `change_kind`, and `content_kind`. The closed
  `change_kind` enum is `added | deleted | modified | renamed | type_changed`;
  `previous_path` is required only for a confirmed `renamed` item. The closed
  `content_kind` enum is `text | binary | unavailable`. The array is bounded by
  `max_changed_files` and sorted by `(path, previous_path ?? "", change_kind)`.
- `REQ-CHANGEOBS-023`: Each `normalized_hunks` item MUST contain `path`, a
  zero-based `ordinal`, `old_start`, `old_line_count`, `new_start`,
  `new_line_count`, `removed_line_count`, `added_line_count`,
  `normalized_removed_sha256`, `normalized_added_sha256`, and `truncated`.
  Line counts are non-negative integers; start lines are positive integers when
  their corresponding line count is nonzero and `0` otherwise. Raw patch text,
  commit messages, author data, and context lines MUST NOT appear in compact
  observations.
- `REQ-CHANGEOBS-024`: Hunk normalization MUST decode UTF-8 text only, convert
  CRLF to LF, remove diff headers, preserve blank lines, right-trim horizontal
  whitespace from changed lines, and hash the resulting added/removed line
  streams with SHA-256. A binary, undecodable, oversized, or over-line-budget
  hunk MUST be represented by a structured gap and, where a range is known, a
  `truncated: true` hunk rather than substituted text.
- `REQ-CHANGEOBS-025`: `symbols` MUST contain at most `max_symbols` items with
  `change_kind: added | removed | modified`,
  `symbol_kind: function | method | class | variable`, `language`, `name`, and
  one or both bounded old/new locations. JavaScript and TypeScript declaration
  parsing are the only supported structural languages in v1; another language,
  unavailable parser, or parser failure MUST be a gap rather than an `unknown`
  symbol fabricated from text matching.
- `REQ-CHANGEOBS-026`: `call_changes` MUST contain at most
  `max_call_changes` direct invocation observations with
  `change_kind: added | removed | modified`, a bounded identifier/member
  `callee_selector`, old/new locations where applicable, and a closed
  `argument_change_kind: none | count_changed | positions_changed` plus bounded
  old/new argument counts. It MUST NOT evaluate argument values, data flow, or
  call reachability.
- `REQ-CHANGEOBS-027`: `event_changes` MUST contain at most
  `max_event_changes` direct-call events with
  `event_kind: direct_call_added | direct_call_removed | direct_call_modified`,
  a selector of at most eight identifier/member segments, and a location. It
  MUST describe syntax only and MUST NOT impose an event order, state, identity,
  or protocol meaning.
- `REQ-CHANGEOBS-028`: `completeness` MUST be exactly `complete`, `partial`,
  or `blocked`. `complete` requires no scope-limiting gap; `partial` requires at
  least one gap but may retain bounded observed facts; `blocked` requires an
  observation-preventing diagnostic and MUST NOT be represented as an empty
  complete observation.
- `REQ-CHANGEOBS-029`: `analysis_gaps` MUST use only these codes:
  `BASE_REVISION_MISSING`, `HEAD_REVISION_MISSING`, `SHALLOW_HISTORY`,
  `BINARY_FILE_SKIPPED`, `UNDECODABLE_TEXT`, `RENAME_AMBIGUOUS`,
  `DIFF_TRUNCATED`, `HUNK_LINE_TRUNCATED`, `PARSER_UNAVAILABLE`,
  `PARSER_FAILED`, `SUBMODULE_SKIPPED`, and `PATH_FILTER_NO_MATCH`.
  Each gap MUST contain its code, optional normalized path, and a bounded
  machine-readable count or parser/language identifier; it MUST NOT contain raw
  source, commit messages, author data, or arbitrary tool stderr.
- `REQ-CHANGEOBS-030`: `provenance` MUST record the service version, detected
  Git object format, sanitized Git executable version, parser versions actually
  used, source `local_git_object_database`, and a closed command-profile version.
  `request_fingerprint` is SHA-256 over canonical service input, revision
  identity, normalized filters, and resolved budget. `observation_fingerprint`
  is SHA-256 over canonical observation fields excluding artifact/replay paths,
  timestamps, and process identifiers.

### Determinism, lifecycle, and safety

- `REQ-CHANGEOBS-031`: Core MUST normalize paths, sort every returned array by
  a documented UTF-8 byte-order tuple, apply every bound before artifact commit,
  and emit `DIFF_TRUNCATED` or the relevant gap when a bound excludes otherwise
  observable data. It MUST NOT depend on locale, filesystem enumeration order,
  Git configuration, or parser iteration order.
- `REQ-CHANGEOBS-032`: The Core service MUST own strict structural validation,
  resolved-budget construction, deterministic normalization, truncation,
  fingerprints, and result assembly. It MUST NOT contain a Decision Policy or
  Capability domain strings/semantics.
- `REQ-CHANGEOBS-033`: The Git adapter MUST use the explicit base/head object
  IDs and a fixed read-only command profile. It MAY inspect Git objects and
  invoke the pinned JavaScript/TypeScript parser only; it MUST NOT invoke
  checkout, reset, clean, switch, merge, rebase, fetch, pull, clone, submodule
  initialization, build, install, test, hook, shell interpolation, or target
  code.
- `REQ-CHANGEOBS-034`: Repository paths MUST be canonicalized and trusted-root
  checked before any Git command. Arguments MUST be passed without shell
  interpretation, and Git external-diff/textconv configuration MUST be disabled.
  Symlink escape, repository escape, and attempted filter escape MUST return a
  structured validation or safety diagnostic.
- `REQ-CHANGEOBS-035`: The service MUST use the existing idempotency identity,
  per-run execution lease, timeout, cancellation chain, atomic artifact commit,
  recovery, and Application-close admission boundary. A caller abort,
  `autovul_run cancel`, timeout, or Application shutdown MUST terminate the
  active child-process tree, preserve an accurate terminal status, and prevent a
  late artifact promotion.
- `REQ-CHANGEOBS-036`: A second execute or replay for the same run MUST either
  serialize behind the existing lease or return the existing stable in-progress
  result; it MUST NOT concurrently write a run database or service artifact.
- `REQ-CHANGEOBS-037`: Tool stderr, environment data, canonical local paths,
  raw diffs, commit messages, author/committer data, and recognized secrets MUST
  be minimized or sanitized in portable artifacts. Compact results expose only
  repository-relative locations and artifact references.

### Artifacts, replay, and real gates

- `REQ-CHANGEOBS-040`: A successful or partial execute MUST atomically commit a
  `change-observation/` artifact containing the normalized request, revision
  identity, resolved budget, sanitized command provenance, observation,
  diagnostics, fingerprints, and replay input. It MUST not mutate source Git
  objects or persist a raw unbounded patch by default.
- `REQ-CHANGEOBS-041`: The persisted operation route MUST be a strict
  `route_kind: "analyzer_service"` branch containing only service identity,
  service version, and the service result-artifact reference. Existing
  `route_kind: "capability"` records remain readable and unchanged; no route
  may infer a branch from an artifact name.
- `REQ-CHANGEOBS-042`: Replay MUST start in a fresh process without a model or
  host session, use only the recorded trusted repository and exact immutable
  OIDs, revalidate the revision identity, service/parser/Git command-profile
  versions, normalized filters, resolved budget, request fingerprint, and
  observation fingerprint, and compare all normalized observation fields.
- `REQ-CHANGEOBS-043`: Replay artifacts MUST write only under
  `change-observation-replay/`. Replay MUST prove the preexisting
  `change-observation/` artifact digest is unchanged before and after replay;
  relocated runs roots MUST not create false mismatches because artifact paths
  are excluded from semantic fingerprints.
- `REQ-CHANGEOBS-044`: A mismatch in revision identity, input/request
  fingerprint, Git/parser/service version, normalized observation semantics, or
  artifact evidence digest MUST return a distinct structured replay outcome. An
  unavailable local object, shallow history, cancellation, or environment
  failure MUST remain blocked/cancelled/failed and MUST NOT be reported as a
  semantic match.
- `REQ-CHANGEOBS-045`: Real acceptance MUST run the OpenClaw authorization
  revision pair `75b4c059b8405dfbd50884b773346a9946fabd20` to
  `80b1fa17bfc3f6a668492f0326ea52f48bb89776`, scoped to
  `extensions/msteams/src/monitor-handler.ts`, and record structural facts
  usable by the host to revise a MissingCheck hypothesis without emitting a
  MissingCheck decision.
- `REQ-CHANGEOBS-046`: Real acceptance MUST run the Ghost session-fixation
  repair commit `6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c` against its recorded
  resolved first-parent full commit OID, scope the actual repaired JavaScript
  file(s), and record the direct-call event facts usable by the host to revise a
  Typestate hypothesis without emitting a Typestate decision.
- `REQ-CHANGEOBS-047`: The real gate MUST demonstrate that the same service
  serves the OpenClaw MissingCheck and Ghost Typestate consumers while neither
  result contains a Capability, hypothesis, decision, verification level, or
  security conclusion.
- `REQ-CHANGEOBS-048`: Before the status advances to Verified, fresh-process
  replay with a relocated artifact root MUST succeed for both real cases and
  prove immutable revision identity, artifact immutability, deterministic
  fingerprints, cancellation, timeout, and per-run replay serialization. A fake
  adapter may cover infrastructure failure paths but MUST NOT satisfy either
  real-case gate.

## Proposed behavior

```text
autovul_research
  ├─ Capability request
  │    └─ flow | missing_check | typestate
  └─ Analyzer Service request
       └─ change_observation
            -> strict input validation
            -> read-only Git objects + JS/TS parser
            -> normalized ChangeObservation.v1
            -> artifact + static replay route

Host interprets observation
  -> may independently revise or execute an owning Capability
```

The service result is an operation result, not a research verdict:

```text
completed + complete/partial ChangeObservation.v1
blocked   + structured unavailable scope
failed    + structured operational diagnostic
cancelled + accurate cancellation diagnostic
```

An observation may state that `req.session.regenerate` was syntactically added
or that a direct authorization call appeared before another call in a hunk. It
cannot state that the session was safely rekeyed, authorization is complete, or
a vulnerability was fixed.

## Contracts and artifacts

### Public input

`ChangeObservationServiceRequest` is the exact service branch from
`REQ-CHANGEOBS-003`. Its `input` schema is:

```text
repository: { kind: trusted_local_git_repository, path: string(1..4096) }
base_revision: full lowercase Git OID (40 or 64 hex)
head_revision: full lowercase Git OID (40 or 64 hex)
path_filters?: unique literal path-prefix[1..32]
budget?: ChangeObservationBudget
```

The resolved budget is persisted even when the caller omits it. Existing
Capability requests remain backward compatible. The public research-request
schema becomes a strict union rather than an optional-field bag; a payload with
both a Capability and service discriminator is invalid.

### Public output

`ChangeObservationExecutionResult` contains:

```text
service: change_observation
service_version: autovul.change-observation/1
operation_status: completed | blocked | failed | cancelled
observation?: ChangeObservation.v1
diagnostics: bounded structured diagnostics
allowed_next_actions: replay | stop
artifact_ref?: run-relative artifact reference
replay_ref?: run-relative replay reference
```

`ChangeObservation.v1` uses the fields, enums, bounds, and fingerprint rules in
`REQ-CHANGEOBS-020` through `REQ-CHANGEOBS-030`. It has no `decision`,
`verification_level`, `hypothesis`, target database, or Capability field.

### Route and compatibility

The persisted research-operation route becomes a strict two-branch union:

```text
{ route_kind: capability, capability, hypothesis_version, result_artifact_ref }
| { route_kind: analyzer_service, service: change_observation,
    service_version: autovul.change-observation/1, result_artifact_ref }
```

The capability branch retains the existing serialized fields and remains
readable. Only the new service branch has the new `route_kind` literal. No
artifact migration rewrites historical runs; older capability routes are read
through an explicit compatibility projection that produces the capability
branch, never the service branch.

## Architecture

### Phase A — Contracts

- Add `change-observation.ts` in `@autovul/contracts` for the exact request,
  result, observation, diagnostic, gap, budget, and route union Schemas.
- Update aggregate research and operation-route Schemas as strict static unions.
- Add contract/validator tests for every field, enum, default, upper bound,
  discriminator conflict, OID, path-filter, dirty-worktree policy, and error
  code. This phase defines no analyzer execution.

### Phase B — Core

- Add one narrow `ChangeObservationPort` and Core service implementing pure
  validation, normalization, sorting, truncation, fingerprints, and result
  assembly.
- Add no Decision Policy, Capability domain type, generic observation layer, or
  generic analyzer/service registry.

### Phase C — Git Analyzer

- Add one fixed read-only Git adapter in the existing Analyzer/Runner package;
  it operates on explicit object IDs and the pinned JS/TS parser only.
- Return file status/rename, normalized hunk inputs, declarations, direct calls,
  argument deltas, direct-call events, provenance, and structured gaps.
- Do not introduce checkout, fetch, target execution, or a reusable Git client
  abstraction.

### Phase D — runtime, Application, and replay

- Attach the service to existing idempotency, target fingerprint, timeout,
  cancellation, run lock, atomic artifact, status/cancel/replay, and Application
  close semantics.
- Add one explicit Application/Pi/CLI service branch and one explicit replay
  branch. Keep both aggregate tools and do not introduce a registry.

### Phase E — real verification and archival

- Run the OpenClaw and Ghost real revision-pair matrix, then independently replay
  from a fresh process and relocated artifact root.
- Record every requirement in `VERIFICATION.md`; unrun real gates remain blocked.
- Advance `Accepted -> Implemented -> Verified -> Archived` only after all
  required evidence passes, then merge stable implemented behavior into root
  `SPEC.md` without converting Ghost/OpenClaw selectors into a product-wide
  security model.

## Safety and privacy

- Git operations are local, object-addressed, read-only, argument-vector based,
  and use the fixed command profile only.
- The service never fetches missing history, initializes submodules, executes
  repository code, or mutates checkout/index/worktree state.
- Trusted-root and symlink checks occur before every repository access; literal
  filters are validated before invoking Git.
- All time, file, diff, hunk, parser, output, and concurrent-run dimensions use
  the fixed v1 bounds.
- Artifacts preserve only bounded structural facts and hashes by default; raw
  diffs and repository metadata remain outside portable compact results.
- Cancellation and Application close use the existing process-tree cleanup and
  atomic-commit boundary, so a partial child process cannot become an
  authoritative observation.

## Compatibility and migration

This is a new, additive Analyzer Service branch under the two existing aggregate
tools. Existing Flow, MissingCheck, Typestate, `ResearchCapability`, capability
request payloads, capability artifacts, and historical operation routes remain
readable and semantically unchanged. A caller that sends the new service fields
to an older version receives a normal schema rejection; a caller that sends a
Capability/service hybrid receives a stable validation error.

Rollback removes admission of the static service branch while retaining committed
versioned service artifacts for read-only inspection/replay. It never changes a
historical capability result or converts an Analyzer Service observation into a
verification level.

## Acceptance criteria

| Requirement | Given / When / Then | Evidence |
| --- | --- | --- |
| `REQ-CHANGEOBS-001` through `REQ-CHANGEOBS-009` | Given aggregate tool calls, when service and Capability requests are parsed and routed, then the two branches are strict, static, and semantically separate | Contract, Application, Pi, and CLI tests |
| `REQ-CHANGEOBS-010` through `REQ-CHANGEOBS-018` | Given valid/invalid paths, OIDs, filters, budgets, equal revisions, missing objects, and shallow history, when the service validates, then exact bounds and structured outcomes apply without worktree reads | Contract/Core and failure-injection tests |
| `REQ-CHANGEOBS-020` through `REQ-CHANGEOBS-030` | Given text, binary, rename, parser-supported, parser-missing, and oversized diffs, when facts are observed, then fields, gaps, order, hashes, and completeness are deterministic and non-narrative | Adapter fixtures and Core normalization tests |
| `REQ-CHANGEOBS-031` through `REQ-CHANGEOBS-037` | Given cancellation, timeout, shutdown, concurrent run/replay, unsafe paths, and hostile Git configuration, when execution occurs, then no unsafe command or late/competing artifact commit succeeds | Runtime, process, lock, and safety tests |
| `REQ-CHANGEOBS-040` through `REQ-CHANGEOBS-044` | Given committed service runs and mutation/relocation cases, when replay runs in a fresh process, then complete semantics and immutable evidence are compared under the replay namespace | Artifact and fresh-process replay tests |
| `REQ-CHANGEOBS-045` through `REQ-CHANGEOBS-048` | Given real OpenClaw and Ghost revision pairs, when the service runs and replays, then two distinct owning-Capability consumers receive deterministic observations without service verdict inflation | Real Git/parser matrix and independent replay artifacts |

## Validation plan

- Focused unit tests: strict schemas, filter normalization, OID rejection,
  default budgets, sort tuples, truncation, digest canonicalization, request and
  observation fingerprints, and non-Capability result shape.
- Failure injection: missing base/head objects, shallow repository, binary and
  undecodable files, ambiguous rename, path escape, unsupported/parser-failed
  language, oversized diff/hunk, Git failure, timeout, caller abort, run cancel,
  shutdown, and concurrent replay.
- Real analyzer/target: local object-database comparison of the frozen OpenClaw
  and Ghost revision pairs with their pinned parsers and exact provenance.
- Differential or negative sample: equal OIDs, an unscoped changed test/changelog
  file, and a structural patch fact that leaves an owning Capability's decision
  uncomputed; none may become a security conclusion.
- Independent replay: new Node process, no model or host session, relocated runs
  root, immutable OID revalidation, artifact hash preservation, and
  fingerprint/version/observation mutation checks.
- Package/integration smoke: Application, Pi, and CLI expose only the existing
  two aggregate tools and route the static service branch through the same API.

## Open questions

- None. Phase C freezes the JavaScript/TypeScript structural parser as the
  runtime dependency `typescript@5.9.3`; its exact version is recorded in every
  observation provenance. Adding a language or parser requires a separate
  accepted change SPEC.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-09-02 | Name the service Change Observation Analyzer v1 | “Delta” is a role-classification term, not a vulnerability paradigm or public Capability. |
| 2026-09-02 | Use object-addressed local Git input only | Full immutable OIDs, no working-tree reads, and no network operation give a bounded replay boundary. |
| 2026-09-02 | Support JS/TS structural facts only in v1 | OpenClaw and Ghost provide two real consumers without prematurely creating a universal language/parser framework. |
| 2026-09-02 | Freeze the structural parser at `typescript@5.9.3` | The adapter needs deterministic JS/TS syntax facts and records the exact pinned parser version in provenance. |
| 2026-09-02 | Keep service routing under the two aggregate tools | The service requires lifecycle/replay access but does not justify a third model tool or an Analyzer registry. |
| 2026-09-02 | Accept this implementation SPEC | The user explicitly authorized contract-first implementation after the Delta classification was archived. |
| 2026-09-02 | Verify the real OpenClaw and Ghost matrix | Both immutable revision pairs completed through the real Git/parser adapter, then matched from a fresh process after the runs root was relocated. |
| 2026-09-02 | Archive Change Observation Analyzer v1 | Stable service behavior is merged into root `SPEC.md`; this change retains the detailed contract and verification evidence. |

## Delivery gate

The Accepted status authorized only the narrow Phases A–D implementation. The
real OpenClaw/Ghost and independent relocated-replay gates then advanced this
change through `Verified` to `Archived`. Neither status authorizes a fourth
Capability, a generic Git/analyzer framework, Variant work, or a security
verdict from a change observation.

## Verification record

The final per-requirement mapping, real Git/parser matrix, relocated fresh-
process replay, artifact hashes, and command gates are recorded in
[`VERIFICATION.md`](./VERIFICATION.md). Root [`SPEC.md`](../../../SPEC.md)
§§2.1, 3.2, 4, and 5.4 are the normative stable-behavior source; this change
preserves the detailed v1 boundary and historical evidence.
