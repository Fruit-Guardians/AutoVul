# @autovul/core

`@autovul/core` implements the deterministic domain rules, research capability decision policies, budget management, lifecycle locks, artifact persistence, and model-free replay services.

## Architecture

Core defines ports (abstract interfaces) for external system capabilities, decoupling domain logic from concrete tools:

```text
Application API
  ├─ Research Capabilities
  │    ├─ Flow: flow validation, CodeQL query synthesis, differential analysis
  │    ├─ MissingCheck: guard dominance decision, single-file CFG analysis
  │    └─ Typestate: protocol witness validation, state violation decisions
  ├─ Analyzer Services
  │    ├─ Change Observation: Git diff fact persistence & replay
  │    └─ Variant Search: seed fact extraction, corpus dispatch & candidate persistence (in progress)
  └─ Shared Runtime Infrastructure
       ├─ RunStatusService: manifest transitions & recovery
       ├─ RunCancellationService: in-flight process tree cancellation
       ├─ ArtifactStorePort: atomic artifact reads, writes, and leases
       ├─ ProcessPort & FileSystemPort: isolated system abstractions
       └─ Replay Services: zero-model deterministic verification
```

## Ports

- `FileSystemPort`: Canonical path resolution, directory creation, atomic file writes, advisory file locks.
- `ProcessPort`: Subprocess execution with explicit timeouts, signal cancellation, and output limits.
- `CodeqlPort`: CodeQL database inspection, validation, query execution, SARIF decoding.
- `MissingCheckExecutionPort`: Dispatch to AST CFG or CodeQL missing-check analyzers.
- `TypestateExecutionPort`: Dispatch to typestate protocol analyzers.
- `ChangeObservationPort`: Read-only Git diff fact collection.
- `VariantSearchPort`: development Port for bounded AST pattern search across explicit Git revisions; verification is pending.

## Application API

The primary entry point for hosts is `Application` (implementing `ApplicationApi`):
- `application.research(request)`: Validates or executes research hypotheses and analyzer services.
- `application.manageRun(request)`: Inspects run status, cancels running executions, or triggers replay comparisons.
- `application.close()`: Idempotent graceful shutdown, cancelling live operations and releasing locks.
