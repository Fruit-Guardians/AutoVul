# @autovul/contracts

`@autovul/contracts` defines versioned schemas, protocols, and domain error types for the AutoVul vulnerability-research capability layer.

## Principles

1. **Minimal Runtime Dependency**: The package depends only on `typebox`; it has no host SDK, filesystem, process, model-provider, or concrete-Analyzer dependency.
2. **Strict Protocol Layering**: Contracts MUST NOT depend on host SDKs, filesystem, processes, databases, LLM providers, or concrete analyzers.
3. **Immutability & Versioning**: Every public schema declares an explicit `schema_version` or `service_version`.

## Supported Schemas & Protocols

### Research Capabilities
- **Flow v1** (`autovul.flow/1`): Source, sink, step, barrier, and query intent definitions (`FlowHypothesis`, `FlowModel`, `FlowValidationResult`, `FlowExecutionResult`).
- **MissingCheck v1** (`autovul.missing-check/1`): Protected operations, required guard checks, CFG relations, and scope definitions (`MissingCheckHypothesis`, `MissingCheckExecutionResult`).
- **Typestate v1** (`autovul.typestate/1`): Resource declarations, event selectors, transition matrices, and witness constraints (`TypestateHypothesis`, `TypestateExecutionResult`).

### Analyzer Services
- **Change Observation v1** (`autovul.change-observation/1`): Read-only Git revision diff facts, modified symbols, and file targets (`ChangeObservationServiceRequest`, `ChangeObservationObservation`).
- **Variant Search v1** (`autovul.variant-search/1`): Development contracts for seed-derived search requests and candidate observations. The owning change SPEC is `Accepted`; these schemas are not yet part of the verified stable baseline.

### Runtime & Operations
- **State & Manifests**: `RunManifest`, `RunPhase`, `RunStatus`, `VerificationLevel`.
- **Aggregate Tool Inputs**: `AutovulResearchToolInput`, `AutovulRunToolInput`.
- **Domain Errors**: `DomainError`, `DomainErrorCode`, `DomainErrorCategory`.
