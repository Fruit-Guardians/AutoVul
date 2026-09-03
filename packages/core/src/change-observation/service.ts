import { Value } from "typebox/value";

import {
  CHANGE_OBSERVATION_SERVICE,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  ChangeObservationExecutionResultSchema,
  ChangeObservationRunArtifactSchema,
  ChangeObservationServiceRequestSchema,
  CONTRACTS_VERSION,
  DomainError,
  asDomainError,
  parseSchema,
  stableDigest,
  type ChangeObservationDiagnostic,
  type ChangeObservationExecutionResult,
  type ChangeObservationInput,
  type ChangeObservationRunArtifact,
  type ChangeObservationServiceRequest,
  type RunId,
} from "@autovul/contracts";

import { readResearchOperationRoute, serializeResearchOperationRoute } from "../research-operation.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { canonicalJson } from "../canonical-json.js";
import { isTerminalRunStatus } from "../state.js";
import {
  normalizeChangeObservation,
  resolveChangeObservationInput,
  toChangeObservationPortRequest,
  type ResolvedChangeObservationInput,
} from "./normalize.js";
import type { ChangeObservationPort } from "./port.js";

export const CHANGE_OBSERVATION_RESULT_ARTIFACT = "research/change-observation/result.json";
const COMMIT_TARGET = "research";
const EXECUTION_PHASE = "change_observation_execute" as const;

export function changeObservationRunIdForInput(input: ResolvedChangeObservationInput): RunId {
  return `run_${stableDigest(canonicalJson({
    service: CHANGE_OBSERVATION_SERVICE,
    service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    repository: input.input.repository,
    base_revision: input.input.base_revision,
    head_revision: input.input.head_revision,
    path_filters: input.normalizedPathFilters,
    resolved_budget: input.resolvedBudget,
  }))}`;
}

export function readChangeObservationRunArtifact(raw: string): ChangeObservationRunArtifact | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Value.Check(ChangeObservationRunArtifactSchema, parsed)
      ? Value.Parse(ChangeObservationRunArtifactSchema, parsed) as ChangeObservationRunArtifact
      : undefined;
  } catch {
    return undefined;
  }
}

/** Non-Capability runtime owner for one static Change Observation service route. */
export class ChangeObservationResearchService {
  constructor(
    private readonly status: RunStatusService,
    private readonly observation: ChangeObservationPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async research(input: unknown, options: CodeqlOperationOptions): Promise<ChangeObservationExecutionResult> {
    if (!Value.Check(ChangeObservationServiceRequestSchema, input)) {
      return compactResult("run_changeobservation_invalid", "failed", [{ code: "CHANGE_OBSERVATION_INVALID_REQUEST", retryable: false }]);
    }
    const request = Value.Parse(ChangeObservationServiceRequestSchema, input) as ChangeObservationServiceRequest;
    const resolved = resolveChangeObservationInput(request.input);
    const runId = changeObservationRunIdForInput(resolved);
    const existing = await this.artifacts.findManifest(runId);
    if (existing !== undefined && isTerminalRunStatus(existing.status)) {
      await this.assertIdempotency(runId, resolved);
      const committed = await this.readCommitted(runId);
      if (committed !== undefined) return committed;
      return terminalResult(runId, existing.status);
    }
    const run = await this.status.create(runId);
    return this.artifacts.withRunOperation(run.runId, options, async () => {
      await this.assertIdempotency(run.runId, resolved);
      const committed = await this.readCommitted(run.runId);
      if (committed !== undefined) return committed;
      const current = await this.status.get(run.runId);
      if (isTerminalRunStatus(current.status)) return terminalResult(run.runId, current.status);
      if (current.status === "created") await this.status.start(run.runId, EXECUTION_PHASE);
      const operation = this.cancellations.begin(run.runId, options.signal);
      try {
        return await this.execute(run.runId, resolved, { ...options, signal: operation.signal });
      } finally {
        operation.release();
      }
    });
  }

  private async execute(
    runId: RunId,
    resolved: ResolvedChangeObservationInput,
    options: CodeqlOperationOptions,
  ): Promise<ChangeObservationExecutionResult> {
    try {
      const raw = await this.observation.observe(toChangeObservationPortRequest(resolved), options);
      assertNotCancelled(options.signal, runId);
      const observation = normalizeChangeObservation(resolved, raw);
      const result = compactResult(runId, "completed", [], observation);
      await this.writeCommitted(runId, resolved, result);
      await this.status.complete(runId, "generated", EXECUTION_PHASE);
      return result;
    } catch (error: unknown) {
      const classified = classifyFailure(error, options.signal);
      const result = compactResult(runId, classified.operationStatus, [classified.diagnostic]);
      if (classified.operationStatus !== "cancelled") {
        await this.writeCommitted(runId, resolved, result);
      }
      if (classified.operationStatus === "cancelled") {
        await this.markCancelled(runId, classified.error);
      } else {
        await this.status.fail(runId, classified.error.toRecord());
      }
      return result;
    }
  }

  private async writeCommitted(
    runId: RunId,
    resolved: ResolvedChangeObservationInput,
    result: ChangeObservationExecutionResult,
  ): Promise<void> {
    const artifact = JSON.stringify(parseSchema(ChangeObservationRunArtifactSchema, {
      schema_version: CONTRACTS_VERSION,
      service: CHANGE_OBSERVATION_SERVICE,
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      input: persistedInput(resolved),
      operation_status: result.operation_status,
      ...(result.observation === undefined ? {} : { observation: result.observation }),
      diagnostics: result.diagnostics,
    }, "Change Observation run artifact"));
    const route = serializeResearchOperationRoute({
      service: CHANGE_OBSERVATION_SERVICE,
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      result_artifact_ref: CHANGE_OBSERVATION_RESULT_ARTIFACT,
    });
    const operationId = `change-observation-commit-${stableDigest(runId)}`;
    try {
      const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, COMMIT_TARGET, [
        { relativePath: "operation.json", content: route },
        { relativePath: "change-observation/result.json", content: artifact },
      ]);
      await this.artifacts.promoteArtifactBundle(runId, bundle);
    } catch (error: unknown) {
      const committedRoute = await readResearchOperationRoute(this.artifacts, runId).catch(() => undefined);
      const committedResult = await this.readCommitted(runId);
      if (committedRoute?.route_kind === "analyzer_service"
        && committedRoute.service === CHANGE_OBSERVATION_SERVICE
        && committedRoute.service_version === CHANGE_OBSERVATION_SERVICE_VERSION
        && committedRoute.result_artifact_ref === CHANGE_OBSERVATION_RESULT_ARTIFACT
        && committedResult !== undefined) return;
      throw error;
    }
  }

  private async readCommitted(runId: RunId): Promise<ChangeObservationExecutionResult | undefined> {
    const raw = await this.artifacts.readArtifact(runId, CHANGE_OBSERVATION_RESULT_ARTIFACT);
    if (raw === undefined) return undefined;
    const artifact = readChangeObservationRunArtifact(raw);
    if (artifact === undefined) return undefined;
    return compactResult(runId, artifact.operation_status, artifact.diagnostics, artifact.observation);
  }

  private async assertIdempotency(runId: RunId, resolved: ResolvedChangeObservationInput): Promise<void> {
    const raw = await this.artifacts.readArtifact(runId, CHANGE_OBSERVATION_RESULT_ARTIFACT);
    const artifact = raw === undefined ? undefined : readChangeObservationRunArtifact(raw);
    if (artifact === undefined) return;
    const recorded = resolveChangeObservationInput(artifact.input);
    if (canonicalJson(idempotencyIdentity(resolved)) !== canonicalJson(idempotencyIdentity(recorded))) {
      throw new DomainError("IDEMPOTENCY_KEY_CONFLICT", "state", "Change Observation run identity is already bound to another request", false, { runId });
    }
  }

  private async markCancelled(runId: RunId, error: DomainError): Promise<void> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const current = await this.status.get(runId);
      if (isTerminalRunStatus(current.status)) return;
      try {
        await this.status.cancel(runId, error.toRecord());
        return;
      } catch (cancelError: unknown) {
        if (asDomainError(cancelError).code !== "RUN_LOCKED" || attempt === 2) throw cancelError;
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
    }
  }
}

function compactResult(
  runId: RunId,
  operationStatus: ChangeObservationExecutionResult["operation_status"],
  diagnostics: readonly ChangeObservationDiagnostic[],
  observation?: ChangeObservationExecutionResult["observation"],
): ChangeObservationExecutionResult {
  return parseSchema(ChangeObservationExecutionResultSchema, {
    schema_version: CONTRACTS_VERSION,
    run_id: runId,
    service: CHANGE_OBSERVATION_SERVICE,
    service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    operation_status: operationStatus,
    ...(observation === undefined ? {} : { observation }),
    diagnostics: diagnostics.slice(0, 32),
    allowed_next_actions: operationStatus === "completed" || operationStatus === "cancelled" ? ["replay", "stop"] : ["stop"],
    ...(operationStatus === "cancelled" ? {} : { artifact_ref: CHANGE_OBSERVATION_RESULT_ARTIFACT }),
  }, "Change Observation execution result");
}

function persistedInput(resolved: ResolvedChangeObservationInput): ChangeObservationInput {
  return {
    repository: { ...resolved.input.repository },
    base_revision: resolved.input.base_revision,
    head_revision: resolved.input.head_revision,
    ...(resolved.normalizedPathFilters.length === 0 ? {} : { path_filters: [...resolved.normalizedPathFilters] }),
    budget: { ...resolved.resolvedBudget },
  };
}

function idempotencyIdentity(resolved: ResolvedChangeObservationInput): unknown {
  return {
    repository: resolved.input.repository,
    base_revision: resolved.input.base_revision,
    head_revision: resolved.input.head_revision,
    path_filters: resolved.normalizedPathFilters,
    resolved_budget: resolved.resolvedBudget,
  };
}

function terminalResult(runId: RunId, status: string): ChangeObservationExecutionResult {
  if (status === "cancelled") return compactResult(runId, "cancelled", [{ code: "CHANGE_OBSERVATION_CANCELLED", retryable: false }]);
  return compactResult(runId, "failed", [{ code: "CHANGE_OBSERVATION_GIT_FAILED", retryable: false }]);
}

function assertNotCancelled(signal: AbortSignal | undefined, runId: RunId): void {
  if (!signal?.aborted) return;
  throw new DomainError("PROCESS_CANCELLED", "process", "Change Observation execution was cancelled", false, { runId });
}

function classifyFailure(error: unknown, signal: AbortSignal | undefined): {
  readonly error: DomainError;
  readonly operationStatus: "blocked" | "failed" | "cancelled";
  readonly diagnostic: ChangeObservationDiagnostic;
} {
  const domain = signal?.aborted
    ? new DomainError("PROCESS_CANCELLED", "process", "Change Observation execution was cancelled", false)
    : asDomainError(error);
  if (domain.code === "PROCESS_CANCELLED") {
    return { error: domain, operationStatus: "cancelled", diagnostic: { code: "CHANGE_OBSERVATION_CANCELLED", retryable: false } };
  }
  if (domain.code === "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED") {
    return { error: domain, operationStatus: "blocked", diagnostic: { code: "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED", retryable: false } };
  }
  if (domain.code === "CHANGE_OBSERVATION_REPOSITORY_INVALID") {
    return { error: domain, operationStatus: "blocked", diagnostic: { code: "CHANGE_OBSERVATION_REPOSITORY_INVALID", retryable: false } };
  }
  if (domain.code === "REVISION_OBJECT_MISSING") {
    return { error: domain, operationStatus: "blocked", diagnostic: { code: "REVISION_OBJECT_MISSING", retryable: false } };
  }
  if (domain.code === "PROCESS_TIMEOUT") {
    return { error: domain, operationStatus: "failed", diagnostic: { code: "CHANGE_OBSERVATION_TIMEOUT", retryable: true } };
  }
  return { error: domain, operationStatus: "failed", diagnostic: { code: "CHANGE_OBSERVATION_GIT_FAILED", retryable: domain.retryable } };
}
