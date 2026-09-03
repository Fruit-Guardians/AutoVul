import {
  CHANGE_OBSERVATION_SERVICE,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  ChangeObservationReplayComparisonSchema,
  CONTRACTS_VERSION,
  DomainError,
  asDomainError,
  parseSchema,
  stableDigest,
  type AnalyzerServiceResearchOperationRoute,
  type ChangeObservation,
  type ChangeObservationDiagnostic,
  type ChangeObservationReplayComparison,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import { canonicalJson } from "../canonical-json.js";
import { normalizeChangeObservation, resolveChangeObservationInput, toChangeObservationPortRequest } from "./normalize.js";
import type { ChangeObservationPort } from "./port.js";
import { CHANGE_OBSERVATION_RESULT_ARTIFACT, readChangeObservationRunArtifact } from "./service.js";
import { sha256Utf8 } from "./sha256.js";

const REPLAY_ROOT = "research/change-observation-replay";

/** Service-owned replay comparison; it does not generalize Observation replay. */
export class ChangeObservationReplayService {
  constructor(
    private readonly status: RunStatusService,
    private readonly observation: ChangeObservationPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async replay(
    runId: RunId,
    route: AnalyzerServiceResearchOperationRoute,
    options: CodeqlOperationOptions,
  ): Promise<ChangeObservationReplayComparison> {
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
        const operation = this.cancellations.begin(runId, options.signal);
        try {
          return await this.replayLocked(runId, route, { ...options, signal: operation.signal });
        } catch (error: unknown) {
          return replayFailure(error, operation.signal);
        } finally {
          operation.release();
        }
      });
    } catch (error: unknown) {
      return replayFailure(error, options.signal);
    }
  }

  private async replayLocked(
    runId: RunId,
    route: AnalyzerServiceResearchOperationRoute,
    options: CodeqlOperationOptions,
  ): Promise<ChangeObservationReplayComparison> {
    assertNotCancelled(options.signal, runId);
    const run = await this.status.get(runId);
    if (run.status === "cancelled") return comparison("cancelled", [{ code: "CHANGE_OBSERVATION_CANCELLED", retryable: false }]);
    if (!validRoute(route)) return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_ROUTE_UNSUPPORTED", retryable: false }]);

    const original = await this.artifacts.readArtifact(runId, route.result_artifact_ref);
    if (original === undefined) return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_ARTIFACT_MISSING", retryable: false }]);
    const originalHash = digest(original);
    const artifact = readChangeObservationRunArtifact(original);
    if (artifact === undefined) return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_ARTIFACT_INVALID", retryable: false }]);
    if (artifact.operation_status !== "completed" || artifact.observation === undefined) {
      return comparison("environment_blocked", artifact.diagnostics);
    }

    let result: ChangeObservationReplayComparison;
    try {
      const resolved = resolveChangeObservationInput(artifact.input);
      const replayRaw = await this.observation.observe(toChangeObservationPortRequest(resolved), options);
      assertNotCancelled(options.signal, runId);
      const replayed = normalizeChangeObservation(resolved, replayRaw);
      result = compareObservations(artifact.observation, replayed);
    } catch (error: unknown) {
      result = replayFailure(error, options.signal);
    }

    const after = await this.artifacts.readArtifact(runId, route.result_artifact_ref);
    if (after === undefined || digest(after) !== originalHash) {
      result = comparison("evidence_mutated", [{ code: "CHANGE_OBSERVATION_ARTIFACT_INVALID", retryable: false }]);
    }
    await this.writeReplayArtifact(runId, result);
    return result;
  }

  private async writeReplayArtifact(runId: RunId, result: ChangeObservationReplayComparison): Promise<void> {
    const prior = await this.artifacts.listArtifactPaths(runId, REPLAY_ROOT);
    const ordinal = prior.length;
    const target = `${REPLAY_ROOT}/${ordinal}`;
    const operationId = `change-observation-replay-${stableDigest(`${runId}:${ordinal}`)}`;
    const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, target, [
      { relativePath: "comparison.json", content: JSON.stringify(result) },
    ]);
    await this.artifacts.promoteArtifactBundle(runId, bundle);
  }
}

function validRoute(route: AnalyzerServiceResearchOperationRoute): boolean {
  return route.service === CHANGE_OBSERVATION_SERVICE
    && route.service_version === CHANGE_OBSERVATION_SERVICE_VERSION
    && route.result_artifact_ref === CHANGE_OBSERVATION_RESULT_ARTIFACT;
}

function compareObservations(recorded: ChangeObservation, replayed: ChangeObservation): ChangeObservationReplayComparison {
  if (canonicalJson(recorded.revision_identity) !== canonicalJson(replayed.revision_identity)) {
    return comparison("revision_identity_difference", [], recorded, replayed);
  }
  if (recorded.request_fingerprint !== replayed.request_fingerprint) {
    return comparison("request_fingerprint_difference", [], recorded, replayed);
  }
  if (!sameVersion(recorded, replayed)) {
    return comparison("version_difference", [], recorded, replayed);
  }
  if (recorded.observation_fingerprint !== replayed.observation_fingerprint) {
    return comparison("semantic_mismatch", [], recorded, replayed);
  }
  if (canonicalJson(semanticObservation(recorded)) !== canonicalJson(semanticObservation(replayed))) {
    return comparison("semantic_mismatch", [], recorded, replayed);
  }
  return comparison("match", [], recorded, replayed);
}

function sameVersion(left: ChangeObservation, right: ChangeObservation): boolean {
  return left.schema_version === right.schema_version
    && left.provenance.service_version === right.provenance.service_version
    && left.provenance.git_version === right.provenance.git_version
    && left.provenance.command_profile_version === right.provenance.command_profile_version
    && canonicalJson(left.provenance.parser_versions) === canonicalJson(right.provenance.parser_versions);
}

/** Normalizes only Change Observation repository-relative paths, never a generic protocol. */
function semanticObservation(observation: ChangeObservation): unknown {
  const location = (value: ChangeObservation["symbols"][number]["old_location"] | undefined) => value === undefined
    ? undefined
    : { ...value, path: normalizePath(value.path) };
  return {
    schema_version: observation.schema_version,
    revision_identity: observation.revision_identity,
    scope: { ...observation.scope, path_filters: observation.scope.path_filters.map(normalizePath) },
    resolved_budget: observation.resolved_budget,
    completeness: observation.completeness,
    changed_files: observation.changed_files.map((file) => ({
      ...file,
      path: normalizePath(file.path),
      ...("previous_path" in file ? { previous_path: normalizePath(file.previous_path) } : {}),
    })),
    normalized_hunks: observation.normalized_hunks.map((hunk) => ({ ...hunk, path: normalizePath(hunk.path) })),
    symbols: observation.symbols.map((symbol) => ({
      ...symbol,
      ...(symbol.old_location === undefined ? {} : { old_location: location(symbol.old_location) }),
      ...(symbol.new_location === undefined ? {} : { new_location: location(symbol.new_location) }),
    })),
    call_changes: observation.call_changes.map((call) => ({
      ...call,
      ...(call.old_location === undefined ? {} : { old_location: location(call.old_location) }),
      ...(call.new_location === undefined ? {} : { new_location: location(call.new_location) }),
    })),
    event_changes: observation.event_changes.map((event) => ({ ...event, location: { ...event.location, path: normalizePath(event.location.path) } })),
    analysis_gaps: observation.analysis_gaps.map((gap) => ({ ...gap, ...(gap.path === undefined ? {} : { path: normalizePath(gap.path) }) })),
    provenance: observation.provenance,
  };
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function comparison(
  status: ChangeObservationReplayComparison["status"],
  diagnostics: readonly ChangeObservationDiagnostic[],
  recorded?: ChangeObservation,
  replayed?: ChangeObservation,
): ChangeObservationReplayComparison {
  return parseSchema(ChangeObservationReplayComparisonSchema, {
    schema_version: CONTRACTS_VERSION,
    service: CHANGE_OBSERVATION_SERVICE,
    service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    status,
    ...(recorded === undefined ? {} : { recorded_observation_fingerprint: recorded.observation_fingerprint }),
    ...(replayed === undefined ? {} : { replay_observation_fingerprint: replayed.observation_fingerprint }),
    diagnostics: diagnostics.slice(0, 32),
  }, "Change Observation replay comparison");
}

function replayFailure(error: unknown, signal: AbortSignal | undefined): ChangeObservationReplayComparison {
  const domain = signal?.aborted
    ? new DomainError("PROCESS_CANCELLED", "process", "Change Observation replay was cancelled", false)
    : asDomainError(error);
  if (domain.code === "PROCESS_CANCELLED") return comparison("cancelled", [{ code: "CHANGE_OBSERVATION_CANCELLED", retryable: false }]);
  if (domain.code === "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED") return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED", retryable: false }]);
  if (domain.code === "CHANGE_OBSERVATION_REPOSITORY_INVALID") return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_REPOSITORY_INVALID", retryable: false }]);
  if (domain.code === "REVISION_OBJECT_MISSING") return comparison("environment_blocked", [{ code: "REVISION_OBJECT_MISSING", retryable: false }]);
  if (domain.code === "PROCESS_TIMEOUT") return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_TIMEOUT", retryable: true }]);
  return comparison("environment_blocked", [{ code: "CHANGE_OBSERVATION_GIT_FAILED", retryable: domain.retryable }]);
}

function assertNotCancelled(signal: AbortSignal | undefined, runId: RunId): void {
  if (!signal?.aborted) return;
  throw new DomainError("PROCESS_CANCELLED", "process", "Change Observation replay was cancelled", false, { runId });
}

function digest(value: string): string {
  return sha256Utf8(value);
}
