import { Value } from "typebox/value";

import {
  CONTRACTS_VERSION,
  DomainError,
  TYPESTATE_DECISION_POLICY_VERSION,
  TYPESTATE_HYPOTHESIS_VERSION,
  TYPESTATE_LIMITS,
  TypestateDecisionSchema,
  TypestateReplayComparisonSchema,
  asDomainError,
  parseSchema,
  type ResearchOperationRoute,
  type RunId,
  type TargetRef,
  type TypestateAnalyzerObservation,
  type TypestateCompactObservation,
  type TypestateDecision,
  type TypestateReplayComparison,
} from "@autovul/contracts";

import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import { decideTypestate } from "./decision.js";
import type { TypestateEvidenceDigest, TypestateEvidenceSnapshotPort, TypestateExecutionPort } from "./port.js";
import { TYPESTATE_RESULT_ARTIFACT, readTypestateRunArtifact } from "./service.js";

/** Capability-owned replay policy; the shared runtime only selects this route. */
export class TypestateReplayService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: TypestateExecutionPort,
    private readonly evidence: TypestateEvidenceSnapshotPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async replay(runId: RunId, route: ResearchOperationRoute, options: CodeqlOperationOptions): Promise<TypestateReplayComparison> {
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
        const operation = this.cancellations.begin(runId, options.signal);
        try {
          return await this.replayLocked(runId, route, { ...options, signal: operation.signal });
        } catch (error: unknown) {
          return replayFailureComparison(unknownDecision(), TYPESTATE_RESULT_ARTIFACT, error, operation.signal);
        } finally {
          operation.release();
        }
      });
    } catch (error: unknown) {
      return replayFailureComparison(unknownDecision(), TYPESTATE_RESULT_ARTIFACT, error, options.signal);
    }
  }

  private async replayLocked(runId: RunId, route: ResearchOperationRoute, options: CodeqlOperationOptions): Promise<TypestateReplayComparison> {
    assertNotCancelled(options.signal, runId);
    const run = await this.status.get(runId);
    if (run.status === "cancelled") {
      return comparison("cancelled", unknownDecision(), [{ code: "TSTATE_REPLAY_CANCELLED", evidence_ref: TYPESTATE_RESULT_ARTIFACT }]);
    }
    const routeError = validateRoute(route);
    if (routeError !== undefined) return comparison("environment_blocked", unknownDecision(), [{ code: routeError, evidence_ref: TYPESTATE_RESULT_ARTIFACT }]);

    const raw = await this.artifacts.readArtifact(run.runId, route.result_artifact_ref);
    if (raw === undefined) return comparison("environment_blocked", unknownDecision(), [{ code: "TSTATE_REPLAY_ARTIFACT_MISSING", evidence_ref: route.result_artifact_ref }]);

    const rawRecord = parseRecord(raw);
    const rawDecision = readRecordedDecision(rawRecord?.decision);
    const policyVersion = rawRecord?.decision_policy_version;
    if (rawDecision !== undefined && policyVersion !== TYPESTATE_DECISION_POLICY_VERSION) {
      return comparison("version_difference", rawDecision, [{ code: policyVersion === undefined ? "TSTATE_REPLAY_POLICY_VERSION_UNRECORDED" : "TSTATE_REPLAY_POLICY_VERSION_DIFFERENCE", evidence_ref: route.result_artifact_ref }]);
    }

    const artifact = readTypestateRunArtifact(raw);
    if (artifact === undefined) return comparison("environment_blocked", rawDecision ?? unknownDecision(), [{ code: "TSTATE_REPLAY_ARTIFACT_INVALID", evidence_ref: route.result_artifact_ref }]);
    if (artifact.decision_policy_version !== TYPESTATE_DECISION_POLICY_VERSION) {
      return comparison("version_difference", artifact.decision, [{ code: artifact.decision_policy_version === undefined ? "TSTATE_REPLAY_POLICY_VERSION_UNRECORDED" : "TSTATE_REPLAY_POLICY_VERSION_DIFFERENCE", evidence_ref: route.result_artifact_ref }]);
    }
    if (artifact.target_fingerprints === undefined) return comparison("environment_blocked", artifact.decision, [{ code: "TSTATE_REPLAY_FINGERPRINT_UNRECORDED", evidence_ref: route.result_artifact_ref }]);
    if ((artifact.target.fixed === undefined) !== (artifact.target_fingerprints.fixed === undefined)) {
      return comparison("environment_blocked", artifact.decision, [{ code: "TSTATE_REPLAY_FINGERPRINT_UNRECORDED", evidence_ref: route.result_artifact_ref }]);
    }
    if (artifact.analyzer.version === undefined || artifact.analyzer.adapter_version === undefined) {
      return comparison("version_difference", artifact.decision, [{ code: "TSTATE_REPLAY_ANALYZER_VERSION_UNRECORDED", evidence_ref: route.result_artifact_ref }]);
    }
    if (artifact.observation === undefined) return comparison("environment_blocked", artifact.decision, [{ code: "TSTATE_REPLAY_OBSERVATION_UNRECORDED", evidence_ref: route.result_artifact_ref }]);
    if (artifact.analyzer.available === false) return comparison("environment_blocked", artifact.decision, [{ code: "TSTATE_REPLAY_ANALYZER_UNAVAILABLE", evidence_ref: route.result_artifact_ref }]);

    const initialEvidence = await this.evidence.snapshotEvidence({
      hypothesis: artifact.hypothesis,
      runId: run.runId,
      artifactRoot: run.artifactRoot,
      workspace: "primary",
    });
    assertNotCancelled(options.signal, runId);

    await validateTarget(this.codeql, artifact.target.vulnerable, artifact.target_fingerprints.vulnerable, options);
    if (artifact.target.fixed !== undefined && artifact.target_fingerprints.fixed !== undefined) {
      await validateTarget(this.codeql, artifact.target.fixed, artifact.target_fingerprints.fixed, options);
    }
    assertNotCancelled(options.signal, runId);

    const replayObservation = await this.execution.execute(
      {
        hypothesis: artifact.hypothesis,
        target: artifact.target,
        analyzer_id: "codeql",
        mode: artifact.mode,
        runId: run.runId,
        artifactRoot: run.artifactRoot,
        workspace: "replay",
      },
      {
        ...options,
        timeoutMs: artifact.budget === undefined ? options.timeoutMs : Math.min(options.timeoutMs, artifact.budget.timeout_ms),
      },
    );
    assertNotCancelled(options.signal, runId);

    const finalEvidence = await this.evidence.snapshotEvidence({
      hypothesis: artifact.hypothesis,
      runId: run.runId,
      artifactRoot: run.artifactRoot,
      workspace: "primary",
    });
    assertNotCancelled(options.signal, runId);
    if (!sameEvidenceDigest(initialEvidence, finalEvidence)) {
      return comparison(
        "semantic_mismatch",
        artifact.decision,
        [{ code: "TSTATE_REPLAY_EVIDENCE_MUTATED", evidence_ref: route.result_artifact_ref }],
        decideTypestate(replayObservation, artifact.mode, artifact.hypothesis).decision,
      );
    }
    if (replayObservation.analyzer.available === false) {
      return comparison("environment_blocked", artifact.decision, [{ code: "TSTATE_REPLAY_ANALYZER_UNAVAILABLE", evidence_ref: route.result_artifact_ref }]);
    }
    if (replayObservation.analyzer.version !== artifact.analyzer.version || replayObservation.analyzer.adapter_version !== artifact.analyzer.adapter_version) {
      return comparison("version_difference", artifact.decision, [{ code: "TSTATE_REPLAY_ANALYZER_VERSION_DIFFERENCE", evidence_ref: route.result_artifact_ref }]);
    }

    const projection = decideTypestate(replayObservation, artifact.mode, artifact.hypothesis);
    if (canonical(projection.decision) !== canonical(artifact.decision) || projection.verificationLevel !== artifact.verification_level) {
      return comparison(
        "semantic_mismatch",
        artifact.decision,
        withReplayCode(projection.observations, "TSTATE_REPLAY_SEMANTIC_MISMATCH", route.result_artifact_ref),
        projection.decision,
      );
    }
    if (!sameTypestateObservation(artifact.observation, replayObservation)) {
      return comparison(
        "semantic_mismatch",
        artifact.decision,
        withReplayCode(projection.observations, "TSTATE_REPLAY_OBSERVATION_SEMANTIC_MISMATCH", route.result_artifact_ref),
        projection.decision,
      );
    }
    return comparison("match", artifact.decision, projection.observations, projection.decision);
  }
}

function validateRoute(route: ResearchOperationRoute): string | undefined {
  if (route.capability !== "typestate") return "TSTATE_REPLAY_ROUTE_UNSUPPORTED";
  if (route.hypothesis_version !== TYPESTATE_HYPOTHESIS_VERSION) return "TSTATE_REPLAY_HYPOTHESIS_VERSION_DIFFERENCE";
  if (route.result_artifact_ref !== TYPESTATE_RESULT_ARTIFACT) return "TSTATE_REPLAY_ROUTE_ARTIFACT_MISMATCH";
  return undefined;
}

async function validateTarget(
  codeql: CodeqlPort,
  target: TargetRef,
  recordedFingerprint: string,
  options: CodeqlOperationOptions,
): Promise<void> {
  const manifest = await codeql.validateDatabase(target.path, options);
  if (manifest.portableFingerprint === undefined) {
    throw new DomainError("DATABASE_FINGERPRINT_UNAVAILABLE", "database", `Replay database fingerprint is unavailable for ${target.path}`, false, { path: target.path });
  }
  if (manifest.portableFingerprint !== recordedFingerprint || (target.expected_fingerprint !== undefined && manifest.portableFingerprint !== target.expected_fingerprint)) {
    throw new DomainError("DATABASE_FINGERPRINT_MISMATCH", "database", `Replay database fingerprint differs for ${target.path}`, false, {
      path: target.path,
      recorded: recordedFingerprint,
      observed: manifest.portableFingerprint,
    });
  }
}

function comparison(
  status: TypestateReplayComparison["status"],
  recordedDecision: TypestateDecision,
  observations: readonly TypestateCompactObservation[],
  replayDecision?: TypestateDecision,
): TypestateReplayComparison {
  return parseSchema(TypestateReplayComparisonSchema, {
    schema_version: CONTRACTS_VERSION,
    capability: "typestate",
    status,
    recorded_decision: recordedDecision,
    ...(replayDecision === undefined ? {} : { replay_decision: replayDecision }),
    observations: observations.slice(0, TYPESTATE_LIMITS.maxCompactObservations),
  }, "Typestate replay comparison");
}

function replayFailureComparison(
  recordedDecision: TypestateDecision,
  evidenceRef: string,
  error: unknown,
  signal: AbortSignal | undefined,
): TypestateReplayComparison {
  const code = replayFailureCode(error, signal);
  return comparison(code === "TSTATE_REPLAY_CANCELLED" ? "cancelled" : "environment_blocked", recordedDecision, [{ code, evidence_ref: evidenceRef }]);
}

function withReplayCode(
  observations: readonly TypestateCompactObservation[],
  code: string,
  evidenceRef: string,
): TypestateCompactObservation[] {
  return [...observations.slice(0, TYPESTATE_LIMITS.maxCompactObservations - 1), { code, evidence_ref: evidenceRef }];
}

function unknownDecision(): TypestateDecision {
  return { capability: "typestate", outcome: "unknown" };
}

function parseRecord(raw: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(raw);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function readRecordedDecision(value: unknown): TypestateDecision | undefined {
  return Value.Check(TypestateDecisionSchema, value) ? Value.Parse(TypestateDecisionSchema, value) as TypestateDecision : undefined;
}

function replayFailureCode(error: unknown, signal: AbortSignal | undefined): string {
  if (signal?.aborted) return "TSTATE_REPLAY_CANCELLED";
  const domain = asDomainError(error);
  if (domain.code === "DATABASE_FINGERPRINT_MISMATCH") return "TSTATE_REPLAY_FINGERPRINT_DIFFERENCE";
  if (domain.code === "DATABASE_FINGERPRINT_UNAVAILABLE") return "TSTATE_REPLAY_FINGERPRINT_UNAVAILABLE";
  if (domain.code === "PROCESS_CANCELLED") return "TSTATE_REPLAY_CANCELLED";
  if (domain.code === "PROCESS_TIMEOUT") return "TSTATE_REPLAY_TIMEOUT";
  return "TSTATE_REPLAY_ENVIRONMENT_BLOCKED";
}

function assertNotCancelled(signal: AbortSignal | undefined, runId: RunId): void {
  if (!signal?.aborted) return;
  throw new DomainError("PROCESS_CANCELLED", "process", `Typestate replay for ${runId} was cancelled`, false, { runId });
}

function sameEvidenceDigest(before: readonly TypestateEvidenceDigest[], after: readonly TypestateEvidenceDigest[]): boolean {
  return canonical(normalizeEvidenceDigest(before)) === canonical(normalizeEvidenceDigest(after));
}

function normalizeEvidenceDigest(digests: readonly TypestateEvidenceDigest[]): readonly TypestateEvidenceDigest[] {
  return [...digests]
    .map((digest) => ({ evidence_ref: normalizeEvidencePath(digest.evidence_ref), sha256: digest.sha256 }))
    .sort((left, right) => left.evidence_ref.localeCompare(right.evidence_ref) || left.sha256.localeCompare(right.sha256));
}

/** Full v1 observation comparison. Arrays retain analyzer order, especially traces. */
function sameTypestateObservation(recorded: TypestateAnalyzerObservation, replayed: TypestateAnalyzerObservation): boolean {
  return canonical(typestateObservationSemantics(recorded)) === canonical(typestateObservationSemantics(replayed));
}

function typestateObservationSemantics(observation: TypestateAnalyzerObservation): unknown {
  const normalizeTrace = (trace: TypestateAnalyzerObservation["traces"][number]) => ({ ...trace, evidence_ref: normalizeEvidencePath(trace.evidence_ref) });
  return {
    schema_version: observation.schema_version,
    compile_accepted: observation.compile_accepted,
    resource: observation.resource,
    events: observation.events,
    traces: observation.traces.map(normalizeTrace),
    ...(observation.fixed_resource === undefined ? {} : { fixed_resource: observation.fixed_resource }),
    ...(observation.fixed_events === undefined ? {} : { fixed_events: observation.fixed_events }),
    ...(observation.fixed_traces === undefined ? {} : { fixed_traces: observation.fixed_traces.map(normalizeTrace) }),
    completeness: observation.completeness,
    capability_gaps: observation.capability_gaps,
    evidence_refs: observation.evidence_refs.map(normalizeEvidencePath),
  };
}

function normalizeEvidencePath(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "");
  return normalized.startsWith("typestate-replay/") ? `typestate/${normalized.slice("typestate-replay/".length)}` : normalized;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
