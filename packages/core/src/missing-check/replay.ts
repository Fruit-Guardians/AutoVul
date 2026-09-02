import {
  asDomainError,
  DomainError,
  type MissingCheckExecutionResult,
  type CapabilityResearchOperationRoute,
  type RunId,
} from "@autovul/contracts";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { RunStatusService } from "../status-service.js";
import { decideMissingCheck } from "./decision.js";
import type { MissingCheckExecutionPort } from "./port.js";
import { compactMissingCheckResult, MISSING_CHECK_RESULT_ARTIFACT, readMissingCheckRunArtifact } from "./service.js";

/** Capability-owned replay policy. The shared run service only selects it. */
export class MissingCheckReplayService {
  constructor(private readonly status: RunStatusService, private readonly codeql: CodeqlPort, private readonly execution: MissingCheckExecutionPort, private readonly artifacts: ArtifactStorePort) {}

  async replay(runId: RunId, route: CapabilityResearchOperationRoute, options: CodeqlOperationOptions): Promise<MissingCheckExecutionResult> {
    const run = await this.status.get(runId);
    const raw = await this.artifacts.readArtifact(run.runId, route.result_artifact_ref);
    if (raw === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_MISSING", ["stop"]);
    const artifact = readMissingCheckRunArtifact(raw);
    if (artifact === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_INVALID", ["stop"]);
    if (artifact.target_fingerprints === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
    try {
      await validateTarget(this.codeql, artifact.target.vulnerable, artifact.target_fingerprints.vulnerable, options);
      if (artifact.target.fixed !== undefined && artifact.target_fingerprints.fixed !== undefined) {
        await validateTarget(this.codeql, artifact.target.fixed, artifact.target_fingerprints.fixed, options);
      } else if (artifact.target.fixed !== undefined || artifact.target_fingerprints.fixed !== undefined) {
        return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
      }
      const observation = await this.execution.execute({ hypothesis: artifact.hypothesis, target: artifact.target, analyzer_id: "codeql", mode: artifact.mode, runId: run.runId, artifactRoot: run.artifactRoot }, { ...options, timeoutMs: artifact.budget === undefined ? options.timeoutMs : Math.min(options.timeoutMs, artifact.budget.timeout_ms) });
      if (!observation.analyzer.available) return this.blocked(run.runId, "MCHECK_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
      if (artifact.analyzer.version === undefined || artifact.analyzer.adapter_version === undefined) {
        return this.versionDifference(run.runId, route.result_artifact_ref, "MCHECK_REPLAY_ANALYZER_VERSION_UNRECORDED");
      }
      if (observation.analyzer.version !== artifact.analyzer.version || observation.analyzer.adapter_version !== artifact.analyzer.adapter_version) {
        return this.versionDifference(run.runId, route.result_artifact_ref, "MCHECK_REPLAY_ANALYZER_VERSION_DIFFERENCE");
      }
      const projection = decideMissingCheck(observation, artifact.mode, artifact.hypothesis.scope);
      const mismatch = projection.decision.outcome !== artifact.decision.outcome || projection.verificationLevel !== artifact.verification_level;
      return compactMissingCheckResult({ runId: run.runId, operationStatus: "completed", decision: projection.decision, verificationLevel: mismatch ? "generated" : projection.verificationLevel, observations: mismatch ? [...projection.observations, { code: "MCHECK_REPLAY_SEMANTIC_MISMATCH", evidence_ref: route.result_artifact_ref }] : projection.observations, revisionHints: projection.revisionHints, allowedNextActions: mismatch ? ["revise", "stop"] : projection.allowedNextActions, artifactRef: route.result_artifact_ref });
    } catch (error: unknown) {
      const domain = asDomainError(error);
      if (domain.code === "DATABASE_FINGERPRINT_MISMATCH") return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_DIFFERENCE", ["stop"]);
      if (domain.code === "DATABASE_FINGERPRINT_UNAVAILABLE") return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_UNAVAILABLE", ["replay", "stop"]);
      return domain.code === "PROCESS_CANCELLED"
        ? compactMissingCheckResult({ runId: run.runId, operationStatus: "cancelled", decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code: "MCHECK_REPLAY_CANCELLED", evidence_ref: route.result_artifact_ref }], revisionHints: [], allowedNextActions: ["replay", "stop"], artifactRef: route.result_artifact_ref })
        : this.blocked(run.runId, "MCHECK_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
    }
  }

  blocked(runId: RunId, code: string, allowedNextActions: readonly ("replay" | "stop")[]): MissingCheckExecutionResult {
    return compactMissingCheckResult({ runId, operationStatus: "blocked", decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code, evidence_ref: MISSING_CHECK_RESULT_ARTIFACT }], revisionHints: [], allowedNextActions, artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
  }

  private versionDifference(runId: RunId, artifactRef: string, code: string): MissingCheckExecutionResult {
    return compactMissingCheckResult({ runId, operationStatus: "completed", decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code, evidence_ref: artifactRef }], revisionHints: [], allowedNextActions: ["replay", "stop"], artifactRef });
  }
}

async function validateTarget(codeql: CodeqlPort, target: import("@autovul/contracts").TargetRef, recordedFingerprint: string, options: CodeqlOperationOptions): Promise<void> {
  const manifest = await codeql.validateDatabase(target.path, options);
  if (manifest.portableFingerprint === undefined) {
    throw new DomainError("DATABASE_FINGERPRINT_UNAVAILABLE", "database", `Replay database fingerprint is unavailable for ${target.path}`, false, { path: target.path });
  }
  if (manifest.portableFingerprint !== recordedFingerprint || (target.expected_fingerprint !== undefined && manifest.portableFingerprint !== target.expected_fingerprint)) {
    throw new DomainError("DATABASE_FINGERPRINT_MISMATCH", "database", `Replay database fingerprint differs for ${target.path}`, false, { path: target.path, recorded: recordedFingerprint, observed: manifest.portableFingerprint });
  }
}
