import {
  asDomainError,
  type MissingCheckExecutionResult,
  type ResearchOperationRoute,
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

  async replay(runId: RunId, route: ResearchOperationRoute, options: CodeqlOperationOptions): Promise<MissingCheckExecutionResult> {
    const run = await this.status.get(runId);
    const raw = await this.artifacts.readArtifact(run.runId, route.result_artifact_ref);
    if (raw === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_MISSING", ["stop"]);
    const artifact = readMissingCheckRunArtifact(raw);
    if (artifact === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_INVALID", ["stop"]);
    try {
      await validateTarget(this.codeql, artifact.target.vulnerable, options);
      if (artifact.target.fixed !== undefined) await validateTarget(this.codeql, artifact.target.fixed, options);
      const observation = await this.execution.execute({ hypothesis: artifact.hypothesis, target: artifact.target, analyzer_id: "codeql", mode: artifact.mode, runId: run.runId, artifactRoot: run.artifactRoot }, { ...options, timeoutMs: artifact.budget === undefined ? options.timeoutMs : Math.min(options.timeoutMs, artifact.budget.timeout_ms) });
      if (!observation.analyzer.available) return this.blocked(run.runId, "MCHECK_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
      const projection = decideMissingCheck(observation, artifact.mode);
      const mismatch = projection.decision.outcome !== artifact.decision.outcome || projection.verificationLevel !== artifact.verification_level;
      return compactMissingCheckResult({ runId: run.runId, operationStatus: "completed", decision: projection.decision, verificationLevel: mismatch ? "generated" : projection.verificationLevel, observations: mismatch ? [...projection.observations, { code: "MCHECK_REPLAY_SEMANTIC_MISMATCH", evidence_ref: route.result_artifact_ref }] : projection.observations, revisionHints: projection.revisionHints, allowedNextActions: mismatch ? ["revise", "stop"] : projection.allowedNextActions, artifactRef: route.result_artifact_ref });
    } catch (error: unknown) {
      return asDomainError(error).code === "PROCESS_CANCELLED"
        ? compactMissingCheckResult({ runId: run.runId, operationStatus: "cancelled", decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code: "MCHECK_REPLAY_CANCELLED", evidence_ref: route.result_artifact_ref }], revisionHints: [], allowedNextActions: ["replay", "stop"], artifactRef: route.result_artifact_ref })
        : this.blocked(run.runId, "MCHECK_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
    }
  }

  blocked(runId: RunId, code: string, allowedNextActions: readonly ("replay" | "stop")[]): MissingCheckExecutionResult {
    return compactMissingCheckResult({ runId, operationStatus: "blocked", decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code, evidence_ref: MISSING_CHECK_RESULT_ARTIFACT }], revisionHints: [], allowedNextActions, artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
  }
}

async function validateTarget(codeql: CodeqlPort, target: import("@autovul/contracts").TargetRef, options: CodeqlOperationOptions): Promise<void> {
  const manifest = await codeql.validateDatabase(target.path, options);
  if (target.expected_fingerprint !== undefined && manifest.fingerprint !== target.expected_fingerprint) {
    throw new Error(`Replay database fingerprint differs for ${target.path}`);
  }
}
