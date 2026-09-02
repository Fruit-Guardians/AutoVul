import {
  asDomainError,
  DomainError,
  type CapabilityResearchOperationRoute,
  type ResearchExecutionResult,
  type RunId,
} from "@autovul/contracts";

import { decideFlow } from "./decision.js";
import type { FlowExecutionPort } from "./port.js";
import { FLOW_RESULT_ARTIFACT, compactFlowResult, readFlowRunArtifact } from "./service.js";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { RunStatusService } from "../status-service.js";

/** Flow-owned replay policy; the shared runtime only routes to this service. */
export class FlowReplayService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: FlowExecutionPort,
    private readonly artifacts: ArtifactStorePort,
  ) {}

  async replay(runId: RunId, route: CapabilityResearchOperationRoute, options: CodeqlOperationOptions): Promise<ResearchExecutionResult> {
    const run = await this.status.get(runId);
    const artifactRef = route.result_artifact_ref;
    const raw = await this.artifacts.readArtifact(run.runId, artifactRef);
    if (raw === undefined) return this.blocked(run.runId, "FLOW_REPLAY_ARTIFACT_MISSING", ["stop"]);
    const artifact = readFlowRunArtifact(raw);
    if (artifact === undefined) return this.blocked(run.runId, "FLOW_REPLAY_ARTIFACT_INVALID", ["stop"]);
    if (artifact.target_fingerprints === undefined) return this.blocked(run.runId, "FLOW_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
    if (artifact.analyzer.version === undefined || artifact.analyzer.adapter_version === undefined) {
      return this.versionDifference(run.runId, artifactRef, "FLOW_REPLAY_ANALYZER_VERSION_UNRECORDED");
    }
    try {
      await validateTarget(this.codeql, artifact.target.vulnerable, artifact.target_fingerprints.vulnerable, options);
      if (artifact.target.fixed !== undefined && artifact.target_fingerprints.fixed !== undefined) {
        await validateTarget(this.codeql, artifact.target.fixed, artifact.target_fingerprints.fixed, options);
      } else if (artifact.target.fixed !== undefined || artifact.target_fingerprints.fixed !== undefined) {
        return this.blocked(run.runId, "FLOW_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
      }
      const observation = await this.execution.execute({
        model: artifact.model,
        target: artifact.target,
        analyzer_id: "codeql",
        mode: artifact.mode,
        ...(artifact.expectation === undefined ? {} : { expectation: artifact.expectation }),
        runId: run.runId,
        artifactRoot: run.artifactRoot,
      }, { ...options, timeoutMs: artifact.budget === undefined ? options.timeoutMs : Math.min(options.timeoutMs, artifact.budget.timeout_ms) });
      if (observation.analyzer.available === false) return this.blocked(run.runId, "FLOW_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
      if (observation.analyzer.version !== artifact.analyzer.version || observation.analyzer.adapter_version !== artifact.analyzer.adapter_version) {
        return this.versionDifference(run.runId, artifactRef, "FLOW_REPLAY_ANALYZER_VERSION_DIFFERENCE");
      }
      const projection = decideFlow(observation, artifact.mode, artifact.expectation);
      const mismatch = projection.decision.outcome !== artifact.decision.outcome
        || projection.verificationLevel !== artifact.verification_level;
      if (mismatch) {
        return compactFlowResult({
          runId: run.runId,
          operationStatus: "completed",
          decision: projection.decision,
          // A replay that changes the domain result cannot inherit the
          // original evidence grade, particularly `differential`.
          verificationLevel: "generated",
          observations: [...projection.observations, { code: "FLOW_REPLAY_SEMANTIC_MISMATCH", evidence_ref: artifactRef }],
          revisionHints: projection.revisionHints,
          allowedNextActions: ["revise", "stop"],
          artifactRef,
        });
      }
      return compactFlowResult({
        runId: run.runId,
        operationStatus: "completed",
        decision: projection.decision,
        verificationLevel: projection.verificationLevel,
        observations: projection.observations,
        revisionHints: projection.revisionHints,
        allowedNextActions: projection.allowedNextActions,
        artifactRef,
      });
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      if (domainError.code === "DATABASE_FINGERPRINT_MISMATCH") return this.blocked(run.runId, "FLOW_REPLAY_FINGERPRINT_DIFFERENCE", ["stop"]);
      if (domainError.code === "DATABASE_FINGERPRINT_UNAVAILABLE") return this.blocked(run.runId, "FLOW_REPLAY_FINGERPRINT_UNAVAILABLE", ["replay", "stop"]);
      if (domainError.code === "PROCESS_CANCELLED") {
        return compactFlowResult({
          runId: run.runId,
          operationStatus: "cancelled",
          decision: { capability: "flow", outcome: "unknown" },
          verificationLevel: "generated",
          observations: [{ code: "FLOW_REPLAY_CANCELLED", evidence_ref: artifactRef }],
          revisionHints: [],
          allowedNextActions: ["replay", "stop"],
          artifactRef,
        });
      }
      return this.blocked(run.runId, "FLOW_REPLAY_ENVIRONMENT_BLOCKED", ["replay", "stop"]);
    }
  }

  blocked(runId: RunId, code: string, allowedNextActions: readonly ("replay" | "stop")[]): ResearchExecutionResult {
    return compactFlowResult({
      runId,
      operationStatus: "blocked",
      decision: { capability: "flow", outcome: "unknown" },
      verificationLevel: "generated",
      observations: [{ code, evidence_ref: FLOW_RESULT_ARTIFACT }],
      revisionHints: [],
      allowedNextActions,
      artifactRef: FLOW_RESULT_ARTIFACT,
    });
  }

  private versionDifference(runId: RunId, artifactRef: string, code: string): ResearchExecutionResult {
    return compactFlowResult({
      runId,
      operationStatus: "completed",
      decision: { capability: "flow", outcome: "unknown" },
      verificationLevel: "generated",
      observations: [{ code, evidence_ref: artifactRef }],
      revisionHints: [],
      allowedNextActions: ["replay", "stop"],
      artifactRef,
    });
  }
}

async function validateTarget(codeql: CodeqlPort, target: import("@autovul/contracts").TargetRef, recordedFingerprint: string, options: CodeqlOperationOptions): Promise<void> {
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
