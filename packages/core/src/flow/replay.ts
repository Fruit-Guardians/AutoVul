import {
  asDomainError,
  type ResearchOperationRoute,
  type ResearchExecutionResult,
  type RunId,
} from "@autovul/contracts";

import { decideFlow } from "./decision.js";
import type { FlowExecutionPort } from "./port.js";
import { FLOW_RESULT_ARTIFACT, compactFlowResult, readFlowRunArtifact } from "./service.js";
import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { RunStatusService } from "../status-service.js";

/** Flow-owned replay policy; the shared runtime only routes to this service. */
export class FlowReplayService {
  constructor(
    private readonly status: RunStatusService,
    private readonly execution: FlowExecutionPort,
    private readonly artifacts: ArtifactStorePort,
  ) {}

  async replay(runId: RunId, route: ResearchOperationRoute, options: CodeqlOperationOptions): Promise<ResearchExecutionResult> {
    const run = await this.status.get(runId);
    const artifactRef = route.result_artifact_ref;
    const raw = await this.artifacts.readArtifact(run.runId, artifactRef);
    if (raw === undefined) return this.blocked(run.runId, "FLOW_REPLAY_ARTIFACT_MISSING", ["stop"]);
    const artifact = readFlowRunArtifact(raw);
    if (artifact === undefined) return this.blocked(run.runId, "FLOW_REPLAY_ARTIFACT_INVALID", ["stop"]);
    try {
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
}
