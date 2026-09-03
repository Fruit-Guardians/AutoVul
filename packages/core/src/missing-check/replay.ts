import {
  asDomainError,
  DomainError,
  MISSING_CHECK_DECISION_POLICY_VERSION,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  stableDigest,
  type MissingCheckExecutionResult,
  type CapabilityResearchOperationRoute,
  type RunId,
} from "@autovul/contracts";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import type { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import { decideMissingCheck } from "./decision.js";
import type { MissingCheckExecutionPort } from "./port.js";
import { compactMissingCheckResult, MISSING_CHECK_RESULT_ARTIFACT, readMissingCheckRunArtifact } from "./service.js";

/** Capability-owned replay policy. The shared run service only selects it. */
export class MissingCheckReplayService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: MissingCheckExecutionPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations?: RunCancellationService,
  ) {}

  async replay(runId: RunId, route: CapabilityResearchOperationRoute, options: CodeqlOperationOptions): Promise<MissingCheckExecutionResult> {
    return await this.artifacts.withRunOperation(runId, options, async () => {
      const operation = this.cancellations?.begin(runId, options.signal);
      const replayOptions: CodeqlOperationOptions = operation?.signal === undefined
        ? options
        : { ...options, signal: operation.signal };
      try {
        return await this.replayLocked(runId, route, replayOptions);
      } finally {
        operation?.release();
      }
    });
  }

  private async replayLocked(runId: RunId, route: CapabilityResearchOperationRoute, options: CodeqlOperationOptions): Promise<MissingCheckExecutionResult> {
    const run = await this.status.get(runId);
    if (route.route_kind !== "capability" || route.capability !== "missing_check" || route.hypothesis_version !== MISSING_CHECK_HYPOTHESIS_VERSION) {
      return this.blocked(run.runId, "MCHECK_REPLAY_ROUTE_MISMATCH", ["stop"]);
    }
    const raw = await this.artifacts.readArtifact(run.runId, route.result_artifact_ref);
    if (raw === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_MISSING", ["stop"]);
    const artifact = readMissingCheckRunArtifact(raw);
    if (artifact === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_ARTIFACT_INVALID", ["stop"]);
    if (artifact.decision_policy_version !== MISSING_CHECK_DECISION_POLICY_VERSION) {
      return this.versionDifference(
        run.runId,
        route.result_artifact_ref,
        artifact.decision_policy_version === undefined ? "MCHECK_REPLAY_POLICY_VERSION_UNRECORDED" : "MCHECK_REPLAY_POLICY_VERSION_DIFFERENCE",
      );
    }
    if (artifact.target_fingerprints === undefined) return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
    try {
      await validateTarget(this.codeql, this.execution, artifact.target.vulnerable, artifact.target_fingerprints.vulnerable, options);
      if (artifact.target.fixed !== undefined && artifact.target_fingerprints.fixed !== undefined) {
        await validateTarget(this.codeql, this.execution, artifact.target.fixed, artifact.target_fingerprints.fixed, options);
      } else if (artifact.target.fixed !== undefined || artifact.target_fingerprints.fixed !== undefined) {
        return this.blocked(run.runId, "MCHECK_REPLAY_FINGERPRINT_UNRECORDED", ["stop"]);
      }
      const evidenceRefs = artifact.observation?.evidence_refs ?? [];
      const preDigests = new Map<string, string>();
      for (const ref of evidenceRefs) {
        const text = await this.artifacts.readArtifact(run.runId, ref);
        if (text !== undefined) {
          preDigests.set(ref, stableDigest(text));
        }
      }

      const analyzerId = (artifact.analyzer.analyzer_id as "codeql" | "javascript_cfg") ?? "codeql";
      const observation = await this.execution.execute(
        {
          hypothesis: artifact.hypothesis,
          target: artifact.target,
          analyzer_id: analyzerId,
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

      for (const [ref, preDigest] of preDigests) {
        const text = await this.artifacts.readArtifact(run.runId, ref);
        if (text === undefined || stableDigest(text) !== preDigest) {
          return compactMissingCheckResult({
            runId: run.runId,
            operationStatus: "completed",
            decision: artifact.decision,
            verificationLevel: "generated",
            observations: [{ code: "MCHECK_REPLAY_EVIDENCE_MUTATED", evidence_ref: ref }],
            revisionHints: [],
            allowedNextActions: ["stop"],
            artifactRef: route.result_artifact_ref,
          });
        }
      }

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

async function validateTarget(
  codeql: CodeqlPort,
  execution: MissingCheckExecutionPort,
  target: import("@autovul/contracts").MissingCheckTarget["vulnerable"],
  recordedFingerprint: string,
  options: CodeqlOperationOptions,
): Promise<void> {
  const observed = target.kind === "codeql_database"
    ? await (async () => {
        const manifest = await codeql.validateDatabase(target.path, options);
        if (manifest.portableFingerprint === undefined) {
          throw new DomainError("DATABASE_FINGERPRINT_UNAVAILABLE", "database", `Replay database fingerprint is unavailable for ${target.path}`, false, { path: target.path });
        }
        return manifest.portableFingerprint;
      })()
    : execution.validateTarget !== undefined
      ? await execution.validateTarget(target, options)
      : target.expected_fingerprint ?? recordedFingerprint;
  if (observed !== recordedFingerprint || (target.expected_fingerprint !== undefined && observed !== target.expected_fingerprint)) {
    const loc = target.kind === "git_revision" ? `${target.repository}@${target.revision}` : target.path;
    throw new DomainError("DATABASE_FINGERPRINT_MISMATCH", "database", `Replay target fingerprint differs for ${loc}`, false, { path: loc, recorded: recordedFingerprint, observed });
  }
}
