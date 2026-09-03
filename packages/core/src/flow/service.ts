import { Value } from "typebox/value";

import {
  FlowResearchToolInputSchema,
  CONTRACTS_VERSION,
  FLOW_DECISION_POLICY_VERSION,
  FLOW_HYPOTHESIS_VERSION,
  FlowRunArtifactSchema,
  DomainError,
  parseSchema,
  asDomainError,
  stableDigest,
  type FlowResearchToolInput,
  type EnvelopeAction,
  type FlowCompactObservation,
  type FlowAnalyzerObservation,
  type FlowDecision,
  type FlowModel,
  type FlowRevisionHint,
  type FlowRunArtifact,
  type FlowValidationIssue,
  type OperationBudget,
  type OperationStatus,
  type ResearchExecutionResult,
  type RunId,
  type TargetRef,
  type VerificationLevel,
} from "@autovul/contracts";

import { decideFlow } from "./decision.js";
import type { FlowExecutionPort } from "./port.js";
import { validateFlowExpectation, validateFlowModel } from "./validate.js";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { RunStatusService } from "../status-service.js";
import { RunCancellationService } from "../run-cancellation.js";
import { readResearchOperationRoute, serializeResearchOperationRoute } from "../research-operation.js";
import { canonicalJson } from "../canonical-json.js";
import { validateTargetFingerprint } from "../codeql-target.js";
import { isTerminalRunStatus } from "../state.js";

/** Flow evidence and the shared route are committed together beneath `research/`. */
export const FLOW_RESULT_ARTIFACT = "research/flow/result.json";
const FLOW_COMMIT_TARGET = "research";

export type ResearchResult = ReturnType<typeof validateFlowModel> | ResearchExecutionResult;

export interface CompactFlowResultInput {
  readonly runId: string;
  readonly operationStatus: OperationStatus;
  readonly decision: FlowDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly FlowCompactObservation[];
  readonly revisionHints: readonly FlowRevisionHint[];
  readonly allowedNextActions: readonly EnvelopeAction[];
  readonly artifactRef: string;
  readonly budgetRemaining?: OperationBudget;
}

export function compactFlowResult(input: CompactFlowResultInput): ResearchExecutionResult {
  return {
    schema_version: CONTRACTS_VERSION,
    run_id: input.runId,
    operation_status: input.operationStatus,
    capability: "flow",
    decision: input.decision,
    verification_level: input.verificationLevel,
    observations: [...input.observations],
    revision_hints: [...input.revisionHints],
    allowed_next_actions: [...input.allowedNextActions],
    ...(input.budgetRemaining === undefined ? {} : { budget_remaining: input.budgetRemaining }),
    artifact_ref: input.artifactRef,
  };
}

export function runIdForIdempotencyKey(key: string): RunId {
  return `run_${stableDigest(`autovul.flow/1:${key}`)}`;
}

export function readFlowRunArtifact(raw: string): FlowRunArtifact | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  return Value.Check(FlowRunArtifactSchema, parsed)
    ? Value.Parse(FlowRunArtifactSchema, parsed) as FlowRunArtifact
    : undefined;
}

function committedExecutionResult(raw: string, runId: string): ResearchExecutionResult | undefined {
  const artifact = readFlowRunArtifact(raw);
  if (artifact !== undefined) {
    return compactFlowResult({
      runId,
      operationStatus: artifact.operation_status,
      decision: artifact.decision,
      verificationLevel: artifact.verification_level,
      observations: artifact.observations,
      revisionHints: artifact.revision_hints,
      allowedNextActions: artifact.allowed_next_actions,
      artifactRef: FLOW_RESULT_ARTIFACT,
      ...(artifact.budget_remaining === undefined ? {} : { budgetRemaining: artifact.budget_remaining }),
    });
  }
  return undefined;
}

function envelopeIssues(input: unknown): FlowValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return [{ code: "FLOW_RESEARCH_ENVELOPE_INVALID", path: "/", expected_kind: "object" }];
  }
  const record = input as Record<string, unknown>;
  const issues: FlowValidationIssue[] = [];
  if (record.action !== "validate" && record.action !== "execute") {
    issues.push({ code: "FLOW_RESEARCH_ACTION_INVALID", path: "/action", allowed_values: ["validate", "execute"] });
  }
  if (record.capability !== "flow") {
    issues.push({ code: "FLOW_RESEARCH_CAPABILITY_INVALID", path: "/capability", allowed_values: ["flow"] });
  }
  if (record.hypothesis_version !== FLOW_HYPOTHESIS_VERSION) {
    issues.push({ code: "FLOW_HYPOTHESIS_VERSION_INVALID", path: "/hypothesis_version", allowed_values: [FLOW_HYPOTHESIS_VERSION] });
  }
  if (issues.length === 0) {
    issues.push({ code: "FLOW_RESEARCH_ENVELOPE_INVALID", path: "/" });
  }
  return issues;
}

/** Explicit Flow-only application branch; it intentionally is not a capability registry. */
export class FlowResearchService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: FlowExecutionPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async research(input: unknown, options: CodeqlOperationOptions): Promise<ResearchResult> {
    if (!Value.Check(FlowResearchToolInputSchema, input)) {
      return { valid: false, issues: envelopeIssues(input).slice(0, 64), allowed_next_actions: ["revise", "stop"] };
    }
    const request = Value.Parse(FlowResearchToolInputSchema, input) as FlowResearchToolInput;
    const validated = validateFlowModel(request.hypothesis);
    if (request.action === "validate" || !validated.valid || validated.model === undefined) return validated;
    return this.execute(request, validated.model, options);
  }

  private async execute(request: FlowResearchToolInput, model: FlowModel, options: CodeqlOperationOptions): Promise<ResearchResult> {
    const mode = request.mode;
    const target = request.target;
    const issues = mode === undefined ? [{ code: "FLOW_MODE_REQUIRED", path: "/mode", allowed_values: ["probe", "reproduce", "differential"] }] : validateFlowExpectation(request.expectation, mode);
    if (target === undefined) issues.push({ code: "FLOW_TARGET_REQUIRED", path: "/target", expected_kind: "object" });
    if (request.analyzer_id !== "codeql") issues.push({ code: "FLOW_ANALYZER_REQUIRED", path: "/analyzer_id", allowed_values: ["codeql"] });
    if (request.budget === undefined) issues.push({ code: "FLOW_BUDGET_REQUIRED", path: "/budget", expected_kind: "object" });
    if (request.idempotency_key === undefined) issues.push({ code: "FLOW_IDEMPOTENCY_KEY_REQUIRED", path: "/idempotency_key" });
    if (mode === "differential" && target?.fixed === undefined) issues.push({ code: "FLOW_FIXED_TARGET_REQUIRED", path: "/target/fixed" });
    if (issues.length > 0 || mode === undefined || target === undefined || request.budget === undefined || request.idempotency_key === undefined) {
      return { valid: false, issues: issues.slice(0, 64), allowed_next_actions: ["revise", "stop"] };
    }
    const runId = runIdForIdempotencyKey(request.idempotency_key);
    const existing = await this.artifacts.findManifest(runId);
    if (existing !== undefined && isTerminalRunStatus(existing.status)) {
      await this.assertCompatibleIdempotency(runId, request, model, target, mode);
      const committed = await this.readCommitted(runId);
      if (committed !== undefined) return committed;
    }
    const run = await this.status.create(runId);
    return this.artifacts.withRunOperation(run.runId, options, async () => {
      // A process may have promoted evidence just before it was interrupted
      // while changing the manifest. Evidence is authoritative at this point.
      await this.assertCompatibleIdempotency(run.runId, request, model, target, mode);
      const committed = await this.readCommitted(run.runId);
      if (committed !== undefined) return committed;
      const current = await this.status.get(run.runId);
      if (isTerminalRunStatus(current.status)) {
        const committed = await this.readCommitted(run.runId);
        if (committed !== undefined) return committed;
        if (current.status === "cancelled") {
          return this.finish(run.runId, new DomainError("PROCESS_CANCELLED", "process", `Flow execution for ${run.runId} was cancelled`, false, { runId: run.runId }), {
            runId: run.runId,
            operationStatus: "cancelled",
            decision: { capability: "flow", outcome: "unknown" },
            verificationLevel: "generated",
            observations: [{ code: "FLOW_EXECUTION_CANCELLED", evidence_ref: FLOW_RESULT_ARTIFACT }],
            revisionHints: [],
            allowedNextActions: ["replay", "stop"],
            artifactRef: FLOW_RESULT_ARTIFACT,
          }, { model, target, mode, request });
        }
        throw new DomainError("INVALID_STATE_TRANSITION", "state", `Flow operation ${run.runId} is terminal without committed evidence`, false, { runId: run.runId, status: current.status });
      }
      if (current.status === "created") {
        await this.status.start(run.runId, "flow_execute");
      }
      const operation = this.cancellations.begin(run.runId, options.signal);
      try {
        return await this.runAnalyzer(request, model, mode, target, { ...options, signal: operation.signal }, run.runId, run.artifactRoot);
      } finally {
        operation.release();
      }
    });
  }

  private async runAnalyzer(
    request: FlowResearchToolInput,
    model: FlowModel,
    mode: "probe" | "reproduce" | "differential",
    target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef },
    options: CodeqlOperationOptions,
    runId: string,
    artifactRoot: string,
  ): Promise<ResearchExecutionResult> {
    let targetFingerprints: { readonly vulnerable: string; readonly fixed?: string } | undefined;
    try {
      const vulnerable = await validateTargetFingerprint(this.codeql, target.vulnerable, options);
      const fixed = target.fixed === undefined ? undefined : await validateTargetFingerprint(this.codeql, target.fixed, options);
      targetFingerprints = { vulnerable, ...(fixed === undefined ? {} : { fixed }) };
    } catch (error: unknown) {
      const classified = classifyFlowFailure(cancellationOr(error, options.signal, runId), "prerequisite");
      return this.finish(runId, classified.error, {
        runId, operationStatus: classified.operationStatus, decision: { capability: "flow", outcome: "unknown" },
        verificationLevel: "generated", observations: [{ code: classified.observationCode, evidence_ref: FLOW_RESULT_ARTIFACT }],
        revisionHints: [], allowedNextActions: ["revise", "stop"], artifactRef: FLOW_RESULT_ARTIFACT,
      }, { model, target, mode, request });
    }
    try {
      const observation = await this.execution.execute({
        model, target, analyzer_id: "codeql", mode,
        ...(request.expectation === undefined ? {} : { expectation: request.expectation }),
        runId, artifactRoot,
      }, { ...options, timeoutMs: Math.min(options.timeoutMs, request.budget?.timeout_ms ?? options.timeoutMs) });
      if (options.signal?.aborted) {
        throw new DomainError("PROCESS_CANCELLED", "process", `Flow execution for ${runId} was cancelled`, false, { runId });
      }
      if (observation.analyzer.available === false) {
        const blocked = compactFlowResult({
          runId, operationStatus: "blocked", decision: { capability: "flow", outcome: "unknown" },
          verificationLevel: "generated",
          observations: [{ code: "FLOW_ANALYZER_UNAVAILABLE", evidence_ref: FLOW_RESULT_ARTIFACT }],
          revisionHints: [], allowedNextActions: ["revise", "stop"], artifactRef: FLOW_RESULT_ARTIFACT,
        });
        await this.writeCommitted(runId, blocked, { model, target, mode, request, observation, targetFingerprints });
        await this.status.fail(runId, asDomainError(new Error("Flow analyzer unavailable")).toRecord());
        return blocked;
      }
      if (observation.capability_gaps.length === 0 && (observation.analyzer.version === undefined || observation.analyzer.adapter_version === undefined)) {
        const blocked = compactFlowResult({
          runId, operationStatus: "blocked", decision: { capability: "flow", outcome: "unknown" },
          verificationLevel: "generated",
          observations: [{ code: "FLOW_ANALYZER_VERSION_UNAVAILABLE", evidence_ref: FLOW_RESULT_ARTIFACT }],
          revisionHints: [], allowedNextActions: ["revise", "stop"], artifactRef: FLOW_RESULT_ARTIFACT,
        });
        await this.writeCommitted(runId, blocked, { model, target, mode, request, observation, targetFingerprints });
        await this.status.fail(runId, new DomainError("CODEQL_RESOLVE_FAILED", "process", "Flow Analyzer or adapter version is unavailable", false).toRecord());
        return blocked;
      }
      const projection = decideFlow(observation, mode, request.expectation);
      const completed = compactFlowResult({
        runId,
        operationStatus: "completed",
        decision: projection.decision,
        verificationLevel: projection.verificationLevel,
        observations: projection.observations,
        revisionHints: projection.revisionHints,
        allowedNextActions: projection.allowedNextActions,
        artifactRef: FLOW_RESULT_ARTIFACT,
      });
      await this.writeCommitted(runId, completed, { model, target, mode, request, observation, targetFingerprints, decisionPolicyVersion: FLOW_DECISION_POLICY_VERSION });
      await this.status.complete(runId, projection.verificationLevel, "flow_execute");
      return completed;
    } catch (error: unknown) {
      const classified = classifyFlowFailure(cancellationOr(error, options.signal, runId), "execution");
      return this.finish(runId, classified.error, {
        runId, operationStatus: classified.operationStatus, decision: { capability: "flow", outcome: "unknown" },
        verificationLevel: "generated", observations: [{ code: classified.observationCode, evidence_ref: FLOW_RESULT_ARTIFACT }],
        revisionHints: [], allowedNextActions: ["revise", "stop"], artifactRef: FLOW_RESULT_ARTIFACT,
      }, { model, target, mode, request, targetFingerprints });
    }
  }

  private async finish(
    runId: string,
    error: unknown,
    input: CompactFlowResultInput,
    extra: {
      readonly model: FlowModel;
      readonly target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef };
      readonly mode: "probe" | "reproduce" | "differential";
      readonly request: FlowResearchToolInput;
      readonly targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string };
    },
  ): Promise<ResearchExecutionResult> {
    const domainError = asDomainError(error);
    const cancelled = domainError.code === "PROCESS_CANCELLED";
    const result = compactFlowResult(cancelled
      ? { ...input, operationStatus: "cancelled", observations: [{ code: input.observations[0]?.code === "FLOW_DATABASE_PREREQUISITE_BLOCKED" ? "FLOW_DATABASE_PREREQUISITE_BLOCKED" : "FLOW_EXECUTION_CANCELLED", evidence_ref: FLOW_RESULT_ARTIFACT }] }
      : input);
    await this.writeCommitted(runId, result, extra);
    if (cancelled) {
      await this.status.cancel(runId, domainError.toRecord());
    } else if (result.operation_status === "blocked" || result.operation_status === "failed") {
      await this.status.fail(runId, domainError.toRecord());
    }
    return result;
  }

  private async writeCommitted(
    runId: string,
    result: ResearchExecutionResult,
    extra: {
      readonly model: FlowModel;
      readonly target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef };
      readonly mode: "probe" | "reproduce" | "differential";
      readonly request: FlowResearchToolInput;
      readonly observation?: FlowAnalyzerObservation;
      readonly targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string };
      readonly decisionPolicyVersion?: string;
    },
  ): Promise<void> {
    const flowArtifact = JSON.stringify(parseSchema(FlowRunArtifactSchema, {
      schema_version: CONTRACTS_VERSION,
      capability: "flow",
      hypothesis_version: extra.model.schema_version,
      model: extra.model,
      target: extra.target,
      mode: extra.mode,
      ...(extra.request.expectation === undefined ? {} : { expectation: extra.request.expectation }),
      ...(extra.request.budget === undefined ? {} : { budget: extra.request.budget }),
      ...(extra.request.idempotency_key === undefined ? {} : { idempotency_key: extra.request.idempotency_key }),
      analyzer: extra.observation?.analyzer ?? { analyzer_id: "codeql", available: false },
      ...(extra.targetFingerprints === undefined ? {} : { target_fingerprints: extra.targetFingerprints }),
      ...(extra.observation === undefined ? {} : { observation: extra.observation }),
      ...(extra.decisionPolicyVersion === undefined ? {} : { decision_policy_version: extra.decisionPolicyVersion }),
      operation_status: result.operation_status,
      decision: result.decision,
      verification_level: result.verification_level,
      observations: result.observations,
      revision_hints: result.revision_hints,
      allowed_next_actions: result.allowed_next_actions,
      ...(result.budget_remaining === undefined ? {} : { budget_remaining: result.budget_remaining }),
    }, "Flow run artifact"));
    const route = serializeResearchOperationRoute({
      capability: "flow",
      hypothesis_version: FLOW_HYPOTHESIS_VERSION,
      result_artifact_ref: FLOW_RESULT_ARTIFACT,
    });
    const operationId = `flow-commit-${stableDigest(runId)}`;
    try {
      const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, FLOW_COMMIT_TARGET, [
        { relativePath: "operation.json", content: route },
        { relativePath: "flow/result.json", content: flowArtifact },
      ]);
      await this.artifacts.promoteArtifactBundle(runId, bundle);
    } catch (error: unknown) {
      // A successful promote followed by an interrupted caller is recoverable:
      // accept it only when both halves of the committed bundle validate.
      const committedRoute = await readResearchOperationRoute(this.artifacts, runId).catch(() => undefined);
      const committedResult = await this.readCommitted(runId);
      if (committedRoute?.route_kind === "capability" && committedRoute.capability === "flow" && committedRoute.result_artifact_ref === FLOW_RESULT_ARTIFACT && committedResult !== undefined) return;
      throw error;
    }
  }

  private async readCommitted(runId: string): Promise<ResearchExecutionResult | undefined> {
    const raw = await this.artifacts.readArtifact(runId, FLOW_RESULT_ARTIFACT);
    if (raw === undefined) return undefined;
    return committedExecutionResult(raw, runId);
  }

  private async assertCompatibleIdempotency(
    runId: string,
    request: FlowResearchToolInput,
    model: FlowModel,
    target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef },
    mode: "probe" | "reproduce" | "differential",
  ): Promise<void> {
    const raw = await this.artifacts.readArtifact(runId, FLOW_RESULT_ARTIFACT);
    if (raw === undefined) return;
    const committed = readFlowRunArtifact(raw);
    if (committed === undefined) return;
    const requestedIdentity = canonicalJson({
      model,
      target,
      mode,
      ...(request.expectation === undefined ? {} : { expectation: request.expectation }),
      budget: request.budget,
      idempotency_key: request.idempotency_key,
    });
    const committedIdentity = canonicalJson({
      model: committed.model,
      target: committed.target,
      mode: committed.mode,
      ...(committed.expectation === undefined ? {} : { expectation: committed.expectation }),
      budget: committed.budget,
      idempotency_key: committed.idempotency_key,
    });
    if (requestedIdentity !== committedIdentity) {
      throw new DomainError("IDEMPOTENCY_KEY_CONFLICT", "state", `Idempotency key is already bound to a different Flow request: ${runId}`, false, { runId });
    }
  }
}

function cancellationOr(error: unknown, signal: AbortSignal | undefined, runId: string): unknown {
  if (!signal?.aborted) return error;
  return new DomainError("PROCESS_CANCELLED", "process", `Flow execution for ${runId} was cancelled`, false, { runId });
}

function classifyFlowFailure(error: unknown, stage: "prerequisite" | "execution"): {
  readonly error: unknown;
  readonly operationStatus: "blocked" | "failed";
  readonly observationCode: string;
} {
  const domainError = asDomainError(error);
  if (domainError.code === "CODEQL_CLI_NOT_FOUND" || domainError.code === "CODEQL_RESOLVE_FAILED" || domainError.code === "CODEQL_EXTRACTOR_MISSING") {
    return { error, operationStatus: "blocked", observationCode: "FLOW_ANALYZER_UNAVAILABLE" };
  }
  if (domainError.code === "DATABASE_NOT_FOUND" || domainError.code === "DATABASE_INVALID" || domainError.code === "DATABASE_PATH_OUTSIDE_WORKSPACE") {
    return { error, operationStatus: "blocked", observationCode: "FLOW_DATABASE_PREREQUISITE_BLOCKED" };
  }
  if (domainError.code === "DATABASE_FINGERPRINT_UNAVAILABLE") {
    return { error, operationStatus: "blocked", observationCode: "FLOW_TARGET_FINGERPRINT_UNAVAILABLE" };
  }
  if (domainError.code === "DATABASE_FINGERPRINT_MISMATCH") {
    return { error, operationStatus: "blocked", observationCode: "FLOW_TARGET_FINGERPRINT_MISMATCH" };
  }
  if (domainError.code === "PROBE_FAILED") {
    return { error, operationStatus: "failed", observationCode: "FLOW_PROBE_FAILED" };
  }
  if (domainError.code === "PROCESS_TIMEOUT") {
    return { error, operationStatus: "failed", observationCode: "FLOW_ANALYZER_TIMEOUT" };
  }
  if (domainError.code === "PROCESS_OUTPUT_LIMIT") {
    return { error, operationStatus: "failed", observationCode: "FLOW_ANALYZER_OUTPUT_LIMIT" };
  }
  return {
    error,
    operationStatus: stage === "prerequisite" ? "blocked" : "failed",
    observationCode: stage === "prerequisite" ? "FLOW_DATABASE_PREREQUISITE_BLOCKED" : "FLOW_EXECUTION_FAILED",
  };
}
