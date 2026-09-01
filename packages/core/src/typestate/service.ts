import { Value } from "typebox/value";

import {
  CONTRACTS_VERSION,
  DomainError,
  TYPESTATE_DECISION_POLICY_VERSION,
  TYPESTATE_HYPOTHESIS_VERSION,
  TypestateExecutionResultSchema,
  TypestateResearchToolInputSchema,
  TypestateRunArtifactSchema,
  asDomainError,
  parseSchema,
  stableDigest,
  type EnvelopeAction,
  type OperationBudget,
  type OperationStatus,
  type RunId,
  type TargetRef,
  type TypestateAnalyzerObservation,
  type TypestateCompactObservation,
  type TypestateDecision,
  type TypestateExecutionResult,
  type TypestateHypothesis,
  type TypestateResearchToolInput,
  type TypestateRevisionHint,
  type TypestateRunArtifact,
  type TypestateValidationIssue,
  type VerificationLevel,
} from "@autovul/contracts";

import { readResearchOperationRoute, serializeResearchOperationRoute } from "../research-operation.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { decideTypestate } from "./decision.js";
import type { TypestateExecutionPort } from "./port.js";
import { validateTypestateHypothesis } from "./validate.js";

export const TYPESTATE_RESULT_ARTIFACT = "research/typestate/result.json";
const COMMIT_TARGET = "research";
const EXECUTION_PHASE = "typestate_execute" as const;

export type TypestateResearchResult = ReturnType<typeof validateTypestateHypothesis> | TypestateExecutionResult;

interface CompactInput {
  readonly runId: string;
  readonly operationStatus: OperationStatus;
  readonly decision: TypestateDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly TypestateCompactObservation[];
  readonly revisionHints: readonly TypestateRevisionHint[];
  readonly allowedNextActions: readonly EnvelopeAction[];
  readonly artifactRef: string;
  readonly budgetRemaining?: OperationBudget;
}

export function compactTypestateResult(input: CompactInput): TypestateExecutionResult {
  return {
    schema_version: CONTRACTS_VERSION,
    run_id: input.runId,
    operation_status: input.operationStatus,
    capability: "typestate",
    decision: input.decision,
    verification_level: input.verificationLevel,
    observations: [...input.observations],
    revision_hints: [...input.revisionHints],
    allowed_next_actions: [...input.allowedNextActions],
    ...(input.budgetRemaining === undefined ? {} : { budget_remaining: input.budgetRemaining }),
    artifact_ref: input.artifactRef,
  };
}

export function typestateRunIdForIdempotencyKey(key: string): RunId {
  return `run_${stableDigest(`${TYPESTATE_HYPOTHESIS_VERSION}:${key}`)}`;
}

export function readTypestateRunArtifact(raw: string): TypestateRunArtifact | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Value.Check(TypestateRunArtifactSchema, parsed)
      ? Value.Parse(TypestateRunArtifactSchema, parsed) as TypestateRunArtifact
      : undefined;
  } catch {
    return undefined;
  }
}

/** Explicit Typestate branch; domain rules stay outside shared runtime code. */
export class TypestateResearchService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: TypestateExecutionPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async research(input: unknown, options: CodeqlOperationOptions): Promise<TypestateResearchResult> {
    if (!Value.Check(TypestateResearchToolInputSchema, input)) {
      return { valid: false, issues: envelopeIssues(input), allowed_next_actions: ["revise", "stop"] };
    }
    const request = Value.Parse(TypestateResearchToolInputSchema, input) as TypestateResearchToolInput;
    const validated = validateTypestateHypothesis(request.hypothesis);
    if (request.action === "validate" || !validated.valid || validated.hypothesis === undefined) return validated;
    return this.execute(request, validated.hypothesis, options);
  }

  private async execute(request: TypestateResearchToolInput, hypothesis: TypestateHypothesis, options: CodeqlOperationOptions): Promise<TypestateResearchResult> {
    const issues = executionIssues(request);
    if (issues.length > 0 || request.target === undefined || request.mode === undefined || request.budget === undefined || request.idempotency_key === undefined) {
      return { valid: false, issues, allowed_next_actions: ["revise", "stop"] };
    }
    const target = request.target;
    const mode = request.mode;
    const budget = request.budget;
    const idempotencyKey = request.idempotency_key;
    const runId = typestateRunIdForIdempotencyKey(idempotencyKey);
    const existing = await this.artifacts.findManifest(runId);
    if (existing !== undefined && isTerminal(existing.status)) {
      await this.assertIdempotency(runId, request, hypothesis);
      const committed = await this.readCommitted(runId);
      if (committed !== undefined) return committed;
    }
    const run = await this.status.create(runId);
    return this.artifacts.withRunOperation(run.runId, options, async () => {
      // Evidence is authoritative if a caller was interrupted after promotion.
      await this.assertIdempotency(run.runId, request, hypothesis);
      const committed = await this.readCommitted(run.runId);
      if (committed !== undefined) return committed;
      const current = await this.status.get(run.runId);
      if (isTerminal(current.status)) {
        const recovered = await this.readCommitted(run.runId);
        if (recovered !== undefined) return recovered;
        if (current.status === "cancelled") {
          return this.failed(run.runId, "TSTATE_EXECUTION_CANCELLED", "cancelled", hypothesis, request, undefined, new DomainError("PROCESS_CANCELLED", "process", `Typestate execution for ${run.runId} was cancelled`, false, { runId: run.runId }));
        }
        throw new DomainError("INVALID_STATE_TRANSITION", "state", `Typestate operation ${run.runId} is terminal without committed evidence`, false, { runId: run.runId, status: current.status });
      }
      if (current.status === "created") await this.status.start(run.runId, EXECUTION_PHASE);
      const operation = this.cancellations.begin(run.runId, options.signal);
      try {
        return await this.runAnalyzer(run.runId, hypothesis, request, target, mode, budget, { ...options, signal: operation.signal }, run.artifactRoot);
      } finally {
        operation.release();
      }
    });
  }

  private async runAnalyzer(
    runId: RunId,
    hypothesis: TypestateHypothesis,
    request: TypestateResearchToolInput,
    target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef },
    mode: "probe" | "reproduce" | "differential",
    budget: OperationBudget,
    options: CodeqlOperationOptions,
    artifactRoot: string,
  ): Promise<TypestateExecutionResult> {
    let targetFingerprints: { readonly vulnerable: string; readonly fixed?: string } | undefined;
    let observation: TypestateAnalyzerObservation | undefined;
    try {
      const vulnerable = await validateAndFingerprint(this.codeql, target.vulnerable, options);
      const fixed = target.fixed === undefined ? undefined : await validateAndFingerprint(this.codeql, target.fixed, options);
      targetFingerprints = { vulnerable, ...(fixed === undefined ? {} : { fixed }) };
      observation = await this.execution.execute(
        { hypothesis, target, analyzer_id: "codeql", mode, runId, artifactRoot },
        { ...options, timeoutMs: Math.min(options.timeoutMs, budget.timeout_ms) },
      );
      if (options.signal?.aborted) throw new DomainError("PROCESS_CANCELLED", "process", `Typestate execution for ${runId} was cancelled`, false, { runId });
      if (!observation.analyzer.available) return this.commitFailure(runId, hypothesis, request, "TSTATE_ANALYZER_UNAVAILABLE", "blocked", observation, targetFingerprints);
      if (observation.analyzer.evidence_kind === "real_analyzer" && (observation.analyzer.version === undefined || observation.analyzer.adapter_version === undefined)) {
        return this.commitFailure(runId, hypothesis, request, "TSTATE_ANALYZER_VERSION_UNAVAILABLE", "blocked", observation, targetFingerprints);
      }
      const projection = decideTypestate(observation, mode, hypothesis);
      const result = compactTypestateResult({
        runId,
        operationStatus: "completed",
        decision: projection.decision,
        verificationLevel: projection.verificationLevel,
        observations: projection.observations,
        revisionHints: projection.revisionHints,
        allowedNextActions: projection.allowedNextActions,
        artifactRef: TYPESTATE_RESULT_ARTIFACT,
      });
      await this.writeCommitted(runId, result, hypothesis, request, observation, targetFingerprints);
      await this.status.complete(runId, projection.verificationLevel, EXECUTION_PHASE);
      return result;
    } catch (error: unknown) {
      const classified = classifyTypestateFailure(cancellationOr(error, options.signal, runId));
      return this.failed(runId, classified.observationCode, classified.operationStatus, hypothesis, request, targetFingerprints, classified.error, observation);
    }
  }

  private async commitFailure(
    runId: RunId,
    hypothesis: TypestateHypothesis,
    request: TypestateResearchToolInput,
    code: string,
    operationStatus: "blocked" | "failed",
    observation?: TypestateAnalyzerObservation,
    targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string },
  ): Promise<TypestateExecutionResult> {
    const result = compactTypestateResult({
      runId,
      operationStatus,
      decision: { capability: "typestate", outcome: "unknown" },
      verificationLevel: "generated",
      observations: [{ code, evidence_ref: TYPESTATE_RESULT_ARTIFACT }],
      revisionHints: [],
      allowedNextActions: ["revise", "stop"],
      artifactRef: TYPESTATE_RESULT_ARTIFACT,
    });
    await this.writeCommitted(runId, result, hypothesis, request, observation, targetFingerprints);
    await this.status.fail(runId, new DomainError("INVALID_STATE_TRANSITION", "state", code, false, { runId }).toRecord());
    return result;
  }

  private async failed(
    runId: RunId,
    code: string,
    operationStatus: "blocked" | "failed" | "cancelled",
    hypothesis: TypestateHypothesis,
    request: TypestateResearchToolInput,
    targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string },
    error?: unknown,
    observation?: TypestateAnalyzerObservation,
  ): Promise<TypestateExecutionResult> {
    const result = compactTypestateResult({
      runId,
      operationStatus,
      decision: { capability: "typestate", outcome: "unknown" },
      verificationLevel: "generated",
      observations: [{ code, evidence_ref: TYPESTATE_RESULT_ARTIFACT }],
      revisionHints: [],
      allowedNextActions: operationStatus === "cancelled" ? ["replay", "stop"] : ["revise", "stop"],
      artifactRef: TYPESTATE_RESULT_ARTIFACT,
    });
    await this.writeCommitted(runId, result, hypothesis, request, observation, targetFingerprints);
    const domain = error === undefined ? new DomainError("INVALID_STATE_TRANSITION", "state", code, false, { runId }) : asDomainError(error);
    if (operationStatus === "cancelled") await this.status.cancel(runId, domain.toRecord());
    else await this.status.fail(runId, domain.toRecord());
    return result;
  }

  private async writeCommitted(
    runId: RunId,
    result: TypestateExecutionResult,
    hypothesis: TypestateHypothesis,
    request: TypestateResearchToolInput,
    observation?: TypestateAnalyzerObservation,
    targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string },
  ): Promise<void> {
    const artifact = JSON.stringify(parseSchema(TypestateRunArtifactSchema, {
      schema_version: CONTRACTS_VERSION,
      capability: "typestate",
      hypothesis_version: TYPESTATE_HYPOTHESIS_VERSION,
      hypothesis,
      target: request.target,
      mode: request.mode,
      ...(request.budget === undefined ? {} : { budget: request.budget }),
      ...(request.idempotency_key === undefined ? {} : { idempotency_key: request.idempotency_key }),
      analyzer: observation?.analyzer ?? { analyzer_id: "codeql", available: false, evidence_kind: "real_analyzer" },
      ...(targetFingerprints === undefined ? {} : { target_fingerprints: targetFingerprints }),
      ...(observation === undefined ? {} : { observation }),
      decision_policy_version: TYPESTATE_DECISION_POLICY_VERSION,
      operation_status: result.operation_status,
      decision: result.decision,
      verification_level: result.verification_level,
      observations: result.observations,
      revision_hints: result.revision_hints,
      allowed_next_actions: result.allowed_next_actions,
      ...(result.budget_remaining === undefined ? {} : { budget_remaining: result.budget_remaining }),
    }, "Typestate run artifact"));
    const route = serializeResearchOperationRoute({ capability: "typestate", hypothesis_version: TYPESTATE_HYPOTHESIS_VERSION, result_artifact_ref: TYPESTATE_RESULT_ARTIFACT });
    const operationId = `typestate-commit-${stableDigest(runId)}`;
    try {
      const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, COMMIT_TARGET, [
        { relativePath: "operation.json", content: route },
        { relativePath: "typestate/result.json", content: artifact },
      ]);
      await this.artifacts.promoteArtifactBundle(runId, bundle);
    } catch (error: unknown) {
      // If promotion won before interruption, accept only a complete route/result pair.
      const committedRoute = await readResearchOperationRoute(this.artifacts, runId).catch(() => undefined);
      const committedResult = await this.readCommitted(runId);
      if (committedRoute?.capability === "typestate" && committedRoute.result_artifact_ref === TYPESTATE_RESULT_ARTIFACT && committedResult !== undefined) return;
      throw error;
    }
  }

  private async readCommitted(runId: RunId): Promise<TypestateExecutionResult | undefined> {
    const raw = await this.artifacts.readArtifact(runId, TYPESTATE_RESULT_ARTIFACT);
    if (raw === undefined) return undefined;
    const artifact = readTypestateRunArtifact(raw);
    if (artifact === undefined) return undefined;
    return compactTypestateResult({
      runId,
      operationStatus: artifact.operation_status,
      decision: artifact.decision,
      verificationLevel: artifact.verification_level,
      observations: artifact.observations,
      revisionHints: artifact.revision_hints,
      allowedNextActions: artifact.allowed_next_actions,
      artifactRef: TYPESTATE_RESULT_ARTIFACT,
      ...(artifact.budget_remaining === undefined ? {} : { budgetRemaining: artifact.budget_remaining }),
    });
  }

  private async assertIdempotency(runId: RunId, request: TypestateResearchToolInput, hypothesis: TypestateHypothesis): Promise<void> {
    const raw = await this.artifacts.readArtifact(runId, TYPESTATE_RESULT_ARTIFACT);
    const artifact = raw === undefined ? undefined : readTypestateRunArtifact(raw);
    if (artifact === undefined) return;
    const requested = canonical({ hypothesis, target: request.target, mode: request.mode, budget: request.budget, idempotency_key: request.idempotency_key });
    const committed = canonical({ hypothesis: artifact.hypothesis, target: artifact.target, mode: artifact.mode, budget: artifact.budget, idempotency_key: artifact.idempotency_key });
    if (requested !== committed) {
      throw new DomainError("IDEMPOTENCY_KEY_CONFLICT", "state", `Idempotency key is already bound to a different Typestate request: ${runId}`, false, { runId });
    }
  }
}

function envelopeIssues(input: unknown): TypestateValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [{ code: "TSTATE_RESEARCH_ENVELOPE_INVALID", path: "/", expected_kind: "object" }];
  const record = input as Record<string, unknown>;
  const issues: TypestateValidationIssue[] = [];
  if (record.action !== "validate" && record.action !== "execute") issues.push({ code: "TSTATE_RESEARCH_ACTION_INVALID", path: "/action", allowed_values: ["validate", "execute"] });
  if (record.capability !== "typestate") issues.push({ code: "TSTATE_RESEARCH_CAPABILITY_INVALID", path: "/capability", allowed_values: ["typestate"] });
  if (record.hypothesis_version !== TYPESTATE_HYPOTHESIS_VERSION) issues.push({ code: "TSTATE_HYPOTHESIS_VERSION_INVALID", path: "/hypothesis_version", allowed_values: [TYPESTATE_HYPOTHESIS_VERSION] });
  return issues.length === 0 ? [{ code: "TSTATE_RESEARCH_ENVELOPE_INVALID", path: "/" }] : issues;
}

function executionIssues(request: TypestateResearchToolInput): TypestateValidationIssue[] {
  const issues: TypestateValidationIssue[] = [];
  if (request.mode === undefined) issues.push({ code: "TSTATE_MODE_REQUIRED", path: "/mode", allowed_values: ["probe", "reproduce", "differential"] });
  if (request.target === undefined) issues.push({ code: "TSTATE_TARGET_REQUIRED", path: "/target", expected_kind: "object" });
  if (request.mode === "differential" && request.target?.fixed === undefined) issues.push({ code: "TSTATE_FIXED_TARGET_REQUIRED", path: "/target/fixed" });
  if (request.analyzer_id !== "codeql") issues.push({ code: "TSTATE_ANALYZER_REQUIRED", path: "/analyzer_id", allowed_values: ["codeql"] });
  if (request.budget === undefined) issues.push({ code: "TSTATE_BUDGET_REQUIRED", path: "/budget", expected_kind: "object" });
  if (request.idempotency_key === undefined) issues.push({ code: "TSTATE_IDEMPOTENCY_KEY_REQUIRED", path: "/idempotency_key" });
  return issues;
}

function isTerminal(status: string): boolean {
  return status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted";
}

function cancellationOr(error: unknown, signal: AbortSignal | undefined, runId: string): unknown {
  return signal?.aborted
    ? new DomainError("PROCESS_CANCELLED", "process", `Typestate execution for ${runId} was cancelled`, false, { runId })
    : error;
}

function classifyTypestateFailure(error: unknown): {
  readonly error: unknown;
  readonly operationStatus: "blocked" | "failed" | "cancelled";
  readonly observationCode: string;
} {
  const domain = asDomainError(error);
  if (domain.code === "PROCESS_CANCELLED") return { error, operationStatus: "cancelled", observationCode: "TSTATE_EXECUTION_CANCELLED" };
  if (domain.code === "CODEQL_CLI_NOT_FOUND" || domain.code === "CODEQL_EXTRACTOR_MISSING") return { error, operationStatus: "blocked", observationCode: "TSTATE_ANALYZER_UNAVAILABLE" };
  if (domain.code === "CODEQL_RESOLVE_FAILED") return { error, operationStatus: "blocked", observationCode: "TSTATE_ANALYZER_VERSION_UNAVAILABLE" };
  if (domain.code === "DATABASE_NOT_FOUND" || domain.code === "DATABASE_INVALID" || domain.code === "DATABASE_PATH_OUTSIDE_WORKSPACE") return { error, operationStatus: "blocked", observationCode: "TSTATE_DATABASE_PREREQUISITE_BLOCKED" };
  if (domain.code === "DATABASE_FINGERPRINT_UNAVAILABLE") return { error, operationStatus: "blocked", observationCode: "TSTATE_TARGET_FINGERPRINT_UNAVAILABLE" };
  if (domain.code === "DATABASE_FINGERPRINT_MISMATCH") return { error, operationStatus: "blocked", observationCode: "TSTATE_TARGET_FINGERPRINT_MISMATCH" };
  if (domain.code === "ARTIFACT_CORRUPT") return { error, operationStatus: "failed", observationCode: "TSTATE_ANALYZER_OUTPUT_PARSE_FAILED" };
  if (domain.code === "PROCESS_TIMEOUT") return { error, operationStatus: "failed", observationCode: "TSTATE_ANALYZER_TIMEOUT" };
  if (domain.code === "PROCESS_OUTPUT_LIMIT") return { error, operationStatus: "failed", observationCode: "TSTATE_ANALYZER_OUTPUT_LIMIT" };
  return { error, operationStatus: "failed", observationCode: "TSTATE_EXECUTION_FAILED" };
}

async function validateAndFingerprint(codeql: CodeqlPort, target: TargetRef, options: CodeqlOperationOptions): Promise<string> {
  const manifest = await codeql.validateDatabase(target.path, options);
  if (manifest.portableFingerprint === undefined) {
    throw new DomainError("DATABASE_FINGERPRINT_UNAVAILABLE", "database", `Database fingerprint is unavailable for ${target.path}`, false, { path: target.path });
  }
  if (target.expected_fingerprint !== undefined && target.expected_fingerprint !== manifest.portableFingerprint) {
    throw new DomainError("DATABASE_FINGERPRINT_MISMATCH", "database", `Database fingerprint differs for ${target.path}`, false, { path: target.path, expected: target.expected_fingerprint, observed: manifest.portableFingerprint });
  }
  return manifest.portableFingerprint;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
