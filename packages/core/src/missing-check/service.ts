import { Value } from "typebox/value";

import {
  CONTRACTS_VERSION,
  MISSING_CHECK_DECISION_POLICY_VERSION,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  MissingCheckExecutionResultSchema,
  MissingCheckRunArtifactSchema,
  MissingCheckResearchToolInputSchema,
  DomainError,
  asDomainError,
  parseSchema,
  stableDigest,
  type MissingCheckAnalyzerObservation,
  type MissingCheckCompactObservation,
  type MissingCheckDecision,
  type MissingCheckExecutionResult,
  type MissingCheckHypothesis,
  type MissingCheckResearchToolInput,
  type MissingCheckRevisionHint,
  type MissingCheckRunArtifact,
  type MissingCheckValidationIssue,
  type OperationBudget,
  type OperationStatus,
  type RunId,
  type TargetRef,
  type VerificationLevel,
} from "@autovul/contracts";

import { RunCancellationService } from "../run-cancellation.js";
import { readResearchOperationRoute, serializeResearchOperationRoute } from "../research-operation.js";
import { RunStatusService } from "../status-service.js";
import type { ArtifactStorePort, CodeqlOperationOptions, CodeqlPort } from "../ports.js";
import { decideMissingCheck } from "./decision.js";
import type { MissingCheckExecutionPort } from "./port.js";
import { validateMissingCheckHypothesis } from "./validate.js";

export const MISSING_CHECK_RESULT_ARTIFACT = "research/missing-check/result.json";
const COMMIT_TARGET = "research";
export type MissingCheckResearchResult = ReturnType<typeof validateMissingCheckHypothesis> | MissingCheckExecutionResult;

interface CompactInput {
  readonly runId: string;
  readonly operationStatus: OperationStatus;
  readonly decision: MissingCheckDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly MissingCheckCompactObservation[];
  readonly revisionHints: readonly MissingCheckRevisionHint[];
  readonly allowedNextActions: readonly ("revise" | "execute" | "replay" | "stop")[];
  readonly artifactRef: string;
  readonly budgetRemaining?: OperationBudget;
}

export function compactMissingCheckResult(input: CompactInput): MissingCheckExecutionResult {
  return {
    schema_version: CONTRACTS_VERSION, run_id: input.runId, operation_status: input.operationStatus,
    capability: "missing_check", decision: input.decision, verification_level: input.verificationLevel,
    observations: [...input.observations], revision_hints: [...input.revisionHints], allowed_next_actions: [...input.allowedNextActions],
    ...(input.budgetRemaining === undefined ? {} : { budget_remaining: input.budgetRemaining }), artifact_ref: input.artifactRef,
  };
}

export function missingCheckRunIdForIdempotencyKey(key: string): RunId {
  return `run_${stableDigest(`${MISSING_CHECK_HYPOTHESIS_VERSION}:${key}`)}`;
}

export function readMissingCheckRunArtifact(raw: string): MissingCheckRunArtifact | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Value.Check(MissingCheckRunArtifactSchema, parsed) ? Value.Parse(MissingCheckRunArtifactSchema, parsed) as MissingCheckRunArtifact : undefined;
  } catch { return undefined; }
}

/** Explicit MissingCheck branch, intentionally separate from Flow. */
export class MissingCheckResearchService {
  constructor(
    private readonly status: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly execution: MissingCheckExecutionPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async research(input: unknown, options: CodeqlOperationOptions): Promise<MissingCheckResearchResult> {
    if (!Value.Check(MissingCheckResearchToolInputSchema, input)) return { valid: false, issues: envelopeIssues(input), allowed_next_actions: ["revise", "stop"] };
    const request = Value.Parse(MissingCheckResearchToolInputSchema, input) as MissingCheckResearchToolInput;
    const validated = validateMissingCheckHypothesis(request.hypothesis);
    if (request.action === "validate" || !validated.valid || validated.hypothesis === undefined) return validated;
    return this.execute(request, validated.hypothesis, options);
  }

  private async execute(request: MissingCheckResearchToolInput, hypothesis: MissingCheckHypothesis, options: CodeqlOperationOptions): Promise<MissingCheckExecutionResult> {
    const issues = executionIssues(request);
    if (issues.length > 0 || request.target === undefined || request.mode === undefined || request.budget === undefined || request.idempotency_key === undefined) return { valid: false, issues, allowed_next_actions: ["revise", "stop"] } as never;
    const runId = missingCheckRunIdForIdempotencyKey(request.idempotency_key);
    const existing = await this.artifacts.findManifest(runId);
    if (existing !== undefined && terminal(existing.status)) {
      await this.assertIdempotency(runId, request, hypothesis);
      const result = await this.readCommitted(runId);
      if (result !== undefined) return result;
    }
    const run = await this.status.create(runId);
    return this.artifacts.withRunOperation(run.runId, options, async () => {
      await this.assertIdempotency(run.runId, request, hypothesis);
      const committed = await this.readCommitted(run.runId);
      if (committed !== undefined) return committed;
      const current = await this.status.get(run.runId);
      if (terminal(current.status)) return this.failed(run.runId, "MCHECK_TERMINAL_WITHOUT_ARTIFACT", "failed", hypothesis, request);
      if (current.status === "created") await this.status.start(run.runId, "missing_check_execute");
      const operation = this.cancellations.begin(run.runId, options.signal);
      try { return await this.runAnalyzer(run.runId, hypothesis, request, { ...options, signal: operation.signal }, run.artifactRoot); }
      finally { operation.release(); }
    });
  }

  private async runAnalyzer(runId: RunId, hypothesis: MissingCheckHypothesis, request: MissingCheckResearchToolInput, options: CodeqlOperationOptions, artifactRoot: string): Promise<MissingCheckExecutionResult> {
    const target = request.target!;
    try {
      const vulnerableFingerprint = await validateAndFingerprint(this.codeql, target.vulnerable, options);
      const fixedFingerprint = target.fixed === undefined ? undefined : await validateAndFingerprint(this.codeql, target.fixed, options);
      const targetFingerprints = { vulnerable: vulnerableFingerprint, ...(fixedFingerprint === undefined ? {} : { fixed: fixedFingerprint }) };
      const observation = await this.execution.execute({ hypothesis, target, analyzer_id: "codeql", mode: request.mode!, runId, artifactRoot }, { ...options, timeoutMs: Math.min(options.timeoutMs, request.budget!.timeout_ms) });
      if (options.signal?.aborted) throw new DomainError("PROCESS_CANCELLED", "process", `MissingCheck execution for ${runId} was cancelled`, false, { runId });
      if (!observation.analyzer.available) return this.commitFailure(runId, hypothesis, request, "MCHECK_ANALYZER_UNAVAILABLE", "blocked", observation, targetFingerprints);
      const projection = decideMissingCheck(observation, request.mode!, hypothesis.scope);
      const result = compactMissingCheckResult({ runId, operationStatus: "completed", decision: projection.decision, verificationLevel: projection.verificationLevel, observations: projection.observations, revisionHints: projection.revisionHints, allowedNextActions: projection.allowedNextActions, artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
      await this.writeCommitted(runId, result, hypothesis, request, observation, targetFingerprints);
      await this.status.complete(runId, projection.verificationLevel, "missing_check_execute");
      return result;
    } catch (error: unknown) {
      const domain = asDomainError(error);
      const code = domain.code === "PROCESS_CANCELLED" || options.signal?.aborted ? "MCHECK_EXECUTION_CANCELLED"
        : domain.code === "PROCESS_TIMEOUT" ? "MCHECK_ANALYZER_TIMEOUT"
          : domain.code === "CODEQL_CLI_NOT_FOUND" ? "MCHECK_ANALYZER_UNAVAILABLE"
            : domain.code === "DATABASE_FINGERPRINT_MISMATCH" ? "MCHECK_TARGET_FINGERPRINT_MISMATCH"
              : domain.code === "DATABASE_FINGERPRINT_UNAVAILABLE" ? "MCHECK_TARGET_FINGERPRINT_UNAVAILABLE"
            : "MCHECK_EXECUTION_FAILED";
      const status: OperationStatus = code === "MCHECK_EXECUTION_CANCELLED" ? "cancelled" : code === "MCHECK_ANALYZER_UNAVAILABLE" || code.startsWith("MCHECK_TARGET_FINGERPRINT_") ? "blocked" : "failed";
      return this.failed(runId, code, status, hypothesis, request, error);
    }
  }

  private async commitFailure(runId: RunId, hypothesis: MissingCheckHypothesis, request: MissingCheckResearchToolInput, code: string, operationStatus: "blocked" | "failed", observation?: MissingCheckAnalyzerObservation, targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string }): Promise<MissingCheckExecutionResult> {
    const result = compactMissingCheckResult({ runId, operationStatus, decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code, evidence_ref: MISSING_CHECK_RESULT_ARTIFACT }], revisionHints: [], allowedNextActions: ["revise", "stop"], artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
    await this.writeCommitted(runId, result, hypothesis, request, observation, targetFingerprints);
    await this.status.fail(runId, new DomainError("INVALID_STATE_TRANSITION", "state", code, false).toRecord());
    return result;
  }

  private async failed(runId: RunId, code: string, operationStatus: "blocked" | "failed" | "cancelled", hypothesis: MissingCheckHypothesis, request: MissingCheckResearchToolInput, error?: unknown): Promise<MissingCheckExecutionResult> {
    const result = compactMissingCheckResult({ runId, operationStatus, decision: { capability: "missing_check", outcome: "unknown" }, verificationLevel: "generated", observations: [{ code, evidence_ref: MISSING_CHECK_RESULT_ARTIFACT }], revisionHints: [], allowedNextActions: operationStatus === "cancelled" ? ["replay", "stop"] : ["revise", "stop"], artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
    await this.writeCommitted(runId, result, hypothesis, request);
    const domain = error === undefined ? new DomainError("INVALID_STATE_TRANSITION", "state", code, false) : asDomainError(error);
    if (operationStatus === "cancelled") await this.status.cancel(runId, domain.toRecord()); else await this.status.fail(runId, domain.toRecord());
    return result;
  }

  private async writeCommitted(runId: RunId, result: MissingCheckExecutionResult, hypothesis: MissingCheckHypothesis, request: MissingCheckResearchToolInput, observation?: MissingCheckAnalyzerObservation, targetFingerprints?: { readonly vulnerable: string; readonly fixed?: string }): Promise<void> {
    const artifact = JSON.stringify(parseSchema(MissingCheckRunArtifactSchema, {
      schema_version: CONTRACTS_VERSION, capability: "missing_check", hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION, hypothesis,
      target: request.target, mode: request.mode, ...(request.budget === undefined ? {} : { budget: request.budget }), ...(request.idempotency_key === undefined ? {} : { idempotency_key: request.idempotency_key }),
      analyzer: observation?.analyzer ?? { analyzer_id: "codeql", available: false, evidence_kind: "real_analyzer" },
      ...(targetFingerprints === undefined ? {} : { target_fingerprints: targetFingerprints }),
      ...(observation === undefined ? {} : { observation }), ...(observation === undefined ? {} : { decision_policy_version: MISSING_CHECK_DECISION_POLICY_VERSION }),
      operation_status: result.operation_status, decision: result.decision, verification_level: result.verification_level, observations: result.observations, revision_hints: result.revision_hints, allowed_next_actions: result.allowed_next_actions,
    }, "MissingCheck run artifact"));
    const route = serializeResearchOperationRoute({ capability: "missing_check", hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION, result_artifact_ref: MISSING_CHECK_RESULT_ARTIFACT });
    const bundle = await this.artifacts.stageArtifactBundle(runId, `missing-check-commit-${stableDigest(runId)}`, COMMIT_TARGET, [{ relativePath: "operation.json", content: route }, { relativePath: "missing-check/result.json", content: artifact }]);
    await this.artifacts.promoteArtifactBundle(runId, bundle);
  }

  private async readCommitted(runId: RunId): Promise<MissingCheckExecutionResult | undefined> {
    const raw = await this.artifacts.readArtifact(runId, MISSING_CHECK_RESULT_ARTIFACT);
    if (raw === undefined) return undefined;
    const artifact = readMissingCheckRunArtifact(raw);
    if (artifact === undefined) return undefined;
    return compactMissingCheckResult({ runId, operationStatus: artifact.operation_status, decision: artifact.decision, verificationLevel: artifact.verification_level, observations: artifact.observations, revisionHints: artifact.revision_hints, allowedNextActions: artifact.allowed_next_actions, artifactRef: MISSING_CHECK_RESULT_ARTIFACT });
  }

  private async assertIdempotency(runId: RunId, request: MissingCheckResearchToolInput, hypothesis: MissingCheckHypothesis): Promise<void> {
    const raw = await this.artifacts.readArtifact(runId, MISSING_CHECK_RESULT_ARTIFACT);
    const artifact = raw === undefined ? undefined : readMissingCheckRunArtifact(raw);
    if (artifact === undefined) return;
    if (canonical({ hypothesis, target: request.target, mode: request.mode, budget: request.budget, idempotency_key: request.idempotency_key }) !== canonical({ hypothesis: artifact.hypothesis, target: artifact.target, mode: artifact.mode, budget: artifact.budget, idempotency_key: artifact.idempotency_key })) {
      throw new DomainError("IDEMPOTENCY_KEY_CONFLICT", "state", `Idempotency key is already bound to a different MissingCheck request: ${runId}`, false, { runId });
    }
  }
}

function envelopeIssues(input: unknown): MissingCheckValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [{ code: "MCHECK_RESEARCH_ENVELOPE_INVALID", path: "/", expected_kind: "object" }];
  const record = input as Record<string, unknown>; const issues: MissingCheckValidationIssue[] = [];
  if (record.action !== "validate" && record.action !== "execute") issues.push({ code: "MCHECK_RESEARCH_ACTION_INVALID", path: "/action", allowed_values: ["validate", "execute"] });
  if (record.capability !== "missing_check") issues.push({ code: "MCHECK_RESEARCH_CAPABILITY_INVALID", path: "/capability", allowed_values: ["missing_check"] });
  if (record.hypothesis_version !== MISSING_CHECK_HYPOTHESIS_VERSION) issues.push({ code: "MCHECK_HYPOTHESIS_VERSION_INVALID", path: "/hypothesis_version", allowed_values: [MISSING_CHECK_HYPOTHESIS_VERSION] });
  return issues.length === 0 ? [{ code: "MCHECK_RESEARCH_ENVELOPE_INVALID", path: "/" }] : issues;
}
function executionIssues(request: MissingCheckResearchToolInput): MissingCheckValidationIssue[] {
  const issues: MissingCheckValidationIssue[] = [];
  if (request.mode === undefined) issues.push({ code: "MCHECK_MODE_REQUIRED", path: "/mode", allowed_values: ["probe", "reproduce", "differential"] });
  if (request.target === undefined) issues.push({ code: "MCHECK_TARGET_REQUIRED", path: "/target", expected_kind: "object" });
  if (request.mode === "differential" && request.target?.fixed === undefined) issues.push({ code: "MCHECK_FIXED_TARGET_REQUIRED", path: "/target/fixed" });
  if (request.analyzer_id !== "codeql") issues.push({ code: "MCHECK_ANALYZER_REQUIRED", path: "/analyzer_id", allowed_values: ["codeql"] });
  if (request.budget === undefined) issues.push({ code: "MCHECK_BUDGET_REQUIRED", path: "/budget", expected_kind: "object" });
  if (request.idempotency_key === undefined) issues.push({ code: "MCHECK_IDEMPOTENCY_KEY_REQUIRED", path: "/idempotency_key" });
  return issues;
}
function terminal(status: string): boolean { return status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted"; }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value !== null && typeof value === "object") { const record = value as Record<string, unknown>; return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`; } return JSON.stringify(value); }

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
