import {
  asDomainError,
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryWorkflowStartInputSchema,
  type QueryWorkflowStatus,
  type RunId,
  type VulnerabilitySpec,
} from "@autovul/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import { databaseRefWithManifest, assertDatabaseLanguage, assertStrictSemanticLocations, assertSupportedSemanticKinds } from "./endpoint-policy.js";
import { caseFingerprintFor, emptyCaseSummary } from "./case-ledger.js";
import { isTerminalRunStatus } from "../state.js";
import type { CodeqlWorkflowContext } from "./context.js";

export async function startWorkflow(
  context: CodeqlWorkflowContext,
  input: unknown,
  options: CodeqlOperationOptions,
  readStatus: (runId: RunId) => Promise<QueryWorkflowStatus>,
): Promise<QueryWorkflowStatus> {
  const spec = parseSchema(QueryWorkflowStartInputSchema, input, "vulnerability spec");
  validateAdmissionInput(spec);
  context.codeql.setTrustedRoots?.([
    ...(spec.project_root === undefined ? [] : [spec.project_root]),
    spec.vulnerable_database.path,
    ...(spec.fixed_database === undefined ? [] : [spec.fixed_database.path]),
  ]);
  const databaseOptions = boundedOptions(options, spec.timeout_ms);
  let createdRunId: RunId | undefined;
  let persistedSpec: VulnerabilitySpec;
  try {
    persistedSpec = await inspectAndPersistSpec(context, spec, databaseOptions);
  } catch (error: unknown) {
    const run = await context.repository.createRun();
    createdRunId = run.runId;
    const domainError = asDomainError(error);
    const withId = withRunId(domainError, run.runId);
    const failureSpec = { ...spec, draft_revision_budget: spec.draft_revision_budget ?? 6 };
    const failureFingerprint = caseFingerprintFor(failureSpec);
    await context.repository.save(run.runId, {
      schema_version: CONTRACTS_VERSION,
      case_fingerprint: failureFingerprint,
      spec: failureSpec,
      draft_revisions: 0,
      candidates: [],
      verifications: [],
    });
    if (withId.code === "PROCESS_CANCELLED") await context.repository.cancelRun(run.runId, withId.toRecord());
    else await context.repository.failRun(run.runId, withId.toRecord());
    const summary = emptyCaseSummary(failureFingerprint, run.runId, failureSpec.max_rounds, context.clock.now());
    const { active_run_id: _activeRunId, ...withoutActiveRun } = summary;
    await context.repository.saveCaseSummary({
      ...withoutActiveRun,
      status: withId.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
      final_run_id: run.runId,
      final_phase: "workflow_start",
      finalized: false,
    });
    throw withId;
  }

  const caseFingerprint = caseFingerprintFor(persistedSpec);
  try {
    return await context.repository.withCaseLock(caseFingerprint, async () => {
      let existingSummary = await context.repository.findCaseSummary(caseFingerprint);
      if (existingSummary?.status === "active" && existingSummary.active_run_id !== undefined) {
        const activeRun = await context.repository.tryGetRun(existingSummary.active_run_id);
        if (activeRun === undefined || isTerminalRunStatus(activeRun.status)) {
          const { active_run_id: _activeRunId, ...withoutActiveRun } = existingSummary;
          const recoveredStatus = activeRun?.status === "cancelled"
            ? "cancelled"
            : activeRun?.status === "completed"
              ? "completed"
              : activeRun?.status === "budget_exhausted"
                ? "budget_exhausted"
                : "failed";
          existingSummary = {
            ...withoutActiveRun,
            status: recoveredStatus,
            final_run_id: existingSummary.active_run_id,
            final_phase: activeRun?.phase ?? "workflow_start",
            finalized: recoveredStatus === "completed" ? existingSummary.finalized : false,
            updated_at: context.clock.now(),
          };
          await context.repository.saveCaseSummary(existingSummary);
        }
      }
      const existingRunId = existingSummary?.status === "active"
        ? existingSummary.active_run_id
        : existingSummary?.status === "completed" || existingSummary?.status === "budget_exhausted"
          ? existingSummary.final_run_id
          : undefined;
      if (existingRunId !== undefined) return readStatus(existingRunId);

      const run = await context.repository.createRun();
      createdRunId = run.runId;
      try {
        await context.repository.startRun(run.runId, "workflow_start");
        await context.repository.save(run.runId, {
          schema_version: CONTRACTS_VERSION,
          case_fingerprint: caseFingerprint,
          spec: persistedSpec,
          draft_revisions: 0,
          candidates: [],
          verifications: [],
        });
        const initialSummary = emptyCaseSummary(caseFingerprint, run.runId, persistedSpec.max_rounds, context.clock.now());
        await context.repository.saveCaseSummary({
          ...initialSummary,
          run_ids: [...(existingSummary?.run_ids ?? []), run.runId],
        });
        return readStatus(run.runId);
      } catch (error: unknown) {
        const domainError = asDomainError(error);
        const record = withRunId(domainError, run.runId).toRecord();
        if (domainError.code === "PROCESS_CANCELLED") await context.repository.cancelRun(run.runId, record).catch(() => undefined);
        else await context.repository.failRun(run.runId, record).catch(() => undefined);
        const terminalSummary = emptyCaseSummary(caseFingerprint, run.runId, persistedSpec.max_rounds, context.clock.now());
        const { active_run_id: _activeRunId, ...withoutActiveRun } = terminalSummary;
        await context.repository.saveCaseSummary({
          ...withoutActiveRun,
          run_ids: [...(existingSummary?.run_ids ?? []), run.runId],
          status: domainError.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
          final_run_id: run.runId,
          final_phase: "workflow_start",
          finalized: false,
          updated_at: context.clock.now(),
        });
        throw domainError;
      }
    });
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    if (createdRunId !== undefined && domainError.details.runId !== createdRunId && domainError.code !== "WORKFLOW_BUSY") {
      const withId = withRunId(domainError, createdRunId);
      if (withId.code === "PROCESS_CANCELLED") await context.repository.cancelRun(createdRunId, withId.toRecord()).catch(() => undefined);
      else await context.repository.failRun(createdRunId, withId.toRecord()).catch(() => undefined);
      throw withId;
    }
    throw createdRunId === undefined ? domainError : withRunId(domainError, createdRunId);
  }
}

function validateAdmissionInput(spec: VulnerabilitySpec): void {
  if (spec.vulnerability_description === undefined && spec.patch_description === undefined) {
    throw new DomainError("INVALID_INPUT", "input", "VulnerabilitySpec requires a vulnerability description or patch description", false, { specId: spec.spec_id });
  }
  if (spec.input_provenance === "user_provided" && spec.project_root === undefined) {
    throw new DomainError("INVALID_INPUT", "input", "User-provided vulnerability cases require project_root so Pi can inspect the supplied source", false, { specId: spec.spec_id });
  }
  assertStrictSemanticLocations(spec);
  assertSupportedSemanticKinds(spec);
}

async function inspectAndPersistSpec(context: CodeqlWorkflowContext, spec: VulnerabilitySpec, options: CodeqlOperationOptions): Promise<VulnerabilitySpec> {
  const vulnerableManifest = await context.codeql.inspectDatabase(spec.vulnerable_database.path, options);
  assertDatabaseLanguage(spec, spec.vulnerable_database.path, vulnerableManifest);
  const fixedPath = spec.fixed_database?.path;
  const fixedManifest = fixedPath === undefined ? undefined : await context.codeql.inspectDatabase(fixedPath, options);
  if (fixedManifest !== undefined && fixedPath !== undefined) assertDatabaseLanguage(spec, fixedPath, fixedManifest);
  return {
    ...spec,
    draft_revision_budget: spec.draft_revision_budget ?? 6,
    vulnerable_database: databaseRefWithManifest(spec.vulnerable_database, vulnerableManifest),
    ...(spec.fixed_database === undefined || fixedManifest === undefined ? {} : { fixed_database: databaseRefWithManifest(spec.fixed_database, fixedManifest) }),
  };
}

function boundedOptions(options: CodeqlOperationOptions, timeoutMs: number): CodeqlOperationOptions {
  return {
    timeoutMs: Math.min(options.timeoutMs, timeoutMs),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

function withRunId(error: DomainError, runId: RunId): DomainError {
  if (error.details.runId === runId) return error;
  return new DomainError(error.code, error.category, error.message, error.retryable, { ...error.details, runId });
}
