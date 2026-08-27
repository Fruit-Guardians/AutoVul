import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryWorkflowStatusSchema,
  RunIdSchema,
  type QueryWorkflowStatus,
} from "@pure-auto-codeql/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import { compactCaseSummary } from "./case-ledger.js";
import type { CodeqlWorkflowContext } from "./context.js";

export async function readWorkflowStatus(context: CodeqlWorkflowContext, input: unknown): Promise<QueryWorkflowStatus> {
  const runId = parseSchema(RunIdSchema, input, "run id");
  let run = await context.status.get(runId);
  const state = await context.repository.load(runId);
  const latest = state.verifications[state.verifications.length - 1];
  let caseSummary = await context.cases.summaryFor(state, run);
  if (caseSummary.status === "budget_exhausted" && run.status !== "budget_exhausted") {
    const exhausted = new DomainError(
      "QUERY_BUDGET_EXCEEDED",
      "policy",
      "The case candidate budget has been exhausted",
      false,
      { caseFingerprint: state.case_fingerprint, runId, maxCandidates: state.spec.max_rounds },
    );
    await context.status.exhaust(runId, exhausted.toRecord());
    run = await context.status.get(runId);
    const { active_run_id: _activeRunId, ...withoutActiveRun } = caseSummary;
    caseSummary = {
      ...withoutActiveRun,
      status: "budget_exhausted",
      final_run_id: runId,
      final_phase: "query_verify",
      finalized: false,
      updated_at: context.clock.now(),
    };
    await context.repository.withCaseLock(state.case_fingerprint, async () => {
      await context.repository.saveCaseSummary(caseSummary);
    });
  }
  return parseSchema(QueryWorkflowStatusSchema, {
    schema_version: CONTRACTS_VERSION,
    run: {
      runId: run.runId,
      status: run.status,
      ...(run.phase === undefined ? {} : { phase: run.phase }),
      verificationLevel: run.verificationLevel,
    },
    case_summary: caseSummary,
    spec: state.spec,
    candidates: state.candidates,
    verifications: state.verifications,
    ...(latest === undefined ? {} : { latest_verification: latest }),
    ...(state.pack === undefined ? {} : { pack: state.pack }),
  }, "query workflow status");
}

export function boundedOperationOptions(options: CodeqlOperationOptions, timeoutMs: number): CodeqlOperationOptions {
  return {
    timeoutMs: Math.min(options.timeoutMs, timeoutMs),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

export function isTerminalWorkflowStatus(status: string): boolean {
  return status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted";
}

export { compactCaseSummary };
