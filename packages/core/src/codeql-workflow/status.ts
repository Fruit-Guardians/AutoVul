import {
  CONTRACTS_VERSION,
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
  const run = await context.repository.getRun(runId);
  const state = await context.repository.load(runId);
  const latest = state.verifications[state.verifications.length - 1];
  const caseSummary = await context.repository.readCaseSummary(state, run);
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

export async function reconcileWorkflowStatus(context: CodeqlWorkflowContext, input: unknown): Promise<void> {
  const runId = parseSchema(RunIdSchema, input, "run id");
  await context.repository.reconcile(runId);
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
