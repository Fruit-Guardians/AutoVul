import {
  asDomainError,
  DomainError,
  parseSchema,
  QueryDraftReportSchema,
  RunIdSchema,
  type QueryDraftReport,
} from "@autovul/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import { qlpackForLanguage } from "../language-packs.js";
import { assertCandidateLanguage, assertCandidateProbeForUserCase } from "./candidate-policy.js";
import { prepareCandidate } from "./candidate-preparation.js";
import type { CodeqlWorkflowContext } from "./context.js";
import { boundedOperationOptions, isTerminalWorkflowStatus } from "./status.js";

export async function draftQuery(
  context: CodeqlWorkflowContext,
  inputRunId: unknown,
  inputCandidate: unknown,
  options: CodeqlOperationOptions,
): Promise<QueryDraftReport> {
  const runId = parseSchema(RunIdSchema, inputRunId, "run id");
  try {
    return await context.repository.withRunOperation(runId, options, async () => {
      const state = await context.repository.load(runId);
      const candidate = await prepareCandidate(context, runId, inputCandidate, state);
      assertCandidateLanguage(candidate, state.spec);
      if (candidate.spec_id !== state.spec.spec_id) {
        throw new DomainError("INVALID_INPUT", "input", "Query draft does not belong to this vulnerability spec", false, {
          runId,
          candidateSpecId: candidate.spec_id,
          specId: state.spec.spec_id,
        });
      }
      assertCandidateProbeForUserCase(candidate, state.spec);
      const run = await context.repository.getRun(runId);
      if (isTerminalWorkflowStatus(run.status)) {
        throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot draft in ${run.status} run`, false, { runId, status: run.status });
      }
      if (run.status === "created" || run.status === "checkpointed") await context.repository.startRun(runId, "query_draft");
      const draftRevisionBudget = state.spec.draft_revision_budget ?? 6;
      const revision = (state.draft_revisions ?? 0) + 1;
      if (revision > draftRevisionBudget) {
        throw new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The LSP draft revision budget has been exhausted", false, { runId, maxDraftRevisions: draftRevisionBudget });
      }
      await context.repository.save(runId, { ...state, draft_revisions: revision });
      await context.repository.writeArtifact(runId, `drafts/${candidate.candidate_id}/query.ql`, candidate.ql_text);
      await context.repository.writeArtifact(runId, `drafts/${candidate.candidate_id}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language));
      await context.repository.writeArtifact(runId, `drafts/${candidate.candidate_id}/candidate.json`, `${JSON.stringify(candidate, null, 2)}\n`);
      const report = parseSchema(QueryDraftReportSchema, await context.drafts.executeDraft({
        runId,
        candidate,
        spec: state.spec,
        artifactRoot: context.repository.artifactRoot(runId),
        revision,
        draftRevisionBudget,
      }, boundedOperationOptions(options, state.spec.timeout_ms)), "query draft report");
      await context.repository.writeArtifact(runId, `drafts/${candidate.candidate_id}/report.json`, `${JSON.stringify(report, null, 2)}\n`);
      return report;
    });
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    const withId = addRunId(domainError, runId);
    if (withId.code === "PROCESS_CANCELLED" && withId.details.waitingForWorkflowLease !== true) await context.repository.cancelRun(runId, withId.toRecord()).catch(() => undefined);
    else if (withId.category !== "input" && withId.code !== "WORKFLOW_BUSY" && withId.code !== "QUERY_BUDGET_EXCEEDED") await context.repository.failRun(runId, withId.toRecord()).catch(() => undefined);
    throw withId;
  }
}

function addRunId(error: DomainError, runId: string): DomainError {
  if (error.details.runId === runId) return error;
  return new DomainError(error.code, error.category, error.message, error.retryable, { ...error.details, runId });
}
