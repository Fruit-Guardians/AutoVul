import {
  asDomainError,
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryDraftReportSchema,
  QueryVerificationSchema,
  RunIdSchema,
  type CaseRunSummary,
  type QueryCandidate,
  type QueryWorkflowState,
  type QueryDraftReport,
  type QueryVerification,
} from "@pure-auto-codeql/contracts";

import type { CodeqlOperationOptions, QueryExecutionResult } from "../ports.js";
import { qlpackForLanguage } from "../language-packs.js";
import { assertCandidateLanguage, assertCandidateProbeForUserCase, candidateDigest } from "./candidate-policy.js";
import { prepareCandidate } from "./candidate-preparation.js";
import { compactCaseSummary } from "./case-ledger.js";
import { assertCandidateSemanticKinds, assertCandidateSemanticLocations } from "./endpoint-policy.js";
import type { CodeqlWorkflowContext } from "./context.js";
import { boundedOperationOptions, isTerminalWorkflowStatus } from "./status.js";
import { evaluateVerification } from "./verification-policy.js";

export async function verifyQuery(
  context: CodeqlWorkflowContext,
  inputRunId: unknown,
  inputCandidate: unknown,
  options: CodeqlOperationOptions,
): Promise<QueryVerification> {
  const runId = parseSchema(RunIdSchema, inputRunId, "run id");
  try {
    return await context.repository.withRunOperation(runId, options, async () => {
      const state = await context.repository.load(runId);
      const candidate = await prepareCandidate(context, runId, inputCandidate, state);
      assertCandidateLanguage(candidate, state.spec);
      if (candidate.spec_id !== state.spec.spec_id) {
        throw new DomainError("INVALID_INPUT", "input", "Query candidate does not belong to this vulnerability spec", false, {
          runId,
          candidateSpecId: candidate.spec_id,
          specId: state.spec.spec_id,
        });
      }
      assertCandidateSemanticKinds(candidate, state.spec);
      assertCandidateSemanticLocations(candidate, state.spec);
      assertCandidateProbeForUserCase(candidate, state.spec);
      if (candidate.round > state.spec.max_rounds) {
        throw new DomainError("INVALID_INPUT", "input", "Query candidate exceeds the workflow round budget", false, {
          runId,
          round: candidate.round,
          maxRounds: state.spec.max_rounds,
        });
      }

      const existingCandidate = state.candidates.find((item) => item.candidate_id === candidate.candidate_id);
      const existingIndex = existingCandidate === undefined ? -1 : state.candidates.indexOf(existingCandidate);
      const existing = state.verifications.find((item) => item.candidate_id === candidate.candidate_id);
      await assertDraftIsUsable(context, runId, candidate);
      if (existingCandidate !== undefined && candidateDigest(existingCandidate) !== candidate.candidate_digest) {
        throw new DomainError("QUERY_INVALID_CANDIDATE", "input", "Candidate id was already used with different content", false, { runId, candidateId: candidate.candidate_id });
      }
      if (existing !== undefined) return existing;
      if (existingIndex < 0 && state.candidates.length >= state.spec.max_rounds) {
        throw new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The query candidate round budget has been exhausted", false, { runId, maxRounds: state.spec.max_rounds });
      }

      const run = await context.status.get(runId);
      if (isTerminalWorkflowStatus(run.status)) {
        throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot verify a candidate in ${run.status} run`, false, { runId, status: run.status });
      }
      if (run.status === "checkpointed" || run.status === "created") await context.status.start(runId, "query_verify");
      await writeCandidateArtifacts(context, runId, candidate, state.spec.language);

      let execution: QueryExecutionResult;
      try {
        execution = await context.queries.execute({
          runId,
          candidate,
          spec: state.spec,
          artifactRoot: context.repository.artifactRoot(runId),
        }, boundedOperationOptions(options, state.spec.timeout_ms));
      } catch (error: unknown) {
        const domainError = asDomainError(error);
        const withId = addRunId(domainError, runId);
        if (withId.code === "PROCESS_CANCELLED") await context.status.cancel(runId, withId.toRecord());
        else await context.status.fail(runId, withId.toRecord());
        throw withId;
      }

      const baseVerification = evaluateVerification(runId, candidate, state.spec, execution);
      const nextState = {
        ...state,
        candidates: existingCandidate === undefined
          ? [...state.candidates, candidate]
          : state.candidates.map((item) => item.candidate_id === candidate.candidate_id ? candidate : item),
        verifications: [...state.verifications, baseVerification],
      };
      if (baseVerification.status === "passed") await context.status.checkpoint(runId, "query_verify", baseVerification.verification_level);
      let caseSummary = await updateCaseSummary(context, nextState, runId);
      const exhausted = baseVerification.status === "failed" && nextState.candidates.length >= state.spec.max_rounds;
      if (exhausted) {
        const exhaustionError = new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The case candidate budget has been exhausted", false, {
          caseFingerprint: state.case_fingerprint,
          runId,
          maxCandidates: state.spec.max_rounds,
        });
        await context.status.exhaust(runId, exhaustionError.toRecord());
        caseSummary = await updateCaseSummary(context, nextState, runId, "budget_exhausted");
      }
      const terminalReason = baseVerification.status === "passed"
        ? "candidate_passed"
        : baseVerification.status === "cancelled"
          ? "cancelled"
          : exhausted
            ? "budget_exhausted"
            : "candidate_failed";
      const verification = parseSchema(QueryVerificationSchema, {
        ...baseVerification,
        case_summary: compactCaseSummary(caseSummary),
        terminal_reason: terminalReason,
      }, "query verification");
      const finalState = {
        ...nextState,
        verifications: nextState.verifications.map((item) => item.candidate_id === candidate.candidate_id ? verification : item),
      };
      await context.repository.writeArtifact(runId, `candidates/${candidate.candidate_id}/verification.json`, `${JSON.stringify(verification, null, 2)}\n`);
      await context.repository.save(runId, finalState);
      return verification;
    });
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    if (domainError.code === "PROCESS_CANCELLED" && domainError.details.waitingForWorkflowLease !== true) {
      const withId = addRunId(domainError, runId);
      await context.status.cancel(runId, withId.toRecord()).catch(() => undefined);
      throw withId;
    }
    if (domainError.code === "PROCESS_CANCELLED") throw addRunId(domainError, runId);
    throw domainError;
  }
}

async function assertDraftIsUsable(context: CodeqlWorkflowContext, runId: string, candidate: QueryCandidate): Promise<void> {
  const draftArtifact = await context.repository.readArtifact(runId, `drafts/${candidate.candidate_id}/report.json`);
  if (draftArtifact === undefined) return;
  let draft: QueryDraftReport;
  try {
    draft = parseSchema(QueryDraftReportSchema, JSON.parse(draftArtifact) as unknown, "query draft report");
  } catch (error: unknown) {
    throw new DomainError("ARTIFACT_CORRUPT", "artifact", "The LSP draft report is not valid", false, {
      runId,
      candidateId: candidate.candidate_id,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  if (draft.status === "errors" || draft.status === "cancelled") {
    throw new DomainError("QUERY_DRAFT_INVALID", "input", "The candidate has unresolved LSP draft diagnostics; revise it before CLI verification", true, {
      runId,
      candidateId: candidate.candidate_id,
      draftStatus: draft.status,
      diagnostics: draft.diagnostics,
    });
  }
}

async function writeCandidateArtifacts(context: CodeqlWorkflowContext, runId: string, candidate: QueryCandidate, language: string): Promise<void> {
  await context.repository.writeArtifact(runId, `candidates/${candidate.candidate_id}/query.ql`, candidate.ql_text);
  await context.repository.writeArtifact(runId, `candidates/${candidate.candidate_id}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(language));
  await context.repository.writeArtifact(runId, `candidates/${candidate.candidate_id}/candidate.json`, `${JSON.stringify(candidate, null, 2)}\n`);
}

async function updateCaseSummary(context: CodeqlWorkflowContext, state: QueryWorkflowState, runId: string, statusOverride?: CaseRunSummary["status"]): Promise<CaseRunSummary> {
  const run = await context.status.get(runId);
  return context.cases.update(state, run, statusOverride);
}

function addRunId(error: DomainError, runId: string): DomainError {
  if (error.details.runId === runId) return error;
  return new DomainError(error.code, error.category, error.message, error.retryable, { ...error.details, runId });
}
