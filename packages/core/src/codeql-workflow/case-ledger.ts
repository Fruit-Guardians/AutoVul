import {
  CONTRACTS_VERSION,
  DomainError,
  type CaseRunSummary,
  type QueryVerification,
  type QueryWorkflowState,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort, ClockPort } from "../ports.js";
import { caseFingerprintFor } from "./state-migrations.js";

export { caseFingerprintFor };

export class CaseLedger {
  constructor(
    private readonly artifacts: ArtifactStorePort,
    private readonly clock: ClockPort,
  ) {}

  async summaryFor(state: QueryWorkflowState, run: { runId: RunId; status: string }): Promise<CaseRunSummary> {
    const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
    return caseSummaryFromState(state, run, this.clock.now(), existing, state.pack === undefined ? undefined : "completed", state.pack?.pack_id);
  }

  async update(
    state: QueryWorkflowState,
    run: { runId: RunId; status: string },
    statusOverride?: CaseRunSummary["status"],
    packId?: string,
  ): Promise<CaseRunSummary> {
    let saved: CaseRunSummary | undefined;
    await this.artifacts.withCaseLock(state.case_fingerprint, async () => {
      const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
      const summary = caseSummaryFromState(
        state,
        run,
        this.clock.now(),
        existing,
        statusOverride,
        packId,
      );
      await this.artifacts.saveCaseSummary(summary);
      saved = summary;
    });
    if (saved === undefined) {
      throw new DomainError(
        "ARTIFACT_CORRUPT",
        "artifact",
        "Case summary was not saved",
        false,
        { caseFingerprint: state.case_fingerprint, runId: run.runId },
      );
    }
    return saved;
  }
}

export function emptyCaseSummary(fingerprint: string, runId: RunId, maxCandidates: number, updatedAt: string): CaseRunSummary {
  return {
    schema_version: CONTRACTS_VERSION,
    case_fingerprint: fingerprint,
    run_ids: [runId],
    active_run_id: runId,
    total_candidates: 0,
    max_candidates: maxCandidates,
    budget_used: 0,
    budget_remaining: maxCandidates,
    status: "active",
    finalized: false,
    candidates: [],
    updated_at: updatedAt,
  };
}

export function compactCaseSummary(summary: CaseRunSummary): Pick<
  CaseRunSummary,
  "case_fingerprint" | "status" | "total_candidates" | "max_candidates" | "budget_used" | "budget_remaining" | "finalized"
> {
  const { case_fingerprint, status, total_candidates, max_candidates, budget_used, budget_remaining, finalized } = summary;
  return { case_fingerprint, status, total_candidates, max_candidates, budget_used, budget_remaining, finalized };
}

export function caseSummaryFromState(
  state: QueryWorkflowState,
  run: { runId: RunId; status: string },
  updatedAt: string,
  existing?: CaseRunSummary,
  statusOverride?: CaseRunSummary["status"],
  packId?: string,
): CaseRunSummary {
  const status = statusOverride ?? caseStatusFromRun(run.status);
  const exhausted = statusOverride === undefined && state.candidates.length >= state.spec.max_rounds && state.verifications.length >= state.spec.max_rounds && state.verifications.every((verification) => verification.status === "failed");
  const effectiveStatus = exhausted ? "budget_exhausted" : status;
  const runIds = existing?.run_ids.includes(run.runId) === true ? existing.run_ids : [...(existing?.run_ids ?? []), run.runId];
  const retainedPackId = packId ?? state.pack?.pack_id;
  return {
    schema_version: CONTRACTS_VERSION,
    case_fingerprint: state.case_fingerprint,
    run_ids: runIds,
    ...(effectiveStatus === "active" ? { active_run_id: run.runId } : {}),
    total_candidates: state.candidates.length,
    max_candidates: state.spec.max_rounds,
    budget_used: state.candidates.length,
    budget_remaining: Math.max(0, state.spec.max_rounds - state.candidates.length),
    status: effectiveStatus,
    ...(effectiveStatus === "active" ? {} : { final_run_id: run.runId }),
    finalized: statusOverride === "completed" || state.pack !== undefined,
    ...(retainedPackId === undefined ? {} : { pack_id: retainedPackId }),
    ...(effectiveStatus === "active" ? {} : { final_phase: statusOverride === "completed" ? "workflow_finalize" : "query_verify" }),
    candidates: state.candidates.map((candidate) => {
      const verification = state.verifications.find((item) => item.candidate_id === candidate.candidate_id);
      return {
        candidate_id: candidate.candidate_id,
        round: candidate.round,
        status: verification?.status ?? "failed",
        diagnostics: verification?.diagnostics.map((item) => item.code) ?? ["QUERY_NOT_VERIFIED"],
      };
    }),
    updated_at: updatedAt,
  };
}

export function isTerminalRunStatus(status: string): boolean {
  return status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted";
}

function caseStatusFromRun(status: string): CaseRunSummary["status"] {
  if (status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted") return status;
  return "active";
}

export function verificationForCandidate(state: QueryWorkflowState, candidateId: string): QueryVerification | undefined {
  return state.verifications.find((item) => item.candidate_id === candidateId);
}
