import {
  CONTRACTS_VERSION,
  asDomainError,
  type AnalyzerServiceResearchOperationRoute,
  type RunId,
  type VariantCandidate,
  type VariantSearchReplayComparison,
} from "@autovul/contracts";

import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import type { VariantSearchPort, VariantSeedPatternFacts } from "./port.js";
import { extractSeedPatternFacts } from "./seed-facts.js";
import { readVariantSearchResultArtifact, VARIANT_SEARCH_RESULT_ARTIFACT } from "./service.js";

export class VariantSearchReplayService {
  constructor(
    _status: RunStatusService,
    private readonly searchPort: VariantSearchPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async replay(
    runId: RunId,
    route: AnalyzerServiceResearchOperationRoute,
    options: CodeqlOperationOptions,
  ): Promise<VariantSearchReplayComparison> {
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
        const operation = this.cancellations.begin(runId, options.signal);
        try {
          return await this.replayLocked(runId, route, { ...options, signal: operation.signal });
        } catch (error: unknown) {
          return replayFailure(runId, error, operation.signal);
        } finally {
          operation.release();
        }
      });
    } catch (error: unknown) {
      return replayFailure(runId, error, options.signal);
    }
  }

  private async replayLocked(
    runId: RunId,
    _route: AnalyzerServiceResearchOperationRoute,
    options: CodeqlOperationOptions,
  ): Promise<VariantSearchReplayComparison> {
    const rawArtifact = await this.artifacts.readArtifact(runId, VARIANT_SEARCH_RESULT_ARTIFACT);
    if (rawArtifact === undefined) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        status: "environment_blocked",
        divergence_reasons: ["Original variant search artifact could not be read"],
      };
    }

    const original = readVariantSearchResultArtifact(rawArtifact);
    if (original === undefined) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        status: "environment_blocked",
        divergence_reasons: ["Original variant search artifact failed schema validation"],
      };
    }

    let seedFacts: VariantSeedPatternFacts;
    try {
      seedFacts = await extractSeedPatternFacts(this.artifacts, original.input.seed_run_id);
    } catch (error: unknown) {
      const domain = asDomainError(error);
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        status: "environment_blocked",
        divergence_reasons: [domain.message],
      };
    }

    const replayed = await this.searchPort.search(
      {
        input: original.input,
        seedFacts,
        resolvedBudget: {
          max_candidates: original.input.budget?.max_candidates ?? 50,
          max_files_per_target: original.input.budget?.max_files_per_target ?? 500,
          timeout_ms: original.input.budget?.timeout_ms ?? 60_000,
        },
      },
      options,
    );

    const reasons: string[] = [];
    if (replayed.candidates.length !== original.observation.candidates.length) {
      reasons.push(`Candidate count mismatch: expected ${original.observation.candidates.length}, observed ${replayed.candidates.length}`);
    } else {
      for (let i = 0; i < replayed.candidates.length; i++) {
        const rep = replayed.candidates[i];
        const orig = original.observation.candidates[i];
        if (rep !== undefined && orig !== undefined && rep.candidate_id !== orig.candidate_id) {
          reasons.push(`Candidate at index ${i} mismatched: expected ${orig.candidate_id}, observed ${rep.candidate_id}`);
          break;
        }
      }
    }

    const replayedCandidates: VariantCandidate[] = replayed.candidates.map((c) => ({
      candidate_id: c.candidate_id,
      target: { ...c.target },
      location: { ...c.location },
      match_kind: c.match_kind,
      matched_symbols: [...c.matched_symbols],
      evidence_ref: c.evidence_ref,
    }));

    return {
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      service: "variant_search",
      service_version: "autovul.variant-search/1",
      status: reasons.length === 0 ? "identical" : "diverged",
      replayed_observation: {
        schema_version: "autovul.variant-search/1",
        seed_run_id: original.input.seed_run_id,
        seed_capability: seedFacts.capability,
        strategy: original.input.strategy,
        candidates: replayedCandidates,
        budget_exhausted: replayed.budgetExhausted,
        targets_inspected: replayed.targetsInspected,
        files_inspected: replayed.filesInspected,
        evidence_refs: [...replayed.evidenceRefs],
        analyzer: replayed.analyzer,
      },
      divergence_reasons: reasons,
    };
  }
}

function replayFailure(runId: RunId, error: unknown, signal?: AbortSignal): VariantSearchReplayComparison {
  const domain = asDomainError(error);
  return {
    schema_version: CONTRACTS_VERSION,
    run_id: runId,
    service: "variant_search",
    service_version: "autovul.variant-search/1",
    status: signal?.aborted || domain.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
    divergence_reasons: [domain.message],
  };
}
