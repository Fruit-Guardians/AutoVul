import {
  CONTRACTS_VERSION,
  asDomainError,
  stableDigest,
  VARIANT_SEARCH_SERVICE,
  VARIANT_SEARCH_SERVICE_VERSION,
  VARIANT_SEARCH_STRATEGY_VERSION,
  type AnalyzerServiceResearchOperationRoute,
  type RunId,
  type VariantCandidate,
  type VariantSearchObservation,
  type VariantSearchReplayComparison,
} from "@autovul/contracts";

import { canonicalJson } from "../canonical-json.js";
import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { RunCancellationService } from "../run-cancellation.js";
import { RunStatusService } from "../status-service.js";
import type { VariantSearchPort, VariantSeedPatternFacts } from "./port.js";
import { extractSeedPatternFacts } from "./seed-facts.js";
import { readVariantSearchResultArtifact, VARIANT_SEARCH_RESULT_ARTIFACT } from "./service.js";

const REPLAY_ROOT = "research/replay";

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
    route: AnalyzerServiceResearchOperationRoute,
    options: CodeqlOperationOptions,
  ): Promise<VariantSearchReplayComparison> {
    if (
      route.route_kind !== "analyzer_service" ||
      route.service !== VARIANT_SEARCH_SERVICE ||
      route.service_version !== VARIANT_SEARCH_SERVICE_VERSION
    ) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "environment_blocked",
        divergence_reasons: ["Invalid or unsupported variant search operation route"],
      };
    }

    const rawArtifact = await this.artifacts.readArtifact(runId, VARIANT_SEARCH_RESULT_ARTIFACT);
    if (rawArtifact === undefined) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "environment_blocked",
        divergence_reasons: ["Original variant search artifact could not be read"],
      };
    }

    const originalResultHash = stableDigest(rawArtifact);
    const original = readVariantSearchResultArtifact(rawArtifact);
    if (original === undefined) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "environment_blocked",
        divergence_reasons: ["Original variant search artifact failed schema validation"],
      };
    }

    // Pre-check candidate evidence files exist and are not tampered
    for (const candidate of original.observation.candidates) {
      const rawCandidate = await this.artifacts.readArtifact(runId, candidate.evidence_ref);
      if (rawCandidate === undefined) {
        return {
          schema_version: CONTRACTS_VERSION,
          run_id: runId,
          service: VARIANT_SEARCH_SERVICE,
          service_version: VARIANT_SEARCH_SERVICE_VERSION,
          status: "environment_blocked",
          divergence_reasons: [`Candidate evidence artifact is missing: ${candidate.evidence_ref}`],
        };
      }
      try {
        const parsed = JSON.parse(rawCandidate) as { candidate?: VariantCandidate };
        if (parsed.candidate?.candidate_id !== candidate.candidate_id) {
          return {
            schema_version: CONTRACTS_VERSION,
            run_id: runId,
            service: VARIANT_SEARCH_SERVICE,
            service_version: VARIANT_SEARCH_SERVICE_VERSION,
            status: "evidence_mutated",
            divergence_reasons: [`Candidate evidence artifact at ${candidate.evidence_ref} was mutated`],
          };
        }
      } catch {
        return {
          schema_version: CONTRACTS_VERSION,
          run_id: runId,
          service: VARIANT_SEARCH_SERVICE,
          service_version: VARIANT_SEARCH_SERVICE_VERSION,
          status: "evidence_mutated",
          divergence_reasons: [`Candidate evidence artifact at ${candidate.evidence_ref} is corrupt`],
        };
      }
    }

    let seedFacts: VariantSeedPatternFacts;
    try {
      seedFacts = await extractSeedPatternFacts(this.artifacts, original.input.seed_run_id);
    } catch (error: unknown) {
      const domain = asDomainError(error);
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "environment_blocked",
        divergence_reasons: [domain.message],
      };
    }

    if (seedFacts.seedDigest !== original.observation.seed_digest) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "diverged",
        divergence_reasons: [
          `Seed artifact digest mismatch: expected ${original.observation.seed_digest}, observed ${seedFacts.seedDigest}`,
        ],
      };
    }

    if (original.observation.strategy_version !== VARIANT_SEARCH_STRATEGY_VERSION) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "diverged",
        divergence_reasons: [
          `Strategy version mismatch: recorded ${original.observation.strategy_version}, current ${VARIANT_SEARCH_STRATEGY_VERSION}`,
        ],
      };
    }

    let replayedObs: VariantSearchObservation;
    try {
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

      const replayedCandidates: VariantCandidate[] = replayed.candidates.map((c) => ({
        candidate_id: c.candidate_id,
        target: { ...c.target },
        location: { ...c.location },
        match_kind: c.match_kind,
        matched_symbols: [...c.matched_symbols],
        evidence_ref: c.evidence_ref,
        ...(c.evidence_digest !== undefined ? { evidence_digest: c.evidence_digest } : {}),
      }));

      replayedObs = {
        schema_version: VARIANT_SEARCH_SERVICE_VERSION,
        seed_run_id: original.input.seed_run_id,
        seed_capability: "missing_check",
        seed_digest: seedFacts.seedDigest,
        seed_verification_level: seedFacts.seedVerificationLevel,
        strategy: original.input.strategy,
        strategy_version: VARIANT_SEARCH_STRATEGY_VERSION,
        completeness: replayed.completeness,
        gaps: [...replayed.gaps],
        candidates: replayedCandidates,
        budget_exhausted: replayed.budgetExhausted,
        targets_inspected: replayed.targetsInspected,
        files_inspected: replayed.filesInspected,
        evidence_refs: [...replayed.evidenceRefs],
        analyzer: replayed.analyzer,
      };
    } catch (error: unknown) {
      return replayFailure(runId, error, options.signal);
    }

    const reasons: string[] = [];
    if (replayedObs.completeness !== original.observation.completeness) {
      reasons.push(
        `Completeness mismatch: expected ${original.observation.completeness}, observed ${replayedObs.completeness}`,
      );
    }

    if (canonicalJson(replayedObs.gaps) !== canonicalJson(original.observation.gaps)) {
      reasons.push(
        `Gaps mismatch: expected ${JSON.stringify(original.observation.gaps)}, observed ${JSON.stringify(replayedObs.gaps)}`,
      );
    }

    if (replayedObs.candidates.length !== original.observation.candidates.length) {
      reasons.push(
        `Candidate count mismatch: expected ${original.observation.candidates.length}, observed ${replayedObs.candidates.length}`,
      );
    } else {
      for (let i = 0; i < replayedObs.candidates.length; i++) {
        const rep = replayedObs.candidates[i];
        const orig = original.observation.candidates[i];
        if (rep !== undefined && orig !== undefined) {
          if (rep.candidate_id !== orig.candidate_id) {
            reasons.push(
              `Candidate at index ${i} mismatched ID: expected ${orig.candidate_id}, observed ${rep.candidate_id}`,
            );
            break;
          }
          if (canonicalJson(rep) !== canonicalJson(orig)) {
            reasons.push(
              `Candidate at index ${i} mismatched facts: expected ${JSON.stringify(orig)}, observed ${JSON.stringify(rep)}`,
            );
            break;
          }
        }
      }
    }

    // Verify original artifact remains untouched
    const afterRaw = await this.artifacts.readArtifact(runId, VARIANT_SEARCH_RESULT_ARTIFACT);
    if (afterRaw === undefined || stableDigest(afterRaw) !== originalResultHash) {
      return {
        schema_version: CONTRACTS_VERSION,
        run_id: runId,
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        status: "evidence_mutated",
        divergence_reasons: ["Original result artifact was modified during replay"],
      };
    }

    const comparison: VariantSearchReplayComparison = {
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      service: VARIANT_SEARCH_SERVICE,
      service_version: VARIANT_SEARCH_SERVICE_VERSION,
      status: reasons.length === 0 ? "identical" : "diverged",
      replayed_observation: replayedObs,
      divergence_reasons: reasons,
    };

    await this.writeReplayArtifact(runId, comparison);
    return comparison;
  }

  private async writeReplayArtifact(runId: RunId, result: VariantSearchReplayComparison): Promise<void> {
    const prior = await this.artifacts.listArtifactPaths(runId, REPLAY_ROOT);
    const ordinal = prior.length;
    const target = `${REPLAY_ROOT}/${ordinal}`;
    const operationId = `variant-search-replay-${stableDigest(`${runId}:${ordinal}`)}`;
    const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, target, [
      { relativePath: "comparison.json", content: JSON.stringify(result, null, 2) },
    ]);
    await this.artifacts.promoteArtifactBundle(runId, bundle);
  }
}

function replayFailure(runId: RunId, error: unknown, signal?: AbortSignal): VariantSearchReplayComparison {
  const domain = asDomainError(error);
  return {
    schema_version: CONTRACTS_VERSION,
    run_id: runId,
    service: VARIANT_SEARCH_SERVICE,
    service_version: VARIANT_SEARCH_SERVICE_VERSION,
    status: signal?.aborted || domain.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
    divergence_reasons: [domain.message],
  };
}
