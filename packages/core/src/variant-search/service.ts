import { Value } from "typebox/value";

import {
  CONTRACTS_VERSION,
  DomainError,
  asDomainError,
  stableDigest,
  VARIANT_SEARCH_LIMITS,
  VARIANT_SEARCH_SERVICE,
  VARIANT_SEARCH_SERVICE_VERSION,
  VARIANT_SEARCH_STRATEGY_VERSION,
  VariantSearchResultArtifactSchema,
  VariantSearchServiceRequestSchema,
  type RunId,
  type VariantCandidate,
  type VariantSearchBudget,
  type VariantSearchExecutionResult,
  type VariantSearchInput,
  type VariantSearchObservation,
  type VariantSearchResultArtifact,
  type VariantSearchServiceRequest,
} from "@autovul/contracts";

import { canonicalJson } from "../canonical-json.js";
import type { ArtifactStorePort, CodeqlOperationOptions } from "../ports.js";
import { serializeResearchOperationRoute } from "../research-operation.js";
import { RunCancellationService } from "../run-cancellation.js";
import { isTerminalRunStatus } from "../state.js";
import { RunStatusService } from "../status-service.js";
import type {
  VariantSearchPort,
  VariantSearchPortRequest,
} from "./port.js";
import { extractSeedPatternFacts } from "./seed-facts.js";

export const VARIANT_SEARCH_RESULT_ARTIFACT = "research/variant-search/result.json";
const EXECUTION_PHASE = "variant_search_execute" as const;

export function variantSearchRunIdForInput(
  input: VariantSearchInput,
  resolvedBudget: VariantSearchBudget,
): RunId {
  return `run_${stableDigest(canonicalJson({
    service: VARIANT_SEARCH_SERVICE,
    service_version: VARIANT_SEARCH_SERVICE_VERSION,
    seed_run_id: input.seed_run_id,
    corpus: input.corpus,
    strategy: input.strategy,
    budget: resolvedBudget,
  }))}`;
}

export function readVariantSearchResultArtifact(raw: string): VariantSearchResultArtifact | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Value.Check(VariantSearchResultArtifactSchema, parsed)
      ? (Value.Parse(VariantSearchResultArtifactSchema, parsed) as VariantSearchResultArtifact)
      : undefined;
  } catch {
    return undefined;
  }
}

export class VariantSearchService {
  constructor(
    private readonly status: RunStatusService,
    private readonly searchPort: VariantSearchPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly cancellations: RunCancellationService,
  ) {}

  async research(input: unknown, options: CodeqlOperationOptions): Promise<VariantSearchExecutionResult> {
    if (!Value.Check(VariantSearchServiceRequestSchema, input)) {
      throw new DomainError("INVALID_INPUT", "input", "Invalid variant search request payload", false);
    }
    const request = Value.Parse(VariantSearchServiceRequestSchema, input) as VariantSearchServiceRequest;
    const resolvedBudget = resolveBudget(request.input.budget);
    const runId = variantSearchRunIdForInput(request.input, resolvedBudget);

    const existing = await this.artifacts.findManifest(runId);
    if (existing !== undefined && isTerminalRunStatus(existing.status)) {
      const committed = await this.readCommitted(runId);
      if (committed !== undefined) return committed;
      return terminalResult(runId, existing.status === "budget_exhausted" ? "failed" : existing.status);
    }

    const run = await this.status.create(runId);
    return this.artifacts.withRunOperation(run.runId, options, async () => {
      const committed = await this.readCommitted(run.runId);
      if (committed !== undefined) return committed;

      const current = await this.status.get(run.runId);
      if (isTerminalRunStatus(current.status)) {
        return terminalResult(run.runId, current.status === "budget_exhausted" ? "failed" : current.status);
      }
      if (current.status === "created") await this.status.start(run.runId, EXECUTION_PHASE);

      const operation = this.cancellations.begin(run.runId, options.signal);
      try {
        return await this.execute(run.runId, request.input, resolvedBudget, { ...options, signal: operation.signal });
      } finally {
        operation.release();
      }
    });
  }

  private async execute(
    runId: RunId,
    input: VariantSearchInput,
    resolvedBudget: VariantSearchBudget,
    options: CodeqlOperationOptions,
  ): Promise<VariantSearchExecutionResult> {
    const seedFacts = await extractSeedPatternFacts(this.artifacts, input.seed_run_id);
    const portRequest: VariantSearchPortRequest = {
      input,
      seedFacts,
      resolvedBudget,
    };

    let observation: VariantSearchObservation;
    try {
      const portObs = await this.searchPort.search(portRequest, options);
      const candidates: VariantCandidate[] = portObs.candidates.map((c) => ({
        candidate_id: c.candidate_id,
        target: { ...c.target },
        location: { ...c.location },
        match_kind: c.match_kind,
        matched_symbols: [...c.matched_symbols],
        evidence_ref: c.evidence_ref,
        ...(c.evidence_digest !== undefined ? { evidence_digest: c.evidence_digest } : {}),
      }));
      observation = {
        schema_version: VARIANT_SEARCH_SERVICE_VERSION,
        seed_run_id: input.seed_run_id,
        seed_capability: "missing_check",
        seed_digest: seedFacts.seedDigest,
        seed_verification_level: seedFacts.seedVerificationLevel,
        strategy: input.strategy,
        strategy_version: VARIANT_SEARCH_STRATEGY_VERSION,
        completeness: portObs.completeness,
        gaps: [...portObs.gaps],
        candidates,
        budget_exhausted: portObs.budgetExhausted,
        targets_inspected: portObs.targetsInspected,
        files_inspected: portObs.filesInspected,
        evidence_refs: [...portObs.evidenceRefs],
        analyzer: portObs.analyzer,
      };
    } catch (error: unknown) {
      const domain = asDomainError(error);
      if (domain.code === "PROCESS_CANCELLED") {
        await this.status.cancel(runId, domain.toRecord());
        return terminalResult(runId, "cancelled");
      }
      await this.status.fail(runId, domain.toRecord());
      return terminalResult(runId, "failed");
    }

    const artifact: VariantSearchResultArtifact = {
      schema_version: VARIANT_SEARCH_SERVICE_VERSION,
      run_id: runId,
      created_at: new Date().toISOString(),
      service: VARIANT_SEARCH_SERVICE,
      service_version: VARIANT_SEARCH_SERVICE_VERSION,
      input,
      observation,
      route: {
        schema_version: CONTRACTS_VERSION,
        route_kind: "analyzer_service",
        service: VARIANT_SEARCH_SERVICE,
        service_version: VARIANT_SEARCH_SERVICE_VERSION,
        result_artifact_ref: VARIANT_SEARCH_RESULT_ARTIFACT,
      },
    };

    const routeJson = serializeResearchOperationRoute({
      service: VARIANT_SEARCH_SERVICE,
      service_version: VARIANT_SEARCH_SERVICE_VERSION,
      result_artifact_ref: VARIANT_SEARCH_RESULT_ARTIFACT,
    });

    const bundleEntries = [
      { relativePath: "operation.json", content: routeJson },
      { relativePath: "variant-search/result.json", content: JSON.stringify(artifact, null, 2) },
      ...observation.candidates.map((candidate) => ({
        relativePath: `variant-search/candidates/${candidate.candidate_id}.json`,
        content: JSON.stringify({
          schema_version: CONTRACTS_VERSION,
          service: VARIANT_SEARCH_SERVICE,
          service_version: VARIANT_SEARCH_SERVICE_VERSION,
          seed_run_id: input.seed_run_id,
          seed_digest: seedFacts.seedDigest,
          candidate,
        }, null, 2),
      })),
    ];

    const operationId = `variant-search-commit-${stableDigest(runId)}`;
    const bundle = await this.artifacts.stageArtifactBundle(runId, operationId, "research", bundleEntries);
    await this.artifacts.promoteArtifactBundle(runId, bundle);

    await this.status.complete(runId, "generated", EXECUTION_PHASE);

    return {
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      service: VARIANT_SEARCH_SERVICE,
      service_version: VARIANT_SEARCH_SERVICE_VERSION,
      operation_status: "completed",
      observation,
      allowed_next_actions: ["execute", "replay", "stop"],
      artifact_ref: VARIANT_SEARCH_RESULT_ARTIFACT,
    };
  }

  private async readCommitted(runId: RunId): Promise<VariantSearchExecutionResult | undefined> {
    const text = await this.artifacts.readArtifact(runId, VARIANT_SEARCH_RESULT_ARTIFACT);
    if (text === undefined) return undefined;
    const artifact = readVariantSearchResultArtifact(text);
    if (artifact === undefined) return undefined;
    return {
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      service: VARIANT_SEARCH_SERVICE,
      service_version: VARIANT_SEARCH_SERVICE_VERSION,
      operation_status: "completed",
      observation: artifact.observation,
      allowed_next_actions: ["execute", "replay", "stop"],
      artifact_ref: VARIANT_SEARCH_RESULT_ARTIFACT,
    };
  }
}

function resolveBudget(override?: VariantSearchInput["budget"]): VariantSearchBudget {
  return {
    max_candidates: override?.max_candidates ?? VARIANT_SEARCH_LIMITS.defaultMaxCandidates,
    max_files_per_target: override?.max_files_per_target ?? VARIANT_SEARCH_LIMITS.defaultMaxFilesPerTarget,
    timeout_ms: override?.timeout_ms ?? VARIANT_SEARCH_LIMITS.defaultTimeoutMs,
  };
}

function terminalResult(
  runId: RunId,
  status: string,
): VariantSearchExecutionResult {
  const opStatus: VariantSearchExecutionResult["operation_status"] =
    status === "completed" ? "completed"
    : status === "cancelled" ? "cancelled"
    : "failed";
  return {
    schema_version: CONTRACTS_VERSION,
    run_id: runId,
    service: VARIANT_SEARCH_SERVICE,
    service_version: VARIANT_SEARCH_SERVICE_VERSION,
    operation_status: opStatus,
    allowed_next_actions: ["stop"],
  };
}
