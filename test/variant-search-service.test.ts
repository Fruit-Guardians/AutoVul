import { describe, expect, it } from "vitest";

import {
  Application,
  type VariantSearchPort,
  type VariantSearchPortObservation,
  type VariantSearchPortRequest,
} from "@autovul/core";
import {
  DomainError,
  type VariantSearchServiceRequest,
} from "@autovul/contracts";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const seedRunId = "run_seed1234567890abcdef12345678";
const seedOid = "75b4c059b8405dfbd50884b773346a9946fabd20";
const targetOid = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";

function createSeedRunArtifact() {
  return JSON.stringify({
    schema_version: "v2.contracts/1",
    hypothesis: {
      operation: { name: "handleSigninTokenExchangeInvoke" },
      required_check: { name: "validateHostHeader" },
      scope: { entry: { name: "authHandler" } },
    },
    verification: { level: "differential" },
  });
}

const candidateSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function fakeVariantSearchPort(candidates = [
  {
    candidate_id: candidateSha256,
    target: { kind: "git_revision" as const, repository: "/trusted/repo", revision: targetOid },
    location: { file: "src/auth/exchange.ts", start_line: 12, end_line: 15, enclosing_symbol: "exchangeHandler" },
    match_kind: "exact_symbol" as const,
    matched_symbols: ["handleSigninTokenExchangeInvoke"],
    evidence_ref: `research/variant-search/candidates/${candidateSha256}.json`,
  },
]): VariantSearchPort {
  return {
    async search(
      _request: VariantSearchPortRequest,
      _options: { readonly signal?: AbortSignal },
    ): Promise<VariantSearchPortObservation> {
      return {
        candidates,
        budgetExhausted: false,
        targetsInspected: 1,
        filesInspected: 10,
        evidenceRefs: candidates.map((c) => c.evidence_ref),
        analyzer: {
          analyzer_id: "variant_search_git",
          evidence_kind: "real_analyzer",
          version: "autovul.variant-search-git/1",
          adapter_version: "autovul.variant-search-git/1",
        },
      };
    },
  };
}

describe("VariantSearchService Core", () => {
  it("executes variant search against a verified seed run and records results", async () => {
    const artifacts = new MemoryArtifactStore();
    const clock = new FixedClock();
    const ids = new FixedIdGenerator(["run_variant_1234"]);

    // Set up seed run in artifact store
    const seedManifest = {
      schemaVersion: "v2.contracts/1" as const,
      runId: seedRunId,
      status: "completed" as const,
      verificationLevel: "differential" as const,
      createdAt: clock.now(),
      updatedAt: clock.now(),
      artifactRoot: "/artifacts",
      checkpoint: {
        phase: "missing_check_execute" as const,
        completedAt: clock.now(),
        verificationLevel: "differential" as const,
      },
    };
    await artifacts.saveManifest(seedManifest);
    await artifacts.writeArtifact(
      seedRunId,
      "research/operation.json",
      JSON.stringify({
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        result_artifact_ref: "research/missing-check/result.json",
      }),
    );
    await artifacts.writeArtifact(seedRunId, "research/missing-check/result.json", createSeedRunArtifact());

    const app = new Application({
      codeql: new FakeCodeqlPort(),
      artifacts,
      clock,
      ids,
      variantSearch: fakeVariantSearchPort(),
    });

    const request: VariantSearchServiceRequest = {
      action: "execute",
      service: "variant_search",
      service_version: "autovul.variant-search/1",
      input: {
        seed_run_id: seedRunId,
        corpus: [
          {
            kind: "git_revision",
            repository: "/trusted/repo",
            revision: targetOid,
          },
        ],
        strategy: "symbol_call_pattern",
      },
    };

    const result = await app.research(request);
    expect(result.operation_status).toBe("completed");
    if ("service" in result && result.service === "variant_search") {
      expect(result.observation?.candidates).toHaveLength(1);
      expect(result.observation?.candidates[0].candidate_id).toBe(candidateSha256);
      expect(result.observation?.seed_capability).toBe("missing_check");
      expect(result.allowed_next_actions).toEqual(["execute", "replay", "stop"]);

      // Verify individual candidate evidence artifact
      const candRaw = await artifacts.readArtifact(result.run_id, result.observation!.candidates[0].evidence_ref);
      expect(candRaw).toBeDefined();
      const candParsed = JSON.parse(candRaw!);
      expect(candParsed).toMatchObject({
        service: "variant_search",
        candidate: { candidate_id: candidateSha256 },
      });

      // Verify replay
      const replay = await app.manageRun({ action: "replay", run_id: result.run_id });
      expect(replay).toMatchObject({
        status: "identical",
        service: "variant_search",
      });
    } else {
      throw new Error("Unexpected result type");
    }
  });

  it("fails when seed run does not exist", async () => {
    const artifacts = new MemoryArtifactStore();
    const clock = new FixedClock();
    const ids = new FixedIdGenerator();

    const app = new Application({
      codeql: new FakeCodeqlPort(),
      artifacts,
      clock,
      ids,
      variantSearch: fakeVariantSearchPort(),
    });

    const request: VariantSearchServiceRequest = {
      action: "execute",
      service: "variant_search",
      service_version: "autovul.variant-search/1",
      input: {
        seed_run_id: "run_nonexistent",
        corpus: [{ kind: "git_revision", repository: "/trusted/repo", revision: targetOid }],
        strategy: "symbol_call_pattern",
      },
    };

    await expect(app.research(request)).rejects.toThrow(DomainError);
  });
});
