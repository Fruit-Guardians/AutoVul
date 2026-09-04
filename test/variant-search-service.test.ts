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

function createSeedRunArtifact(overrides: Partial<Record<string, unknown>> = {}) {
  return JSON.stringify({
    schema_version: "v2.contracts/1",
    capability: "missing_check",
    hypothesis_version: "autovul.missing-check/1",
    hypothesis: {
      schema_version: "autovul.missing-check/1",
      hypothesis_id: "mcheck-test-seed",
      language: "javascript",
      operation: { kind: "direct_call", name: "handleSigninTokenExchangeInvoke" },
      required_check: { kind: "direct_call", name: "validateHostHeader" },
      required_relation: "same_callback_cfg_dominates_operation",
      scope: {
        kind: "single_file_named_entry_cfg",
        file: "src/auth.js",
        entry: { kind: "named_function", name: "authHandler" },
      },
    },
    target: {
      vulnerable: {
        kind: "git_revision",
        repository: "/trusted/repo",
        revision: seedOid,
      },
    },
    mode: "reproduce",
    analyzer: {
      analyzer_id: "javascript_cfg",
      available: true,
      evidence_kind: "real_analyzer",
      version: "autovul.javascript-cfg/1",
      adapter_version: "autovul.javascript-cfg/1",
    },
    decision: {
      capability: "missing_check",
      outcome: "check_missing",
    },
    verification_level: "differential",
    operation_status: "completed",
    observations: [],
    revision_hints: [],
    allowed_next_actions: ["execute", "replay", "stop"],
    ...overrides,
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
        completeness: "complete",
        gaps: [],
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
      expect(result.observation?.seed_verification_level).toBe("differential");
      expect(result.observation?.seed_digest).toBeDefined();
      expect(result.observation?.completeness).toBe("complete");
      expect(result.observation?.gaps).toEqual([]);
      expect(result.observation?.strategy_version).toBe("autovul.variant-strategy/1");
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

  it("rejects seed run whose verification level is below reproduced (e.g. generated)", async () => {
    const artifacts = new MemoryArtifactStore();
    const clock = new FixedClock();
    const ids = new FixedIdGenerator(["run_variant_unverified"]);

    const weakSeedRunId = "run_seed_generated_12345678";
    await artifacts.saveManifest({
      schemaVersion: "v2.contracts/1" as const,
      runId: weakSeedRunId,
      status: "completed" as const,
      verificationLevel: "generated" as const,
      createdAt: clock.now(),
      updatedAt: clock.now(),
      artifactRoot: "/artifacts",
    });
    await artifacts.writeArtifact(
      weakSeedRunId,
      "research/operation.json",
      JSON.stringify({
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        result_artifact_ref: "research/missing-check/result.json",
      }),
    );
    await artifacts.writeArtifact(
      weakSeedRunId,
      "research/missing-check/result.json",
      createSeedRunArtifact({ verification_level: "generated" }),
    );

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
        seed_run_id: weakSeedRunId,
        corpus: [{ kind: "git_revision", repository: "/trusted/repo", revision: targetOid }],
        strategy: "symbol_call_pattern",
      },
    };

    await expect(app.research(request)).rejects.toThrow(/must be at least reproduced/);
  });

  it("rejects non-missing_check seed run", async () => {
    const artifacts = new MemoryArtifactStore();
    const clock = new FixedClock();
    const ids = new FixedIdGenerator(["run_variant_flow_seed"]);

    const flowSeedRunId = "run_seed_flow_1234567890ab";
    await artifacts.saveManifest({
      schemaVersion: "v2.contracts/1" as const,
      runId: flowSeedRunId,
      status: "completed" as const,
      verificationLevel: "reproduced" as const,
      createdAt: clock.now(),
      updatedAt: clock.now(),
      artifactRoot: "/artifacts",
    });
    await artifacts.writeArtifact(
      flowSeedRunId,
      "research/operation.json",
      JSON.stringify({
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "flow",
        hypothesis_version: "autovul.flow/1",
        result_artifact_ref: "research/flow/result.json",
      }),
    );
    await artifacts.writeArtifact(
      flowSeedRunId,
      "research/flow/result.json",
      JSON.stringify({ schema_version: "v2.contracts/1", capability: "flow" }),
    );

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
        seed_run_id: flowSeedRunId,
        corpus: [{ kind: "git_revision", repository: "/trusted/repo", revision: targetOid }],
        strategy: "symbol_call_pattern",
      },
    };

    await expect(app.research(request)).rejects.toThrow(/Variant Search v1 only supports real MissingCheck seeds/);
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
