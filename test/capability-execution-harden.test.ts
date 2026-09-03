import { describe, expect, it } from "vitest";
import { Value } from "typebox/value";

import {
  CapabilityResearchRequestSchema,
  CapabilityResearchOperationRouteSchema,
  DomainError,
  FLOW_HYPOTHESIS_VERSION,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  TYPESTATE_HYPOTHESIS_VERSION,
  type FlowAnalyzerObservation,
} from "@autovul/contracts";
import {
  Application,
  FlowReplayService,
  MissingCheckReplayService,
  type FlowExecutionPort,
  type FlowExecutionRequest,
  type MissingCheckExecutionPort,
  type MissingCheckExecutionRequest,
} from "@autovul/core";
import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const flowModel = {
  schema_version: "autovul.flow/1",
  model_id: "flow-harden",
  language: "python",
  flow_mode: "taint",
  source: { kind: "environment", name: "USER_INPUT" },
  sink: { kind: "call_argument", name: "eval", argument_index: 0 },
} as const;

function flowObservation(): FlowAnalyzerObservation {
  return {
    schema_version: "autovul.flow/1",
    compile_accepted: true,
    source: { state: "observed", locations: [] },
    sink: { state: "observed", locations: [] },
    path: { state: "observed", path_count: 1 },
    capability_gaps: [],
    evidence_refs: ["flow.json"],
    analyzer: {
      analyzer_id: "codeql",
      available: true,
      evidence_kind: "real_analyzer",
      version: "CodeQL CLI version 2.26.1",
      adapter_version: "autovul.codeql-flow/1",
    },
  };
}

class FakeFlowPort implements FlowExecutionPort {
  async execute(_request: FlowExecutionRequest): Promise<FlowAnalyzerObservation> {
    return flowObservation();
  }
}

class FakeMissingCheckPort implements MissingCheckExecutionPort {
  async execute(request: MissingCheckExecutionRequest): Promise<import("@autovul/contracts").MissingCheckAnalyzerObservation> {
    return {
      schema_version: "autovul.missing-check/1",
      compile_accepted: true,
      operation: { state: "observed", locations: [] },
      required_check: { state: "observed", locations: [] },
      relation: { state: "unchecked_witness", unchecked_witnesses: [{ evidence_ref: "mcheck.json" }], checked_witnesses: [] },
      completeness: { vulnerable: { status: "complete", scope: request.hypothesis.scope, limitations: [] } },
      capability_gaps: [],
      evidence_refs: ["mcheck.json"],
      analyzer: {
        analyzer_id: "codeql",
        available: true,
        evidence_kind: "real_analyzer",
        version: "CodeQL CLI version 2.26.1",
        adapter_version: "autovul.codeql-missing-check/1",
      },
    };
  }
}

function makeApp(artifacts = new MemoryArtifactStore()): Application {
  return new Application({
    codeql: new FakeCodeqlPort(),
    artifacts,
    clock: new FixedClock(1_700_000_000_000),
    ids: new FixedIdGenerator(["run-harden-1", "run-harden-2"]),
    flow: new FakeFlowPort(),
    missingCheck: new FakeMissingCheckPort(),
  });
}

describe("Capability execution contracts hardening", () => {
  describe("REQ-HARDEN-PAIR-001 / REQ-HARDEN-PAIR-002: Closed pairing", () => {
    it("accepts valid capability and hypothesis_version pairings", () => {
      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "flow",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        hypothesis: flowModel,
      })).toBe(true);

      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "missing_check",
        hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION,
        hypothesis: {},
      })).toBe(true);

      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "typestate",
        hypothesis_version: TYPESTATE_HYPOTHESIS_VERSION,
        hypothesis: {},
      })).toBe(true);
    });

    it("rejects mismatched capability and hypothesis_version pairings", () => {
      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "flow",
        hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION,
        hypothesis: flowModel,
      })).toBe(false);

      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "missing_check",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        hypothesis: {},
      })).toBe(false);

      expect(Value.Check(CapabilityResearchRequestSchema, {
        action: "validate",
        capability: "typestate",
        hypothesis_version: "autovul.unknown/1",
        hypothesis: {},
      })).toBe(false);
    });

    it("enforces closed pairing on persisted routes", () => {
      expect(Value.Check(CapabilityResearchOperationRouteSchema, {
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "flow",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        result_artifact_ref: "research/flow/result.json",
      })).toBe(true);

      expect(Value.Check(CapabilityResearchOperationRouteSchema, {
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "flow",
        hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION,
        result_artifact_ref: "research/flow/result.json",
      })).toBe(false);
    });
  });

  describe("REQ-HARDEN-DISPATCH-001 / REQ-HARDEN-DISPATCH-002: Explicit routing without silent Flow fallback", () => {
    it("explicitly rejects unknown capability with DomainError(INVALID_INPUT)", async () => {
      const app = makeApp();
      await expect(app.research({
        action: "validate",
        capability: "invalid_cap",
        hypothesis_version: "autovul.flow/1",
        hypothesis: flowModel,
      })).rejects.toThrowError(DomainError);

      try {
        await app.research({
          action: "validate",
          capability: "invalid_cap",
          hypothesis_version: "autovul.flow/1",
          hypothesis: flowModel,
        });
      } catch (err) {
        expect(err).toBeInstanceOf(DomainError);
        const domainErr = err as DomainError;
        expect(domainErr.code).toBe("INVALID_INPUT");
        expect(domainErr.category).toBe("input");
      }
      await app.close();
    });

    it("explicitly rejects unknown service with DomainError(INVALID_INPUT)", async () => {
      const app = makeApp();
      await expect(app.research({
        action: "execute",
        service: "unknown_analyzer_service",
      })).rejects.toThrowError(DomainError);
      await app.close();
    });

    it("rejects non-object input with DomainError(INVALID_INPUT)", async () => {
      const app = makeApp();
      await expect(app.research("not-an-object")).rejects.toThrowError(DomainError);
      await app.close();
    });
  });

  describe("REQ-HARDEN-REPLAY-BASE-001~006: Consistent Replay Baseline", () => {
    it("blocks Flow replay when route capability does not match Flow", async () => {
      const artifacts = new MemoryArtifactStore();
      const app = makeApp(artifacts);
      const executed = await app.research({
        action: "execute",
        capability: "flow",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        hypothesis: flowModel,
        analyzer_id: "codeql",
        mode: "probe",
        target: { vulnerable: { kind: "codeql_database", path: "/test/db" } },
        budget: { timeout_ms: 5_000 },
        idempotency_key: "harden-flow-1",
      }) as any;

      const status = new (await import("@autovul/core")).RunStatusService(artifacts, new FixedClock(1_700_000_000_000), new FixedIdGenerator(["run-1"]));
      const replay = new FlowReplayService(status, new FakeCodeqlPort(), new FakeFlowPort(), artifacts);
      const blocked = await replay.replay(executed.run_id, {
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "missing_check" as any,
        hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION as any,
        result_artifact_ref: "research/flow/result.json",
      }, { timeoutMs: 5_000 });

      expect(blocked.operation_status).toBe("blocked");
      expect(blocked.observations).toContainEqual(expect.objectContaining({ code: "FLOW_REPLAY_ROUTE_MISMATCH" }));
      await app.close();
    });

    it("blocks MissingCheck replay when route capability does not match MissingCheck", async () => {
      const artifacts = new MemoryArtifactStore();
      const app = makeApp(artifacts);
      const executed = await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: MISSING_CHECK_HYPOTHESIS_VERSION,
        hypothesis: {
          schema_version: "autovul.missing-check/1",
          hypothesis_id: "mcheck-harden",
          language: "javascript",
          operation: { kind: "direct_call", name: "exec" },
          required_check: { kind: "direct_call", name: "check" },
          required_relation: "same_callback_cfg_dominates_operation",
          scope: { kind: "single_file_named_entry_cfg", file: "test.js", entry: { kind: "named_function", name: "handler" } },
        },
        analyzer_id: "codeql",
        mode: "reproduce",
        target: { vulnerable: { kind: "codeql_database", path: "/test/db" } },
        budget: { timeout_ms: 5_000 },
        idempotency_key: "harden-mcheck-1",
      }) as any;

      const status = new (await import("@autovul/core")).RunStatusService(artifacts, new FixedClock(1_700_000_000_000), new FixedIdGenerator(["run-1"]));
      const replay = new MissingCheckReplayService(status, new FakeCodeqlPort(), new FakeMissingCheckPort(), artifacts);
      const blocked = await replay.replay(executed.run_id, {
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "flow" as any,
        hypothesis_version: FLOW_HYPOTHESIS_VERSION as any,
        result_artifact_ref: "research/missing-check/result.json",
      }, { timeoutMs: 5_000 });

      expect(blocked.operation_status).toBe("blocked");
      expect(blocked.observations).toContainEqual(expect.objectContaining({ code: "MCHECK_REPLAY_ROUTE_MISMATCH" }));
      await app.close();
    });

    it("reports policy version difference when Flow replay finds mismatched policy version", async () => {
      const artifacts = new MemoryArtifactStore();
      const app = makeApp(artifacts);
      const executed = await app.research({
        action: "execute",
        capability: "flow",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        hypothesis: flowModel,
        analyzer_id: "codeql",
        mode: "probe",
        target: { vulnerable: { kind: "codeql_database", path: "/test/db" } },
        budget: { timeout_ms: 5_000 },
        idempotency_key: "harden-flow-policy",
      }) as any;

      // Tamper artifact to have outdated policy version
      const raw = await artifacts.readArtifact(executed.run_id, "research/flow/result.json");
      const parsed = JSON.parse(raw!);
      parsed.decision_policy_version = "autovul.flow.decision/0-outdated";
      await artifacts.writeArtifact(executed.run_id, "research/flow/result.json", JSON.stringify(parsed));

      const status = new (await import("@autovul/core")).RunStatusService(artifacts, new FixedClock(1_700_000_000_000), new FixedIdGenerator(["run-1"]));
      const replay = new FlowReplayService(status, new FakeCodeqlPort(), new FakeFlowPort(), artifacts);

      const result = await replay.replay(executed.run_id, {
        schema_version: "v2.contracts/1",
        route_kind: "capability",
        capability: "flow",
        hypothesis_version: FLOW_HYPOTHESIS_VERSION,
        result_artifact_ref: "research/flow/result.json",
      }, { timeoutMs: 5_000 });

      expect(result.operation_status).toBe("completed");
      expect(result.decision.outcome).toBe("unknown");
      expect(result.observations).toContainEqual(expect.objectContaining({ code: "FLOW_REPLAY_POLICY_VERSION_DIFFERENCE" }));
      await app.close();
    });
  });
});
