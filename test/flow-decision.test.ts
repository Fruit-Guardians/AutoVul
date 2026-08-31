import { describe, expect, it } from "vitest";
import type { FlowAnalyzerObservation, TaintQueryIntent } from "@autovul/contracts";
import { decideFlow, projectTaintIntentToFlow, validateFlowExpectation, validateFlowModel } from "@autovul/core";

const model = {
  schema_version: "autovul.flow/1",
  model_id: "flow-test",
  language: "python",
  flow_mode: "taint",
  source: { kind: "environment", name: "USER_INPUT" },
  sink: { kind: "call_argument", name: "eval", argument_index: 0 },
} as const;

function observation(overrides: Partial<FlowAnalyzerObservation> = {}): FlowAnalyzerObservation {
  return {
    schema_version: "autovul.flow/1", compile_accepted: true,
    source: { state: "observed", locations: [] }, sink: { state: "observed", locations: [] },
    path: { state: "not_observed", path_count: 0 }, capability_gaps: [], evidence_refs: ["flow.json"],
    analyzer: { analyzer_id: "codeql", available: true }, ...overrides,
  };
}

describe("Flow v1 deterministic policy", () => {
  it("returns actionable endpoint-without-path feedback without a SARIF payload", () => {
    const result = decideFlow(observation(), "reproduce", { vulnerable: { min_paths: 1, max_paths: 1 } });
    expect(result.decision).toEqual({ capability: "flow", outcome: "no_path" });
    expect(result.observations.map((item) => item.code)).toContain("ENDPOINTS_OBSERVED_WITHOUT_PATH");
    expect(result.revisionHints).toContainEqual({ action: "revise_step", path: "/steps", reason_code: "ENDPOINTS_OBSERVED_WITHOUT_PATH" });
    expect(result.verificationLevel).toBe("compiled");
  });

  it("does not let probe facts raise the verification level or conclude a path", () => {
    const result = decideFlow(observation({ path: { state: "observed", path_count: 1 } }), "probe");
    expect(result.verificationLevel).toBe("generated");
    expect(result.decision.outcome).toBe("unknown");
  });

  it("accepts an uncompiled probe as endpoint evidence rather than a compile failure", () => {
    const result = decideFlow(observation({ compile_accepted: "not_run" }), "probe");
    expect(result.decision.outcome).toBe("unknown");
    expect(result.allowedNextActions).toEqual(["execute", "stop"]);
    expect(result.observations.map((item) => item.code)).not.toContain("COMPILE_NOT_RUN");
  });

  it("does not grant differential evidence when the fixed target was not run", () => {
    const result = decideFlow(observation({
      path: { state: "observed", path_count: 1 },
      fixed_path: { state: "not_run", path_count: 0 },
    }), "differential", {
      vulnerable: { min_paths: 1, max_paths: 1 },
      fixed: { min_paths: 0, max_paths: 0 },
    });
    expect(result.decision).toMatchObject({ fixed_outcome: "unknown", fixed_policy_satisfied: false });
    expect(result.verificationLevel).toBe("reproduced");
  });

  it("does not treat an unrun path as a completed no-path decision", () => {
    const result = decideFlow(observation({ path: { state: "not_run", path_count: 0 } }), "probe");
    expect(result.decision.outcome).toBe("unknown");
    expect(result.verificationLevel).toBe("generated");
    expect(result.observations.map((item) => item.code)).not.toContain("ENDPOINTS_OBSERVED_WITHOUT_PATH");
  });

  it("keeps capability mismatch separate from completed no-path", () => {
    const result = decideFlow(observation({ capability_gaps: [{ code: "FLOW_ENDPOINT_UNSUPPORTED", path: "/source" }] }), "reproduce");
    expect(result.decision.outcome).toBe("unknown");
    expect(result.observations).toContainEqual({ code: "CAPABILITY_MISMATCH", path: "/source" });
  });

  it("validates model and bounded expectation range independently", () => {
    expect(validateFlowModel(model).valid).toBe(true);
    expect(validateFlowExpectation({ vulnerable: { min_paths: 2, max_paths: 1 } }, "reproduce")).toContainEqual({ code: "FLOW_PATH_RANGE_INVALID", path: "/expectation/vulnerable/max_paths" });
  });

  it("projects legacy selectors, steps, sanitizers, and metadata without putting metadata in FlowModel", () => {
    const intent: TaintQueryIntent = {
      schema_version: "v2.contracts/1", intent_id: "legacy-flow", language: "python", cwe: "CWE-78", query_kind: "path-problem", flow_mode: "taint",
      source: { kind: "environment", name: "USER_INPUT" }, sink: { kind: "call_argument", name: "exec", argument_index: 0 }, message: "unsafe",
      additional_flow: [{ kind: "property", property: "value" }], sanitizer: [{ kind: "call", name: "escape" }], rationale: "legacy context",
    };
    const projection = projectTaintIntentToFlow(intent);
    expect(projection.model.steps).toEqual([{ from: { kind: "property", property: "value" }, to: { kind: "property", property: "value" } }]);
    expect(projection.model.barriers).toEqual([{ endpoint: { kind: "call", name: "escape" } }]);
    expect(projection.model).not.toHaveProperty("cwe");
    expect(projection.context).toMatchObject({ cwe: "CWE-78", message: "unsafe", rationale: "legacy context" });
  });
});
