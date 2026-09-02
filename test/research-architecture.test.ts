import { describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Application, runIdForIdempotencyKey, type FlowExecutionPort, type FlowExecutionRequest } from "@autovul/core";
import { DomainError, type FlowAnalyzerObservation, type ResearchExecutionResult } from "@autovul/contracts";
import { runCli } from "@autovul/cli";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const model = {
  schema_version: "autovul.flow/1",
  model_id: "flow-test",
  language: "python",
  flow_mode: "taint",
  source: { kind: "environment", name: "USER_INPUT" },
  sink: { kind: "call_argument", name: "eval", argument_index: 0 },
};

function observation(overrides: Partial<FlowAnalyzerObservation> = {}): FlowAnalyzerObservation {
  return {
    schema_version: "autovul.flow/1",
    compile_accepted: true,
    source: { state: "observed", locations: [] },
    sink: { state: "observed", locations: [] },
    path: { state: "not_observed", path_count: 0 },
    capability_gaps: [],
    evidence_refs: ["flow.json"],
    analyzer: { analyzer_id: "codeql", available: true, version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-flow/1" },
    ...overrides,
  };
}

class ScriptedFlowPort implements FlowExecutionPort {
  readonly requests: FlowExecutionRequest[] = [];
  constructor(private readonly handler: (request: FlowExecutionRequest) => FlowAnalyzerObservation | Promise<FlowAnalyzerObservation>) {}
  async execute(request: FlowExecutionRequest): Promise<FlowAnalyzerObservation> {
    this.requests.push(request);
    return this.handler(request);
  }
}

class AbortableFlowPort implements FlowExecutionPort {
  private resolveStarted: (() => void) | undefined;
  readonly started = new Promise<void>((resolve) => { this.resolveStarted = resolve; });

  async execute(_request: FlowExecutionRequest, options: { readonly signal?: AbortSignal }): Promise<FlowAnalyzerObservation> {
    this.resolveStarted?.();
    return new Promise<FlowAnalyzerObservation>((_resolve, reject) => {
      if (options.signal?.aborted) {
        reject(new Error("abort signal was already set"));
        return;
      }
      options.signal?.addEventListener("abort", () => reject(new Error("adapter received cancellation")), { once: true });
    });
  }
}

class RejectingResearchPromotionStore extends MemoryArtifactStore {
  override async promoteArtifactBundle(...args: Parameters<MemoryArtifactStore["promoteArtifactBundle"]>): ReturnType<MemoryArtifactStore["promoteArtifactBundle"]> {
    void args;
    throw new Error("simulated promote failure");
  }
}

class InterruptedAfterResearchPromotionStore extends MemoryArtifactStore {
  private interrupted = false;

  override async promoteArtifactBundle(...args: Parameters<MemoryArtifactStore["promoteArtifactBundle"]>): ReturnType<MemoryArtifactStore["promoteArtifactBundle"]> {
    await super.promoteArtifactBundle(...args);
    if (!this.interrupted) {
      this.interrupted = true;
      throw new Error("simulated interruption after promote");
    }
  }
}

function application(flow: FlowExecutionPort, artifacts = new MemoryArtifactStore(), runId = "run_flow01", codeql = new FakeCodeqlPort()) {
  return {
    artifacts,
    app: new Application({
      codeql,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator(runId),
      flow,
    }),
  };
}

describe("research capability architecture", () => {
  it("keeps validate side-effect free", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const result = await app.research({
      action: "validate",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
    });
    expect(result).toMatchObject({ valid: true });
    expect(artifacts.manifests.size).toBe(0);
    expect(artifacts.artifacts.size).toBe(0);
    expect(flow.requests).toHaveLength(0);
    await app.close();
  });

  it("returns field issues without creating a run for invalid hypotheses", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const result = await app.research({
      action: "validate",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: { ...model, sink: { kind: "call_argument", name: "eval" } },
    });
    expect(result).toMatchObject({
      valid: false,
      issues: [{ code: "FLOW_ENDPOINT_POSITION_REQUIRED", path: "/sink/argument_index" }],
      allowed_next_actions: ["revise", "stop"],
    });
    expect(artifacts.manifests.size).toBe(0);
    await app.close();
  });

  it("lets Core write the Flow decision and records a completed no-path result", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-no-path",
    });
    expect(result).toMatchObject({
      operation_status: "completed",
      capability: "flow",
      decision: { capability: "flow", outcome: "no_path" },
      verification_level: "compiled",
    });
    expect("observations" in result && result.observations.map((item) => item.code)).toContain("ENDPOINTS_OBSERVED_WITHOUT_PATH");
    const route = JSON.parse(await artifacts.readArtifact((result as ResearchExecutionResult).run_id, "research/operation.json") ?? "null");
    expect(route).toEqual({
      schema_version: "v2.contracts/1",
      route_kind: "capability",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      result_artifact_ref: "research/flow/result.json",
    });
    await app.close();
  });

  it("projects a historical capability route without rewriting its artifact", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "probe",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "legacy-route-projection",
    });
    if (!("run_id" in result)) throw new Error("expected execution result");
    const historical = JSON.stringify({
      schema_version: "v2.contracts/1",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      result_artifact_ref: "research/flow/result.json",
    });
    await artifacts.writeArtifact(result.run_id, "research/operation.json", historical);

    const replayed = await app.manageRun({ action: "replay", run_id: result.run_id });
    expect(replayed).toMatchObject({ capability: "flow", operation_status: "completed" });
    expect(await artifacts.readArtifact(result.run_id, "research/operation.json")).toBe(historical);
    await app.close();
  });

  it("rejects a second Capability without creating a run", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const result = await app.research({
      action: "validate",
      capability: "missingcheck",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
    });
    expect(result).toMatchObject({
      valid: false,
      issues: [{ code: "FLOW_RESEARCH_CAPABILITY_INVALID", path: "/capability", allowed_values: ["flow"] }],
    });
    expect(artifacts.manifests.size).toBe(0);
    await app.close();
  });

  it("marks Analyzer failure as failed rather than completed success", async () => {
    const flow = new ScriptedFlowPort(() => {
      throw new Error("analyzer crashed");
    });
    const { app } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "probe",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-fail",
    }) as ResearchExecutionResult;
    expect(result).toMatchObject({ operation_status: "failed", decision: { outcome: "unknown" }, verification_level: "generated" });
    const status = await app.manageRun({ action: "status", run_id: result.run_id });
    expect(status).toMatchObject({ runId: result.run_id, status: "failed" });
    const replayed = await app.manageRun({ action: "replay", run_id: result.run_id });
    expect(replayed).toMatchObject({
      operation_status: "completed",
      decision: { outcome: "unknown" },
      observations: [{ code: "FLOW_REPLAY_ANALYZER_VERSION_UNRECORDED" }],
    });
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("maps Adapter timeout to a stable actionable observation", async () => {
    const flow = new ScriptedFlowPort(() => {
      throw new DomainError("PROCESS_TIMEOUT", "process", "CodeQL timed out", true);
    });
    const { app } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-adapter-timeout",
    }) as ResearchExecutionResult;
    expect(result).toMatchObject({ operation_status: "failed", observations: [{ code: "FLOW_ANALYZER_TIMEOUT" }] });
    await app.close();
  });

  it("maps a failed endpoint probe to FLOW_PROBE_FAILED", async () => {
    const flow = new ScriptedFlowPort(() => {
      throw new DomainError("PROBE_FAILED", "process", "endpoint probe failed", false);
    });
    const { app } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-probe-failed",
    }) as ResearchExecutionResult;
    expect(result).toMatchObject({ operation_status: "failed", observations: [{ code: "FLOW_PROBE_FAILED" }] });
    await app.close();
  });

  it("blocks execution when the requested target fingerprint differs", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db", expected_fingerprint: "fedcba9876543210" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-target-fingerprint-mismatch",
    }) as ResearchExecutionResult;
    expect(result).toMatchObject({ operation_status: "blocked", observations: [{ code: "FLOW_TARGET_FINGERPRINT_MISMATCH" }] });
    expect(flow.requests).toHaveLength(0);
    await app.close();
  });

  it("cancels an active Flow Adapter through autovul_run", async () => {
    const flow = new AbortableFlowPort();
    const { app } = application(flow);
    const executing = app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-active-cancel",
    }) as Promise<ResearchExecutionResult>;
    await flow.started;
    const runId = runIdForIdempotencyKey("flow-active-cancel");
    const cancelled = await app.manageRun({ action: "cancel", run_id: runId });
    expect(cancelled).toMatchObject({ status: "cancelled" });
    await expect(executing).resolves.toMatchObject({
      operation_status: "cancelled",
      observations: [{ code: "FLOW_EXECUTION_CANCELLED" }],
    });
    await app.close();
  });

  it("blocks when the Analyzer is unavailable instead of inventing success", async () => {
    const { app } = application(new ScriptedFlowPort(() => observation({ analyzer: { analyzer_id: "codeql", available: false } })));
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-unavailable",
    });
    expect(result).toMatchObject({
      operation_status: "blocked",
      decision: { outcome: "unknown" },
      verification_level: "generated",
    });
    await app.close();
  });

  it("rejects malformed Adapter observations before committing a completed Flow result", async () => {
    const malformed = new ScriptedFlowPort(() => ({
      schema_version: "autovul.flow/1",
      compile_accepted: true,
      source: { state: "observed", locations: [] },
      sink: { state: "observed", locations: [] },
      path: { state: "not_observed", path_count: 0 },
      capability_gaps: [],
      evidence_refs: [],
      analyzer: { analyzer_id: "codeql", available: true, version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-flow/1" },
      unexpected: true,
    }) as unknown as FlowAnalyzerObservation);
    const { app, artifacts } = application(malformed);
    const result = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-malformed-observation",
    }) as ResearchExecutionResult;
    expect(result).toMatchObject({ operation_status: "failed", decision: { outcome: "unknown" } });
    const committed = JSON.parse(await artifacts.readArtifact(result.run_id, "research/flow/result.json") ?? "null");
    expect(committed.observation).toBeUndefined();
    await app.close();
  });

  it("resumes the same bounded operation for the same idempotency key", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow);
    const request = {
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-idempotent",
    };
    const first = await app.research(request) as ResearchExecutionResult;
    const second = await app.research(request) as ResearchExecutionResult;
    expect(second.run_id).toBe(first.run_id);
    expect(second.decision).toEqual(first.decision);
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("rejects reuse of an idempotency key for a different Flow operation", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow);
    const request = {
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-idempotency-conflict",
    };
    await app.research(request);
    await expect(app.research({ ...request, target: { vulnerable: { kind: "codeql_database", path: "/isolated/other-db" } } }))
      .rejects.toMatchObject({ code: "IDEMPOTENCY_KEY_CONFLICT" });
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("never exposes a route without its Flow artifact when bundle promotion fails", async () => {
    const artifacts = new RejectingResearchPromotionStore();
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow, artifacts);
    const request = {
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-atomic-failure",
    };
    await expect(app.research(request)).rejects.toThrow("simulated promote failure");
    expect([...artifacts.artifacts.keys()].filter((key) => key.includes("/research/"))).toEqual([]);
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("recovers a fully promoted bundle after interruption without executing Flow twice", async () => {
    const artifacts = new InterruptedAfterResearchPromotionStore();
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow, artifacts);
    const request = {
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-atomic-recovery",
    };
    const first = await app.research(request) as ResearchExecutionResult;
    const second = await app.research(request) as ResearchExecutionResult;
    expect(first).toMatchObject({ operation_status: "completed", decision: { outcome: "no_path" } });
    expect(second).toEqual(first);
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("replays a committed Flow artifact without calling a model", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const executed = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-replay",
    }) as ResearchExecutionResult;
    expect(executed).toMatchObject({ operation_status: "completed" });
    const replayed = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replayed).toMatchObject({
      operation_status: "completed",
      decision: { capability: "flow", outcome: "no_path" },
      verification_level: "compiled",
    });
    expect(flow.requests).toHaveLength(2);
    const artifact = JSON.parse(await artifacts.readArtifact(executed.run_id, "research/flow/result.json") ?? "null");
    expect(artifact).toMatchObject({
      target_fingerprints: { vulnerable: "0123456789abcdef" },
      analyzer: { version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-flow/1" },
    });
    await app.close();
  });

  it("blocks replay before Analyzer execution when the target fingerprint changes", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const codeql = new FakeCodeqlPort();
    const { app } = application(flow, new MemoryArtifactStore(), "run_flow_fingerprint_replay", codeql);
    const executed = await app.research({
      action: "execute", capability: "flow", hypothesis_version: "autovul.flow/1", hypothesis: model,
      analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } }, budget: { timeout_ms: 5_000 }, idempotency_key: "flow-fingerprint-replay",
    }) as ResearchExecutionResult;
    codeql.database = { ...codeql.database, fingerprint: "fedcba9876543210", portableFingerprint: "fedcba9876543210" };
    const replayed = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replayed).toMatchObject({ operation_status: "blocked", observations: [{ code: "FLOW_REPLAY_FINGERPRINT_DIFFERENCE" }] });
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("downgrades replay when the Analyzer or adapter version differs", async () => {
    let calls = 0;
    const flow = new ScriptedFlowPort(() => {
      calls += 1;
      return observation(calls === 1 ? {} : { analyzer: { analyzer_id: "codeql", available: true, version: "CodeQL CLI version 2.27.0", adapter_version: "autovul.codeql-flow/2" } });
    });
    const { app } = application(flow);
    const executed = await app.research({
      action: "execute", capability: "flow", hypothesis_version: "autovul.flow/1", hypothesis: model,
      analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } }, budget: { timeout_ms: 5_000 }, idempotency_key: "flow-version-replay",
    }) as ResearchExecutionResult;
    const replayed = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replayed).toMatchObject({
      operation_status: "completed", decision: { outcome: "unknown" }, verification_level: "generated",
      observations: [{ code: "FLOW_REPLAY_ANALYZER_VERSION_DIFFERENCE" }],
    });
    await app.close();
  });

  it("blocks replay when committed Flow evidence is corrupted", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app, artifacts } = application(flow);
    const executed = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-corrupt-artifact",
    }) as ResearchExecutionResult;
    artifacts.artifacts.set(`${executed.run_id}/research/flow/result.json`, "{}");
    const replayed = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replayed).toMatchObject({
      operation_status: "blocked",
      observations: [{ code: "FLOW_REPLAY_ARTIFACT_INVALID" }],
    });
    expect(flow.requests).toHaveLength(1);
    await app.close();
  });

  it("blocks replay at the shared route boundary when no operation route was committed", async () => {
    const flow = new ScriptedFlowPort(() => observation());
    const { app } = application(flow);
    const run = await app.workflowStart({
      schema_version: "v2.contracts/1",
      spec_id: "legacy-run",
      language: "python",
      cwe: "CWE-78",
      vulnerability_description: "legacy compatibility workflow without a research operation route",
      vulnerable_database: { path: "/isolated/db", language: "python" },
      validation: { vulnerable_min_results: 1, vulnerable_max_results: 1, fixed_min_results: 0, fixed_max_results: 0, must_have_code_flow: true },
      max_rounds: 1,
      timeout_ms: 5_000,
      created_at: "2026-08-01T00:00:00.000Z",
      input_provenance: "golden_fixture",
      reference_query_excluded: true,
      provenance: { fixture: "test", license: "MIT", source: "test" },
    });
    const replayed = await app.manageRun({ action: "replay", run_id: run.run.runId });
    expect(replayed).toMatchObject({
      operation_status: "blocked",
      observations: [{ code: "RESEARCH_REPLAY_ROUTE_MISSING" }],
    });
    expect(flow.requests).toHaveLength(0);
    await app.close();
  });

  it("reports a semantic mismatch when replay observations change", async () => {
    let calls = 0;
    const flow = new ScriptedFlowPort(() => {
      calls += 1;
      return observation(calls === 1 ? {} : { path: { state: "observed", path_count: 1 } });
    });
    const { app } = application(flow);
    const executed = await app.research({
      action: "execute",
      capability: "flow",
      hypothesis_version: "autovul.flow/1",
      hypothesis: model,
      analyzer_id: "codeql",
      mode: "reproduce",
      target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
      expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
      budget: { timeout_ms: 5_000 },
      idempotency_key: "flow-mismatch",
    }) as ResearchExecutionResult;
    const replayed = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replayed).toMatchObject({ operation_status: "completed", decision: { outcome: "connected" }, verification_level: "generated" });
    expect("observations" in replayed && replayed.observations.map((item) => item.code)).toContain("FLOW_REPLAY_SEMANTIC_MISMATCH");
    await app.close();
  });
});

describe("research CLI aggregate commands", () => {
  it("validates a Flow hypothesis through the research command", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-research-cli-"));
    try {
      const requestPath = join(root, "request.json");
      await writeFile(requestPath, JSON.stringify({
        capability: "flow",
        hypothesis_version: "autovul.flow/1",
        hypothesis: model,
      }), "utf8");
      const output: string[] = [];
      const exitCode = await runCli(
        ["research", "validate", "--request", requestPath, "--json", "--runs-dir", root],
        { stdout: (value) => output.push(value), stderr: () => undefined },
      );
      expect(exitCode).toBe(0);
      const envelope = JSON.parse(output.join("")) as { ok: boolean; result?: { valid?: boolean } };
      expect(envelope.ok).toBe(true);
      expect(envelope.result?.valid).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
