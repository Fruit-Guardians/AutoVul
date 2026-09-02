import { describe, expect, it } from "vitest";

import {
  DomainError,
  type TypestateAnalyzerObservation,
  type TypestateHypothesis,
} from "@autovul/contracts";
import {
  RunCancellationService,
  RunStatusService,
  TypestateResearchService,
  readTypestateRunArtifact,
  type TypestateExecutionPort,
} from "@autovul/core";
import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const scope = {
  kind: "single_file_named_function" as const,
  file: "fixture.js",
  entry: { kind: "named_function" as const, name: "login" },
  event_scope: "named_function_including_inline_callbacks" as const,
  alias_boundary: "direct_lexical_binding" as const,
};

const hypothesis: TypestateHypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-service",
  language: "javascript",
  resource: { id: "login_session", kind: "local_binding", binding_name: "session", acquisition_event: "session_acquired", identity_model: "direct_lexical_binding" },
  initial_state: "preauth",
  states: ["preauth", "rekeyed", "authenticated"],
  events: [
    { id: "session_acquired", selector: { kind: "direct_call", name: "getSession" } },
    { id: "regenerate_request_session", selector: { kind: "direct_method", receiver: "req.session", name: "regenerate" } },
    { id: "assign_user", selector: { kind: "direct_call", name: "assignUserToSession", argument_property: "session" } },
  ],
  transitions: [
    { from_state: "preauth", event: "session_acquired", to_state: "preauth" },
    { from_state: "preauth", event: "regenerate_request_session", to_state: "rekeyed" },
    { from_state: "rekeyed", event: "assign_user", to_state: "authenticated" },
  ],
  violation: { kind: "prohibited_transition", from_state: "preauth", event: "assign_user", to_state: "authenticated", requires_same_identity: true },
  analysis_scope: scope,
};

const location = { file: "fixture.js", start_line: 10 };

function observation(overrides: Partial<TypestateAnalyzerObservation> = {}): TypestateAnalyzerObservation {
  return {
    schema_version: "autovul.typestate/1",
    compile_accepted: true,
    resource: { state: "observed", locations: [location], identity_evidence: ["direct_lexical_binding:login_session"] },
    events: [
      { event_id: "session_acquired", state: "observed", locations: [location] },
      { event_id: "regenerate_request_session", state: "not_found", locations: [] },
      { event_id: "assign_user", state: "observed", locations: [location] },
    ],
    traces: [{
      state: "violating_witness",
      resource_id: "login_session",
      events: [
        { event_id: "session_acquired", from_state: "preauth", to_state: "preauth", location },
        { event_id: "assign_user", from_state: "preauth", to_state: "authenticated", location },
      ],
      identity_evidence: [{ kind: "same_binding", resource_id: "login_session", event_ids: ["session_acquired", "assign_user"], locations: [location] }],
      violation_step: 1,
      evidence_ref: "typestate/tstate-service/vulnerable/violation.sarif",
    }],
    completeness: { vulnerable: { status: "complete", scope, limitations: ["cross_file_aliases_excluded"] } },
    capability_gaps: [],
    evidence_refs: ["typestate/tstate-service/vulnerable/violation.sarif"],
    analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "test_double", version: "CodeQL CLI 2.26.1", adapter_version: "autovul.codeql-typestate/1" },
    ...overrides,
  };
}

function requestFor(idempotencyKey: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    action: "execute",
    capability: "typestate",
    hypothesis_version: "autovul.typestate/1",
    hypothesis,
    target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } },
    analyzer_id: "codeql",
    mode: "reproduce",
    budget: { timeout_ms: 5_000 },
    idempotency_key: idempotencyKey,
    ...overrides,
  };
}

function serviceFor(
  execution: TypestateExecutionPort,
  codeql = new FakeCodeqlPort(),
  artifacts = new MemoryArtifactStore(),
): { readonly service: TypestateResearchService; readonly codeql: FakeCodeqlPort; readonly artifacts: MemoryArtifactStore } {
  const status = new RunStatusService(artifacts, new FixedClock(), new FixedIdGenerator());
  const service = new TypestateResearchService(status, codeql, execution, artifacts, new RunCancellationService());
  return { service, codeql, artifacts };
}

describe("TypestateResearchService", () => {
  it("keeps validate side-effect free and executes one normalized hypothesis", async () => {
    let executions = 0;
    const execution: TypestateExecutionPort = { async execute(): Promise<TypestateAnalyzerObservation> { executions += 1; return observation(); } };
    const { service, artifacts } = serviceFor(execution);

    const validated = await service.research({ action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis }, { timeoutMs: 5_000 });
    expect(validated).toMatchObject({ valid: true, allowed_next_actions: ["execute", "stop"] });
    expect(executions).toBe(0);
    expect(artifacts.manifests.size).toBe(0);

    const result = await service.research(requestFor("service-execute"), { timeoutMs: 5_000 });
    expect(result).toMatchObject({ capability: "typestate", operation_status: "completed", decision: { outcome: "violation_observed" }, verification_level: "generated" });
    expect(executions).toBe(1);
  });

  it("fingerprints targets and atomically commits route plus Typestate artifact", async () => {
    const execution: TypestateExecutionPort = { async execute(): Promise<TypestateAnalyzerObservation> { return observation(); } };
    const { service, codeql, artifacts } = serviceFor(execution);
    const result = await service.research(requestFor("service-commit"), { timeoutMs: 5_000 });
    if (!("run_id" in result)) throw new Error("expected execution result");

    const runId = result.run_id;
    expect(codeql.database.portableFingerprint).toBe("0123456789abcdef");
    expect(artifacts.artifacts.has(`${runId}/research/operation.json`)).toBe(true);
    const rawArtifact = await artifacts.readArtifact(runId, "research/typestate/result.json");
    const artifact = rawArtifact === undefined ? undefined : readTypestateRunArtifact(rawArtifact);
    expect(artifact).toMatchObject({
      capability: "typestate",
      hypothesis_version: "autovul.typestate/1",
      target_fingerprints: { vulnerable: "0123456789abcdef" },
      decision_policy_version: "autovul.typestate.decision/1",
      observation: { analyzer: { adapter_version: "autovul.codeql-typestate/1" } },
    });
    expect(JSON.parse(await artifacts.readArtifact(runId, "research/operation.json") ?? "null")).toEqual({ schema_version: "v2.contracts/1", route_kind: "capability", capability: "typestate", hypothesis_version: "autovul.typestate/1", result_artifact_ref: "research/typestate/result.json" });
    expect(artifacts.manifests.get(runId)?.phase).toBe("typestate_execute");
    expect(artifacts.manifests.get(runId)?.status).toBe("completed");
  });

  it("reuses a committed result for the same request and rejects an idempotency conflict", async () => {
    let executions = 0;
    const execution: TypestateExecutionPort = { async execute(): Promise<TypestateAnalyzerObservation> { executions += 1; return observation(); } };
    const { service } = serviceFor(execution);
    const first = await service.research(requestFor("service-idempotent"), { timeoutMs: 5_000 });
    const second = await service.research(requestFor("service-idempotent"), { timeoutMs: 5_000 });
    expect(second).toEqual(first);
    expect(executions).toBe(1);

    await expect(service.research(requestFor("service-idempotent", { target: { vulnerable: { kind: "codeql_database", path: "/isolated/other" } } }), { timeoutMs: 5_000 })).rejects.toMatchObject({ code: "IDEMPOTENCY_KEY_CONFLICT" });
  });

  it("keeps fingerprint, analyzer version, and cancellation failures out of completed decisions", async () => {
    const fingerprintCodeql = new FakeCodeqlPort();
    const fingerprintExecution: TypestateExecutionPort = { async execute(): Promise<TypestateAnalyzerObservation> { throw new Error("must not execute"); } };
    const fingerprint = serviceFor(fingerprintExecution, fingerprintCodeql);
    const fingerprintResult = await fingerprint.service.research(requestFor("service-fingerprint", { target: { vulnerable: { kind: "codeql_database", path: "/isolated/v", expected_fingerprint: "fedcba9876543210" } } }), { timeoutMs: 5_000 });
    expect(fingerprintResult).toMatchObject({ operation_status: "blocked", decision: { outcome: "unknown" }, observations: [{ code: "TSTATE_TARGET_FINGERPRINT_MISMATCH" }] });

    const versionExecution: TypestateExecutionPort = { async execute(): Promise<TypestateAnalyzerObservation> { return observation({ analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", adapter_version: "autovul.codeql-typestate/1" } }); } };
    const version = serviceFor(versionExecution);
    const versionResult = await version.service.research(requestFor("service-version"), { timeoutMs: 5_000 });
    expect(versionResult).toMatchObject({ operation_status: "blocked", decision: { outcome: "unknown" }, observations: [{ code: "TSTATE_ANALYZER_VERSION_UNAVAILABLE" }] });

    let started!: () => void;
    const startedPromise = new Promise<void>((resolve) => { started = resolve; });
    const cancellationExecution: TypestateExecutionPort = { async execute(_request, options): Promise<TypestateAnalyzerObservation> {
      started();
      return new Promise((_resolve, reject) => options.signal?.addEventListener("abort", () => reject(new DomainError("PROCESS_CANCELLED", "process", "cancelled", false)), { once: true }));
    } };
    const cancellation = serviceFor(cancellationExecution);
    const controller = new AbortController();
    const pending = cancellation.service.research(requestFor("service-cancel"), { timeoutMs: 5_000, signal: controller.signal });
    await startedPromise;
    controller.abort();
    const cancelled = await pending;
    expect(cancelled).toMatchObject({ operation_status: "cancelled", decision: { outcome: "unknown" }, observations: [{ code: "TSTATE_EXECUTION_CANCELLED" }] });
  });
});
