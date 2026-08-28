import { describe, expect, it } from "vitest";

import {
  CONTRACTS_VERSION,
  DomainError,
  QueryCandidateSchema,
  parseSchema,
  type QueryVerification,
  type VulnerabilitySpec,
} from "@autovul/contracts";
import {
  Application,
  type CodeqlOperationOptions,
  type QueryExecutionPort,
  type QueryExecutionRequest,
  type QueryExecutionResult,
} from "@autovul/core";

import { FixedClock, FixedIdGenerator, MemoryArtifactStore, FakeCodeqlPort } from "./helpers.js";

async function waitFor(condition: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) {
      throw new Error("Timed out waiting for the workflow operation lease");
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "python-command-injection",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "Environment-controlled input reaches os.system.",
  patch_description: "Remove the tainted flow before shell execution.",
  vulnerable_database: { path: "/isolated/vulnerable", language: "python" },
  fixed_database: { path: "/isolated/fixed", language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
    source: { label: "source", description: "os.getenv" },
    sink: { label: "sink", description: "os.system" },
  },
  max_rounds: 3,
  timeout_ms: 30_000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: {
    fixture: "test/golden/python_command_injection",
    license: "repository fixture; see repository license",
    source: "AutoVul V1 Golden Cases",
  },
};

function candidate(id: string, round = 1): unknown {
  return {
    schema_version: CONTRACTS_VERSION,
    candidate_id: id,
    query_id: id,
    spec_id: spec.spec_id,
    language: "python",
    ql_text: "import python\nfrom DataFlow::Node source, DataFlow::Node sink\nselect sink, source, sink, \"flow\"",
    round,
    origin: "test",
  };
}

class FakeQueryExecution implements QueryExecutionPort {
  shouldCancel = false;
  delayMs = 0;
  flowSourceLine = 5;
  flowSinkLine = 6;
  readonly requests: QueryExecutionRequest[] = [];

  async execute(request: QueryExecutionRequest, _options: CodeqlOperationOptions): Promise<QueryExecutionResult> {
    this.requests.push(request);
    if (this.shouldCancel) {
      throw new DomainError("PROCESS_CANCELLED", "process", "cancelled", false);
    }
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    const failed = request.candidate.ql_text.includes("FAIL");
    return {
      compile: { status: failed ? "failed" : "passed", elapsed_ms: 2 },
      vulnerable: {
        database: "vulnerable",
        status: failed ? "failed" : "passed",
        result_count: failed ? 0 : 1,
        code_flow_count: failed ? 0 : 1,
        rule_ids: ["test-rule"],
        locations: [{ file: "app.py", start_line: this.flowSourceLine }],
        flow_evidence: [{
          path: [{ file: "app.py", start_line: this.flowSourceLine }, { file: "app.py", start_line: this.flowSinkLine }],
          source: { file: "app.py", start_line: this.flowSourceLine },
          sink: { file: "app.py", start_line: this.flowSinkLine },
        }],
        semantic_matches: [
          { role: "source", label: "source", locations: [{ file: "app.py", start_line: this.flowSourceLine }] },
          { role: "sink", label: "sink", locations: [{ file: "app.py", start_line: this.flowSinkLine }] },
        ],
        elapsed_ms: 3,
      },
      fixed: {
        database: "fixed",
        status: failed ? "failed" : "passed",
        result_count: failed ? 0 : 0,
        code_flow_count: 0,
        rule_ids: [],
        locations: [],
        flow_evidence: [],
        semantic_matches: [],
        elapsed_ms: 3,
      },
      diagnostics: [],
      elapsedMs: 8,
    };
  }
}

describe("M2 Python query workflow", () => {
  it("persists a passing differential verification and emits a replayable Query Pack", async () => {
    const artifacts = new MemoryArtifactStore();
    const queries = new FakeQueryExecution();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2pass"),
    });

    const started = await app.workflowStart(spec);
    expect(started.run.status).toBe("running");
    const verified = await app.queryVerify("run_m2pass", candidate("candidate-pass"));
    expect(verified.status).toBe("passed");
    expect(verified.verification_level).toBe("differential");
    expect(verified.vulnerable.code_flow_count).toBe(1);
    expect(verified.fixed.result_count).toBe(0);

    const pack = await app.workflowFinalize("run_m2pass");
    expect(pack.files.query).toBe("query.ql");
    expect(pack.files.candidate).toBe("candidate.json");
    expect(pack.files.evidence).toBe("evidence.json");
    expect(pack.files.reproduce).toBe("REPRODUCE.md");
    expect(pack.files.manifest).toBe("query-pack-manifest.json");
    expect(artifacts.artifacts.has("run_m2pass/query-pack/evidence.json")).toBe(true);
    expect(artifacts.artifacts.has("run_m2pass/query-pack/REPRODUCE.md")).toBe(true);
    expect(pack.replay.vulnerable).toContain("--output=vulnerable.sarif");
    const status = await app.workflowStatus("run_m2pass");
    expect(status.run.status).toBe("completed");
    expect(status.pack?.pack_id).toBe(pack.pack_id);
    expect(queries.requests).toHaveLength(1);
  });

  it("returns structured revision diagnostics without consuming a second workflow", async () => {
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2diag"),
    });
    await app.workflowStart(spec);
    const failed = await app.queryVerify("run_m2diag", {
      ...parseSchema(QueryCandidateSchema, candidate("candidate-fail"), "candidate"),
      ql_text: "FAIL",
    });
    expect(failed.status).toBe("failed");
    expect(failed.diagnostics.some((item) => item.code === "QUERY_COMPILE_FAILED")).toBe(true);
    expect((await app.workflowStatus("run_m2diag")).run.status).toBe("running");
  });

  it("returns language-neutral compile repair guidance for non-Python candidates", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const javascriptSpec: VulnerabilitySpec = {
      ...spec,
      spec_id: "javascript-command-injection",
      language: "javascript",
      vulnerable_database: { ...spec.vulnerable_database, language: "javascript" },
      fixed_database: { ...spec.fixed_database!, language: "javascript" },
    };
    const app = new Application({
      codeql,
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2language_hint"),
    });
    await app.workflowStart(javascriptSpec);
    const failed = await app.queryVerify("run_m2language_hint", {
      ...parseSchema(QueryCandidateSchema, candidate("candidate-javascript-fail"), "candidate"),
      spec_id: javascriptSpec.spec_id,
      language: "javascript",
      ql_text: "FAIL",
    });
    expect(failed.status).toBe("failed");
    expect(failed.repair_brief?.hints).toEqual([
      "Revise the structured javascript candidate; the language pack owns metadata, imports, module, PathGraph and select.",
    ]);
  });

  it("rejects a candidate whose language does not match the workflow before CodeQL", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const queries = new FakeQueryExecution();
    const javascriptSpec: VulnerabilitySpec = {
      ...spec,
      spec_id: "javascript-language-admission",
      language: "javascript",
      vulnerable_database: { ...spec.vulnerable_database, language: "javascript" },
      fixed_database: { ...spec.fixed_database!, language: "javascript" },
    };
    const app = new Application({
      codeql,
      queries,
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2language_admission"),
    });
    await app.workflowStart(javascriptSpec);
    await expect(app.queryVerify("run_m2language_admission", {
      ...parseSchema(QueryCandidateSchema, candidate("candidate-language-mismatch"), "candidate"),
      spec_id: javascriptSpec.spec_id,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(queries.requests).toHaveLength(0);
  });

  it("requires the authoritative flow to connect the probed Source and Sink for user cases", async () => {
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2probe-flow-gate"),
    });
    const userSpec: VulnerabilitySpec = {
      ...spec,
      project_root: "/project",
      fixed_database: undefined,
      input_provenance: "user_provided",
      validation: {
        ...spec.validation,
        source: { label: "source", description: "os.getenv", file: "app.py", line: 5 },
        sink: { label: "sink", description: "os.system", file: "app.py", line: 6 },
      },
    };
    await app.workflowStart(userSpec);
    const candidateInput = {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-probe-flow-gate",
      query_id: "candidate-probe-flow-gate",
      spec_id: spec.spec_id,
      language: "python",
      intent: {
        schema_version: CONTRACTS_VERSION,
        intent_id: "probe-flow-gate-intent",
        language: "python",
        cwe: "CWE-078",
        query_kind: "path-problem",
        flow_mode: "taint",
        source: { kind: "environment", name: "getenv" },
        sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
        message: "Environment-controlled input reaches os.system.",
      },
      probe_evidence: {
        schema_version: CONTRACTS_VERSION,
        probe_id: "probe-flow-gate",
        language: "python",
        intent_id: "probe-flow-gate-intent",
        status: "passed",
        source: { role: "source", locations: [{ file: "app.py", start_line: 50 }] },
        sink: { role: "sink", locations: [{ file: "app.py", start_line: 51 }] },
        diagnostics: ["probe passed"],
        elapsed_ms: 1,
      },
      round: 1,
      origin: "pi_generated",
    } as const;
    const verification = await app.queryVerify("run_m2probe-flow-gate", candidateInput);
    expect(verification.passed).toBe(false);
    expect(verification.diagnostics.filter((item) => item.code === "QUERY_SEMANTIC_MISMATCH")).toHaveLength(1);
    expect(verification.repair_brief?.next_action).toBe("revise_candidate");

    const passingApp = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2probe-flow-pass"),
    });
    await passingApp.workflowStart(userSpec);
    const passing = await passingApp.queryVerify("run_m2probe-flow-pass", {
      ...candidateInput,
      candidate_id: "candidate-probe-flow-pass",
      query_id: "candidate-probe-flow-pass",
      probe_evidence: {
        ...candidateInput.probe_evidence,
        probe_id: "probe-flow-pass",
        source: { role: "source", locations: [{ file: "app.py", start_line: 5 }] },
        sink: { role: "sink", locations: [{ file: "app.py", start_line: 6 }] },
      },
    });
    expect(passing.passed).toBe(true);
    expect(passing.fixed.status).toBe("not_run");
    expect(passing.diagnostics.some((item) => item.code === "QUERY_DIFFERENTIAL_NOT_RUN")).toBe(true);
  });

  it("requires exact Source/Sink locations for user cases even without a fixed database", async () => {
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2single-location-gate"),
    });
    const userSpec: VulnerabilitySpec = {
      ...spec,
      project_root: "/project",
      fixed_database: undefined,
      input_provenance: "user_provided",
      validation: {
        ...spec.validation,
        source: undefined,
        sink: undefined,
      },
    };

    await expect(app.workflowStart(userSpec)).rejects.toMatchObject({
      code: "SPEC_SEMANTIC_LOCATION_REQUIRED",
      details: { missing: ["source.file/source.line", "sink.file/sink.line"] },
    });
  });

  it("persists cancellation and does not finalize it as a successful pack", async () => {
    const artifacts = new MemoryArtifactStore();
    const queries = new FakeQueryExecution();
    queries.shouldCancel = true;
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2cancel"),
    });
    await app.workflowStart(spec);
    await expect(app.queryVerify("run_m2cancel", candidate("candidate-cancel"))).rejects.toMatchObject({
      code: "PROCESS_CANCELLED",
      details: { runId: "run_m2cancel" },
    });
    await expect(app.workflowFinalize("run_m2cancel")).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });
  });

  it("propagates workflow-start cancellation and persists the run id", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.inspectDelayMs = 100;
    const app = new Application({
      codeql,
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2startcancel"),
    });
    const controller = new AbortController();
    const starting = app.workflowStart(spec, { signal: controller.signal, timeoutMs: 1000 });
    setTimeout(() => controller.abort(), 5);
    await expect(starting).rejects.toMatchObject({ code: "PROCESS_CANCELLED", details: { runId: "run_m2startcancel" } });
    expect((await app.status("run_m2startcancel")).status).toBe("cancelled");
    expect(codeql.inspectedPaths).toHaveLength(1);
  });

  it("cancels a waiter without cancelling the operation that already owns the lease", async () => {
    const queries = new FakeQueryExecution();
    queries.delayMs = 40;
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2waitcancel"),
    });
    await app.workflowStart(spec);
    const first = app.queryVerify("run_m2waitcancel", candidate("candidate-owner"));
    await waitFor(() => artifacts.isRunOperationLocked("run_m2waitcancel"));
    const controller = new AbortController();
    const waiter = app.queryVerify("run_m2waitcancel", candidate("candidate-waiter"), { signal: controller.signal, timeoutMs: 1000 });
    controller.abort();
    await expect(waiter).rejects.toMatchObject({ code: "PROCESS_CANCELLED", details: { runId: "run_m2waitcancel", waitingForWorkflowLease: true } });
    await expect(first).resolves.toMatchObject({ passed: true });
    expect((await app.workflowStatus("run_m2waitcancel")).run.status).toBe("checkpointed");
  });

  it("marks a single-database run as reproduced rather than differential", async () => {
    const singleDatabaseSpec = { ...spec, fixed_database: undefined };
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2single"),
    });
    await app.workflowStart(singleDatabaseSpec);
    const verification = await app.queryVerify("run_m2single", candidate("candidate-single"));
    expect(verification.passed).toBe(true);
    expect(verification.verification_level).toBe("reproduced");
    expect(verification.fixed.status).toBe("not_run");
    expect(verification.diagnostics.some((item) => item.code === "QUERY_DIFFERENTIAL_NOT_RUN")).toBe(true);
    expect(verification.terminal_reason).toBe("candidate_passed");
    expect(verification.case_summary).toMatchObject({
      status: "active",
      total_candidates: 1,
      budget_used: 1,
      budget_remaining: 2,
    });
  });

  it("rejects a fourth candidate deterministically after the three-round budget", async () => {
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2budget"),
    });
    await app.workflowStart(spec);
    await app.queryVerify("run_m2budget", candidate("candidate-budget-1", 1));
    await app.queryVerify("run_m2budget", candidate("candidate-budget-2", 2));
    await app.queryVerify("run_m2budget", candidate("candidate-budget-3", 3));
    await expect(app.queryVerify("run_m2budget", candidate("candidate-budget-4", 3))).rejects.toMatchObject({
      code: "QUERY_BUDGET_EXCEEDED",
    });
  });

  it("binds the candidate budget to a case fingerprint instead of model-controlled spec_id", async () => {
    const artifacts = new MemoryArtifactStore();
    const first = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2case_a"),
    });
    const second = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2case_b"),
    });
    const started = await first.workflowStart(spec);
    const replay = await second.workflowStart({ ...spec, spec_id: "python-command-injection-retry" });
    expect(replay.run.runId).toBe(started.run.runId);
    expect(replay.case_summary.case_fingerprint).toBe(started.case_summary.case_fingerprint);
    expect(replay.case_summary.run_ids).toEqual([started.run.runId]);
    expect(artifacts.manifests.has("run_m2case_b")).toBe(false);
  });

  it("uses inspected canonical database identity so path aliases cannot reopen the case budget", async () => {
    const artifacts = new MemoryArtifactStore();
    const first = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2canonical_a"),
    });
    const second = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2canonical_b"),
    });
    const started = await first.workflowStart({
      ...spec,
      vulnerable_database: { ...spec.vulnerable_database, path: "/alias/vulnerable-a" },
      fixed_database: { ...spec.fixed_database!, path: "/alias/fixed-a" },
    });
    const replay = await second.workflowStart({
      ...spec,
      vulnerable_database: { ...spec.vulnerable_database, path: "/alias/vulnerable-b" },
      fixed_database: { ...spec.fixed_database!, path: "/alias/fixed-b" },
    });
    expect(replay.run.runId).toBe(started.run.runId);
    expect(replay.case_summary.case_fingerprint).toBe(started.case_summary.case_fingerprint);
    expect(artifacts.manifests.has("run_m2canonical_b")).toBe(false);
  });

  it("terminates a case after three failed candidates and exposes a deterministic summary", async () => {
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2exhaust"),
    });
    await app.workflowStart(spec);
    let lastVerification: QueryVerification | undefined;
    for (const [id, round] of [["candidate-exhaust-1", 1], ["candidate-exhaust-2", 2], ["candidate-exhaust-3", 3]] as const) {
      lastVerification = await app.queryVerify("run_m2exhaust", {
        ...parseSchema(QueryCandidateSchema, candidate(id, round), "candidate"),
        ql_text: "FAIL",
      });
      expect(lastVerification.passed).toBe(false);
    }
    expect(lastVerification).toMatchObject({
      terminal_reason: "budget_exhausted",
      case_summary: {
        status: "budget_exhausted",
        total_candidates: 3,
        budget_used: 3,
        budget_remaining: 0,
      },
    });
    const status = await app.workflowStatus("run_m2exhaust");
    expect(status.run.status).toBe("budget_exhausted");
    expect(status.case_summary.status).toBe("budget_exhausted");
    expect(status.case_summary.total_candidates).toBe(3);
    expect(status.case_summary.budget_remaining).toBe(0);
    await expect(app.queryVerify("run_m2exhaust", candidate("candidate-exhaust-4", 3))).rejects.toMatchObject({
      code: "QUERY_BUDGET_EXCEEDED",
    });
  });

  it("serializes concurrent candidates without losing state or leaking a filesystem lock error", async () => {
    const artifacts = new MemoryArtifactStore();
    const queries = new FakeQueryExecution();
    queries.delayMs = 2;
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2concurrency"),
    });
    await app.workflowStart(spec);
    const results = await Promise.allSettled(Array.from({ length: 24 }, (_, index) =>
      app.queryVerify("run_m2concurrency", candidate(`candidate-concurrent-${index + 1}`))));
    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(3);
    expect(results.filter((item) => item.status === "rejected").every((item) =>
      item.reason?.code === "QUERY_BUDGET_EXCEEDED")).toBe(true);
    const status = await app.workflowStatus("run_m2concurrency");
    expect(status.candidates).toHaveLength(3);
    expect(status.verifications).toHaveLength(3);
    expect(queries.requests).toHaveLength(3);
  });

  it("makes candidate identity idempotent and rejects changed content before CodeQL", async () => {
    const queries = new FakeQueryExecution();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2idempotent"),
    });
    await app.workflowStart(spec);
    const first = await app.queryVerify("run_m2idempotent", candidate("candidate-idempotent"));
    const replay = await app.queryVerify("run_m2idempotent", candidate("candidate-idempotent"));
    expect(replay.verification_id).toBe(first.verification_id);
    expect(queries.requests).toHaveLength(1);
    await expect(app.queryVerify("run_m2idempotent", {
      ...parseSchema(QueryCandidateSchema, candidate("candidate-idempotent"), "candidate"),
      ql_text: "changed query",
    })).rejects.toMatchObject({ code: "QUERY_INVALID_CANDIDATE" });
    expect(queries.requests).toHaveLength(1);
  });

  it("does not reopen the same case when only operational policy changes", async () => {
    const artifacts = new MemoryArtifactStore();
    const first = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2identity_a"),
    });
    const second = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2identity_b"),
    });
    const started = await first.workflowStart(spec);
    const changedPolicy = {
      ...spec,
      spec_id: "same-visible-label-but-not-case-identity",
      max_rounds: 1,
      timeout_ms: spec.timeout_ms + 60_000,
      created_at: "2099-01-01T00:00:00.000Z",
      validation: { ...spec.validation, vulnerable_max_results: 9 },
      provenance: { ...spec.provenance, source: "changed run policy text" },
    };
    const resumed = await second.workflowStart(changedPolicy);
    expect(resumed.run.runId).toBe(started.run.runId);
    expect(resumed.case_summary.budget_used).toBe(0);
  });

  it("rejects a result whose flow endpoints do not match the declared Source/Sink", async () => {
    const queries = new FakeQueryExecution();
    queries.flowSinkLine = 99;
    const strictSpec = {
      ...spec,
      validation: {
        ...spec.validation,
        source: { label: "source", description: "os.getenv", file: "app.py", line: 5 },
        sink: { label: "sink", description: "os.system", file: "app.py", line: 6 },
      },
    };
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2semantic"),
    });
    await app.workflowStart(strictSpec);
    const verification = await app.queryVerify("run_m2semantic", candidate("candidate-semantic"));
    expect(verification.passed).toBe(false);
    expect(verification.diagnostics.some((item) => item.code === "QUERY_SEMANTIC_MISMATCH")).toBe(true);
  });

  it("does not accept a basename when strict Source/Sink paths differ", async () => {
    const strictSpec = {
      ...spec,
      validation: {
        ...spec.validation,
        source: { label: "source", description: "os.getenv", file: "src/app.py", line: 5 },
        sink: { label: "sink", description: "os.system", file: "src/app.py", line: 6 },
      },
    };
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries: new FakeQueryExecution(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m2basename"),
    });
    await app.workflowStart(strictSpec);
    const verification = await app.queryVerify("run_m2basename", candidate("candidate-basename"));
    expect(verification.passed).toBe(false);
    expect(verification.diagnostics.some((item) => item.code === "QUERY_SEMANTIC_MISMATCH")).toBe(true);
  });

  it.each([
    ["wrong source", 99, 6],
    ["reversed direction", 6, 5],
  ])("rejects a %s flow even when result and flow counts pass", async (_label, sourceLine, sinkLine) => {
    const queries = new FakeQueryExecution();
    queries.flowSourceLine = sourceLine;
    queries.flowSinkLine = sinkLine;
    const strictSpec = {
      ...spec,
      validation: {
        ...spec.validation,
        source: { label: "source", description: "os.getenv", file: "app.py", line: 5 },
        sink: { label: "sink", description: "os.system", file: "app.py", line: 6 },
      },
    };
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      queries,
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator(`run_m2_semantic_${String(sourceLine)}_${String(sinkLine)}`),
    });
    const runId = `run_m2_semantic_${String(sourceLine)}_${String(sinkLine)}`;
    await app.workflowStart(strictSpec);
    const verification = await app.queryVerify(runId, candidate(`candidate-semantic-${sourceLine}-${sinkLine}`));
    expect(verification.vulnerable.result_count).toBe(1);
    expect(verification.vulnerable.code_flow_count).toBe(1);
    expect(verification.passed).toBe(false);
    expect(verification.diagnostics.some((item) => item.code === "QUERY_SEMANTIC_MISMATCH")).toBe(true);
  });
});
