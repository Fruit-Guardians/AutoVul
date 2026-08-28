import { describe, expect, it } from "vitest";

import {
  type CodeqlOperationOptions,
  type QueryExecutionPort,
  type QueryExecutionRequest,
  type QueryExecutionResult,
  type QueryProbeExecutionPort,
  type QueryProbeRequest,
  type QueryDraftExecutionPort,
  type QueryDraftRequest,
  Application,
} from "@autovul/core";
import { CONTRACTS_VERSION, DomainError, type VulnerabilitySpec } from "@autovul/contracts";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "javascript-command-injection",
  language: "javascript",
  cwe: "CWE-078",
  vulnerability_description: "Request input reaches child_process.exec.",
  vulnerable_database: { path: "/isolated/javascript-vulnerable", language: "javascript" },
  fixed_database: { path: "/isolated/javascript-fixed", language: "javascript" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
    source: { label: "source", description: "request" },
    sink: { label: "sink", description: "exec" },
  },
  max_rounds: 3,
  timeout_ms: 30_000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "m3/javascript-command-injection", license: "test", source: "M3 fixture" },
};

class PassingQuery implements QueryExecutionPort {
  async execute(_request: QueryExecutionRequest, _options: CodeqlOperationOptions): Promise<QueryExecutionResult> {
    return {
      compile: { status: "passed", elapsed_ms: 1 },
      vulnerable: {
        database: "vulnerable", status: "passed", result_count: 1, code_flow_count: 1,
        rule_ids: ["pure-auto-codeql/javascript-command-injection"], locations: [{ file: "app.js", start_line: 8 }],
        flow_evidence: [{ path: [{ file: "app.js", start_line: 5 }, { file: "app.js", start_line: 8 }], source: { file: "app.js", start_line: 5 }, sink: { file: "app.js", start_line: 8 } }],
        semantic_matches: [{ role: "source", label: "source", locations: [{ file: "app.js", start_line: 5 }] }, { role: "sink", label: "sink", locations: [{ file: "app.js", start_line: 8 }] }], elapsed_ms: 1,
      },
      fixed: {
        database: "fixed", status: "passed", result_count: 0, code_flow_count: 0,
        rule_ids: [], locations: [], flow_evidence: [], semantic_matches: [], elapsed_ms: 1,
      },
      diagnostics: [], elapsedMs: 3,
    };
  }
}

class PassingProbe implements QueryProbeExecutionPort {
  async executeProbe(request: QueryProbeRequest, _options: CodeqlOperationOptions) {
    return {
      schema_version: CONTRACTS_VERSION,
      probe_id: `${request.intent.intent_id}-javascript`,
      language: request.intent.language,
      intent_id: request.intent.intent_id,
      status: "passed" as const,
      source: { role: "source" as const, locations: [{ file: "app.js", start_line: 5 }] },
      sink: { role: "sink" as const, locations: [{ file: "app.js", start_line: 8 }] },
      diagnostics: ["Source and sink probes completed"],
      elapsed_ms: 1,
    };
  }
}

class PassingDraft implements QueryDraftExecutionPort {
  closed = false;

  async executeDraft(request: QueryDraftRequest, _options: CodeqlOperationOptions) {
    return {
      schema_version: CONTRACTS_VERSION,
      draft_id: `${request.runId}-${request.candidate.candidate_id}`,
      run_id: request.runId,
      candidate_id: request.candidate.candidate_id,
      revision: request.revision,
      draft_revision_budget: request.draftRevisionBudget,
      status: "clean" as const,
      lsp_available: true,
      diagnostics: [],
      definition_locations: [],
      hover_text: [],
      completion_labels: [],
      elapsed_ms: 1,
    };
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class RejectingDraft implements QueryDraftExecutionPort {
  async executeDraft(request: QueryDraftRequest, _options: CodeqlOperationOptions) {
    return {
      schema_version: CONTRACTS_VERSION,
      draft_id: `${request.runId}-${request.candidate.candidate_id}`,
      run_id: request.runId,
      candidate_id: request.candidate.candidate_id,
      revision: request.revision,
      draft_revision_budget: request.draftRevisionBudget,
      status: "errors" as const,
      lsp_available: true,
      diagnostics: [{ schema_version: CONTRACTS_VERSION, severity: "error" as const, message: "unresolved QL symbol", file: "query.ql", start_line: 2, related_locations: [] }],
      definition_locations: [],
      hover_text: [],
      completion_labels: [],
      elapsed_ms: 1,
    };
  }
}

describe("M3 language-neutral workflow", () => {
  it("closes the draft adapter when the application closes", async () => {
    const draft = new PassingDraft();
    const app = new Application({ codeql: new FakeCodeqlPort(), drafts: draft, artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_m3close") });

    await app.close();
    await app.close();

    expect(draft.closed).toBe(true);
  });

  it("routes a JavaScript intent through the same Core workflow and selects javascript-all", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const artifacts = new MemoryArtifactStore();
    const app = new Application({ codeql, queries: new PassingQuery(), artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_m3jstest") });
    await app.workflowStart(spec);
    const verification = await app.queryVerify("run_m3jstest", {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-js-1",
      query_id: "javascript-command-injection",
      spec_id: spec.spec_id,
      language: "javascript",
      intent: {
        schema_version: CONTRACTS_VERSION,
        intent_id: "javascript-command-injection",
        language: "javascript",
        cwe: "CWE-078",
        query_kind: "path-problem",
        flow_mode: "taint",
        source: { kind: "environment", name: "env" },
        sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 },
        message: "Request input reaches exec.",
      },
      round: 1,
      origin: "test",
    });
    expect(verification.passed).toBe(true);
    const pack = await app.workflowFinalize("run_m3jstest");
    expect(pack.language).toBe("javascript");
    expect(await artifacts.readArtifact("run_m3jstest", "query-pack/qlpack.yml")).toContain("codeql/javascript-all");
  });

  it("persists structured probe evidence before query verification", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const artifacts = new MemoryArtifactStore();
    const app = new Application({ codeql, queries: new PassingQuery(), probes: new PassingProbe(), artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_m3probe") });
    await app.workflowStart(spec);
    const evidence = await app.queryProbe("run_m3probe", {
      schema_version: CONTRACTS_VERSION,
      intent_id: "javascript-command-injection",
      language: "javascript",
      cwe: "CWE-078",
      query_kind: "path-problem",
      flow_mode: "taint",
      source: { kind: "environment", name: "env" },
      sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 },
      message: "Request input reaches exec.",
    });
    expect(evidence.status).toBe("passed");
    expect(evidence.source.locations[0]?.start_line).toBe(5);
    expect(await artifacts.readArtifact("run_m3probe", "probes/javascript-command-injection/probe-evidence.json")).toContain("Source and sink probes completed");
  });

  it("hydrates persisted probe evidence when Pi omits the repeated JSON envelope", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql,
      queries: new PassingQuery(),
      probes: new PassingProbe(),
      drafts: new PassingDraft(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m3hydrate"),
    });
    const userSpec: VulnerabilitySpec = {
      ...spec,
      project_root: "/project",
      fixed_database: undefined,
      input_provenance: "user_provided",
      validation: {
        ...spec.validation,
        source: { label: "source", description: "request", file: "app.js", line: 5 },
        sink: { label: "sink", description: "exec", file: "app.js", line: 8 },
      },
    };
    await app.workflowStart(userSpec);
    const intent = {
      schema_version: CONTRACTS_VERSION,
      intent_id: "javascript-hydrate-intent",
      language: "javascript" as const,
      cwe: "CWE-078",
      query_kind: "path-problem" as const,
      flow_mode: "taint" as const,
      source: { kind: "environment" as const, name: "env" },
      sink: { kind: "call" as const, module: "child_process", member: "exec", argument_index: 0 },
      message: "Request input reaches exec.",
    };
    await app.queryProbe("run_m3hydrate", intent);
    const candidate = {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-hydrate",
      query_id: "javascript-hydrate",
      spec_id: spec.spec_id,
      language: "javascript" as const,
      intent,
      round: 1,
      origin: "pi_generated" as const,
    };
    expect((await app.queryDraft("run_m3hydrate", candidate)).status).toBe("clean");
    expect((await app.queryVerify("run_m3hydrate", candidate)).passed).toBe(true);
  });

  it("keeps LSP drafts outside the formal three-candidate budget", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const artifacts = new MemoryArtifactStore();
    const app = new Application({ codeql, queries: new PassingQuery(), probes: new PassingProbe(), drafts: new PassingDraft(), artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_m3draft") });
    await app.workflowStart(spec);
    const candidate = {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-draft-1",
      query_id: "javascript-command-injection",
      spec_id: spec.spec_id,
      language: "javascript" as const,
      intent: {
        schema_version: CONTRACTS_VERSION,
        intent_id: "javascript-command-injection",
        language: "javascript" as const,
        cwe: "CWE-078",
        query_kind: "path-problem" as const,
        flow_mode: "taint" as const,
        source: { kind: "environment" as const, name: "env" },
        sink: { kind: "call" as const, module: "child_process", member: "exec", argument_index: 0 },
        message: "Request input reaches exec.",
      },
      round: 1,
      origin: "test" as const,
    };
    const draft = await app.queryDraft("run_m3draft", candidate);
    expect(draft.status).toBe("clean");
    let lastDraft = draft;
    for (let revision = 2; revision <= 6; revision += 1) {
      lastDraft = await app.queryDraft("run_m3draft", candidate);
    }
    expect(lastDraft.revision).toBe(6);
    await expect(app.queryDraft("run_m3draft", candidate)).rejects.toMatchObject({ code: "QUERY_BUDGET_EXCEEDED" });
    expect((await app.workflowStatus("run_m3draft")).candidates).toHaveLength(0);
    expect(await artifacts.readArtifact("run_m3draft", "drafts/candidate-draft-1/report.json")).toContain("lsp_available");
    const verification = await app.queryVerify("run_m3draft", candidate);
    expect(verification.passed).toBe(true);
    expect((await app.workflowStatus("run_m3draft")).case_summary.budget_used).toBe(1);
  });

  it("does not send an LSP-error draft to the authoritative CLI or consume budget", async () => {
    const codeql = new FakeCodeqlPort();
    codeql.database = { ...codeql.database, language: "javascript" };
    const artifacts = new MemoryArtifactStore();
    const queries = new PassingQuery();
    const app = new Application({ codeql, queries, drafts: new RejectingDraft(), artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_m3draftgate") });
    await app.workflowStart(spec);
    const candidate = {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-draft-gate",
      query_id: "javascript-command-injection",
      spec_id: spec.spec_id,
      language: "javascript" as const,
      ql_text: "select 1",
      round: 1,
      origin: "test" as const,
    };
    await app.queryDraft("run_m3draftgate", candidate);
    await expect(app.queryVerify("run_m3draftgate", candidate)).rejects.toMatchObject({ code: "QUERY_DRAFT_INVALID" });
    expect((await app.workflowStatus("run_m3draftgate")).candidates).toHaveLength(0);
  });

  it("keeps the run active when a probe intent needs Pi repair", async () => {
    const codeql = new FakeCodeqlPort();
    const artifacts = new MemoryArtifactStore();
    const repairProbe: QueryProbeExecutionPort = {
      async executeProbe() {
        throw new DomainError("CAPABILITY_MISMATCH", "input", "Python call matcher requires module and member", false);
      },
    };
    const app = new Application({ codeql, queries: new PassingQuery(), probes: repairProbe, artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_m3repair") });
    const pythonSpec: VulnerabilitySpec = {
      ...spec,
      spec_id: "python-probe-repair",
      language: "python",
      vulnerable_database: { path: "/isolated/python-vulnerable", language: "python" },
      fixed_database: { path: "/isolated/python-fixed", language: "python" },
    };
    await app.workflowStart(pythonSpec);
    await expect(app.queryProbe("run_m3repair", {
      schema_version: CONTRACTS_VERSION,
      intent_id: "python-probe-repair",
      language: "python",
      cwe: "CWE-078",
      query_kind: "path-problem",
      flow_mode: "taint",
      source: { kind: "parameter", name: "value" },
      sink: { kind: "call" },
      message: "value reaches a sink.",
    })).rejects.toMatchObject({ code: "CAPABILITY_MISMATCH" });
    const status = await app.workflowStatus("run_m3repair");
    expect(status.run.status).toBe("running");
    expect(status.case_summary.status).toBe("active");
    expect(status.case_summary.budget_used).toBe(0);
  });

  it("recovers a stale active case summary after a terminal probe failure", async () => {
    const artifacts = new MemoryArtifactStore();
    const crashingProbe: QueryProbeExecutionPort = {
      async executeProbe() {
        throw new DomainError("PROCESS_CRASHED", "process", "probe crashed", false);
      },
    };
    const firstCodeql = new FakeCodeqlPort();
    firstCodeql.database = { ...firstCodeql.database, language: "javascript" };
    const first = new Application({
      codeql: firstCodeql,
      queries: new PassingQuery(),
      probes: crashingProbe,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m3stale_a"),
    });
    await first.workflowStart(spec);
    await expect(first.queryProbe("run_m3stale_a", {
      schema_version: CONTRACTS_VERSION,
      intent_id: "javascript-command-injection",
      language: "javascript",
      cwe: "CWE-078",
      query_kind: "path-problem",
      flow_mode: "taint",
      source: { kind: "environment", name: "env" },
      sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 },
      message: "Request input reaches exec.",
    })).rejects.toMatchObject({ code: "PROCESS_CRASHED" });

    const secondCodeql = new FakeCodeqlPort();
    secondCodeql.database = { ...secondCodeql.database, language: "javascript" };
    const second = new Application({
      codeql: secondCodeql,
      queries: new PassingQuery(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_m3stale_b"),
    });
    const restarted = await second.workflowStart(spec);
    expect(restarted.run.runId).toBe("run_m3stale_b");
    expect(restarted.case_summary.status).toBe("active");
    expect(restarted.case_summary.run_ids).toEqual(["run_m3stale_a", "run_m3stale_b"]);
  });
});
