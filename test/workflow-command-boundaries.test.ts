import { describe, expect, it } from "vitest";

import {
  Application,
  type CodeqlOperationOptions,
  type QueryDraftExecutionPort,
  type QueryDraftRequest,
  type QueryExecutionPort,
  type QueryExecutionRequest,
  type QueryProbeExecutionPort,
  type QueryProbeRequest,
} from "@pure-auto-codeql/core";
import { CONTRACTS_VERSION, DomainError, type VulnerabilitySpec } from "@pure-auto-codeql/contracts";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "boundary-test",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "input reaches a shell sink",
  vulnerable_database: { path: "/isolated/vulnerable", language: "python" },
  fixed_database: { path: "/isolated/fixed", language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
    source: { label: "source", description: "environment" },
    sink: { label: "sink", description: "shell" },
  },
  max_rounds: 3,
  timeout_ms: 30_000,
  created_at: "2026-08-27T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test/boundary", license: "test", source: "boundary" },
};

function candidate(): unknown {
  return {
    schema_version: CONTRACTS_VERSION,
    candidate_id: "boundary-candidate",
    query_id: "boundary-query",
    spec_id: spec.spec_id,
    language: "python",
    ql_text: "select 1",
    round: 1,
    origin: "test",
  };
}

class CancelledProbe implements QueryProbeExecutionPort {
  async executeProbe(_request: QueryProbeRequest, _options: CodeqlOperationOptions): Promise<never> {
    throw new DomainError("PROCESS_CANCELLED", "process", "probe cancelled", false);
  }
}

class CancelledDraft implements QueryDraftExecutionPort {
  async executeDraft(_request: QueryDraftRequest, _options: CodeqlOperationOptions): Promise<never> {
    throw new DomainError("PROCESS_CANCELLED", "process", "draft cancelled", false);
  }
}

class CancelledQuery implements QueryExecutionPort {
  async execute(_request: QueryExecutionRequest, _options: CodeqlOperationOptions): Promise<never> {
    throw new DomainError("PROCESS_CANCELLED", "process", "verify cancelled", false);
  }
}

class CancelledLeaseStore extends MemoryArtifactStore {
  override withRunOperation<T>(runId: string, options: CodeqlOperationOptions, operation: () => Promise<T>): Promise<T> {
    if (options.signal?.aborted === true) {
      return Promise.reject(new DomainError("PROCESS_CANCELLED", "process", "cancelled while waiting", false, { runId, waitingForWorkflowLease: true }));
    }
    return super.withRunOperation(runId, options, operation);
  }
}

function app(artifacts: MemoryArtifactStore, overrides: { probes?: QueryProbeExecutionPort; drafts?: QueryDraftExecutionPort; queries?: QueryExecutionPort } = {}): Application {
  return new Application({
    codeql: new FakeCodeqlPort(),
    artifacts,
    clock: new FixedClock(),
    ids: new FixedIdGenerator("run_boundary"),
    probes: overrides.probes,
    drafts: overrides.drafts,
    queries: overrides.queries,
  });
}

describe("extracted workflow command boundaries", () => {
  it("persists probe cancellation and leaves no candidate success", async () => {
    const artifacts = new MemoryArtifactStore();
    const application = app(artifacts, { probes: new CancelledProbe() });
    await application.workflowStart(spec);
    await expect(application.queryProbe("run_boundary", { schema_version: CONTRACTS_VERSION, intent_id: "boundary-intent", language: "python", cwe: "CWE-078", query_kind: "path-problem", flow_mode: "taint", source: { kind: "environment", name: "value" }, sink: { kind: "call", module: "os", member: "system" }, message: "input reaches shell" })).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });
    expect((await application.workflowStatus("run_boundary")).run.status).toBe("cancelled");
    expect((await application.workflowStatus("run_boundary")).candidates).toHaveLength(0);
  });

  it("persists draft cancellation without recording a formal candidate", async () => {
    const application = app(new MemoryArtifactStore(), { drafts: new CancelledDraft() });
    await application.workflowStart(spec);
    await expect(application.queryDraft("run_boundary", candidate())).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });
    expect((await application.workflowStatus("run_boundary")).run.status).toBe("cancelled");
    expect((await application.workflowStatus("run_boundary")).candidates).toHaveLength(0);
  });

  it("persists authoritative verification cancellation before state mutation", async () => {
    const artifacts = new MemoryArtifactStore();
    const application = app(artifacts, { queries: new CancelledQuery() });
    await application.workflowStart(spec);
    await expect(application.queryVerify("run_boundary", candidate())).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });
    expect((await application.workflowStatus("run_boundary")).run.status).toBe("cancelled");
    expect((await application.workflowStatus("run_boundary")).candidates).toHaveLength(0);
    expect(artifacts.artifacts.has("run_boundary/workflow/state.json")).toBe(true);
  });

  it("distinguishes finalization lease cancellation from cancelling its owner", async () => {
    const artifacts = new CancelledLeaseStore();
    const application = app(artifacts);
    await application.workflowStart(spec);
    const controller = new AbortController();
    controller.abort();
    await expect(application.workflowFinalize("run_boundary", { signal: controller.signal })).rejects.toMatchObject({
      code: "PROCESS_CANCELLED",
      details: { waitingForWorkflowLease: true },
    });
    expect((await application.workflowStatus("run_boundary")).run.status).toBe("running");
  });
});
