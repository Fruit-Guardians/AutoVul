import { describe, expect, it } from "vitest";

import {
  Application,
  type CodeqlOperationOptions,
  type QueryDraftExecutionPort,
  type QueryDraftRequest,
  type QueryExecutionPort,
  type QueryExecutionRequest,
  type QueryExecutionResult,
  type QueryProbeExecutionPort,
  type QueryProbeRequest,
} from "@pure-auto-codeql/core";
import { CONTRACTS_VERSION, DomainError, type VulnerabilitySpec } from "@pure-auto-codeql/contracts";

import {
  FakeCodeqlPort,
  FixedClock,
  FixedIdGenerator,
  MemoryArtifactStore,
} from "./helpers.js";

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "workflow-commit-boundary",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "input reaches a shell sink",
  vulnerable_database: { path: "/isolated/vulnerable", language: "python" },
  fixed_database: { path: "/isolated/fixed", language: "python" },
  validation: { vulnerable_min_results: 1, vulnerable_max_results: 1, fixed_min_results: 0, fixed_max_results: 0, must_have_code_flow: true },
  max_rounds: 3,
  timeout_ms: 30_000,
  created_at: "2026-08-27T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test/workflow-commit-boundary", license: "test", source: "test" },
};

function candidate(): unknown {
  return {
    schema_version: CONTRACTS_VERSION,
    candidate_id: "commit-boundary-candidate",
    query_id: "commit-boundary-query",
    spec_id: spec.spec_id,
    language: "python",
    ql_text: "select 1",
    round: 1,
    origin: "test",
  };
}

class PassingQuery implements QueryExecutionPort {
  calls = 0;

  async execute(_request: QueryExecutionRequest, _options: CodeqlOperationOptions): Promise<QueryExecutionResult> {
    this.calls += 1;
    return {
      compile: { status: "passed", elapsed_ms: 1 },
      vulnerable: { database: "vulnerable", status: "passed", result_count: 1, code_flow_count: 1, rule_ids: ["boundary-rule"], locations: [], flow_evidence: [], semantic_matches: [], elapsed_ms: 1 },
      fixed: { database: "fixed", status: "passed", result_count: 0, code_flow_count: 0, rule_ids: [], locations: [], flow_evidence: [], semantic_matches: [], elapsed_ms: 1 },
      diagnostics: [],
      elapsedMs: 3,
    };
  }
}

class FailingProbe implements QueryProbeExecutionPort {
  async executeProbe(_request: QueryProbeRequest, _options: CodeqlOperationOptions): Promise<never> {
    throw new DomainError("PROCESS_CRASHED", "process", "probe failed", false);
  }
}

class FailingDraft implements QueryDraftExecutionPort {
  async executeDraft(_request: QueryDraftRequest, _options: CodeqlOperationOptions): Promise<never> {
    throw new DomainError("PROCESS_CRASHED", "process", "draft failed", false);
  }
}

class FaultStore extends MemoryArtifactStore {
  failpoint: "verification-evidence" | "state-commit" | "run-projection" | "case-projection" | "pack-staging" | "pack-promotion" | undefined;
  abortAfterStateCommit: AbortController | undefined;

  override async writeArtifact(runId: string, relativePath: string, content: string): Promise<void> {
    if (this.failpoint === "verification-evidence" && relativePath.endsWith("/verification.json")) {
      this.failpoint = undefined;
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "injected evidence write failure", false);
    }
    if (this.failpoint === "state-commit" && relativePath === "workflow/state.json") {
      this.failpoint = undefined;
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "injected state commit failure", false);
    }
    await super.writeArtifact(runId, relativePath, content);
    if (relativePath === "workflow/state.json" && this.abortAfterStateCommit !== undefined) {
      this.abortAfterStateCommit.abort();
      this.abortAfterStateCommit = undefined;
    }
  }

  override async saveManifest(manifest: Parameters<MemoryArtifactStore["saveManifest"]>[0]): Promise<void> {
    if (this.failpoint === "run-projection") {
      this.failpoint = undefined;
      throw new DomainError("PROCESS_CRASHED", "artifact", "injected run projection failure", false);
    }
    await super.saveManifest(manifest);
  }

  override async saveCaseSummary(summary: Parameters<MemoryArtifactStore["saveCaseSummary"]>[0]): Promise<void> {
    if (this.failpoint === "case-projection") {
      this.failpoint = undefined;
      throw new DomainError("PROCESS_CRASHED", "artifact", "injected case projection failure", false);
    }
    await super.saveCaseSummary(summary);
  }

  override async stageArtifactBundle(...args: Parameters<MemoryArtifactStore["stageArtifactBundle"]>): ReturnType<MemoryArtifactStore["stageArtifactBundle"]> {
    if (this.failpoint === "pack-staging") {
      this.failpoint = undefined;
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "injected pack staging failure", false);
    }
    return super.stageArtifactBundle(...args);
  }

  override async promoteArtifactBundle(...args: Parameters<MemoryArtifactStore["promoteArtifactBundle"]>): ReturnType<MemoryArtifactStore["promoteArtifactBundle"]> {
    if (this.failpoint === "pack-promotion") {
      this.failpoint = undefined;
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "injected pack promotion failure", false);
    }
    return super.promoteArtifactBundle(...args);
  }
}

function app(artifacts: MemoryArtifactStore, query: QueryExecutionPort = new PassingQuery(), overrides: { probes?: QueryProbeExecutionPort; drafts?: QueryDraftExecutionPort } = {}): Application {
  return new Application({
    codeql: new FakeCodeqlPort(),
    artifacts,
    clock: new FixedClock(),
    ids: new FixedIdGenerator("run_commit01"),
    queries: query,
    probes: overrides.probes,
    drafts: overrides.drafts,
  });
}

async function preparedApp(artifacts: FaultStore, query = new PassingQuery()): Promise<{ app: Application; query: PassingQuery }> {
  const application = app(artifacts, query);
  await application.workflowStart(spec);
  await application.queryVerify("run_commit01", candidate());
  return { app: application, query };
}

describe("workflow commit and recovery boundaries", () => {
  it("fails admission, probe and draft without fabricating candidate success", async () => {
    const admissionCodeql = new FakeCodeqlPort();
    admissionCodeql.failure = new DomainError("PROCESS_CRASHED", "process", "admission failed", false);
    const admission = new Application({ codeql: admissionCodeql, artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_commit01") });
    await expect(admission.workflowStart(spec)).rejects.toMatchObject({ code: "PROCESS_CRASHED" });

    const probeArtifacts = new MemoryArtifactStore();
    const probe = app(probeArtifacts, new PassingQuery(), { probes: new FailingProbe() });
    await probe.workflowStart(spec);
    await expect(probe.queryProbe("run_commit01", { schema_version: CONTRACTS_VERSION, intent_id: "commit-probe", language: "python", cwe: "CWE-078", query_kind: "path-problem", flow_mode: "taint", source: { kind: "environment", name: "input" }, sink: { kind: "call", module: "os", member: "system" }, message: "input reaches sink" })).rejects.toMatchObject({ code: "PROCESS_CRASHED" });

    const draft = app(new MemoryArtifactStore(), new PassingQuery(), { drafts: new FailingDraft() });
    await draft.workflowStart(spec);
    await expect(draft.queryDraft("run_commit01", candidate())).rejects.toMatchObject({ code: "PROCESS_CRASHED" });
  });

  it("does not commit verification when evidence or state persistence fails", async () => {
    for (const failpoint of ["verification-evidence", "state-commit"] as const) {
      const artifacts = new FaultStore();
      const application = app(artifacts);
      await application.workflowStart(spec);
      artifacts.failpoint = failpoint;
      await expect(application.queryVerify("run_commit01", candidate())).rejects.toBeDefined();
      const state = artifacts.artifacts.get("run_commit01/workflow/state.json");
      expect(state).toBeDefined();
      expect(JSON.parse(state ?? "{}").verifications).toHaveLength(0);
      expect((await application.workflowStatus("run_commit01")).run.status).not.toBe("checkpointed");
    }
  });

  it("repairs a post-commit run projection without rerunning CodeQL", async () => {
    const artifacts = new FaultStore();
    const query = new PassingQuery();
    const application = app(artifacts, query);
    await application.workflowStart(spec);
    artifacts.failpoint = "run-projection";
    const verification = await application.queryVerify("run_commit01", candidate());
    expect(verification.status).toBe("passed");
    expect(query.calls).toBe(1);
    expect((await application.workflowStatus("run_commit01")).run.status).toBe("checkpointed");
    expect(query.calls).toBe(1);
  });

  it("repairs a post-commit case projection without rerunning CodeQL", async () => {
    const artifacts = new FaultStore();
    const query = new PassingQuery();
    const application = app(artifacts, query);
    await application.workflowStart(spec);
    artifacts.failpoint = "case-projection";
    await expect(application.queryVerify("run_commit01", candidate())).resolves.toMatchObject({ status: "passed" });
    expect((await application.workflowStatus("run_commit01")).case_summary.total_candidates).toBe(1);
    expect(query.calls).toBe(1);
  });

  it("keeps a committed verification when cancellation arrives after the commit point", async () => {
    const artifacts = new FaultStore();
    const controller = new AbortController();
    const application = app(artifacts);
    await application.workflowStart(spec);
    artifacts.abortAfterStateCommit = controller;
    await expect(application.queryVerify("run_commit01", candidate(), { signal: controller.signal })).resolves.toMatchObject({ status: "passed" });
    expect((await application.workflowStatus("run_commit01")).run.status).toBe("checkpointed");
  });

  it("stages and promotes Query Packs only after the complete bundle validates", async () => {
    for (const failpoint of ["pack-staging", "pack-promotion", "state-commit"] as const) {
      const artifacts = new FaultStore();
      const { app: application } = await preparedApp(artifacts);
      artifacts.failpoint = failpoint;
      await expect(application.workflowFinalize("run_commit01")).rejects.toBeDefined();
      expect(artifacts.staged.size).toBe(0);
      expect([...artifacts.artifacts.keys()].some((key) => key.startsWith("run_commit01/query-pack/"))).toBe(false);
      expect(JSON.parse(artifacts.artifacts.get("run_commit01/workflow/state.json") ?? "{}").pack).toBeUndefined();
    }
  });

  it("repairs post-commit finalization projections and reuses the committed pack", async () => {
    const artifacts = new FaultStore();
    const { app: application, query } = await preparedApp(artifacts);
    artifacts.failpoint = "run-projection";
    const pack = await application.workflowFinalize("run_commit01");
    expect(pack.pack_id).toContain("run_commit01");
    expect((await application.workflowStatus("run_commit01")).run.status).toBe("completed");
    expect(query.calls).toBe(1);

    artifacts.failpoint = "case-projection";
    await expect(application.workflowFinalize("run_commit01")).resolves.toMatchObject({ pack_id: pack.pack_id });
    expect((await application.workflowStatus("run_commit01")).case_summary.pack_id).toBe(pack.pack_id);
    expect(query.calls).toBe(1);
  });

  it("fails closed on corrupt recovery metadata and cleans orphaned staging", async () => {
    const artifacts = new FaultStore();
    const application = app(artifacts);
    await application.workflowStart(spec);
    artifacts.artifacts.set("run_commit01/workflow/internal/commits/corrupt.json", "{not-json");
    await expect(application.workflowStatus("run_commit01")).rejects.toMatchObject({ code: "ARTIFACT_CORRUPT" });

    artifacts.artifacts.delete("run_commit01/workflow/internal/commits/corrupt.json");
    await artifacts.stageArtifactBundle("run_commit01", "orphan-stage", "query-pack", [{ relativePath: "query.ql", content: "orphan" }]);
    artifacts.artifacts.set("run_commit01/query-pack/orphan.txt", "orphan");
    await application.workflowStatus("run_commit01");
    expect(artifacts.staged.size).toBe(0);
    expect([...artifacts.artifacts.keys()].some((key) => key.startsWith("run_commit01/query-pack/"))).toBe(false);
  });

  it("reconciles a crash window where state committed before recovery metadata advanced", async () => {
    const artifacts = new FaultStore();
    const query = new PassingQuery();
    const application = app(artifacts, query);
    await application.workflowStart(spec);
    await application.queryVerify("run_commit01", candidate());
    const recoveryKey = [...artifacts.artifacts.keys()].find((key) => key.includes("/workflow/internal/commits/") && key.endsWith(".json"));
    expect(recoveryKey).toBeDefined();
    const recovery = JSON.parse(artifacts.artifacts.get(recoveryKey ?? "") ?? "{}");
    recovery.phase = "prepared";
    artifacts.artifacts.set(recoveryKey ?? "", `${JSON.stringify(recovery)}\n`);
    const manifest = artifacts.manifests.get("run_commit01");
    expect(manifest).toBeDefined();
    if (manifest !== undefined) {
      const { checkpoint: _checkpoint, ...withoutCheckpoint } = manifest;
      artifacts.manifests.set("run_commit01", { ...withoutCheckpoint, status: "running" });
    }
    artifacts.caseSummaries.clear();

    const status = await application.workflowStatus("run_commit01");
    expect(status.run.status).toBe("checkpointed");
    expect(status.case_summary.total_candidates).toBe(1);
    expect(query.calls).toBe(1);
  });
});
