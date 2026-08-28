import { describe, expect, it } from "vitest";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { Application } from "@autovul/core";
import { LocalArtifactStore, NodeFileSystemPort } from "@autovul/codeql-runner";
import { CONTRACTS_VERSION, type VulnerabilitySpec } from "@autovul/contracts";

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "python-cross-process",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "input reaches a shell sink",
  vulnerable_database: { path: "/isolated/vulnerable", language: "python" },
  fixed_database: { path: "/isolated/fixed", language: "python" },
  validation: { vulnerable_min_results: 1, vulnerable_max_results: 1, fixed_min_results: 0, fixed_max_results: 0, must_have_code_flow: true },
  max_rounds: 3,
  timeout_ms: 10_000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test", license: "test", source: "test" },
};

describe("M2 cross-process workflow lease", () => {
  it("serializes independent Node processes and preserves exactly the budgeted state", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-m2-process-"));
    try {
      const store = new LocalArtifactStore(root, new NodeFileSystemPort());
      const database = {
        schemaVersion: CONTRACTS_VERSION,
        path: "/isolated/db",
        canonicalPath: "/isolated/db",
        exists: true,
        isDirectory: true,
        valid: true,
        language: "python" as const,
        checkedAt: "2026-08-24T00:00:00.000Z",
        diagnostics: [],
      };
      const app = new Application({
        artifacts: store,
        clock: { now: () => new Date().toISOString() },
        ids: { next: () => "run_parent01" },
        codeql: { doctor: async () => { throw new Error("not used"); }, inspectDatabase: async () => database, validateDatabase: async () => database },
        queries: { execute: async () => { throw new Error("not used"); } },
      });
      const started = await app.workflowStart(spec);
      const worker = join(process.cwd(), "test", "m2-cross-process-worker.mjs");
      const outcomes = await Promise.all(Array.from({ length: 24 }, (_, index) => runWorker(worker, root, started.run.runId, `candidate-process-${index + 1}`)));
      const successes = outcomes.filter((item) => item.ok);
      expect(successes).toHaveLength(3);
      expect(outcomes.filter((item) => !item.ok).every((item) => item.code === "QUERY_BUDGET_EXCEEDED")).toBe(true);
      const status = await app.workflowStatus(started.run.runId);
      expect(status.candidates).toHaveLength(3);
      expect(status.verifications).toHaveLength(3);
      expect(await readdir(join(root, started.run.runId, ".workflow.lock")).catch(() => [])).toEqual([]);
      await app.close();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});

function runWorker(worker: string, runsDir: string, runId: string, candidateId: string): Promise<{ ok: boolean; code?: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [worker, runsDir, runId, candidateId], { cwd: process.cwd(), shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.once("error", reject);
    child.once("close", (code) => {
      if (code !== 0 && code !== 2) {
        reject(new Error(`worker exited ${code}: ${Buffer.concat(stderr).toString("utf8")}`));
        return;
      }
      resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")) as { ok: boolean; code?: string });
    });
  });
}
