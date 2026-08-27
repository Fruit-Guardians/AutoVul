import { Application } from "@pure-auto-codeql/core";
import { LocalArtifactStore, NodeFileSystemPort } from "@pure-auto-codeql/codeql-runner";

const [runsDir, runId, candidateId] = process.argv.slice(2);
const filesystem = new NodeFileSystemPort();
const database = {
  schemaVersion: "v2.contracts/1",
  path: "/isolated/db",
  canonicalPath: "/isolated/db",
  exists: true,
  isDirectory: true,
  valid: true,
  language: "python",
  checkedAt: "2026-08-24T00:00:00.000Z",
  diagnostics: [],
};
const app = new Application({
  artifacts: new LocalArtifactStore(runsDir, filesystem),
  clock: { now: () => new Date().toISOString() },
  ids: { next: () => "run_worker01" },
  codeql: {
    doctor: async () => ({ schemaVersion: "v2.contracts/1", available: true, cliPath: "fake", languages: ["python"], checkedAt: new Date().toISOString(), diagnostics: [] }),
    inspectDatabase: async () => database,
    validateDatabase: async () => database,
  },
  queries: {
    execute: async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return {
        compile: { status: "passed", elapsed_ms: 1 },
        vulnerable: {
          database: "vulnerable", status: "passed", result_count: 1, code_flow_count: 1,
          rule_ids: ["worker/rule"], locations: [{ file: "app.py", start_line: 5 }],
          flow_evidence: [{ path: [{ file: "app.py", start_line: 5 }, { file: "app.py", start_line: 6 }], source: { file: "app.py", start_line: 5 }, sink: { file: "app.py", start_line: 6 } }],
          semantic_matches: [], elapsed_ms: 1,
        },
        fixed: { database: "fixed", status: "passed", result_count: 0, code_flow_count: 0, rule_ids: [], locations: [], flow_evidence: [], semantic_matches: [], elapsed_ms: 1 },
        diagnostics: [], elapsedMs: 5,
      };
    },
  },
});

const candidate = {
  schema_version: "v2.contracts/1",
  candidate_id: candidateId,
  query_id: candidateId,
  spec_id: "python-cross-process",
  language: "python",
  ql_text: "import python\nselect 1, 'worker'",
  round: 1,
  origin: "test",
};
try {
  const result = await app.queryVerify(runId, candidate, { timeoutMs: 10_000 });
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, code: error?.code ?? "unknown" }));
  process.exitCode = 2;
} finally {
  await app.close();
}
