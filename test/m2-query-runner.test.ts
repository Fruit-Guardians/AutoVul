import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CodeqlQueryRunner, NodeFileSystemPort } from "@autovul/codeql-runner";
import { CONTRACTS_VERSION, type QueryCandidate, type VulnerabilitySpec } from "@autovul/contracts";
import type { QueryExecutionRequest } from "@autovul/core";

import { processResult, ScriptedProcessPort } from "./helpers.js";

const candidate: QueryCandidate = {
  schema_version: CONTRACTS_VERSION,
  candidate_id: "candidate-runner",
  query_id: "query-runner",
  spec_id: "python-command-injection",
  language: "python",
  ql_text: "/** @kind path-problem @id test/query-runner */\nimport python\nselect 1, \"candidate\"",
  round: 1,
  origin: "test",
};

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "python-command-injection",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "input reaches command execution",
  vulnerable_database: { path: "/db/vulnerable", language: "python" },
  fixed_database: { path: "/db/fixed", language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 2,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
  },
  max_rounds: 3,
  timeout_ms: 2000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test", license: "test", source: "test" },
};

function request(root: string): QueryExecutionRequest {
  return {
    runId: "run_runner01",
    candidate,
    spec,
    artifactRoot: root,
  };
}

describe("M2 CodeQL query adapter", () => {
  it("compiles, analyzes both databases, and extracts SARIF flow facts", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-query-runner-"));
    try {
      const process = new ScriptedProcessPort(async (command) => {
        if (command.args[0] === "version") {
          return processResult({ stdout: "CodeQL CLI version 2.26.1\n" });
        }
        if (command.args[0] === "resolve") {
          return processResult({ stdout: "python (/fake/python)\n" });
        }
        if (command.args[0] === "query") {
          return processResult();
        }
        const database = command.args[2];
        const output = command.args.find((item) => item.startsWith("--output="))?.slice("--output=".length);
        if (output === undefined) {
          return processResult({ exitCode: 2, stderr: "missing output" });
        }
        await writeFile(output, JSON.stringify({
          runs: [{ results: database === "/db/fixed" ? [] : [{
            ruleId: "test/rule",
            locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 4 } } }],
            codeFlows: [{ threadFlows: [{ locations: [
              { location: { physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 5 } } }, message: { text: "source" } },
              { location: { physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 6 } } }, message: { text: "sink" } },
            ] }] }],
          }] }],
        }), "utf8");
        return processResult();
      });
      const runner = new CodeqlQueryRunner({ process, filesystem: new NodeFileSystemPort() });
      const result = await runner.execute(request(root), { timeoutMs: 1000 });
      expect(result.compile.status).toBe("passed");
      expect(result.vulnerable.result_count).toBe(1);
      expect(result.vulnerable.code_flow_count).toBe(1);
      expect(result.vulnerable.locations[0]?.start_line).toBe(4);
      expect(result.vulnerable.flow_evidence[0]?.source?.start_line).toBe(5);
      expect(result.vulnerable.flow_evidence[0]?.sink?.start_line).toBe(6);
      expect(result.vulnerable.semantic_matches.map((item) => item.label)).toEqual(["sink", "source"]);
      expect(result.fixed.result_count).toBe(0);
      expect(process.calls).toHaveLength(6);
      expect(process.calls.every((call) => call.command.shell === false)).toBe(true);
      expect(await readFile(join(root, "candidates", candidate.candidate_id, "vulnerable.sarif"), "utf8")).toContain("test/rule");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("returns a structured compile diagnostic and does not analyze databases after compile failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-query-compile-fail-"));
    try {
      const process = new ScriptedProcessPort((command) => command.args[0] === "version"
        ? processResult({ stdout: "CodeQL CLI version 2.26.1\n" })
        : command.args[0] === "resolve"
          ? processResult({ stdout: "python\n" })
          : processResult({ exitCode: 1, stderr: "syntax error" }));
      const result = await new CodeqlQueryRunner({ process, filesystem: new NodeFileSystemPort() }).execute(request(root), { timeoutMs: 1000 });
      expect(result.compile.status).toBe("failed");
      expect(result.vulnerable.status).toBe("not_run");
      expect(result.diagnostics[0]?.code).toBe("QUERY_COMPILE_FAILED");
      expect(result.diagnostics[0]?.details.stderr).toBe("syntax error");
      expect(process.calls).toHaveLength(3);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("stops at metadata preflight before spawning CodeQL processes", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-query-metadata-preflight-"));
    try {
      const process = new ScriptedProcessPort(() => processResult({ exitCode: 99, stderr: "must not run" }));
      const result = await new CodeqlQueryRunner({ process, filesystem: new NodeFileSystemPort() }).execute({
        ...request(root),
        candidate: { ...candidate, ql_text: "import python\nselect 1, \"missing metadata\"" },
      }, { timeoutMs: 1000 });
      expect(result.compile.status).toBe("failed");
      expect(result.vulnerable.status).toBe("not_run");
      expect(result.fixed.status).toBe("not_run");
      expect(result.diagnostics.map((item) => item.code)).toEqual([
        "QUERY_METADATA_KIND_REQUIRED",
        "QUERY_METADATA_ID_REQUIRED",
      ]);
      expect(process.calls).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not run the fixed database when vulnerable analysis fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-query-vulnerable-fail-"));
    try {
      const process = new ScriptedProcessPort((command) => {
        if (command.args[0] === "version") return processResult({ stdout: "CodeQL CLI version 2.26.1\n" });
        if (command.args[0] === "resolve") return processResult({ stdout: "python (/fake/python)\n" });
        if (command.args[0] === "query") return processResult();
        if (command.args[0] === "database" && command.args[2] === "/db/vulnerable") return processResult({ exitCode: 1, stderr: "database failed" });
        throw new Error("fixed database should not run");
      });
      const result = await new CodeqlQueryRunner({ process, filesystem: new NodeFileSystemPort() }).execute(request(root), { timeoutMs: 1000 });
      expect(result.vulnerable.status).toBe("failed");
      expect(result.fixed.status).toBe("not_run");
      expect(result.diagnostics.map((item) => item.code)).toEqual(["QUERY_ANALYZE_FAILED"]);
      expect(process.calls).toHaveLength(5);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
