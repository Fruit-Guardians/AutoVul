import { describe, expect, it } from "vitest";
import { access, chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runCli } from "@autovul/cli";

function buffer(): { stdout: string[]; stderr: string[] } {
  return { stdout: [], stderr: [] };
}

async function fakeCodeql(root: string): Promise<string> {
  const path = join(root, "fake-codeql");
  await writeFile(path, `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "CodeQL CLI version 2.26.1"
elif [ "$1" = "query" ]; then
  exit 0
elif [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  output=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) output="\${arg#--output=}" ;;
    esac
  done
  case "$3" in
    *fixed*) echo '{"runs":[{"results":[]}]}' > "$output" ;;
    *) echo '{"runs":[{"results":[{"ruleId":"fake/python-command-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":5}}}],"codeFlows":[{"threadFlows":[]}] }]}]}' > "$output" ;;
  esac
  exit 0
elif [ "$1" = "resolve" ]; then
  if [ "$2" = "database" ]; then
    echo '{"language":"python","codeqlVersion":"2.26.1"}'
  else
    echo 'python (/fake/python)'
  fi
  exit 0
fi
exit 2
`, "utf8");
  await chmod(path, 0o755);
  return path;
}

const spec = {
  schema_version: "v2.contracts/1",
  spec_id: "python-cli-golden",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "environment input reaches os.system",
  vulnerable_database: { path: "/isolated/vulnerable", language: "python" },
  fixed_database: { path: "/isolated/fixed", language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
  },
  max_rounds: 3,
  timeout_ms: 10_000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test/golden/python_command_injection", license: "test", source: "test" },
};

describe("M2 CLI replay", () => {
  it("submits a QL file through the shared workflow and finalizes without a model", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-m2-cli-"));
    try {
      const codeql = await fakeCodeql(root);
      await mkdir(join(root, "vulnerable"));
      await mkdir(join(root, "fixed"));
      const specPath = join(root, "spec.json");
      const queryPath = join(root, "candidate.ql");
      const intentPath = join(root, "intent.json");
      await writeFile(specPath, `${JSON.stringify({
        ...spec,
        vulnerable_database: { path: join(root, "vulnerable"), language: "python" },
        fixed_database: { path: join(root, "fixed"), language: "python" },
      })}\n`, "utf8");
      await writeFile(queryPath, "/** @kind path-problem @id test/query-cli */\nimport python\nselect 1, \"candidate\"\n", "utf8");
      await writeFile(intentPath, `${JSON.stringify({
        schema_version: "v2.contracts/1",
        intent_id: "python-cli-probe",
        language: "python",
        cwe: "CWE-078",
        query_kind: "path-problem",
        flow_mode: "taint",
        source: { kind: "environment", name: "env" },
        sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
        message: "Environment input reaches os.system.",
      })}\n`, "utf8");
      const startOutput = buffer();
      const startCode = await runCli(["workflow", "start", "--spec", specPath, "--json", "--runs-dir", root, "--workspace-root", root, "--codeql", codeql], {
        stdout: (value) => startOutput.stdout.push(value),
        stderr: (value) => startOutput.stderr.push(value),
      });
      expect(startCode).toBe(0);
      const started = JSON.parse(startOutput.stdout.join("")) as { result: { run: { runId: string } } };
      const runId = started.result.run.runId;

      const probeOutput = buffer();
      expect(await runCli([
        "query", "probe", runId, "--intent", intentPath,
        "--json", "--runs-dir", root, "--workspace-root", root, "--codeql", codeql,
      ], {
        stdout: (value) => probeOutput.stdout.push(value),
        stderr: (value) => probeOutput.stderr.push(value),
      })).toBe(0);
      expect(JSON.parse(probeOutput.stdout.join("")).result.status).toBe("passed");

      const verifyOutput = buffer();
      expect(await runCli([
        "query", "verify", runId,
        "--query-file", queryPath,
        "--candidate-id", "candidate-cli",
        "--query-id", "query-cli",
        "--json", "--runs-dir", root, "--workspace-root", root, "--codeql", codeql,
      ], {
        stdout: (value) => verifyOutput.stdout.push(value),
        stderr: (value) => verifyOutput.stderr.push(value),
      })).toBe(0);
      expect(JSON.parse(verifyOutput.stdout.join("")).result.status).toBe("passed");

      const finalizeOutput = buffer();
      const outputPack = join(root, "output-pack");
      expect(await runCli(["workflow", "finalize", runId, "--output", outputPack, "--json", "--runs-dir", root, "--workspace-root", root, "--codeql", codeql], {
        stdout: (value) => finalizeOutput.stdout.push(value),
        stderr: (value) => finalizeOutput.stderr.push(value),
      })).toBe(0);
      expect(JSON.parse(finalizeOutput.stdout.join("")).result.files.query).toBe("query.ql");
      await access(join(outputPack, "query-pack-manifest.json"));
      const replayOutput = buffer();
      expect(await runCli([
        "query-pack", "verify", outputPack,
        "--vulnerable-db", join(root, "vulnerable"),
        "--fixed-db", join(root, "fixed"),
        "--json", "--runs-dir", join(root, "replay-runs"), "--codeql", codeql,
      ], {
        stdout: (value) => replayOutput.stdout.push(value),
        stderr: (value) => replayOutput.stderr.push(value),
      })).toBe(0);
      expect(JSON.parse(replayOutput.stdout.join("")).result.verification.passed).toBe(true);
      await writeFile(join(outputPack, "query.ql"), "tampered\n", "utf8");
      const tamperedOutput = buffer();
      expect(await runCli([
        "query-pack", "verify", outputPack,
        "--vulnerable-db", join(root, "vulnerable"),
        "--fixed-db", join(root, "fixed"),
        "--json", "--runs-dir", join(root, "tampered-runs"), "--workspace-root", root, "--codeql", codeql,
      ], {
        stdout: (value) => tamperedOutput.stdout.push(value),
        stderr: (value) => tamperedOutput.stderr.push(value),
      })).toBe(1);
      expect(JSON.parse(tamperedOutput.stdout.join("")).error.code).toBe("ARTIFACT_CORRUPT");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 15_000);
});
