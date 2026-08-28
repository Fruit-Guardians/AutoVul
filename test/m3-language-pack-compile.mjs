import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";

import { qlpackForLanguage, renderTaintProbe, renderTaintQuery } from "@autovul/core";

const intents = [
  {
    language: "python",
    intent: {
      schema_version: "v2.contracts/1", intent_id: "python-command-injection", language: "python", cwe: "CWE-078",
      query_kind: "path-problem", flow_mode: "taint", source: { kind: "call", module: "os", member: "getenv" },
      sink: { kind: "call", module: "os", member: "system", argument_index: 0 }, message: "source to sink",
    },
  },
  {
    language: "javascript",
    intent: {
      schema_version: "v2.contracts/1", intent_id: "javascript-command-injection", language: "javascript", cwe: "CWE-078",
      query_kind: "path-problem", flow_mode: "taint", source: { kind: "environment", name: "env.USER_COMMAND" },
      sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 }, message: "source to sink",
    },
  },
  {
    language: "java",
    intent: {
      schema_version: "v2.contracts/1", intent_id: "java-path-traversal", language: "java", cwe: "CWE-022",
      query_kind: "path-problem", flow_mode: "taint", source: { kind: "call", type: "java.lang.System", member: "getenv" },
      sink: { kind: "constructor", type: "java.io.File", argument_index: 0 }, message: "source to sink",
    },
  },
  {
    language: "cpp",
    intent: {
      schema_version: "v2.contracts/1", intent_id: "cpp-buffer-overflow", language: "cpp", cwe: "CWE-120",
      query_kind: "path-problem", flow_mode: "taint", source: { kind: "function", name: "atoi" },
      sink: { kind: "array_index" }, message: "source to sink",
    },
  },
];

for (const item of intents) {
  const root = await mkdtemp(join(tmpdir(), `autovul-m3-${item.language}-`));
  try {
    const queries = [{ name: "path", text: renderTaintQuery(`m3-${item.language}`, item.intent) }, ...["source", "sink"].map((role) => ({ name: `probe-${role}`, text: renderTaintProbe(item.intent, role) }))];
    for (const query of queries) {
      const queryRoot = join(root, query.name);
      await mkdir(queryRoot, { recursive: true });
      await writeFile(join(queryRoot, "query.ql"), query.text);
      await writeFile(join(queryRoot, "qlpack.yml"), qlpackForLanguage(item.language));
      const result = await runCodeql(queryRoot);
      process.stdout.write(`${JSON.stringify({ language: item.language, query: query.name, status: result.code === 0 ? "passed" : "failed", stderr: result.stderr.slice(-1600) })}\n`);
      if (result.code !== 0) process.exitCode = 1;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function runCodeql(cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.env.CODEQL_PATH ?? "codeql", ["query", "compile", "query.ql", "--threads=1"], { cwd });
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, 180_000);
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${chunk}`.slice(-16_384);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ code: 127, stderr: error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: timedOut ? 124 : code ?? 1, stderr: timedOut ? `${stderr}\nCodeQL compile timed out` : stderr });
    });
  });
}
