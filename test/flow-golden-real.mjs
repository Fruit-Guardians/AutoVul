import { cp, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { createLocalApplication } from "@autovul/codeql-runner";
import { GoldenManifestSchema, parseSchema } from "@autovul/contracts";

const repoRoot = resolve(import.meta.dirname, "../..");
const codeql = process.env.CODEQL_PATH ?? "codeql";
const selectedCase = process.env.FLOW_GOLDEN_CASE;
const manifest = parseSchema(GoldenManifestSchema, JSON.parse(await readFile(join(repoRoot, "test/golden/manifest.json"), "utf8")), "golden manifest");
const cases = manifest.cases.filter((item) => selectedCase === undefined || item.case_id === selectedCase);
if (cases.length === 0) throw new Error(`Unknown Flow Golden case: ${selectedCase}`);

const root = await mkdtemp(join(tmpdir(), "autovul-flow-golden-"));
const app = createLocalApplication({ runsDir: join(root, "runs"), workspaceRoot: root, codeqlPath: codeql, timeoutMs: 300_000 });
const output = [];
let failed = false;
try {
  for (const item of cases) {
    const fixture = join(repoRoot, "test/golden", item.fixture_root);
    const caseRoot = join(root, item.case_id);
    const vulnerableSource = join(caseRoot, "vulnerable-source");
    const fixedSource = join(caseRoot, "fixed-source");
    const vulnerableDb = join(caseRoot, "vulnerable-db");
    const fixedDb = join(caseRoot, "fixed-db");
    await cp(join(fixture, item.source.vulnerable), join(vulnerableSource, "src"), { recursive: true });
    await cp(join(fixture, item.source.fixed), join(fixedSource, "src"), { recursive: true });
    await createDatabase(vulnerableDb, vulnerableSource, item.language);
    await createDatabase(fixedDb, fixedSource, item.language);
    const executed = await app.research({
      action: "execute", capability: "flow", hypothesis_version: "autovul.flow/1",
      hypothesis: makeFlowModel(item), analyzer_id: "codeql", mode: "differential",
      target: { vulnerable: { kind: "codeql_database", path: vulnerableDb }, fixed: { kind: "codeql_database", path: fixedDb } },
      expectation: { vulnerable: { min_paths: item.expected.vulnerable.min_code_flows, max_paths: item.expected.vulnerable.max_code_flows }, fixed: { min_paths: 0, max_paths: 0 } },
      budget: { timeout_ms: 300_000 }, idempotency_key: `golden-${item.case_id}`,
    }, { timeoutMs: 300_000 });
    const replayed = "run_id" in executed ? await app.manageRun({ action: "replay", run_id: executed.run_id }, { timeoutMs: 300_000 }) : undefined;
    const passed = executed.valid === undefined && executed.operation_status === "completed" && executed.decision?.outcome === "connected"
      && executed.verification_level === "differential" && replayed?.operation_status === "completed"
      && replayed.decision?.outcome === "connected" && replayed.verification_level === "differential";
    const record = { case_id: item.case_id, language: item.language, passed, execute: compact(executed), replay: replayed === undefined ? undefined : compact(replayed) };
    output.push(record);
    process.stdout.write(`${JSON.stringify(record)}\n`);
    if (!passed) failed = true;
  }
} catch (error) {
  failed = true;
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
} finally {
  await app.close();
  await rm(root, { recursive: true, force: true });
}
process.stdout.write(`${JSON.stringify({ schema_version: "autovul.flow.golden.real/1", selected_case: selectedCase ?? null, passed: !failed, cases: output })}\n`);
if (failed) process.exitCode = 1;

function compact(result) {
  return result.valid === false ? { valid: false, issues: result.issues }
    : { operation_status: result.operation_status, decision: result.decision, verification_level: result.verification_level, observations: result.observations };
}

function makeFlowModel(item) {
  const common = { schema_version: "autovul.flow/1", model_id: `golden-${item.case_id}`, language: item.language, flow_mode: "taint" };
  if (item.language === "python") {
    const sinks = { python_command_injection: { kind: "call", module: "os", member: "system", argument_index: 0 }, python_path_traversal: { kind: "call", module: "os", member: "open", argument_index: 0 }, python_sql_injection: { kind: "call", module: "sqlite3", member: "connect", argument_index: 0 }, python_ssrf: { kind: "call", module: "requests", member: "get", argument_index: 0 }, python_unsafe_deserialization: { kind: "call", module: "pickle", member: "loads", argument_index: 0 } };
    return { ...common, source: { kind: "environment", name: "getenv" }, sink: sinks[item.case_id] };
  }
  if (item.language === "javascript") {
    const sinks = { javascript_command_injection: { kind: "call", module: "child_process", member: "exec", argument_index: 0 }, javascript_eval_injection: { kind: "call", module: "vm", member: "runInNewContext", argument_index: 0 }, javascript_file_write: { kind: "call", module: "fs", member: "writeFileSync", argument_index: 0 }, javascript_path_traversal: { kind: "call", module: "fs", member: "readFileSync", argument_index: 0 }, javascript_ssrf: { kind: "call", module: "http", member: "request", argument_index: 0 } };
    const source = item.case_id === "javascript_command_injection" ? "env.USER_COMMAND" : item.case_id === "javascript_eval_injection" ? "env.USER_CODE" : item.case_id === "javascript_ssrf" ? "env.USER_URL" : "env.USER_FILE";
    return { ...common, source: { kind: "environment", name: source }, sink: sinks[item.case_id] };
  }
  if (item.language === "java") {
    const sinks = { java_command_injection: { kind: "call", type: "java.lang.Runtime", member: "exec", argument_index: 0 }, java_file_write: { kind: "constructor", type: "java.io.FileOutputStream", argument_index: 0 }, java_path_traversal: { kind: "constructor", type: "java.io.File", argument_index: 0 }, java_sql_injection: { kind: "call", type: "java.sql.Statement", member: "executeQuery", argument_index: 0 }, java_ssrf: { kind: "constructor", type: "java.net.URL", argument_index: 0 } };
    return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: sinks[item.case_id] };
  }
  const sinks = { cpp_allocation_size: { kind: "function", name: "malloc", argument_index: 0 }, cpp_buffer_overflow: { kind: "array_index" }, cpp_command_injection: { kind: "function", name: "system", argument_index: 0 }, cpp_path_traversal: { kind: "function", name: "fopen", argument_index: 0 }, cpp_popen_command_injection: { kind: "function", name: "popen", argument_index: 0 }, cpp_unsafe_copy: { kind: "function", name: "strcpy", argument_index: 1 } };
  const source = item.case_id === "cpp_buffer_overflow" || item.case_id === "cpp_unsafe_copy" ? { kind: "function", name: "atoi" } : { kind: "function", name: "getenv" };
  return { ...common, source, sink: sinks[item.case_id] };
}

function createDatabase(database, sourceRoot, language) {
  return mkdir(dirname(database), { recursive: true }).then(() => new Promise((resolvePromise, reject) => {
    const child = spawn(codeql, ["database", "create", database, `--language=${language}`, `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], { shell: false });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4096); });
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolvePromise() : reject(new Error(`database create failed: ${stderr}`)));
  }));
}
