import { cp, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { createLocalApplication } from "@autovul/codeql-runner";
import { runCli } from "@autovul/cli";
import { GoldenManifestSchema, parseSchema } from "@autovul/contracts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = parseSchema(GoldenManifestSchema, JSON.parse(await readFile(join(repoRoot, "test/golden/manifest.json"), "utf8")), "golden manifest");
const codeql = process.env.CODEQL_PATH ?? "codeql";
const selectedCase = process.env.M3_GOLDEN_CASE;
const skipFixedDatabase = process.env.M3_GOLDEN_SKIP_FIXED === "true";
const cases = manifest.cases.filter((item) => selectedCase === undefined || item.case_id === selectedCase).map((item) => ({
  id: item.case_id,
  language: item.language,
  cwe: item.cwe,
  description: item.description,
  fixture: join(repoRoot, "test/golden", item.fixture_root),
  vulnerableSource: item.source.vulnerable,
  fixedSource: item.source.fixed,
  expected: item.expected,
}));
if (cases.length === 0) throw new Error(`Unknown M3 Golden case: ${selectedCase}`);

const root = await mkdtemp(join(tmpdir(), "autovul-m3-golden-"));
const output = [];
let failed = false;
const app = createLocalApplication({ runsDir: join(root, "runs"), workspaceRoot: root, codeqlPath: codeql, timeoutMs: 300_000 });
try {
  for (const item of cases) {
    const vulnerableDb = join(root, item.id, "vulnerable-db");
    const fixedDb = skipFixedDatabase ? undefined : join(root, item.id, "fixed-db");
    // Keep SARIF locations project-relative so the manifest's strict
    // project-root endpoint paths remain meaningful, while staging only the
    // selected vulnerable/fixed tree into the same `src/` layout.
    const vulnerableSourceRoot = join(root, item.id, "vulnerable-source");
    const fixedSourceRoot = join(root, item.id, "fixed-source");
    await cp(join(item.fixture, item.vulnerableSource), join(vulnerableSourceRoot, "src"), { recursive: true });
    await createDatabase(vulnerableDb, vulnerableSourceRoot, item.language);
    if (fixedDb !== undefined) {
      await cp(join(item.fixture, item.fixedSource), join(fixedSourceRoot, "src"), { recursive: true });
      await createDatabase(fixedDb, fixedSourceRoot, item.language);
    }

    const runsDir = join(root, "runs", item.id);
    {
      const spec = makeSpec(item, vulnerableDb, fixedDb, vulnerableSourceRoot);
      const started = await app.workflowStart(spec, { timeoutMs: 300_000 });
      const intent = makeIntent(item);
      const probe = await app.queryProbe(started.run.runId, intent, { timeoutMs: 300_000 });
      const candidate = {
        schema_version: "v2.contracts/1",
        candidate_id: `${item.id}-intent-r1`,
        query_id: `${item.id}-intent`,
        spec_id: item.id,
        language: item.language,
        intent,
        probe_evidence: probe,
        round: 1,
        origin: "test",
      };
      const invalidDraft = await app.queryDraft(started.run.runId, {
        ...candidate,
        candidate_id: `${item.id}-intent-invalid-draft`,
        ql_text: "this is deliberately invalid QL syntax",
      }, { timeoutMs: 120_000 });
      const draft = await app.queryDraft(started.run.runId, candidate, { timeoutMs: 120_000 });
      const verification = draft.status === "clean"
        ? await app.queryVerify(started.run.runId, candidate, { timeoutMs: 300_000 })
        : {
          status: "failed",
          passed: false,
          compile: { status: "failed" },
          vulnerable: { status: "not_run", result_count: 0, code_flow_count: 0 },
          fixed: { status: "not_run", result_count: 0, code_flow_count: 0 },
          diagnostics: [{ code: `QUERY_DRAFT_${draft.status.toUpperCase()}` }],
        };
      let replayPassed = false;
      let replayResult = { passed: false, exit_code: undefined };
      if (verification.passed) {
        await app.workflowFinalize(started.run.runId, { timeoutMs: 300_000 });
        const completed = await app.status(started.run.runId);
        const relocatedPack = join(root, item.id, "relocated-query-pack");
        await cp(join(completed.artifactRoot, "query-pack"), relocatedPack, { recursive: true });
        const replayOutput = [];
        const replayArgs = [
          "query-pack", "verify", relocatedPack,
          "--vulnerable-db", vulnerableDb,
          "--json",
          "--runs-dir", join(root, item.id, "replay-runs"),
          "--workspace-root", root,
          "--codeql", codeql,
        ];
        if (fixedDb !== undefined) replayArgs.splice(5, 0, "--fixed-db", fixedDb);
        const replayStderr = [];
        const replayCode = await runCli(replayArgs, {
          stdout: (value) => replayOutput.push(value),
          stderr: (value) => replayStderr.push(value),
        });
        replayPassed = replayCode === 0;
        const replayEnvelope = parseLastJson(replayOutput);
        const replayError = replayEnvelope?.ok === false && replayEnvelope.error !== undefined
          ? {
            code: replayEnvelope.error.code,
            message: replayEnvelope.error.message,
          }
          : undefined;
        replayResult = {
          passed: replayPassed,
          exit_code: replayCode,
          ...(replayError === undefined ? {} : { error: replayError }),
          ...(replayPassed || replayStderr.length === 0 ? {} : { stderr_tail: replayStderr.join("").slice(-4_096) }),
        };
      }
      const record = {
        case_id: item.id,
        language: item.language,
        status: verification.status,
        passed: verification.passed,
        compile: verification.compile.status,
        vulnerable: { status: verification.vulnerable.status, results: verification.vulnerable.result_count, flows: verification.vulnerable.code_flow_count },
        fixed: { status: verification.fixed.status, results: verification.fixed.result_count, flows: verification.fixed.code_flow_count },
        diagnostics: verification.diagnostics.map((diagnostic) => diagnostic.code),
        replay: replayResult,
        draft: {
          status: draft.status,
          lsp_available: draft.lsp_available,
          diagnostics: draft.diagnostics,
          definitions: draft.definition_locations.length,
          completions: draft.completion_labels.length,
        },
        invalid_draft: {
          status: invalidDraft.status,
          diagnostics: invalidDraft.diagnostics,
        },
        probe: { status: probe.status, source_locations: probe.source.locations.length, sink_locations: probe.sink.locations.length, diagnostics: probe.diagnostics, source: probe.source, sink: probe.sink },
        ...(verification.passed ? {} : { observed_flows: verification.vulnerable.flow_evidence, observed_locations: verification.vulnerable.locations, semantic_matches: verification.vulnerable.semantic_matches }),
      };
      output.push(record);
      process.stdout.write(`${JSON.stringify(record)}\n`);
      if (!verification.passed || !replayPassed || draft.status !== "clean" || invalidDraft.status !== "errors") failed = true;
    }
  }
} catch (error) {
  failed = true;
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
} finally {
  await app.close();
  await rm(root, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify({ schema_version: "m3.golden.real/v1", passed: !failed, cases: output })}\n`);
if (failed) process.exitCode = 1;

function makeSpec(item, vulnerableDb, fixedDb, projectRoot) {
  return {
    schema_version: "v2.contracts/1",
    spec_id: item.id,
    language: item.language,
    cwe: item.cwe,
    project_root: projectRoot,
    vulnerability_description: item.description,
    vulnerable_database: { path: vulnerableDb, language: item.language },
    ...(fixedDb === undefined ? {} : { fixed_database: { path: fixedDb, language: item.language } }),
    validation: {
      vulnerable_min_results: item.expected.vulnerable.min_results,
      vulnerable_max_results: item.expected.vulnerable.max_results,
      fixed_min_results: item.expected.fixed.min_results,
      fixed_max_results: item.expected.fixed.max_results,
      must_have_code_flow: item.expected.vulnerable.requires_code_flow,
      expected_rule_ids: [`pure-auto-codeql/${item.id}-intent`],
      source: {
        label: item.expected.vulnerable.source.semantic_id,
        description: item.expected.vulnerable.source.semantic_id,
        file: item.expected.vulnerable.source.path,
        line: item.expected.vulnerable.source.line,
      },
      sink: {
        label: item.expected.vulnerable.sink.semantic_id,
        description: item.expected.vulnerable.sink.semantic_id,
        file: item.expected.vulnerable.sink.path,
        line: item.expected.vulnerable.sink.line,
      },
    },
    max_rounds: 3,
    timeout_ms: 300_000,
    created_at: new Date().toISOString(),
    // Exercise the same admission path used by Pi. The fixture remains
    // deterministic, but its source root, exact endpoints and probe evidence
    // are now required just like a user-supplied case.
    input_provenance: "user_provided",
    reference_query_excluded: true,
    provenance: { fixture: `test/golden/${item.id}`, license: "MIT", source: "M3 structured-intent renderer gate" },
  };
}

function parseLastJson(values) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    try {
      const parsed = JSON.parse(values[index]);
      if (parsed !== null && typeof parsed === "object") return parsed;
    } catch {
      // CLI output may arrive in multiple chunks; continue looking for a full JSON envelope.
    }
  }
  return undefined;
}

function makeIntent(item) {
  const common = {
    schema_version: "v2.contracts/1",
    intent_id: `${item.id}-intent`,
    language: item.language,
    cwe: item.cwe,
    query_kind: "path-problem",
    flow_mode: "taint",
    message: item.description,
  };
  if (item.language === "python") {
    if (item.id === "python_sql_injection") {
      return { ...common, source: { kind: "environment", name: "getenv" }, sink: { kind: "call", module: "sqlite3", member: "connect", argument_index: 0 } };
    }
    if (item.id === "python_path_traversal") {
      return { ...common, source: { kind: "environment", name: "getenv" }, sink: { kind: "call", module: "os", member: "open", argument_index: 0 } };
    }
    if (item.id === "python_ssrf") {
      return { ...common, source: { kind: "environment", name: "getenv" }, sink: { kind: "call", module: "requests", member: "get", argument_index: 0 } };
    }
    if (item.id === "python_unsafe_deserialization") {
      return { ...common, source: { kind: "environment", name: "getenv" }, sink: { kind: "call", module: "pickle", member: "loads", argument_index: 0 } };
    }
    return { ...common, source: { kind: "environment", name: "getenv" }, sink: { kind: "call", module: "os", member: "system", argument_index: 0 } };
  }
  if (item.language === "javascript") {
    if (item.id === "javascript_path_traversal") {
      return { ...common, source: { kind: "environment", name: "env.USER_FILE" }, sink: { kind: "call", module: "fs", member: "readFileSync", argument_index: 0 } };
    }
    if (item.id === "javascript_eval_injection") {
      return { ...common, source: { kind: "environment", name: "env.USER_CODE" }, sink: { kind: "call", module: "vm", member: "runInNewContext", argument_index: 0 } };
    }
    if (item.id === "javascript_file_write") {
      return { ...common, source: { kind: "environment", name: "env.USER_FILE" }, sink: { kind: "call", module: "fs", member: "writeFileSync", argument_index: 0 } };
    }
    if (item.id === "javascript_ssrf") {
      return { ...common, source: { kind: "environment", name: "env.USER_URL" }, sink: { kind: "call", module: "http", member: "request", argument_index: 0 } };
    }
    return { ...common, source: { kind: "environment", name: "env.USER_COMMAND" }, sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 } };
  }
  if (item.language === "java") {
    if (item.id === "java_command_injection") {
      return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: { kind: "call", type: "java.lang.Runtime", member: "exec", argument_index: 0 } };
    }
    if (item.id === "java_sql_injection") {
      return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: { kind: "call", type: "java.sql.Statement", member: "executeQuery", argument_index: 0 } };
    }
    if (item.id === "java_ssrf") {
      return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: { kind: "constructor", type: "java.net.URL", argument_index: 0 } };
    }
    if (item.id === "java_file_write") {
      return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: { kind: "constructor", type: "java.io.FileOutputStream", argument_index: 0 } };
    }
    return { ...common, source: { kind: "call", type: "java.lang.System", member: "getenv" }, sink: { kind: "constructor", type: "java.io.File", argument_index: 0 } };
  }
  if (item.id === "cpp_command_injection") {
    return { ...common, source: { kind: "function", name: "getenv" }, sink: { kind: "function", name: "system", argument_index: 0 } };
  }
  if (item.id === "cpp_popen_command_injection") {
    return { ...common, source: { kind: "function", name: "getenv" }, sink: { kind: "function", name: "popen", argument_index: 0 } };
  }
  if (item.id === "cpp_path_traversal") {
    return { ...common, source: { kind: "function", name: "getenv" }, sink: { kind: "function", name: "fopen", argument_index: 0 } };
  }
  if (item.id === "cpp_allocation_size") {
    return { ...common, source: { kind: "function", name: "getenv" }, sink: { kind: "function", name: "malloc", argument_index: 0 } };
  }
  return { ...common, source: { kind: "function", name: "atoi" }, sink: { kind: "array_index" } };
}

function createDatabase(database, sourceRoot, language) {
  return mkdir(dirname(database), { recursive: true }).then(() => run(codeql, ["database", "create", database, `--language=${language}`, `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot, 300_000));
}

function run(executable, args, cwd, timeoutMs) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { cwd, shell: false });
    let stderr = "";
    let stdout = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${executable} ${args.join(" ")} timed out`));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-16_384); });
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-16_384); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolvePromise({ stdout, stderr });
      else reject(new Error(`${executable} ${args.join(" ")} failed (${code ?? signal})\n${stderr}`));
    });
  });
}
