import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

import { createLocalApplication, readAutovulEnv } from "@autovul/codeql-runner";
import { M2GoldenReportSchema, parseSchema, QueryCandidateSchema, stableDigest } from "@autovul/contracts";
import { runCli } from "@autovul/cli";

const repoRoot = resolve(new URL("..", import.meta.url).pathname, "..");
const fixtureRoot = join(repoRoot, "test", "golden", "python_command_injection");
const manifestPath = join(repoRoot, "test", "golden", "manifest.json");
const codeql = readAutovulEnv("M2_CODEQL") ?? process.env.CODEQL_PATH ?? "codeql";
const generator = readAutovulEnv("M2_GENERATOR");
const generatorArgsValue = readAutovulEnv("M2_GENERATOR_ARGS");
const generatorArgs = generatorArgsValue === undefined
  ? []
  : JSON.parse(generatorArgsValue);
const generatorMode = readAutovulEnv("M2_GENERATOR_MODE") ?? "diagnostic";
const countedApproved = generatorMode === "counted" && readAutovulEnv("M2_GENERATOR_APPROVED") === "true";
const caseFilePath = readAutovulEnv("M2_CASE_FILE");
const externalVulnerableDatabase = readAutovulEnv("M2_VULNERABLE_DB");
const externalFixedDatabase = readAutovulEnv("M2_FIXED_DB");
const externalWorkspaceRoot = readAutovulEnv("M2_WORKSPACE_ROOT");

if (generator === undefined || typeof generator !== "string" || generator.length === 0) {
  console.error("M2 Golden BLOCKED: set AUTOVUL_M2_GENERATOR to an approved model-wrapper executable; no fake result is counted.");
  process.exitCode = 2;
} else {
  await runGolden();
}

async function runGolden() {
  const root = await mkdtemp(join(tmpdir(), "autovul-m2-golden-"));
  const report = [];
  try {
    const goldenCase = await loadGoldenCase();
    const databases = await createDatabases(root);
    for (let runNumber = 1; runNumber <= 5; runNumber += 1) {
      report.push(await runOne(root, databases, goldenCase, runNumber));
    }
    const counted = report.filter((item) => item.counted && item.metadata_complete);
    const successes = counted.filter((item) => item.success).length;
    const status = counted.length === 0 ? "diagnostic" : successes >= 4 ? "passed" : "failed";
    const envelope = parseSchema(M2GoldenReportSchema, JSON.parse(JSON.stringify({
      report_schema_version: "v2.m2.golden-report/1", evaluator_version: "m2.1/2026-08-24", status, successes,
      counted_runs: counted.length, total: report.length, admission: "suggested >=4/5", runs: report,
    })), "M2 Golden report");
    const rendered = JSON.stringify(envelope, null, 2);
    const reportPath = readAutovulEnv("M2_REPORT");
    if (reportPath !== undefined) {
      await writeFile(reportPath, `${rendered}\n`, "utf8");
    }
    console.log(rendered);
    if (status === "diagnostic") {
      process.exitCode = 2;
    } else if (successes < 4) {
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`M2 Golden BLOCKED: ${error instanceof Error ? error.message : "real evaluator failed"}`);
    process.exitCode = 2;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function loadGoldenCase() {
  if (caseFilePath !== undefined) {
    const external = JSON.parse(await readFile(caseFilePath, "utf8"));
    if (typeof external !== "object" || external === null || external.case_id === undefined) {
      throw new Error("external M2 case file must contain case_id");
    }
    return external;
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const goldenCase = manifest.cases.find((item) => item.case_id === "python_command_injection");
  if (goldenCase === undefined) {
    throw new Error("python_command_injection is missing from the shared Golden manifest");
  }
  return goldenCase;
}

async function createDatabases(root) {
  if (externalVulnerableDatabase !== undefined) {
    if (externalFixedDatabase === undefined) {
      throw new Error("AUTOVUL_M2_FIXED_DB is required when using an external vulnerable database");
    }
    return { vulnerable: externalVulnerableDatabase, fixed: externalFixedDatabase };
  }
  const vulnerable = join(root, "vulnerable");
  const fixed = join(root, "fixed");
  await runProcess(codeql, ["database", "create", vulnerable, "--language=python", `--source-root=${join(fixtureRoot, "src")}`, "--overwrite"], 180_000);
  await runProcess(codeql, ["database", "create", fixed, "--language=python", `--source-root=${join(fixtureRoot, "src_fixed")}`, "--overwrite"], 180_000);
  return { vulnerable, fixed };
}

async function runOne(root, databases, goldenCase, runNumber) {
  const runRoot = join(root, `run-${runNumber}`);
  const runsDir = join(runRoot, "runs");
  const source = goldenCase.expected.vulnerable.source;
  const sink = goldenCase.expected.vulnerable.sink;
  const spec = {
    schema_version: "v2.contracts/1", spec_id: `python-command-injection-${runNumber}`, language: "python", cwe: goldenCase.cwe,
    vulnerability_description: `${goldenCase.description} Generate a Python source-to-sink query without using the reference query.`,
    patch_description: goldenCase.patch_description ?? "The fixed variant removes the tainted source-to-sink flow.",
    vulnerable_database: { path: databases.vulnerable, language: "python" }, fixed_database: { path: databases.fixed, language: "python" },
    validation: {
      vulnerable_min_results: goldenCase.expected.vulnerable.min_results, vulnerable_max_results: goldenCase.expected.vulnerable.max_results,
      fixed_min_results: goldenCase.expected.fixed.min_results, fixed_max_results: goldenCase.expected.fixed.max_results,
      must_have_code_flow: goldenCase.expected.vulnerable.requires_code_flow, expected_rule_ids: [goldenCase.expected.vulnerable.rule_id],
      source: { label: source.semantic_id, description: "manifest source", file: source.path, line: source.line },
      sink: { label: sink.semantic_id, description: "manifest sink", file: sink.path, line: sink.line },
    },
    max_rounds: 3, timeout_ms: 120_000, created_at: new Date().toISOString(), input_provenance: goldenCase.input_provenance ?? "golden_fixture", reference_query_excluded: true,
    provenance: goldenCase.provenance ?? { fixture: "golden-case", license: "MIT", source: "shared Golden manifest" },
  };
  const workspaceRoot = externalWorkspaceRoot ?? root;
  const app = createLocalApplication({ cwd: repoRoot, runsDir, workspaceRoot, codeqlPath: codeql, timeoutMs: 120_000 });
  const diagnostics = [];
  const rounds = [];
  let finalVerification;
  let finalCandidate;
  let workflow;
  const report = {
    run: runNumber, counted: countedApproved, success: false, run_id: "not_started", rounds, diagnostics,
    metadata_complete: false, provider: "not_reported", model: "not_reported", adapter_version: "not_reported", parameters: {}, usage: { status: "unavailable" }, generator_calls: [],
    generator_elapsed_ms: 0, failure_classification: undefined,
  };
  try {
    workflow = await app.workflowStart(spec);
    report.run_id = workflow.run.runId;
    for (let round = 1; round <= 3; round += 1) {
      const generatedInput = generatorInput(spec, round, diagnostics);
      const generated = await runGenerator(generatedInput, runRoot);
      report.provider = generated.metadata.provider; report.model = generated.metadata.model; report.adapter_version = generated.metadata.adapter_version;
      report.parameters = generated.metadata.parameters;
      report.usage = report.usage.status === "unavailable" ? generated.metadata.usage : addUsage(report.usage, generated.metadata.usage);
      report.metadata_complete = true;
      report.generator_calls.push({ round, input_sha256: generatedInput.input_sha256, provider: generated.metadata.provider, model: generated.metadata.model, adapter_version: generated.metadata.adapter_version, parameters: generated.metadata.parameters, usage: generated.metadata.usage, elapsed_ms: generated.elapsedMs });
      report.generator_elapsed_ms += generated.elapsedMs;
      const candidate = normalizeCandidate(generated.value.candidate, spec, runNumber, round, goldenCase);
      const referencePath = goldenCase.reference?.query === undefined
        ? undefined
        : join(repoRoot, "test", "golden", goldenCase.fixture_root, goldenCase.reference.query);
      const referenceText = referencePath === undefined ? undefined : await readFile(referencePath, "utf8");
      if (referenceText !== undefined && (candidate.ql_text.trim() === referenceText.trim() || candidate.ql_text.includes(referenceText.trim()))) {
        report.failure_classification = "reference_leak";
        rounds.push({ round, candidate_digest: candidateDigest(candidate), diagnostics: ["REFERENCE_LEAK"] });
        return report;
      }
      finalCandidate = candidate;
      finalVerification = await app.queryVerify(workflow.run.runId, candidate);
      rounds.push({ round, candidate_digest: candidateDigest(candidate), parent_candidate_id: candidate.parent_candidate_id, diagnostics: finalVerification.diagnostics.map((item) => item.code), elapsed_ms: finalVerification.elapsed_ms });
      diagnostics.push(...finalVerification.diagnostics.map((item) => item.code));
      if (finalVerification.passed) break;
    }
    if (finalVerification?.passed !== true || finalCandidate === undefined) {
      report.failure_classification = finalVerification?.diagnostics[0]?.code ?? "QUERY_NOT_VERIFIED";
      return report;
    }
    await app.workflowFinalize(workflow.run.runId);
  } catch (error) {
    if (error instanceof Error && /(GENERATOR_METADATA|GENERATOR_USAGE)/.test(error.message)) {
      report.metadata_complete = false;
    }
    report.failure_classification = error?.code ?? (error instanceof Error ? error.message : "GENERATOR_OR_WORKFLOW_FAILURE");
    return report;
  } finally {
    await app.close();
  }

  const replayPack = join(runRoot, "relocated-pack");
  const finalized = await invokeCli(["workflow", "finalize", workflow.run.runId, "--output", replayPack, "--json", "--runs-dir", runsDir, "--workspace-root", workspaceRoot, "--codeql", codeql]);
  const replay = await invokeCli(["query-pack", "verify", replayPack, "--vulnerable-db", databases.vulnerable, "--fixed-db", databases.fixed, "--json", "--runs-dir", join(runRoot, "replay-runs"), "--workspace-root", workspaceRoot, "--codeql", codeql]);
  report.success = replay.result.verification.passed === true && finalized.result.files.manifest === "query-pack-manifest.json";
  report.failure_classification = report.success ? undefined : "QUERY_PACK_REPLAY_FAILED";
  report.replay = { passed: replay.result.verification.passed, pack_id: replay.result.pack.pack_id };
  return report;
}

function generatorInput(spec, round, previousDiagnostics) {
  const sanitizedSpec = { ...spec, vulnerable_database: { path: "<provided-python-database>", language: "python" }, fixed_database: { path: "<provided-fixed-python-database>", language: "python" } };
  const input = { schema_version: "v2.m2.generator-input/2", template_version: "m2-python-query/2", spec: sanitizedSpec, round, previous_diagnostics: previousDiagnostics };
  return { ...input, input_sha256: createHash("sha256").update(JSON.stringify(input)).digest("hex") };
}

function normalizeCandidate(value, spec, runNumber, round, goldenCase) {
  const candidate = typeof value === "string" ? { ql_text: value } : value;
  if (typeof candidate !== "object" || candidate === null || typeof candidate.ql_text !== "string") throw new Error("model wrapper candidate must contain QL text");
  return parseSchema(QueryCandidateSchema, {
    schema_version: "v2.contracts/1", candidate_id: typeof candidate.candidate_id === "string" ? candidate.candidate_id : `m2-${runNumber}-${round}`,
    query_id: typeof candidate.query_id === "string" ? candidate.query_id : goldenCase.query_id ?? `python-command-injection-${runNumber}`, spec_id: spec.spec_id, language: "python",
    ql_text: candidate.ql_text, round, origin: round === 1 ? "pi_generated" : "pi_revised",
    ...(typeof candidate.parent_candidate_id === "string" ? { parent_candidate_id: candidate.parent_candidate_id } : {}),
    ...(typeof candidate.rationale === "string" ? { rationale: candidate.rationale } : {}),
  }, "model query candidate");
}

function candidateDigest(candidate) {
  return stableDigest(JSON.stringify({
    schema_version: candidate.schema_version, candidate_id: candidate.candidate_id, query_id: candidate.query_id, spec_id: candidate.spec_id,
    language: candidate.language, ql_text: candidate.ql_text, round: candidate.round, origin: candidate.origin,
    parent_candidate_id: candidate.parent_candidate_id, rationale: candidate.rationale,
  }));
}

async function runGenerator(input, runRoot) {
  const startedAt = Date.now();
  const generatorRoot = join(runRoot, "generator");
  await mkdir(generatorRoot, { recursive: true });
  const result = await runProcess(generator, generatorArgs, 120_000, JSON.stringify(input), generatorRoot, sanitizedEnvironment());
  let value;
  try { value = JSON.parse(result.stdout); } catch (error) { throw new Error(`model wrapper returned invalid JSON: ${error instanceof Error ? error.message : "parse error"}`); }
  if (typeof value !== "object" || value === null || typeof value.metadata !== "object" || value.metadata === null || value.candidate === undefined) throw new Error("GENERATOR_METADATA_MISSING: wrapper must return candidate and metadata");
  const metadata = value.metadata;
  if (typeof metadata.provider !== "string" || typeof metadata.model !== "string" || typeof metadata.adapter_version !== "string" || typeof metadata.parameters !== "object" || metadata.parameters === null || typeof metadata.usage !== "object" || metadata.usage === null) throw new Error("GENERATOR_METADATA_MISSING: provider, model, adapter_version, parameters and usage are required");
  return { value, elapsedMs: Date.now() - startedAt, metadata: { provider: metadata.provider, model: metadata.model, adapter_version: metadata.adapter_version, parameters: sanitizeMetadataRecord(metadata.parameters), usage: sanitizeUsage(metadata.usage) } };
}

function sanitizeMetadataRecord(value) {
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (/(api[_-]?key|secret|password|authorization|bearer|token)/i.test(key)) throw new Error("GENERATOR_METADATA_SECRET: refusing to persist secret-looking model metadata");
    if (!["string", "number", "boolean"].includes(typeof item) || (typeof item === "number" && !Number.isFinite(item))) throw new Error(`GENERATOR_METADATA_INVALID: parameter ${key} is not a scalar`);
    result[key] = item;
  }
  return result;
}

function sanitizeUsage(value) {
  const result = {};
  for (const key of ["input_tokens", "output_tokens", "total_tokens", "cache_input_tokens", "cost_usd"]) {
    if (value[key] !== undefined) {
      if (typeof value[key] !== "number" || !Number.isFinite(value[key]) || value[key] < 0) throw new Error(`GENERATOR_USAGE_INVALID: ${key} must be a non-negative number`);
      result[key] = value[key];
    }
  }
  if (result.input_tokens === undefined || result.output_tokens === undefined || result.total_tokens === undefined) throw new Error("GENERATOR_USAGE_UNAVAILABLE: input_tokens, output_tokens and total_tokens are required for counted runs");
  return result;
}

function addUsage(left, right) {
  const result = {};
  for (const key of ["input_tokens", "output_tokens", "total_tokens", "cache_input_tokens", "cost_usd"]) {
    if (left[key] !== undefined || right[key] !== undefined) result[key] = (left[key] ?? 0) + (right[key] ?? 0);
  }
  return result;
}

function sanitizedEnvironment() {
  const allowed = [
    "PATH", "NODE_PATH", "SystemRoot", "TMPDIR", "TMP", "TEMP",
    "M2_API_KEY", "M2_API_BASE", "M2_MODEL",
    "M2_PROVIDER", "M2_TEMPERATURE", "M2_MAX_TOKENS",
  ];
  return Object.fromEntries(allowed.map((key) => [key, readAutovulEnv(key)]).filter(([, value]) => value !== undefined).map(([key, value]) => [`AUTOVUL_${key}`, value]));
}

async function invokeCli(args) {
  const stdout = []; const stderr = [];
  const code = await runCli(args, { stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value) });
  const envelope = JSON.parse(stdout.join(""));
  if (code !== 0 || envelope.ok !== true) throw new Error(`CLI replay failed: ${envelope.error?.code ?? stderr.join("")}`);
  return envelope;
}

function runProcess(executable, args, timeoutMs, input = undefined, cwd = undefined, env = undefined) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { shell: false, cwd, env, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; const stderr = [];
    const timer = setTimeout(() => { try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); } }, timeoutMs);
    child.stdout.on("data", (chunk) => stdout.push(chunk)); child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(`${executable} exited with ${code ?? signal}: ${Buffer.concat(stderr).toString("utf8").slice(0, 2000)}`)); return; }
      resolvePromise({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
    });
    child.stdin.end(input === undefined ? undefined : input);
  });
}
