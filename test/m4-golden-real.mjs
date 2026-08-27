import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { createLocalApplication } from "@pure-auto-codeql/codeql-runner";
import { runCli } from "@pure-auto-codeql/cli";
import {
  GoldenManifestSchema,
  TaintQueryIntentSchema,
  parseSchema,
  stableDigest,
} from "@pure-auto-codeql/contracts";
import { buildSourceContext } from "./m4-golden-input.mjs";
import { sanitizedGeneratorEnvironment } from "./m4-golden-environment.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = parseSchema(
  GoldenManifestSchema,
  JSON.parse(await readFile(join(repoRoot, "test/golden/manifest.json"), "utf8")),
  "golden manifest",
);
const codeql = process.env.CODEQL_PATH ?? "codeql";
const generator = process.env.PURE_AUTO_CODEQL_M4_GENERATOR;
const generatorArgs = process.env.PURE_AUTO_CODEQL_M4_GENERATOR_ARGS === undefined
  ? []
  : JSON.parse(process.env.PURE_AUTO_CODEQL_M4_GENERATOR_ARGS);
const generatorMode = process.env.PURE_AUTO_CODEQL_M4_GENERATOR_MODE ?? "diagnostic";
const countedApproved = generatorMode === "counted" && process.env.PURE_AUTO_CODEQL_M4_GENERATOR_APPROVED === "true";
const selectedCase = process.env.M4_GOLDEN_CASE ?? "python_command_injection";
const runCount = Number(process.env.M4_GOLDEN_RUNS ?? "5");
const skipFixed = process.env.M4_GOLDEN_SKIP_FIXED === "true";

if (generator === undefined || generator.length === 0) {
  console.error("M4 Golden BLOCKED: set PURE_AUTO_CODEQL_M4_GENERATOR to an approved structured-intent model wrapper; no fake result is counted.");
  process.exitCode = 2;
} else if (!Number.isInteger(runCount) || runCount < 1 || runCount > 5) {
  console.error("M4 Golden BLOCKED: M4_GOLDEN_RUNS must be an integer from 1 to 5.");
  process.exitCode = 2;
} else {
  await runGolden();
}

async function runGolden() {
  const item = manifest.cases.find((candidate) => selectedCase === undefined || candidate.case_id === selectedCase);
  if (item === undefined) {
    console.error(`M4 Golden BLOCKED: unknown case ${selectedCase}`);
    process.exitCode = 2;
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-m4-golden-"));
  const reports = [];
  try {
    for (let run = 1; run <= runCount; run += 1) {
      const report = await runOne(root, item, run);
      reports.push(report);
      process.stdout.write(`${JSON.stringify(report)}\n`);
    }
    const counted = reports.filter((report) => report.counted && report.metadata_complete);
    const successes = counted.filter((report) => report.success).length;
    const status = counted.length === 0 ? "diagnostic" : successes >= 4 ? "passed" : "failed";
    const envelope = {
      schema_version: "v2.m4.golden-report/1",
      evaluator_version: "m4-structured-intent/2026-08-26",
      status,
      case_id: item.case_id,
      counted_runs: counted.length,
      successes,
      total: reports.length,
      admission: "counted 5 independent runs, suggested >=4/5",
      fixed_database: skipFixed ? "not_provided" : "provided",
      runs: reports,
    };
    process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
    if (process.env.PURE_AUTO_CODEQL_M4_REPORT !== undefined) {
      await import("node:fs/promises").then(({ writeFile }) => writeFile(process.env.PURE_AUTO_CODEQL_M4_REPORT, `${JSON.stringify(envelope, null, 2)}\n`, "utf8"));
    }
    if (status === "diagnostic") process.exitCode = 2;
    else if (status !== "passed") process.exitCode = 1;
  } catch (error) {
    console.error(`M4 Golden BLOCKED: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    process.exitCode = 2;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function runOne(root, item, run) {
  const runRoot = join(root, `run-${run}`);
  const vulnerableRoot = join(runRoot, "vulnerable-source");
  const fixedRoot = join(runRoot, "fixed-source");
  const vulnerableDb = join(runRoot, "vulnerable-db");
  const fixedDb = skipFixed ? undefined : join(runRoot, "fixed-db");
  await cp(join(repoRoot, "test/golden", item.fixture_root, item.source.vulnerable), join(vulnerableRoot, "src"), { recursive: true });
  await createDatabase(vulnerableDb, vulnerableRoot, item.language);
  if (fixedDb !== undefined) {
    await cp(join(repoRoot, "test/golden", item.fixture_root, item.source.fixed), join(fixedRoot, "src"), { recursive: true });
    await createDatabase(fixedDb, fixedRoot, item.language);
  }

  const spec = makeSpec(item, vulnerableDb, fixedDb, vulnerableRoot);
  const app = createLocalApplication({
    cwd: repoRoot,
    runsDir: join(runRoot, "runs"),
    workspaceRoot: root,
    codeqlPath: codeql,
    timeoutMs: 300_000,
  });
  const report = {
    run,
    counted: countedApproved,
    success: false,
    run_id: "not_started",
    metadata_complete: false,
    provider: "not_reported",
    model: "not_reported",
    adapter_version: "not_reported",
    parameters: {},
    usage: { status: "unavailable" },
    generator_calls: [],
    rounds: [],
    diagnostics: [],
    failure_classification: undefined,
    fixed_database: fixedDb === undefined ? "not_provided" : "provided",
  };
  let workflow;
  let successfulCandidate;
  try {
    workflow = await app.workflowStart(spec, { timeoutMs: 300_000 });
    report.run_id = workflow.run.runId;
    const sourceContext = await buildSourceContext(vulnerableRoot, item.language);
    let previousFeedback = [];
    for (let round = 1; round <= 3; round += 1) {
      const modelInput = buildModelInput(item, spec, run, round, previousFeedback, sourceContext);
      const generated = await runGenerator(modelInput, runRoot);
      absorbMetadata(report, generated.metadata, generated.elapsedMs, modelInput.input_sha256, round);
      let intent;
      try {
        intent = parseSchema(TaintQueryIntentSchema, generated.candidate.intent, "model Source/Sink intent");
      } catch (error) {
        const intentError = compactModelInputError(error, "INTENT_INVALID");
        report.rounds.push({
          round,
          candidate_digest: "not_submitted",
          failure: intentError.code,
        });
        previousFeedback = [{ phase: "intent", result: intentError }];
        continue;
      }
      let probe;
      let probeError;
      try {
        probe = await app.queryProbe(workflow.run.runId, intent, { timeoutMs: 300_000 });
      } catch (error) {
        if (error?.category !== "input") throw error;
        probeError = compactProbeError(error);
        probe = { status: "failed", source: { locations: [] }, sink: { locations: [] }, diagnostics: probeError.diagnostics };
      }
      const roundRecord = {
        round,
        candidate_digest: "not_submitted",
        probe: compactProbe(probe),
        draft: undefined,
        verification: undefined,
      };
      if (probeError !== undefined) {
        roundRecord.failure = probeError.code;
        previousFeedback = [{ phase: "probe", result: probeError }];
        report.rounds.push(roundRecord);
        continue;
      }
      if (probe.status !== "passed" || probe.source.locations.length === 0 || probe.sink.locations.length === 0) {
        roundRecord.failure = "PROBE_FAILED";
        previousFeedback = [{ phase: "probe", result: compactProbe(probe) }];
        report.rounds.push(roundRecord);
        continue;
      }
      const candidate = {
        schema_version: "v2.contracts/1",
        candidate_id: validId(generated.candidate.candidate_id, `${item.case_id}-pi-${run}-r${round}`),
        query_id: validId(generated.candidate.query_id, `${item.case_id}-pi-${run}-r${round}`),
        spec_id: spec.spec_id,
        language: spec.language,
        intent,
        probe_evidence: probe,
        round,
        origin: round === 1 ? "pi_generated" : "pi_revised",
        ...(typeof generated.candidate.parent_candidate_id === "string" ? { parent_candidate_id: generated.candidate.parent_candidate_id } : {}),
        ...(typeof generated.candidate.rationale === "string" ? { rationale: generated.candidate.rationale } : {}),
      };
      const draft = await app.queryDraft(workflow.run.runId, candidate, { timeoutMs: 120_000 });
      roundRecord.draft = compactDraft(draft);
      if (draft.status === "errors" || draft.status === "cancelled") {
        roundRecord.failure = `QUERY_DRAFT_${draft.status.toUpperCase()}`;
        previousFeedback = [{ phase: "draft", result: compactDraft(draft) }];
        report.rounds.push(roundRecord);
        continue;
      }
      const verification = await app.queryVerify(workflow.run.runId, candidate, { timeoutMs: 300_000 });
      roundRecord.candidate_digest = candidateDigest(candidate);
      roundRecord.verification = compactVerification(verification);
      report.diagnostics.push(...verification.diagnostics.map((diagnostic) => diagnostic.code));
      report.rounds.push(roundRecord);
      if (verification.passed) {
        successfulCandidate = candidate;
        break;
      }
      previousFeedback = [{ phase: "verification", result: compactVerification(verification) }];
      if (verification.case_summary?.status === "budget_exhausted") break;
    }
    if (successfulCandidate === undefined) {
      report.failure_classification = report.rounds.at(-1)?.failure ?? report.rounds.at(-1)?.verification?.diagnostics?.[0]?.code ?? "QUERY_NOT_VERIFIED";
      return report;
    }
    await app.workflowFinalize(workflow.run.runId, { timeoutMs: 300_000 });
    const completed = await app.status(workflow.run.runId);
    const relocatedPack = join(runRoot, "relocated-pack");
    await cp(join(completed.artifactRoot, "query-pack"), relocatedPack, { recursive: true });
    const replay = await replayPack(relocatedPack, vulnerableDb, fixedDb, runRoot);
    report.replay = replay;
    report.success = replay.passed === true;
    report.failure_classification = report.success ? undefined : "QUERY_PACK_REPLAY_FAILED";
    return report;
  } catch (error) {
    report.failure_classification = error?.code ?? (error instanceof Error ? error.message : "M4_WORKFLOW_FAILURE");
    return report;
  } finally {
    await app.close();
  }
}

function makeSpec(item, vulnerableDb, fixedDb, projectRoot) {
  return {
    schema_version: "v2.contracts/1",
    spec_id: item.case_id,
    language: item.language,
    cwe: item.cwe,
    project_root: projectRoot,
    vulnerability_description: item.description,
    patch_description: item.patch_description ?? "The fixed variant removes the vulnerable Source-to-Sink flow.",
    vulnerable_database: { path: vulnerableDb, language: item.language },
    ...(fixedDb === undefined ? {} : { fixed_database: { path: fixedDb, language: item.language } }),
    validation: {
      vulnerable_min_results: item.expected.vulnerable.min_results,
      vulnerable_max_results: item.expected.vulnerable.max_results,
      fixed_min_results: item.expected.fixed.min_results,
      fixed_max_results: item.expected.fixed.max_results,
      must_have_code_flow: item.expected.vulnerable.requires_code_flow,
      source: { label: item.expected.vulnerable.source.semantic_id, description: item.expected.vulnerable.source.semantic_id, file: item.expected.vulnerable.source.path, line: item.expected.vulnerable.source.line },
      sink: { label: item.expected.vulnerable.sink.semantic_id, description: item.expected.vulnerable.sink.semantic_id, file: item.expected.vulnerable.sink.path, line: item.expected.vulnerable.sink.line },
    },
    max_rounds: 3,
    timeout_ms: 300_000,
    created_at: new Date().toISOString(),
    input_provenance: "user_provided",
    reference_query_excluded: true,
    provenance: { fixture: `test/golden/${item.case_id}`, license: "MIT", source: "M4 structured-intent evaluator" },
  };
}

function buildModelInput(item, spec, run, round, previousFeedback, sourceContext) {
  const input = {
    schema_version: "v2.m4.generator-input/1",
    template_version: "m4-source-sink-probe-draft/1",
    run,
    round,
    project_root: spec.project_root,
    language: item.language,
    cwe: item.cwe,
    vulnerability_description: item.description,
    patch_description: item.patch_description ?? "The fixed variant removes the vulnerable Source-to-Sink flow.",
    source_context: sourceContext,
    databases: {
      vulnerable: "<provided-codeql-database>",
      ...(skipFixed ? {} : { fixed: "<provided-fixed-codeql-database>" }),
    },
    previous_feedback: previousFeedback,
    constraints: {
      return_structured_intent_only: true,
      no_reference_query_or_intent: true,
      no_database_creation: true,
      max_formal_candidates: 3,
    },
  };
  return {
    ...input,
    input_sha256: createHash("sha256").update(JSON.stringify(input)).digest("hex"),
  };
}

async function runGenerator(input, cwd) {
  const startedAt = Date.now();
  const result = await runProcess(generator, generatorArgs, cwd, 180_000, JSON.stringify(input), sanitizedGeneratorEnvironment());
  let value;
  try {
    value = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`M4 model wrapper returned invalid JSON: ${error instanceof Error ? error.message : "parse error"}`);
  }
  if (typeof value !== "object" || value === null || typeof value.metadata !== "object" || value.metadata === null || typeof value.candidate !== "object" || value.candidate === null || value.candidate.intent === undefined) {
    throw new Error("GENERATOR_METADATA_MISSING: wrapper must return candidate.intent and metadata");
  }
  const metadata = value.metadata;
  if (typeof metadata.provider !== "string" || typeof metadata.model !== "string" || typeof metadata.adapter_version !== "string" || typeof metadata.parameters !== "object" || metadata.parameters === null || typeof metadata.usage !== "object" || metadata.usage === null) {
    throw new Error("GENERATOR_METADATA_MISSING: provider, model, adapter_version, parameters and usage are required");
  }
  return {
    candidate: value.candidate,
    elapsedMs: Date.now() - startedAt,
    metadata: {
      provider: metadata.provider,
      model: metadata.model,
      adapter_version: metadata.adapter_version,
      parameters: sanitizeMetadata(metadata.parameters),
      usage: sanitizeUsage(metadata.usage),
    },
  };
}

function absorbMetadata(report, metadata, elapsedMs, inputSha256, round) {
  report.provider = metadata.provider;
  report.model = metadata.model;
  report.adapter_version = metadata.adapter_version;
  report.parameters = metadata.parameters;
  report.usage = report.usage.status === "unavailable" ? metadata.usage : addUsage(report.usage, metadata.usage);
  report.metadata_complete = true;
  report.generator_calls.push({ round, input_sha256: inputSha256, ...metadata, elapsed_ms: elapsedMs });
}

function compactProbe(probe) {
  return {
    status: probe.status,
    diagnostics: probe.diagnostics,
    source: { locations: probe.source.locations },
    sink: { locations: probe.sink.locations },
  };
}

function compactProbeError(error) {
  return {
    status: "failed",
    code: typeof error?.code === "string" ? error.code : "PROBE_INPUT_REJECTED",
    message: typeof error?.message === "string" ? error.message : "The Source/Sink intent was rejected before probing.",
    diagnostics: [{
      code: typeof error?.code === "string" ? error.code : "PROBE_INPUT_REJECTED",
      message: typeof error?.message === "string" ? error.message : "The Source/Sink intent was rejected before probing.",
    }],
    source: { locations: [] },
    sink: { locations: [] },
  };
}

function compactModelInputError(error, fallbackCode) {
  const issues = Array.isArray(error?.details?.issues)
    ? error.details.issues.slice(0, 16).map((issue) => ({
      path: typeof issue?.path === "string" ? issue.path : "",
      message: typeof issue?.message === "string" ? issue.message : "invalid value",
    }))
    : undefined;
  return {
    status: "failed",
    code: typeof error?.code === "string" ? error.code : fallbackCode,
    message: typeof error?.message === "string" ? error.message : "The model returned an invalid structured intent.",
    ...(issues === undefined ? {} : { issues }),
  };
}

function compactDraft(draft) {
  return {
    status: draft.status,
    lsp_available: draft.lsp_available,
    diagnostics: draft.diagnostics,
    definition_locations: draft.definition_locations,
    hover_text: draft.hover_text,
    completion_labels: draft.completion_labels,
  };
}

function compactVerification(verification) {
  return {
    status: verification.status,
    passed: verification.passed,
    diagnostics: verification.diagnostics,
    repair_brief: verification.repair_brief,
    case_summary: verification.case_summary,
    vulnerable: {
      status: verification.vulnerable.status,
      result_count: verification.vulnerable.result_count,
      code_flow_count: verification.vulnerable.code_flow_count,
      flow_evidence: verification.vulnerable.flow_evidence,
    },
    fixed: { status: verification.fixed.status, result_count: verification.fixed.result_count, code_flow_count: verification.fixed.code_flow_count },
  };
}

function candidateDigest(candidate) {
  return stableDigest(JSON.stringify({ candidate_id: candidate.candidate_id, query_id: candidate.query_id, spec_id: candidate.spec_id, intent: candidate.intent, round: candidate.round }));
}

function validId(value, fallback) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9._-]{2,127}$/.test(value) ? value : fallback;
}

function sanitizeMetadata(value) {
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (/(api[_-]?key|secret|password|authorization|bearer|token)/i.test(key)) throw new Error("GENERATOR_METADATA_SECRET");
    if (!["string", "number", "boolean"].includes(typeof item) || typeof item === "number" && !Number.isFinite(item)) throw new Error(`GENERATOR_METADATA_INVALID: ${key}`);
    result[key] = item;
  }
  return result;
}

function sanitizeUsage(value) {
  const result = {};
  for (const key of ["input_tokens", "output_tokens", "total_tokens", "cache_input_tokens", "cost_usd"]) {
    if (value[key] !== undefined) {
      if (typeof value[key] !== "number" || !Number.isFinite(value[key]) || value[key] < 0) throw new Error(`GENERATOR_USAGE_INVALID: ${key}`);
      result[key] = value[key];
    }
  }
  if (result.input_tokens === undefined || result.output_tokens === undefined || result.total_tokens === undefined) throw new Error("GENERATOR_USAGE_UNAVAILABLE");
  return result;
}

function addUsage(left, right) {
  const result = {};
  for (const key of ["input_tokens", "output_tokens", "total_tokens", "cache_input_tokens", "cost_usd"]) {
    if (left[key] !== undefined || right[key] !== undefined) result[key] = (left[key] ?? 0) + (right[key] ?? 0);
  }
  return result;
}

async function replayPack(pack, vulnerableDb, fixedDb, runRoot) {
  const args = ["query-pack", "verify", pack, "--vulnerable-db", vulnerableDb];
  if (fixedDb !== undefined) args.push("--fixed-db", fixedDb);
  args.push("--json", "--runs-dir", join(runRoot, "replay-runs"), "--workspace-root", runRoot, "--codeql", codeql);
  const stdout = [];
  const code = await runCli(args, { stdout: (value) => stdout.push(value), stderr: () => undefined });
  if (code !== 0) return { passed: false };
  const envelope = JSON.parse(stdout.join(""));
  return { passed: envelope.ok === true && envelope.result?.verification?.passed === true, pack_id: envelope.result?.pack?.pack_id ?? "unknown" };
}

async function createDatabase(database, sourceRoot, language) {
  await mkdir(dirname(database), { recursive: true });
  await runProcess(codeql, ["database", "create", database, `--language=${language}`, `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot, 300_000);
}

function runProcess(executable, args, cwd, timeoutMs, input = undefined, env = undefined) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    const kill = () => {
      try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); }
    };
    const timer = setTimeout(kill, timeoutMs);
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`${executable} ${args.join(" ")} failed (${code ?? signal})\n${Buffer.concat(stderr).toString("utf8").slice(-4000)}`));
        return;
      }
      resolvePromise({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
    });
    child.stdin.end(input);
  });
}
