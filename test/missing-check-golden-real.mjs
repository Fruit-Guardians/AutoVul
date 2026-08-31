import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createLocalApplication } from "@autovul/codeql-runner";

const codeql = process.env.CODEQL_PATH ?? "codeql";
const vulnerableCommit = "75b4c059b8405dfbd50884b773346a9946fabd20";
const fixedCommit = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const sourceFile = "extensions/msteams/src/monitor-handler.ts";
const scriptPath = fileURLToPath(import.meta.url);
const replayRoot = process.argv[2] === "--replay" ? process.argv[3] : undefined;

if (replayRoot !== undefined) {
  const app = createLocalApplication({ cwd: replayRoot, workspaceRoot: replayRoot, runsDir: join(replayRoot, "runs"), codeqlPath: codeql, timeoutMs: 300_000 });
  try {
    const replay = await app.manageRun({ action: "replay", run_id: process.argv[4] }, { timeoutMs: 300_000 });
    process.stdout.write(`${JSON.stringify(compact(replay))}\n`);
    if (replay.operation_status !== "completed" || replay.capability !== "missing_check" || replay.verification_level !== "differential") process.exitCode = 1;
  } finally {
    await app.close();
  }
} else {
  const root = await mkdtemp(join(tmpdir(), "autovul-mcheck-golden-"));
  let failed = false;
  let report = {};
  try {
    await stageFile(vulnerableCommit, process.env.MCHECK_VULNERABLE_SOURCE, join(root, "vulnerable-source"));
    await stageFile(fixedCommit, process.env.MCHECK_FIXED_SOURCE, join(root, "fixed-source"));
    const vulnerableDb = join(root, "vulnerable-db");
    const fixedDb = join(root, "fixed-db");
    await createDatabase(vulnerableDb, join(root, "vulnerable-source"));
    await createDatabase(fixedDb, join(root, "fixed-source"));
    const app = createLocalApplication({ cwd: root, workspaceRoot: root, runsDir: join(root, "runs"), codeqlPath: codeql, timeoutMs: 300_000 });
    try {
      const execute = await app.research(request({ vulnerableDb, fixedDb }), { timeoutMs: 300_000 });
      const checkedSafe = await app.research(request({ vulnerableDb: fixedDb, mode: "reproduce", key: "openclaw-checked-safe" }), { timeoutMs: 300_000 });
      const wrongOperation = await app.research(request({ vulnerableDb, mode: "reproduce", key: "openclaw-wrong-operation", operation: "doesNotExist" }), { timeoutMs: 300_000 });
      const replay = "run_id" in execute ? await replayInFreshProcess(root, execute.run_id) : { failed: true };
      const passed = isDifferential(execute) && isCheckedSafe(checkedSafe) && isWrongOperation(wrongOperation) && replay.operation_status === "completed" && replay.verification_level === "differential";
      const portableEvidence = "run_id" in execute ? await buildPortableEvidence(root, execute.run_id, replay) : undefined;
      report = { schema_version: "autovul.missing-check.golden.real/1", case_id: "openclaw-cve-2026-43572", passed, execute: compact(execute), checked_safe: compact(checkedSafe), wrong_operation: compact(wrongOperation), replay, ...(portableEvidence === undefined ? {} : { portable_evidence: portableEvidence }) };
      failed = !passed;
    } finally {
      await app.close();
    }
  } catch (error) {
    failed = true;
    report = { schema_version: "autovul.missing-check.golden.real/1", passed: false, error: error instanceof Error ? error.message : String(error) };
  } finally {
    const serialized = `${JSON.stringify(report, null, process.env.MCHECK_REPORT_PATH === undefined ? 0 : 2)}\n`;
    process.stdout.write(serialized);
    if (process.env.MCHECK_REPORT_PATH !== undefined) {
      await mkdir(dirname(resolve(process.env.MCHECK_REPORT_PATH)), { recursive: true });
      await writeFile(resolve(process.env.MCHECK_REPORT_PATH), serialized, "utf8");
    }
    if (process.env.MCHECK_KEEP_ARTIFACTS !== "true") await rm(root, { recursive: true, force: true });
  }
  if (failed) process.exitCode = 1;
}

function hypothesis(operation = "handleSigninTokenExchangeInvoke") {
  return { schema_version: "autovul.missing-check/1", hypothesis_id: "mcheck-openclaw", language: "javascript", operation: { kind: "direct_call", name: operation }, required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" }, required_relation: "same_callback_cfg_dominates_operation", scope: { kind: "single_file_named_entry_cfg", file: sourceFile, entry: { kind: "named_function", name: "registerMSTeamsHandlers" } } };
}

function request({ vulnerableDb, fixedDb, mode = "differential", key = "openclaw-cve-2026-43572", operation }) {
  return { action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis: hypothesis(operation), analyzer_id: "codeql", mode, target: { vulnerable: { kind: "codeql_database", path: vulnerableDb }, ...(fixedDb === undefined ? {} : { fixed: { kind: "codeql_database", path: fixedDb } }) }, budget: { timeout_ms: 300_000 }, idempotency_key: key };
}

function isDifferential(result) { return result.valid === undefined && result.operation_status === "completed" && result.decision?.outcome === "check_missing" && result.decision?.fixed_outcome === "check_present" && result.verification_level === "differential"; }
function isCheckedSafe(result) { return result.valid === undefined && result.operation_status === "completed" && result.decision?.outcome === "check_present" && result.verification_level === "compiled"; }
function isWrongOperation(result) { return result.valid === undefined && result.decision?.outcome === "unknown" && result.observations?.some((item) => item.code === "MCHECK_OPERATION_NOT_FOUND") && result.revision_hints?.some((item) => item.action === "revise_operation"); }
function compact(result) { return result.valid === false ? { valid: false, issues: result.issues } : { operation_status: result.operation_status, capability: result.capability, decision: result.decision, verification_level: result.verification_level, observations: result.observations?.map((item) => item.code), revision_hints: result.revision_hints }; }

async function stageFile(commit, localSource, sourceRoot) {
  const source = localSource === undefined
    ? await fetchSource(commit)
    : await readFile(resolve(localSource), "utf8");
  const destination = join(sourceRoot, sourceFile);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, source, "utf8");
}

async function fetchSource(commit) {
  const url = `https://raw.githubusercontent.com/openclaw/openclaw/${commit}/${sourceFile}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`source fetch failed (${response.status}) for ${commit}`);
  return response.text();
}

async function createDatabase(database, sourceRoot) {
  await mkdir(dirname(database), { recursive: true });
  await command(codeql, ["database", "create", database, "--language=javascript", `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot);
}

async function replayInFreshProcess(root, runId) {
  const output = await command(process.execPath, [scriptPath, "--replay", root, runId], root, true);
  return JSON.parse(output.trim());
}

async function buildPortableEvidence(root, runId, replay) {
  const runRoot = join(root, "runs", runId);
  const artifact = JSON.parse(await readFile(join(runRoot, "research/missing-check/result.json"), "utf8"));
  const evidence = [];
  for (const ref of artifact.observation?.evidence_refs ?? []) {
    evidence.push({ ref, sha256: await sha256File(join(runRoot, ref)) });
  }
  const queries = [];
  for (const name of ["operations.ql", "checks.ql", "unchecked.ql", "checked.ql"]) {
    const ref = `missing-check/${artifact.hypothesis.hypothesis_id}/${name}`;
    queries.push({ ref, sha256: await sha256File(join(runRoot, ref)) });
  }
  return {
    schema_version: "autovul.missing-check.portable-evidence/1",
    inputs: {
      vulnerable: { commit: vulnerableCommit, source_file: sourceFile, source_sha256: await sha256File(join(root, "vulnerable-source", sourceFile)) },
      fixed: { commit: fixedCommit, source_file: sourceFile, source_sha256: await sha256File(join(root, "fixed-source", sourceFile)) },
    },
    hypothesis: artifact.hypothesis,
    target_fingerprints: artifact.target_fingerprints,
    analyzer: artifact.analyzer,
    decision_policy_version: artifact.decision_policy_version,
    observation: {
      compile_accepted: artifact.observation?.compile_accepted,
      relation: artifact.observation?.relation,
      fixed_relation: artifact.observation?.fixed_relation,
      completeness: artifact.observation?.completeness,
    },
    decision: artifact.decision,
    verification_level: artifact.verification_level,
    queries,
    evidence,
    replay,
    external_dependencies: ["CodeQL CLI and JavaScript packs matching analyzer provenance", "the two immutable source snapshots identified by commit and SHA-256"],
  };
}

async function sha256File(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function command(executable, args, cwd, capture = false) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { cwd, shell: false, stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit" });
    let stdout = ""; let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4_096); });
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolvePromise(stdout) : reject(new Error(`${executable} failed (${status}): ${stderr}`)));
  });
}
