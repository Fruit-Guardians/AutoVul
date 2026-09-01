import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";

import { createLocalApplication } from "@autovul/codeql-runner";
import { runCli } from "@autovul/cli";
import { decideTypestate } from "@autovul/core";

const codeql = process.env.CODEQL_PATH ?? "codeql";
const vulnerableCommit = "a8bea3a4ceec4c852b880f4885119453c3d8588e";
const fixedCommit = "6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c";
const sourceFile = "ghost/core/core/server/services/auth/session/session-service.js";
const root = await mkdtemp(join(tmpdir(), "autovul-typestate-golden-real-"));
const initialRuns = join(root, "initial-runs");
const relocatedRuns = join(root, "relocated-runs");
const vulnerableSource = join(root, "vulnerable-source");
const fixedSource = join(root, "fixed-source");
const preRekeySource = join(root, "pre-rekey-source");
const differentIdentitySource = join(root, "different-identity-source");
const vulnerableDatabase = join(root, "vulnerable-db");
const fixedDatabase = join(root, "fixed-db");
const preRekeyDatabase = join(root, "pre-rekey-db");
const differentIdentityDatabase = join(root, "different-identity-db");

const scope = {
  kind: "single_file_named_function",
  file: sourceFile,
  entry: { kind: "named_function", name: "createSessionForUser" },
  event_scope: "named_function_including_inline_callbacks",
  alias_boundary: "direct_lexical_binding",
};

const hypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-ghost-real-golden",
  language: "javascript",
  resource: { id: "login_session", kind: "local_binding", binding_name: "session", acquisition_event: "session_acquired", identity_model: "direct_lexical_binding" },
  initial_state: "preauth",
  states: ["preauth", "rekeyed", "authenticated"],
  events: [
    { id: "session_acquired", selector: { kind: "direct_call", name: "getSession" } },
    { id: "regenerate_request_session", selector: { kind: "direct_method", receiver: "req.session", name: "regenerate" } },
    { id: "assign_user", selector: { kind: "direct_call", name: "assignUserToSession", argument_property: "session" } },
  ],
  transitions: [
    { from_state: "preauth", event: "session_acquired", to_state: "preauth" },
    { from_state: "preauth", event: "regenerate_request_session", to_state: "rekeyed" },
    { from_state: "rekeyed", event: "assign_user", to_state: "authenticated" },
  ],
  violation: { kind: "prohibited_transition", from_state: "preauth", event: "assign_user", to_state: "authenticated", requires_same_identity: true },
  analysis_scope: scope,
};

try {
  await stageSource(vulnerableCommit, vulnerableSource);
  await stageSource(fixedCommit, fixedSource);
  await stageFixture(preRekeySource, `async function createSessionForUser(req, res, user) {
  const acquired = await getSession(req, res);
  const session = req.session;
  await new Promise((resolve, reject) => {
    req.session.regenerate((err) => err ? reject(err) : resolve());
  });
  await assignUserToSession({session, user, origin: "https://example.test"});
}
`);
  await stageFixture(differentIdentitySource, await readFile(join(evidenceRoot(), "safe-different-resource.js"), "utf8"));
  await createDatabase(vulnerableDatabase, vulnerableSource);
  await createDatabase(fixedDatabase, fixedSource);
  await createDatabase(preRekeyDatabase, preRekeySource);
  await createDatabase(differentIdentityDatabase, differentIdentitySource);

  const app = createLocalApplication({ cwd: process.cwd(), runsDir: initialRuns, workspaceRoot: root, codeqlPath: codeql, timeoutMs: 300_000 });
  let primary;
  try {
    const validation = await app.research({ action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis });
    assert(validation.valid === true, `Typestate validation failed: ${JSON.stringify(validation)}`);
    primary = await execute(app, hypothesis, { vulnerable: vulnerableDatabase, fixed: fixedDatabase }, "differential", "typestate-real-golden-primary");
    assert(primary.result.operation_status === "completed", `primary operation did not complete: ${JSON.stringify(primary.result)}`);
    assert(primary.result.decision.outcome === "violation_observed" && primary.result.decision.fixed_outcome === "no_violation_observed" && primary.result.decision.fixed_policy_satisfied === true && primary.result.verification_level === "differential", `primary differential result is wrong: ${JSON.stringify(primary.result)}`);
    assert(primary.artifact.observation.traces.some((trace) => trace.state === "violating_witness"), "Ghost vulnerable target did not retain a violating witness");
    assert(primary.artifact.observation.fixed_traces?.some((trace) => trace.state === "safe_trace") === true, "Ghost fixed target did not retain a safe trace");

    const cliRequest = join(root, "typestate-cli-request.json");
    await writeFile(cliRequest, JSON.stringify({
      capability: "typestate",
      hypothesis_version: "autovul.typestate/1",
      hypothesis,
      target: { vulnerable: { kind: "codeql_database", path: vulnerableDatabase }, fixed: { kind: "codeql_database", path: fixedDatabase } },
      analyzer_id: "codeql",
      mode: "differential",
      budget: { timeout_ms: 300_000 },
      idempotency_key: "typestate-real-golden-primary",
    }), "utf8");
    const cliFlags = ["--json", "--runs-dir", initialRuns, "--workspace-root", root, "--codeql", codeql, "--timeout-ms", "300000"];
    const cliValidation = await runCliJson(["research", "validate", "--request", cliRequest, ...cliFlags]);
    assert(cliValidation.exitCode === 0 && cliValidation.value.result?.valid === true, `CLI Typestate validation failed: ${JSON.stringify(cliValidation.value)}`);
    const cliExecution = await runCliJson(["research", "execute", "--request", cliRequest, ...cliFlags]);
    assert(cliExecution.exitCode === 0 && cliExecution.value.result?.verification_level === "differential", `CLI Typestate execution did not preserve the aggregate result: ${JSON.stringify(cliExecution.value)}`);
    const cliReplay = await runCliJson(["run", "replay", primary.result.run_id, ...cliFlags]);
    assert(cliReplay.exitCode === 0 && cliReplay.value.result?.status === "match", `CLI Typestate replay failed: ${JSON.stringify(cliReplay.value)}`);

    const preRekey = await execute(app, hypothesis, { vulnerable: preRekeyDatabase }, "reproduce", "typestate-real-golden-pre-rekey");
    assert(preRekey.result.decision.outcome === "no_violation_observed", `pre-rekey binding unexpectedly produced a violation: ${JSON.stringify(preRekey.result)}`);
    assert(preRekey.artifact.observation.traces.filter((trace) => trace.state === "safe_trace").length === 0, "pre-rekey binding produced a safe trace");

    const differentIdentity = await execute(app, hypothesis, { vulnerable: differentIdentityDatabase }, "reproduce", "typestate-real-golden-different-identity");
    assert(differentIdentity.artifact.observation.traces.filter((trace) => trace.state === "violating_witness").length === 0, "different resource fixture produced a violating witness");

    const wrongResource = await execute(app, { ...hypothesis, hypothesis_id: "tstate-ghost-wrong-resource", resource: { ...hypothesis.resource, binding_name: "wrongSession" } }, { vulnerable: vulnerableDatabase }, "reproduce", "typestate-real-golden-wrong-resource");
    assert(wrongResource.result.decision.outcome === "unknown" && wrongResource.result.revision_hints.some((hint) => hint.action === "revise_resource"), `wrong resource did not produce revise_resource: ${JSON.stringify(wrongResource.result)}`);

    const wrongEvent = await execute(app, { ...hypothesis, hypothesis_id: "tstate-ghost-wrong-event", events: hypothesis.events.map((event) => event.id === "assign_user" ? { ...event, selector: { kind: "direct_call", name: "assignUserToWrongSession", argument_property: "session" } } : event) }, { vulnerable: vulnerableDatabase }, "reproduce", "typestate-real-golden-wrong-event");
    assert(wrongEvent.result.decision.outcome === "unknown" && wrongEvent.result.revision_hints.some((hint) => hint.action === "revise_event"), `wrong event did not produce revise_event: ${JSON.stringify(wrongEvent.result)}`);

    const incompleteProjection = decideTypestate({
      ...primary.artifact.observation,
      completeness: { vulnerable: { ...primary.artifact.observation.completeness.vulnerable, status: "incomplete" } },
    }, "reproduce", hypothesis);
    assert(incompleteProjection.decision.outcome === "unknown" && incompleteProjection.revisionHints.some((hint) => hint.action === "revise_scope"), `incomplete scope did not remain unknown: ${JSON.stringify(incompleteProjection)}`);
  } finally {
    await app.close();
  }

  if (primary === undefined) throw new Error("primary run was not created");
  const sourceRun = join(initialRuns, primary.result.run_id);
  const relocatedRun = join(relocatedRuns, primary.result.run_id);
  await mkdir(relocatedRuns, { recursive: true });
  await cp(sourceRun, relocatedRun, { recursive: true });
  const relocatedManifestPath = join(relocatedRun, "manifest.json");
  const relocatedManifest = JSON.parse(await readFile(relocatedManifestPath, "utf8"));
  relocatedManifest.artifactRoot = relocatedRun;
  await writeFile(relocatedManifestPath, JSON.stringify(relocatedManifest, null, 2), "utf8");

  const primaryEvidence = join(relocatedRun, "typestate");
  const evidenceBefore = await digestEvidence(primaryEvidence);
  const replayConfigPath = join(root, "replay-config.json");
  await writeFile(replayConfigPath, JSON.stringify({
    codeql,
    workspaceRoot: root,
    runsDir: relocatedRuns,
    runId: primary.result.run_id,
    resultArtifact: join(relocatedRun, "research", "typestate", "result.json"),
    vulnerableCommit,
    fixedCommit,
    sourceFile,
    vulnerableSource,
    fixedSource,
    vulnerableDatabase,
    fixedDatabase,
  }), "utf8");
  const replayOutput = await commandOutput(process.execPath, [join(process.cwd(), "test", "typestate-replay-real.mjs"), replayConfigPath], process.cwd());
  const replayReport = parseLastJsonLine(replayOutput);
  assert(replayReport.passed === true, `fresh-process replay failed: ${replayOutput}`);
  const evidenceAfter = await digestEvidence(primaryEvidence);
  assert(JSON.stringify(evidenceAfter) === JSON.stringify(evidenceBefore), "replay changed the original QL/SARIF evidence");

  process.stdout.write(`${JSON.stringify({
    schema_version: "autovul.typestate.golden.real/1",
    passed: true,
    primary: "differential",
    pre_rekey_safe_trace_count: 0,
    different_identity_violation_count: 0,
    wrong_resource: "revise_resource",
    wrong_event: "revise_event",
    incomplete_scope: "unknown",
    cli: "validate_execute_replay_match",
    relocated_fresh_process_replay: replayReport,
    primary_evidence_unchanged: true,
  })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ schema_version: "autovul.typestate.golden.real/1", passed: false, error: error instanceof Error ? error.message : String(error) })}\n`);
  process.exitCode = 1;
} finally {
  if (process.env.TYPESTATE_KEEP_ARTIFACTS !== "true") await rm(root, { recursive: true, force: true });
}

async function execute(app, scenarioHypothesis, target, mode, idempotencyKey) {
  const result = await app.research({
    action: "execute",
    capability: "typestate",
    hypothesis_version: "autovul.typestate/1",
    hypothesis: scenarioHypothesis,
    target: {
      vulnerable: { kind: "codeql_database", path: target.vulnerable },
      ...(target.fixed === undefined ? {} : { fixed: { kind: "codeql_database", path: target.fixed } }),
    },
    analyzer_id: "codeql",
    mode,
    budget: { timeout_ms: 300_000 },
    idempotency_key: idempotencyKey,
  });
  if (!("run_id" in result)) throw new Error(`Typestate execution did not return a run: ${JSON.stringify(result)}`);
  const artifact = JSON.parse(await readFile(join(initialRuns, result.run_id, "research", "typestate", "result.json"), "utf8"));
  return { result, artifact };
}

async function stageSource(commit, destinationRoot) {
  const url = `https://raw.githubusercontent.com/TryGhost/Ghost/${commit}/${sourceFile}`;
  const source = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    .then((response) => response.ok ? response.text() : Promise.reject(new Error(`Ghost source fetch failed (${response.status})`)))
    .catch(() => commandOutput("curl", ["--fail", "--silent", "--show-error", "--location", url], process.cwd()));
  await stageFixture(destinationRoot, source);
}

async function stageFixture(destinationRoot, source) {
  const destination = join(destinationRoot, sourceFile);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, source, "utf8");
}

function createDatabase(database, sourceRoot) {
  return command(codeql, ["database", "create", database, "--language=javascript", `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot);
}

async function digestEvidence(root) {
  const paths = await listFiles(root);
  return Promise.all(paths.filter((path) => path.endsWith(".ql") || path.endsWith(".sarif")).sort().map(async (path) => ({
    path: relative(root, path),
    sha256: createHash("sha256").update(await readFile(path)).digest("hex"),
  })));
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => entry.isDirectory() ? listFiles(join(directory, entry.name)) : [join(directory, entry.name)]));
  return nested.flat();
}

function command(executable, args, cwd) {
  return commandOutput(executable, args, cwd).then(() => undefined);
}

function commandOutput(executable, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4_096); });
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolve(stdout) : reject(new Error(`${executable} failed (${status}): ${stderr}\n${stdout.slice(-4_096)}`)));
  });
}

function parseLastJsonLine(output) {
  const line = output.trim().split("\n").findLast((candidate) => candidate.startsWith("{"));
  if (line === undefined) throw new Error(`child process did not emit JSON: ${output}`);
  return JSON.parse(line);
}

async function runCliJson(args) {
  const stdout = [];
  const stderr = [];
  const exitCode = await runCli(args, { stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value) });
  const text = stdout.join("");
  try {
    return { exitCode, value: JSON.parse(text) };
  } catch {
    throw new Error(`CLI did not return JSON (${exitCode}): ${text}\n${stderr.join("")}`);
  }
}

function evidenceRoot() {
  return join(process.cwd(), "specs", "changes", "admit-typestate-capability-v1", "evidence", "ghost-cve-2026-70594");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
