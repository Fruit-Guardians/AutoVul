import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { CodeqlTypestateAdapter } from "@autovul/codeql-runner";
import { decideTypestate } from "@autovul/core";

const codeql = process.env.CODEQL_PATH ?? "codeql";
const vulnerableCommit = "a8bea3a4ceec4c852b880f4885119453c3d8588e";
const fixedCommit = "6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c";
const sourceFile = "ghost/core/core/server/services/auth/session/session-service.js";
async function main() {
  const root = await mkdtemp(join(tmpdir(), "autovul-typestate-adapter-real-"));

  try {
  await stageSource(vulnerableCommit, join(root, "vulnerable-source"));
  await stageSource(fixedCommit, join(root, "fixed-source"));
  const vulnerableDb = join(root, "vulnerable-db");
  const fixedDb = join(root, "fixed-db");
  await createDatabase(vulnerableDb, join(root, "vulnerable-source"));
  await createDatabase(fixedDb, join(root, "fixed-source"));

  const observation = await new CodeqlTypestateAdapter({ executable: codeql }).execute({
    hypothesis,
    target: {
      vulnerable: { kind: "codeql_database", path: vulnerableDb },
      fixed: { kind: "codeql_database", path: fixedDb },
    },
    analyzer_id: "codeql",
    mode: "differential",
    runId: "run_tstate_real",
    artifactRoot: join(root, "artifacts"),
  }, { timeoutMs: 300_000 });
  const decision = decideTypestate(observation, "differential", hypothesis);
  const report = {
    schema_version: "autovul.typestate.adapter.golden.real/1",
    passed: observation.traces.some((trace) => trace.state === "violating_witness")
      && observation.fixed_traces?.some((trace) => trace.state === "safe_trace") === true
      && decision.verificationLevel === "differential",
    analyzer: observation.analyzer,
    observation: {
      resource: observation.resource.state,
      fixed_resource: observation.fixed_resource?.state,
      traces: observation.traces.map((trace) => trace.state),
      fixed_traces: observation.fixed_traces?.map((trace) => trace.state),
      fixed_identity: observation.fixed_traces?.[0]?.identity_evidence[0]?.kind,
    },
    decision: decision.decision,
    verification_level: decision.verificationLevel,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.passed) process.exitCode = 1;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ schema_version: "autovul.typestate.adapter.golden.real/1", passed: false, error: error instanceof Error ? error.message : String(error) })}\n`);
    process.exitCode = 1;
  } finally {
    if (process.env.TYPESTATE_KEEP_ARTIFACTS !== "true") await rm(root, { recursive: true, force: true });
  }
}

function stageSource(commit, destinationRoot) {
  return fetch(`https://raw.githubusercontent.com/TryGhost/Ghost/${commit}/${sourceFile}`, { signal: AbortSignal.timeout(30_000) })
    .then((response) => response.ok ? response.text() : Promise.reject(new Error(`Ghost source fetch failed (${response.status})`)))
    .catch(() => commandOutput("curl", ["--fail", "--silent", "--show-error", "--location", `https://raw.githubusercontent.com/TryGhost/Ghost/${commit}/${sourceFile}`], process.cwd()))
    .then(async (source) => {
      const destination = join(destinationRoot, sourceFile);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, source, "utf8");
    });
}

async function createDatabase(database, sourceRoot) {
  await command(codeql, ["database", "create", database, "--language=javascript", `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot);
}

function command(executable, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4_096); });
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolve() : reject(new Error(`${executable} failed (${status}): ${stderr}`)));
  });
}

function commandOutput(executable, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4_096); });
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolve(stdout) : reject(new Error(`${executable} failed (${status}): ${stderr}`)));
  });
}

const scope = {
  kind: "single_file_named_function",
  file: sourceFile,
  entry: { kind: "named_function", name: "createSessionForUser" },
  event_scope: "named_function_including_inline_callbacks",
  alias_boundary: "direct_lexical_binding",
};

const hypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-ghost-adapter-real",
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

await main();
