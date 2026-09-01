import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";

import { createLocalApplication } from "@autovul/codeql-runner";

const configPath = process.argv[2];
if (configPath === undefined) throw new Error("usage: node test/typestate-replay-real.mjs <config.json>");

const config = JSON.parse(await readFile(configPath, "utf8"));
const codeql = config.codeql;

try {
  await stageSource(config.vulnerableCommit, config.sourceFile, config.vulnerableSource);
  await stageSource(config.fixedCommit, config.sourceFile, config.fixedSource);
  await recreateDatabase(config.vulnerableDatabase, config.vulnerableSource);
  await recreateDatabase(config.fixedDatabase, config.fixedSource);

  const app = createLocalApplication({
    cwd: process.cwd(),
    runsDir: config.runsDir,
    workspaceRoot: config.workspaceRoot,
    codeqlPath: codeql,
    timeoutMs: 300_000,
  });
  try {
    const original = await readFile(config.resultArtifact, "utf8");
    const replay = await app.manageRun({ action: "replay", run_id: config.runId });
    assert(replay.status === "match", `independent replay did not match: ${JSON.stringify(replay)}`);

    const fingerprint = JSON.parse(original);
    fingerprint.target_fingerprints.vulnerable = "0000000000000000";
    await writeFile(config.resultArtifact, JSON.stringify(fingerprint), "utf8");
    const fingerprintReplay = await app.manageRun({ action: "replay", run_id: config.runId });
    assert(fingerprintReplay.status === "environment_blocked" && hasCode(fingerprintReplay, "TSTATE_REPLAY_FINGERPRINT_DIFFERENCE"), `fingerprint mutation was not isolated: ${JSON.stringify(fingerprintReplay)}`);

    const version = JSON.parse(original);
    version.analyzer.version = "CodeQL command-line toolchain release 0.0.0.";
    await writeFile(config.resultArtifact, JSON.stringify(version), "utf8");
    const versionReplay = await app.manageRun({ action: "replay", run_id: config.runId });
    assert(versionReplay.status === "version_difference" && hasCode(versionReplay, "TSTATE_REPLAY_ANALYZER_VERSION_DIFFERENCE"), `analyzer version mutation was not isolated: ${JSON.stringify(versionReplay)}`);

    const policy = JSON.parse(original);
    policy.decision_policy_version = "autovul.typestate.decision/other";
    await writeFile(config.resultArtifact, JSON.stringify(policy), "utf8");
    const policyReplay = await app.manageRun({ action: "replay", run_id: config.runId });
    assert(policyReplay.status === "version_difference" && hasCode(policyReplay, "TSTATE_REPLAY_POLICY_VERSION_DIFFERENCE"), `policy mutation was not isolated: ${JSON.stringify(policyReplay)}`);

    const trace = JSON.parse(original);
    trace.observation.traces[0].events[1].location.start_line += 1;
    await writeFile(config.resultArtifact, JSON.stringify(trace), "utf8");
    const traceReplay = await app.manageRun({ action: "replay", run_id: config.runId });
    assert(traceReplay.status === "semantic_mismatch" && hasCode(traceReplay, "TSTATE_REPLAY_OBSERVATION_SEMANTIC_MISMATCH"), `trace mutation was not isolated: ${JSON.stringify(traceReplay)}`);

    await writeFile(config.resultArtifact, original, "utf8");
    process.stdout.write(`${JSON.stringify({
      schema_version: "autovul.typestate.replay.golden.real/1",
      passed: true,
      replay: replay.status,
      fingerprint: fingerprintReplay.status,
      analyzer_version: versionReplay.status,
      policy: policyReplay.status,
      trace: traceReplay.status,
    })}\n`);
  } finally {
    await app.close();
  }
} catch (error) {
  process.stdout.write(`${JSON.stringify({ schema_version: "autovul.typestate.replay.golden.real/1", passed: false, error: error instanceof Error ? error.message : String(error) })}\n`);
  process.exitCode = 1;
}

async function stageSource(commit, sourceFile, destinationRoot) {
  const destination = join(destinationRoot, sourceFile);
  await rm(destinationRoot, { recursive: true, force: true });
  await mkdir(dirname(destination), { recursive: true });
  const url = `https://raw.githubusercontent.com/TryGhost/Ghost/${commit}/${sourceFile}`;
  const source = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    .then((response) => response.ok ? response.text() : Promise.reject(new Error(`Ghost source fetch failed (${response.status})`)))
    .catch(() => commandOutput("curl", ["--fail", "--silent", "--show-error", "--location", url], process.cwd()));
  await writeFile(destination, source, "utf8");
}

async function recreateDatabase(database, sourceRoot) {
  await rm(database, { recursive: true, force: true });
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

function hasCode(result, code) {
  return result.observations?.some((observation) => observation.code === code) === true;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
