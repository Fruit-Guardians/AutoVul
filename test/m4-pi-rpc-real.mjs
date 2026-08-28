import { cp, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { runCli } from "@autovul/cli";
import { startPiRpc } from "./pi-rpc-client.mjs";

const root = await mkdtemp(join(tmpdir(), "autovul-m4-pi-rpc-"));
const configDir = join(root, "pi-config");
const runsDir = join(root, "runs");
const vulnerableSource = join(root, "vulnerable-source");
const fixedSource = join(root, "fixed-source");
const vulnerableDatabase = join(root, "vulnerable-db");
const fixedDatabase = join(root, "fixed-db");
const relocatedPack = join(root, "relocated-pack");
const repoRoot = resolve(process.cwd(), "..");
const codeql = process.env.CODEQL_PATH ?? "codeql";
const extension = join(process.cwd(), "packages/pi-extension/dist/index.js");
const provider = join(process.cwd(), "test/m4-pi-rpc-provider.mjs");

try {
  await mkdir(configDir, { recursive: true });
  await cp(join(repoRoot, "test/golden/python_command_injection/src"), join(vulnerableSource, "src"), { recursive: true });
  await cp(join(repoRoot, "test/golden/python_command_injection/src_fixed"), join(fixedSource, "src"), { recursive: true });
  await createDatabase(vulnerableDatabase, vulnerableSource);
  await createDatabase(fixedDatabase, fixedSource);

  const rpc = startRpc();
  try {
    await rpc.request({ id: "m4-prompt", type: "prompt", message: [
      "Analyze the supplied Python project for the described command injection.",
      `Project source root: ${vulnerableSource}`,
      `Vulnerable CodeQL database: ${vulnerableDatabase}`,
      `Fixed CodeQL database: ${fixedDatabase}`,
      "Environment-controlled command reaches os.system.",
    ].join("\n") });
    await rpc.waitFor((value) => value.type === "agent_settled", 180_000);
    const messages = await rpc.request({ type: "get_messages" });
    const results = messages.data.messages.filter((message) => message.role === "toolResult");
    const codeqlResults = results.filter((message) => ["codeql_database", "codeql_workflow", "codeql_query"].includes(message.toolName));
    if (codeqlResults.length !== 7 || codeqlResults.some((message) => message.isError)) {
      throw new Error(`M4 Pi RPC tool chain failed: ${JSON.stringify(codeqlResults)}`);
    }
    const workflowResult = parseToolResult(codeqlResults.findLast((message) => message.toolName === "codeql_workflow"));
    if (workflowResult?.pack_id === undefined) throw new Error(`M4 Pi RPC did not finalize a Query Pack: ${JSON.stringify(workflowResult)}`);
    const manifests = await readManifests(runsDir);
    const completed = manifests.find((manifest) => manifest.status === "completed" && manifest.phase === "workflow_finalize");
    if (completed?.artifactRoot === undefined) throw new Error(`M4 Pi RPC completed manifest missing artifactRoot: ${JSON.stringify(manifests)}`);
    await cp(join(completed.artifactRoot, "query-pack"), relocatedPack, { recursive: true });
    const stdout = [];
    const replayCode = await runCli([
      "query-pack", "verify", relocatedPack,
      "--vulnerable-db", vulnerableDatabase,
      "--fixed-db", fixedDatabase,
      "--json",
      "--runs-dir", join(root, "replay-runs"),
      "--workspace-root", root,
      "--codeql", codeql,
    ], { stdout: (value) => stdout.push(value), stderr: () => undefined });
    if (replayCode !== 0) throw new Error(`M4 Pi RPC Query Pack replay failed: ${stdout.join("")}`);
    const replay = JSON.parse(stdout.join(""));
    if (replay.ok !== true || replay.result?.verification?.passed !== true) {
      throw new Error(`M4 Pi RPC replay did not pass: ${JSON.stringify(replay)}`);
    }
    console.log("M4 Pi RPC diagnostic passed: host Pi tool chain, real CodeQL, and relocated Query Pack replay");
  } finally {
    await rpc.close();
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

function startRpc() {
  return startPiRpc({
    configDir,
    extension,
    provider,
    providerId: "autovul-m4-test",
    modelId: "autovul-m4-test",
    includeBuiltInExtensions: false,
    timeoutMs: 30_000,
    environment: {
      AUTOVUL_RUNS_DIR: runsDir,
      AUTOVUL_PI_M4_VULNERABLE_DB: vulnerableDatabase,
      AUTOVUL_PI_M4_FIXED_DB: fixedDatabase,
      AUTOVUL_PI_M4_PROJECT_ROOT: vulnerableSource,
      CODEQL_PATH: codeql,
    },
  });
}

async function createDatabase(database, sourceRoot) {
  await runProcess(codeql, [
    "database", "create", database,
    "--language=python",
    `--source-root=${sourceRoot}`,
    "--build-mode=none",
    "--overwrite",
  ], sourceRoot);
}

function runProcess(executable, args, cwd) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: false });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(new Error(`${executable} ${args.join(" ")} failed (${code ?? signal})\n${Buffer.concat(stderr).toString("utf8").slice(-4000)}`));
        return;
      }
      resolvePromise({ stdout: Buffer.concat(stdout).toString("utf8") });
    });
  });
}

async function readManifests(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const manifests = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      manifests.push(JSON.parse(await readFile(join(directory, entry.name, "manifest.json"), "utf8")));
    } catch {
      // Ignore transient or unrelated directories.
    }
  }
  return manifests;
}

function parseToolResult(message) {
  if (message === undefined) return undefined;
  for (const block of message.content ?? []) {
    if (block.type !== "text") continue;
    try {
      const envelope = JSON.parse(block.text);
      if (envelope.ok === true) return envelope.result;
    } catch {
      // Continue looking for structured tool output.
    }
  }
  return undefined;
}
