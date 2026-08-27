import { cp, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

import { runCli } from "@pure-auto-codeql/cli";

const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-m4-pi-rpc-"));
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
  const child = spawn("pi", [
    "--offline",
    "--no-session",
    "--no-skills",
    "--no-prompt-templates",
    "--no-themes",
    "--no-context-files",
    "--no-extensions",
    "--mode", "rpc",
    "--extension", extension,
    "--extension", provider,
    "--provider", "pure-auto-codeql-m4-test",
    "--model", "pure-auto-codeql-m4-test/pure-auto-codeql-m4-test",
  ], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PI_CODING_AGENT_DIR: configDir,
      PURE_AUTO_CODEQL_V2_RUNS_DIR: runsDir,
      PURE_AUTO_CODEQL_PI_M4_VULNERABLE_DB: vulnerableDatabase,
      PURE_AUTO_CODEQL_PI_M4_FIXED_DB: fixedDatabase,
      PURE_AUTO_CODEQL_PI_M4_PROJECT_ROOT: vulnerableSource,
      CODEQL_PATH: codeql,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let buffer = "";
  let stderr = "";
  const messages = [];
  const waiters = [];
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline).replace(/\r$/, "");
      buffer = buffer.slice(newline + 1);
      if (line.length === 0) continue;
      const value = JSON.parse(line);
      messages.push(value);
      for (let index = waiters.length - 1; index >= 0; index -= 1) {
        if (!waiters[index].predicate(value)) continue;
        const waiter = waiters.splice(index, 1)[0];
        waiter.resolve(value);
      }
    }
  });
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  const waitFor = (predicate, timeoutMs = 30_000) => new Promise((resolvePromise, reject) => {
    const existing = messages.find(predicate);
    if (existing !== undefined) {
      resolvePromise(existing);
      return;
    }
    const timer = setTimeout(() => {
      const index = waiters.findIndex((item) => item.predicate === predicate);
      if (index >= 0) waiters.splice(index, 1);
      reject(new Error(`Timed out waiting for Pi RPC event; stderr=${stderr}`));
    }, timeoutMs);
    waiters.push({ predicate, resolve: (value) => { clearTimeout(timer); resolvePromise(value); } });
  });
  const request = async (command) => {
    const id = command.id ?? `request-${Math.random().toString(36).slice(2)}`;
    child.stdin.write(`${JSON.stringify({ ...command, id })}\n`);
    return waitFor((value) => value.type === "response" && value.id === id, 30_000);
  };
  const close = async () => {
    child.stdin.end();
    const exitCode = await new Promise((resolvePromise) => child.once("close", resolvePromise));
    if (exitCode !== 0) throw new Error(`Pi RPC exited with ${exitCode}: ${stderr}`);
  };
  return { request, waitFor, close };
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
