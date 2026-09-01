import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import { startPiRpc } from "./pi-rpc-client.mjs";

const root = await mkdtemp(join(tmpdir(), "autovul-typestate-pi-rpc-"));
const codeql = process.env.CODEQL_PATH ?? "codeql";
const vulnerableCommit = "a8bea3a4ceec4c852b880f4885119453c3d8588e";
const fixedCommit = "6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c";
const sourceFile = "ghost/core/core/server/services/auth/session/session-service.js";
const vulnerableSource = join(root, "vulnerable-source");
const fixedSource = join(root, "fixed-source");
const vulnerableDatabase = join(root, "vulnerable-db");
const fixedDatabase = join(root, "fixed-db");
const runsDir = join(root, "runs");
const configDir = join(root, "pi-config");

try {
  await mkdir(configDir, { recursive: true });
  await stageSource(vulnerableCommit, vulnerableSource);
  await stageSource(fixedCommit, fixedSource);
  await createDatabase(vulnerableDatabase, vulnerableSource);
  await createDatabase(fixedDatabase, fixedSource);
  const rpc = startPiRpc({
    configDir,
    extension: join(process.cwd(), "packages", "pi-extension", "dist", "index.js"),
    provider: join(process.cwd(), "test", "typestate-pi-rpc-provider.mjs"),
    providerId: "autovul-typestate-test",
    modelId: "autovul-typestate-test",
    includeBuiltInExtensions: false,
    timeoutMs: 30_000,
    environment: {
      AUTOVUL_RUNS_DIR: runsDir,
      AUTOVUL_TIMEOUT_MS: "300000",
      AUTOVUL_PI_TYPESTATE_VULNERABLE_DB: vulnerableDatabase,
      AUTOVUL_PI_TYPESTATE_FIXED_DB: fixedDatabase,
      CODEQL_PATH: codeql,
    },
  });
  try {
    await rpc.request({ id: "typestate-aggregate", type: "prompt", message: "Validate, execute, and replay the supplied Typestate hypothesis." });
    await rpc.waitFor((value) => value.type === "agent_settled", 300_000);
    const messages = await rpc.request({ type: "get_messages" });
    const results = messages.data.messages.filter((message) => message.role === "toolResult" && ["autovul_research", "autovul_run"].includes(message.toolName));
    if (results.length !== 3 || results.some((message) => message.isError)) throw new Error(`Typestate aggregate tools failed: ${JSON.stringify(results)}`);
    const validation = parseResult(results[0]);
    const execution = parseResult(results[1]);
    const replay = parseResult(results[2]);
    if (validation?.valid !== true) throw new Error(`Typestate aggregate validation failed: ${JSON.stringify(validation)}`);
    if (execution?.operation_status !== "completed" || execution?.decision?.outcome !== "violation_observed" || execution?.decision?.fixed_outcome !== "no_violation_observed" || execution?.verification_level !== "differential") {
      throw new Error(`Typestate aggregate execution failed: ${JSON.stringify(execution)}`);
    }
    if (replay?.status !== "match") throw new Error(`Typestate aggregate replay failed: ${JSON.stringify(replay)}`);
    await rpc.waitFor((value) => value.type === "extension_ui_request"
      && value.method === "setStatus"
      && value.statusKey === "autovul"
      && value.statusText?.includes("typestate")
      && value.statusText?.includes("differential"));
    console.log("Typestate Pi RPC E2E passed: aggregate validate, real differential execute, replay match, and terminal UI");
  } finally {
    await rpc.close();
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

async function stageSource(commit, destinationRoot) {
  const url = `https://raw.githubusercontent.com/TryGhost/Ghost/${commit}/${sourceFile}`;
  const source = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    .then((response) => response.ok ? response.text() : Promise.reject(new Error(`Ghost source fetch failed (${response.status})`)))
    .catch(() => commandOutput("curl", ["--fail", "--silent", "--show-error", "--location", url], process.cwd()));
  const destination = join(destinationRoot, sourceFile);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, source, "utf8");
}

function createDatabase(database, sourceRoot) {
  return commandOutput(codeql, ["database", "create", database, "--language=javascript", `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot).then(() => undefined);
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

function parseResult(message) {
  for (const block of message?.content ?? []) {
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
