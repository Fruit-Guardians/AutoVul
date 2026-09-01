import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { startPiRpc } from "./pi-rpc-client.mjs";

const root = await mkdtemp(join(tmpdir(), "autovul-flow-pi-rpc-"));
const repoRoot = resolve(process.cwd(), "..");
const codeql = process.env.CODEQL_PATH ?? "codeql";
const vulnerableSource = join(root, "vulnerable-source");
const fixedSource = join(root, "fixed-source");
const vulnerableDatabase = join(root, "vulnerable-db");
const fixedDatabase = join(root, "fixed-db");
const configDir = join(root, "pi-config");
const runsDir = join(root, "runs");

try {
  await mkdir(configDir, { recursive: true });
  await cp(join(repoRoot, "test/golden/python_command_injection/src"), join(vulnerableSource, "src"), { recursive: true });
  await cp(join(repoRoot, "test/golden/python_command_injection/src_fixed"), join(fixedSource, "src"), { recursive: true });
  await createDatabase(vulnerableDatabase, vulnerableSource);
  await createDatabase(fixedDatabase, fixedSource);
  const rpc = startPiRpc({
    configDir,
    extension: join(process.cwd(), "packages/pi-extension/dist/index.js"),
    provider: join(process.cwd(), "test/flow-pi-rpc-provider.mjs"),
    providerId: "autovul-flow-test",
    modelId: "autovul-flow-test",
    includeBuiltInExtensions: false,
    timeoutMs: 30_000,
    environment: {
      AUTOVUL_RUNS_DIR: runsDir,
      AUTOVUL_TIMEOUT_MS: "300000",
      AUTOVUL_PI_FLOW_VULNERABLE_DB: vulnerableDatabase,
      AUTOVUL_PI_FLOW_FIXED_DB: fixedDatabase,
      CODEQL_PATH: codeql,
    },
  });
  try {
    await rpc.request({ id: "flow-aggregate", type: "prompt", message: "Validate, execute, and replay the supplied Flow hypothesis." });
    await rpc.waitFor((value) => value.type === "agent_settled", 300_000);
    const messages = await rpc.request({ type: "get_messages" });
    const results = messages.data.messages.filter((message) => message.role === "toolResult" && ["autovul_research", "autovul_run"].includes(message.toolName));
    if (results.length !== 3 || results.some((message) => message.isError)) throw new Error(`Flow aggregate tools failed: ${JSON.stringify(results)}`);
    const validate = parseResult(results[0]);
    const execute = parseResult(results[1]);
    const replay = parseResult(results[2]);
    if (validate?.valid !== true) throw new Error(`Flow aggregate validation failed: ${JSON.stringify(validate)}`);
    for (const [name, result] of [["execute", execute], ["replay", replay]]) {
      if (result?.operation_status !== "completed" || result?.decision?.outcome !== "connected" || result?.verification_level !== "differential") {
        throw new Error(`Flow aggregate ${name} failed: ${JSON.stringify(result)}`);
      }
    }
    await rpc.waitFor((value) => value.type === "extension_ui_request"
      && value.method === "setStatus"
      && value.statusKey === "autovul"
      && value.statusText?.includes("flow")
      && value.statusText?.includes("differential"));
    console.log("Flow Pi RPC E2E passed: aggregate validate, real differential execute, replay, and terminal UI");
  } finally {
    await rpc.close();
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

function createDatabase(database, sourceRoot) {
  return runProcess(codeql, ["database", "create", database, "--language=python", `--source-root=${sourceRoot}`, "--build-mode=none", "--overwrite"], sourceRoot);
}

function runProcess(executable, args, cwd) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const stderr = [];
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (status) => status === 0 ? resolvePromise() : reject(new Error(`${executable} failed (${status}): ${Buffer.concat(stderr).toString("utf8").slice(-4_000)}`)));
  });
}

function parseResult(message) {
  for (const block of message?.content ?? []) {
    if (block.type !== "text") continue;
    try {
      const envelope = JSON.parse(block.text);
      if (envelope.ok === true) return envelope.result;
    } catch {
      // Continue looking for structured output.
    }
  }
  return undefined;
}
