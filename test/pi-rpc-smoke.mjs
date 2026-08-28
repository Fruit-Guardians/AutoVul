import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startPiRpc } from "./pi-rpc-client.mjs";

const configDir = await mkdtemp(join(tmpdir(), "autovul-v2-pi-rpc-config-"));
const runsDir = await mkdtemp(join(tmpdir(), "autovul-v2-pi-rpc-runs-"));
const extension = join(process.cwd(), "packages/pi-extension/dist/index.js");
const provider = join(process.cwd(), "test/pi-rpc-provider.mjs");
const fakeCodeql = join(process.cwd(), "test/pi-fake-codeql.mjs");
const m2DbRoot = join(process.cwd(), "test", ".pi-m2-db");

function startRpc(scenario, extraEnv = {}) {
  return startPiRpc({
    configDir,
    extension,
    provider,
    providerId: "autovul-test",
    modelId: "autovul-test",
    timeoutMs: 10_000,
    environment: {
      AUTOVUL_RUNS_DIR: runsDir,
      AUTOVUL_PI_SCENARIO: scenario,
      CODEQL_PATH: fakeCodeql,
      ...extraEnv,
    },
  });
}

async function manifests() {
  const entries = await readdir(runsDir, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      result.push(JSON.parse(await readFile(join(runsDir, entry.name, "manifest.json"), "utf8")));
    } catch {
      // Ignore the transient directory while a run is being created.
    }
  }
  return result;
}

let successfulRun;
const success = startRpc("success");
try {
  const commands = await success.request({ type: "get_commands" });
  const commandNames = commands.data.commands.map((command) => command.name);
  if (!commands.success || !commandNames.includes("codeql-doctor") || !commandNames.includes("codeql-status")) {
    throw new Error(`Pi RPC command registration failed: ${JSON.stringify(commands)}`);
  }
  const state = await success.request({ type: "get_state" });
  if (!state.success || state.data.model?.provider !== "autovul-test") {
    throw new Error(`Pi RPC provider setup failed: ${JSON.stringify(state)}`);
  }
  await success.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setStatus"
    && value.statusKey === "autovul"
    && value.statusText === "CodeQL ready");
  await success.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setWidget"
    && value.widgetKey === "autovul"
    && value.widgetLines === undefined);
  await success.request({ id: "doctor-prompt", type: "prompt", message: "run the CodeQL doctor tool" });
  await success.waitFor((value) => value.type === "agent_settled");
  await success.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setStatus"
    && value.statusKey === "autovul"
    && value.statusText?.includes("CodeQL ✓"));
  const messages = await success.request({ type: "get_messages" });
  const toolResult = messages.data.messages.find((message) => message.role === "toolResult" && message.toolName === "codeql_database");
  if (!toolResult || toolResult.isError) {
    throw new Error(`Pi RPC tool call did not succeed: ${JSON.stringify(messages)}`);
  }
  successfulRun = (await manifests()).find((manifest) => manifest.status === "completed");
  if (!successfulRun) throw new Error("Successful doctor run was not persisted");

  await success.request({ id: "reload", type: "prompt", message: "/pi-e2e-reload" });
  await success.waitFor((value) => value.type === "extension_ui_request" && value.method === "notify" && value.message === "pi-e2e-reload-complete");
  const reloadedCommands = await success.request({ type: "get_commands" });
  if (!reloadedCommands.success || !reloadedCommands.data.commands.some((command) => command.name === "codeql-status")) {
    throw new Error("Pi RPC extension reload did not restore commands");
  }
  await success.request({ id: "status-after-reload", type: "prompt", message: `/codeql-status ${successfulRun.runId}` });
  await success.waitFor((value) => value.type === "extension_ui_request" && value.method === "notify" && value.message.includes(successfulRun.runId));
} finally {
  await success.close();
}

if (!successfulRun) throw new Error("No completed run available for exit recovery");
const recovered = startRpc("success");
try {
  await recovered.request({ id: "status-after-exit", type: "prompt", message: `/codeql-status ${successfulRun.runId}` });
  await recovered.waitFor((value) => value.type === "extension_ui_request" && value.method === "notify" && value.message.includes(successfulRun.runId));
} finally {
  await recovered.close();
}

const cancelled = startRpc("cancel", { PI_FAKE_CODEQL_SLEEP: "1" });
try {
  await cancelled.request({ id: "cancel-prompt", type: "prompt", message: "run the CodeQL doctor tool" });
  await cancelled.waitFor((value) => value.type === "tool_execution_start" && value.toolName === "codeql_database");
  await cancelled.request({ id: "abort", type: "abort" });
  await cancelled.waitFor((value) => value.type === "agent_settled");
  const cancelledRun = (await manifests()).find((manifest) => manifest.status === "cancelled");
  if (!cancelledRun || cancelledRun.error?.code !== "PROCESS_CANCELLED" || cancelledRun.error.details?.runId !== cancelledRun.runId) {
    throw new Error(`Cancelled doctor run was not persisted: ${JSON.stringify(await manifests())}`);
  }
} finally {
  await cancelled.close();
}

await mkdir(join(m2DbRoot, "vulnerable"), { recursive: true });
await mkdir(join(m2DbRoot, "fixed"), { recursive: true });
const cancelledWorkflow = startRpc("m2-cancel-start", { PI_FAKE_CODEQL_SLEEP: "1", AUTOVUL_PI_M2_DB_ROOT: m2DbRoot });
try {
  await cancelledWorkflow.request({ id: "m2-cancel-start-prompt", type: "prompt", message: "start the Python CodeQL workflow" });
  await cancelledWorkflow.waitFor((value) => value.type === "tool_execution_start" && value.toolName === "codeql_workflow");
  await cancelledWorkflow.request({ id: "m2-cancel-start-abort", type: "abort" });
  await cancelledWorkflow.waitFor((value) => value.type === "agent_settled");
  const cancelledWorkflowRun = (await manifests()).find((manifest) => manifest.status === "cancelled");
  if (!cancelledWorkflowRun || cancelledWorkflowRun.error?.code !== "PROCESS_CANCELLED" || cancelledWorkflowRun.error.details?.runId !== cancelledWorkflowRun.runId) {
    throw new Error(`Cancelled workflow start was not persisted: ${JSON.stringify(await manifests())}`);
  }
} finally {
  await cancelledWorkflow.close();
}

const failedTool = startRpc("error");
try {
  await failedTool.request({ id: "error-prompt", type: "prompt", message: "inspect a missing CodeQL database" });
  await failedTool.waitFor((value) => value.type === "agent_settled");
  const messages = await failedTool.request({ type: "get_messages" });
  const toolResult = messages.data.messages.find((message) => message.role === "toolResult" && message.toolName === "codeql_database");
  if (!toolResult?.isError) {
    throw new Error(`Pi RPC tool failure was not marked isError: ${JSON.stringify(messages)}`);
  }
} finally {
  await failedTool.close();
}

await mkdir(join(m2DbRoot, "vulnerable"), { recursive: true });
await mkdir(join(m2DbRoot, "fixed"), { recursive: true });
const m2 = startRpc("m2", { AUTOVUL_PI_M2_DB_ROOT: m2DbRoot });
let m2Run;
try {
  await m2.request({ id: "m2-prompt", type: "prompt", message: "run the Python CodeQL workflow" });
  await m2.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setWidget"
    && value.widgetKey === "autovul"
    && value.widgetLines?.some((line) => line.includes("checking compile")));
  await m2.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setWidget"
    && value.widgetKey === "autovul"
    && value.widgetLines?.length === 1
    && value.widgetLines[0].includes("pack ready"));
  await m2.waitFor((value) => value.type === "agent_settled");
  await m2.waitFor((value) => value.type === "extension_ui_request"
    && value.method === "setWidget"
    && value.widgetKey === "autovul"
    && value.widgetLines === undefined);
  const m2Messages = await m2.request({ type: "get_messages" });
  const m2Tools = m2Messages.data.messages.filter((message) =>
    message.role === "toolResult" && ["codeql_workflow", "codeql_query"].includes(message.toolName));
  if (m2Tools.length < 3 || m2Tools.some((message) => message.isError)) {
    throw new Error(`Pi RPC M2 workflow did not complete: ${JSON.stringify(m2Messages)}`);
  }
  m2Run = (await manifests()).find((manifest) => manifest.status === "completed" && manifest.phase === "workflow_finalize");
  if (!m2Run) throw new Error(`Pi RPC M2 final run was not persisted: ${JSON.stringify(await manifests())}`);
} finally {
  await m2.close();
}
if (!m2Run) throw new Error("No completed M2 run available for exit recovery");
const m2Recovered = startRpc("success");
try {
  await m2Recovered.request({ id: "m2-status-after-exit", type: "prompt", message: `/codeql-status ${m2Run.runId}` });
  await m2Recovered.waitFor((value) => value.type === "extension_ui_request" && value.method === "notify" && value.message.includes(m2Run.runId));
} finally {
  await m2Recovered.close();
}

await rm(configDir, { recursive: true, force: true });
await rm(runsDir, { recursive: true, force: true });
await rm(m2DbRoot, { recursive: true, force: true });
console.log("Pi RPC E2E passed: tool call, M2 workflow, cancellation, reload, exit artifact recovery, and tool errors");
