import { spawn } from "node:child_process";

/** Starts Pi's JSONL RPC mode and exposes the small protocol surface tests use. */
export function startPiRpc({
  configDir,
  extension,
  provider,
  providerId,
  modelId,
  environment = {},
  timeoutMs = 30_000,
  includeBuiltInExtensions = true,
}) {
  const child = spawn("pi", [
    "--offline",
    "--no-session",
    "--no-skills",
    "--no-prompt-templates",
    "--no-themes",
    "--no-context-files",
    ...(includeBuiltInExtensions ? [] : ["--no-extensions"]),
    "--mode", "rpc",
    "--extension", extension,
    "--extension", provider,
    "--provider", providerId,
    "--model", `${providerId}/${modelId}`,
  ], {
    cwd: process.cwd(),
    env: { ...process.env, PI_CODING_AGENT_DIR: configDir, ...environment },
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
      if (newline < 0) return;
      const line = buffer.slice(0, newline).replace(/\r$/, "");
      buffer = buffer.slice(newline + 1);
      if (line.length === 0) continue;
      const message = JSON.parse(line);
      messages.push(message);
      for (let index = waiters.length - 1; index >= 0; index -= 1) {
        if (waiters[index].predicate(message)) waiters.splice(index, 1)[0].resolve(message);
      }
    }
  });
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  const waitFor = (predicate, waitTimeoutMs = timeoutMs) => new Promise((resolve, reject) => {
    const existing = messages.find(predicate);
    if (existing !== undefined) return resolve(existing);
    const timer = setTimeout(() => {
      const index = waiters.findIndex((waiter) => waiter.predicate === predicate);
      if (index >= 0) waiters.splice(index, 1);
      reject(new Error(`Timed out waiting for Pi RPC event; messages=${JSON.stringify(messages.slice(-8))}; stderr=${stderr}`));
    }, waitTimeoutMs);
    waiters.push({ predicate, resolve: (message) => { clearTimeout(timer); resolve(message); } });
  });

  return {
    request: async (command) => {
      const id = command.id ?? `request-${Math.random().toString(36).slice(2)}`;
      child.stdin.write(`${JSON.stringify({ ...command, id })}\n`);
      return waitFor((message) => message.type === "response" && message.id === id);
    },
    waitFor,
    close: async () => {
      child.stdin.end();
      const exitCode = await new Promise((resolve) => child.once("close", resolve));
      if (exitCode !== 0) throw new Error(`Pi RPC exited with ${exitCode}: ${stderr}`);
    },
  };
}
