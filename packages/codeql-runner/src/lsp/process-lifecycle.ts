import type { ChildProcess } from "node:child_process";

export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

export async function delay(timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));
}

export function waitForExit(
  child: ChildProcess,
): Promise<number | null> {
  if (child.exitCode !== null) {
    return Promise.resolve(child.exitCode);
  }
  return new Promise((resolve) => child.once("exit", (code) => resolve(code)));
}

export async function waitWithKill(
  exit: Promise<number | null>,
  child: ChildProcess,
  timeoutMs: number,
): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const outcome = await Promise.race([
    exit.then(() => "exited" as const),
    new Promise<"timed_out">((resolve) => {
      timer = setTimeout(() => resolve("timed_out"), timeoutMs);
    }),
  ]);
  if (timer !== undefined) {
    clearTimeout(timer);
  }
  if (outcome === "timed_out") {
    terminateProcessTree(child, "SIGTERM");
    await delay(500);
  }
  terminateProcessTree(child, "SIGTERM");
  await waitForProcessGroupExit(child, 500);
  if (processGroupExists(child)) {
    terminateProcessTree(child, "SIGKILL");
  }
}

export function processGroupExists(
  child: ChildProcess,
): boolean {
  if (child.pid === undefined || process.platform === "win32") {
    return child.exitCode === null;
  }
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function sanitize(value: string): string {
  return value
    .replaceAll(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replaceAll(/(token|password|secret|api[_-]?key)=\S+/gi, "$1=[REDACTED]")
    .trim();
}

async function waitForProcessGroupExit(
  child: ChildProcess,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(child) && Date.now() < deadline) {
    await delay(25);
  }
}

export function terminateProcessTree(
  child: ChildProcess,
  signal: NodeJS.Signals = "SIGTERM",
): void {
  if (child.pid === undefined) {
    return;
  }
  try {
    if (process.platform === "win32") {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch {
    try {
      child.kill(signal);
    } catch {
      // The child exited between the checks; cleanup is complete.
    }
  }
}
