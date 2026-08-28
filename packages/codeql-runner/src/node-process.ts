import { spawn, type ChildProcess } from "node:child_process";

import { DomainError } from "@autovul/contracts";
import type { ProcessCommand, ProcessOptions, ProcessPort, ProcessResult } from "@autovul/core";

import { limitOutput, sanitizeOutput } from "./output.js";
import { terminateProcessTree } from "./lsp/process-lifecycle.js";

interface CapturedOutput {
  chunks: Buffer[];
  size: number;
  truncated: boolean;
}

const EMPTY_RESULT: ProcessResult = {
  exitCode: null,
  signal: null,
  stdout: "",
  stderr: "",
  stdoutTruncated: false,
  stderrTruncated: false,
  timedOut: false,
  cancelled: false,
};

export class NodeProcessPort implements ProcessPort {
  async execute(command: ProcessCommand, options: ProcessOptions): Promise<ProcessResult> {
    assertSafeCommand(command);
    if (options.signal?.aborted) {
      return { ...EMPTY_RESULT, cancelled: true };
    }

    const child = spawn(command.executable, [...command.args], {
      cwd: command.cwd,
      env: command.env === undefined ? process.env : { ...process.env, ...command.env },
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdout = captureStream(child.stdout, options.maxOutputBytes);
    const stderr = captureStream(child.stderr, options.maxOutputBytes);
    let timedOut = false;
    let cancelled = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;
    let timeoutTimer: NodeJS.Timeout | undefined;

    const terminate = (reason: "timeout" | "cancel"): void => {
      if (settled) {
        return;
      }
      timedOut ||= reason === "timeout";
      cancelled ||= reason === "cancel";
      terminateProcessTree(child);
      killTimer = setTimeout(() => terminateProcessTree(child, "SIGKILL"), 250);
    };

    const abortHandler = (): void => terminate("cancel");
    options.signal?.addEventListener("abort", abortHandler, { once: true });
    if (options.timeoutMs > 0) {
      timeoutTimer = setTimeout(() => terminate("timeout"), options.timeoutMs);
    }

    try {
      const [exitCode, signal] = await waitForClose(child);
      settled = true;
      const stdoutText = limitOutput(sanitizeOutput(Buffer.concat(stdout.chunks).toString("utf8")), options.maxOutputBytes);
      const stderrText = limitOutput(sanitizeOutput(Buffer.concat(stderr.chunks).toString("utf8")), options.maxOutputBytes);
      return {
        exitCode,
        signal,
        stdout: stdoutText.value,
        stderr: stderrText.value,
        stdoutTruncated: stdout.truncated || stdoutText.truncated,
        stderrTruncated: stderr.truncated || stderrText.truncated,
        timedOut,
        cancelled,
      };
    } catch (error: unknown) {
      settled = true;
      const message = error instanceof Error ? error.message : "Process failed to start";
      throw new DomainError("PROCESS_CRASHED", "process", message, true, { executable: command.executable });
    } finally {
      if (timeoutTimer !== undefined) {
        clearTimeout(timeoutTimer);
      }
      if (killTimer !== undefined) {
        clearTimeout(killTimer);
      }
      options.signal?.removeEventListener("abort", abortHandler);
    }
  }
}

function waitForClose(child: ChildProcess): Promise<[number | null, NodeJS.Signals | null]> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (exitCode: number | null, signal: NodeJS.Signals | null) => resolve([exitCode, signal]));
  });
}

function captureStream(stream: NodeJS.ReadableStream, maxBytes: number): CapturedOutput {
  const capture: CapturedOutput = { chunks: [], size: 0, truncated: false };
  stream.on("data", (chunk: Buffer | string) => {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (capture.size >= maxBytes) {
      capture.truncated = true;
      return;
    }
    const remaining = maxBytes - capture.size;
    capture.chunks.push(buffer.subarray(0, remaining));
    capture.size += Math.min(buffer.byteLength, remaining);
    capture.truncated ||= buffer.byteLength > remaining;
  });
  return capture;
}

function assertSafeCommand(command: ProcessCommand): void {
  if (command.executable.length === 0 || command.executable.includes("\0")) {
    throw new DomainError("INVALID_INPUT", "input", "Executable must be a non-empty safe string", false);
  }
  for (const argument of command.args) {
    if (argument.includes("\0")) {
      throw new DomainError("INVALID_INPUT", "input", "Process arguments cannot contain NUL bytes", false);
    }
  }
}
