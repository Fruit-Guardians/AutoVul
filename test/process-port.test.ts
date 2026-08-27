import { describe, expect, it } from "vitest";

import { NodeProcessPort } from "@pure-auto-codeql/codeql-runner";

describe("NodeProcessPort", () => {
  it("uses shell-free argv execution, redacts credentials, and caps output", async () => {
    const result = await new NodeProcessPort().execute(
      {
        executable: process.execPath,
        args: ["-e", "process.stdout.write('\\u001b[31m token=super-secret ' + 'x'.repeat(200))"],
        shell: false,
      },
      { timeoutMs: 2000, maxOutputBytes: 32 },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).not.toContain("super-secret");
    expect(result.stdout).not.toContain("\u001b");
    expect(result.stdoutTruncated).toBe(true);
  });

  it("times out and cleans up a long-running child", async () => {
    const result = await new NodeProcessPort().execute(
      {
        executable: process.execPath,
        args: ["-e", "setInterval(() => {}, 1000)"],
        shell: false,
      },
      { timeoutMs: 100, maxOutputBytes: 1024 },
    );
    expect(result.timedOut).toBe(true);
    expect(result.exitCode).not.toBe(0);
  });

  it("honors AbortSignal cancellation", async () => {
    const controller = new AbortController();
    const promise = new NodeProcessPort().execute(
      {
        executable: process.execPath,
        args: ["-e", "setInterval(() => {}, 1000)"],
        shell: false,
      },
      { signal: controller.signal, timeoutMs: 2000, maxOutputBytes: 1024 },
    );
    setTimeout(() => controller.abort(), 50);
    const result = await promise;
    expect(result.cancelled).toBe(true);
  });
});
