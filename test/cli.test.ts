import { describe, expect, it } from "vitest";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runCli } from "@autovul/cli";

interface Envelope {
  readonly ok: boolean;
  readonly result?: {
    readonly run?: { readonly runId: string; readonly status: string };
    readonly runId?: string;
    readonly status?: string;
    readonly database?: { readonly valid: boolean };
  };
  readonly error?: { readonly code: string; readonly details?: { readonly runId?: string } };
}

async function makeFakeCodeql(root: string): Promise<string> {
  const path = join(root, "fake-codeql");
  const script = `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "CodeQL CLI version 2.17.6"
elif [ "$1" = "resolve" ]; then
  if [ "$2" = "database" ]; then
    echo '{"language":"python","codeqlVersion":"2.17.6"}'
  else
    printf 'python (/fake/python)\\ncpp (/fake/cpp)\\n'
  fi
else
  exit 2
fi
`;
  await writeFile(path, script, "utf8");
  await chmod(path, 0o755);
  return path;
}

function ioBuffer(): { stdout: string[]; stderr: string[] } {
  return { stdout: [], stderr: [] };
}

describe("V2 CLI", () => {
  it("runs doctor and status through the same persisted Application API", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-cli-"));
    try {
      const codeql = await makeFakeCodeql(root);
      const output = ioBuffer();
      const exitCode = await runCli(
        ["doctor", "--json", "--runs-dir", root, "--codeql", codeql],
        { stdout: (value) => output.stdout.push(value), stderr: (value) => output.stderr.push(value) },
      );
      expect(exitCode).toBe(0);
      const doctor = JSON.parse(output.stdout.join("")) as Envelope;
      expect(doctor.ok).toBe(true);
      expect(doctor.result?.run.status).toBe("completed");
      const runId = doctor.result?.run.runId;
      expect(runId).toBeDefined();

      const statusOutput = ioBuffer();
      expect(await runCli(["status", runId ?? "", "--json", "--runs-dir", root], {
        stdout: (value) => statusOutput.stdout.push(value),
        stderr: (value) => statusOutput.stderr.push(value),
      })).toBe(0);
      const status = JSON.parse(statusOutput.stdout.join("")) as Envelope;
      expect(status.result?.runId).toBe(runId);
      expect(status.result?.status).toBe("completed");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("supports read-only database inspect and stable CLI errors", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-cli-db-"));
    try {
      const codeql = await makeFakeCodeql(root);
      const database = join(root, "db");
      await mkdir(database);
      const output = ioBuffer();
      expect(await runCli(["database", "inspect", database, "--json", "--runs-dir", root, "--workspace-root", root, "--codeql", codeql], {
        stdout: (value) => output.stdout.push(value),
        stderr: (value) => output.stderr.push(value),
      })).toBe(0);
      const inspected = JSON.parse(output.stdout.join("")) as Envelope;
      expect(inspected.result?.database?.valid).toBe(true);

      const failureOutput = ioBuffer();
      expect(await runCli(["doctor", "--json", "--runs-dir", root, "--codeql", join(root, "missing-codeql")], {
        stdout: (value) => failureOutput.stdout.push(value),
        stderr: (value) => failureOutput.stderr.push(value),
      })).toBe(1);
      const failure = JSON.parse(failureOutput.stdout.join("")) as Envelope;
      expect(failure.ok).toBe(false);
      expect(failure.error?.code).toBe("CODEQL_CLI_NOT_FOUND");
      expect(failure.error?.details?.runId).toMatch(/^run_/);
      const failedStatusOutput = ioBuffer();
      expect(await runCli(["status", failure.error?.details?.runId ?? "", "--json", "--runs-dir", root], {
        stdout: (value) => failedStatusOutput.stdout.push(value),
        stderr: (value) => failedStatusOutput.stderr.push(value),
      })).toBe(0);
      const failedStatus = JSON.parse(failedStatusOutput.stdout.join("")) as Envelope;
      expect(failedStatus.result?.status).toBe("failed");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
