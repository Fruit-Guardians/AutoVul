import { describe, expect, it } from "vitest";
import { access, mkdtemp, mkdir, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { NodeFileSystemPort } from "@pure-auto-codeql/codeql-runner";
import { DomainError } from "@pure-auto-codeql/contracts";

const TEST_ROOT_PREFIX = "pure-auto-codeql-lock-";
const DEAD_PID = 99999999;

describe("NodeFileSystemPort lock protocol", () => {
  it("enforces normal single-process mutual exclusion", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort();
      const lockPath = join(root, ".lock");
      const owner = await filesystem.acquireLock(lockPath);

      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
      await owner.release();
      await expect(filesystem.acquireLock(lockPath)).resolves.toBeDefined();
    });
  });

  it("takes over a dead-PID owner without waiting for the stale threshold", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 60_000 });
      const lockPath = join(root, ".lock");
      await seedOwner(lockPath, { ownerToken: "dead", pid: DEAD_PID, createdAt: "2020-01-01T00:00:00.000Z" });

      const owner = await filesystem.acquireLock(lockPath);
      await owner.release();
      await expect(access(lockPath)).rejects.toThrow();
    });
  });

  it("migrates a dead legacy regular-file lock through the recovery gate", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 60_000 });
      const lockPath = join(root, ".lock");
      await writeFile(lockPath, JSON.stringify({ pid: DEAD_PID, createdAt: "2020-01-01T00:00:00.000Z" }), "utf8");

      const owner = await filesystem.acquireLock(lockPath);
      await owner.release();
      await expect(access(lockPath)).rejects.toThrow();
      await expect(access(`${lockPath}.legacy-recovery`)).rejects.toThrow();
    });
  });

  it("does not migrate a legacy regular-file lock held by a live PID", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 1 });
      const lockPath = join(root, ".lock");
      await writeFile(lockPath, JSON.stringify({ pid: process.pid, createdAt: "2020-01-01T00:00:00.000Z" }), "utf8");

      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
      expect((await stat(lockPath)).isDirectory()).toBe(false);
    });
  });

  it("never takes over an old lock held by the current live PID", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 1 });
      const lockPath = join(root, ".lock");
      await seedOwner(lockPath, { ownerToken: "live", pid: process.pid, createdAt: "2020-01-01T00:00:00.000Z" });

      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
    });
  });

  it("holds a corrupt owner until stale, then recovers it", async () => {
    await withTemporaryRoot(async (root) => {
      // Keep the pre-stale assertion above filesystem/test-runner scheduling
      // jitter; the second assertion explicitly moves the lock past the gate.
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 1_000 });
      const lockPath = join(root, ".lock");
      await mkdir(lockPath);
      await writeFile(join(lockPath, ".owner-corrupt"), "{not-json", "utf8");

      const now = new Date();
      await utimes(lockPath, now, now);
      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });

      const old = new Date(Date.now() - 5_000);
      await utimes(lockPath, old, old);
      const owner = await filesystem.acquireLock(lockPath);
      await owner.release();
      await expect(access(lockPath)).rejects.toThrow();
    });
  });

  it("keeps maxActive at one across 100 rounds of 24 concurrent takeovers", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 60_000 });
      for (let round = 0; round < 100; round += 1) {
        const lockPath = join(root, `round-${round}`, ".lock");
        await seedOwner(lockPath, {
          ownerToken: `dead-${round}`,
          pid: DEAD_PID,
          createdAt: "2020-01-01T00:00:00.000Z",
        });

        let active = 0;
        let maxActive = 0;
        let successes = 0;
        const diagnostics: string[] = [];
        await Promise.all(
          Array.from({ length: 24 }, async (_, contender) => {
            let owner: { release(): Promise<void> } | undefined;
            try {
              owner = await filesystem.acquireLock(lockPath);
              active += 1;
              maxActive = Math.max(maxActive, active);
              if (maxActive > 1) {
                throw new Error(`round=${round} contender=${contender} active=${active} maxActive=${maxActive}`);
              }
              await delay(15);
              successes += 1;
            } catch (error) {
              if (!(error instanceof DomainError) || error.code !== "RUN_LOCKED") {
                diagnostics.push(error instanceof Error ? error.message : String(error));
              }
            } finally {
              if (active > 0 && owner !== undefined) {
                active -= 1;
              }
              await owner?.release();
            }
          }),
        );

        expect(diagnostics, `lock stress diagnostics: ${diagnostics.join(" | ")}`).toEqual([]);
        expect(successes, `lock stress round ${round} had no winner`).toBeGreaterThanOrEqual(1);
        expect(maxActive, `lock stress round ${round} violated mutual exclusion`).toBe(1);
      }
    });
  }, 30_000);

  it("uses real independent Node processes for cross-process competition", async () => {
    await withTemporaryRoot(async (root) => {
      const lockPath = join(root, ".lock");
      const workerPath = join(dirname(fileURLToPath(import.meta.url)), "lock-worker.mjs");
      const cwd = resolve(dirname(fileURLToPath(import.meta.url)), "..");
      const results = await Promise.all(
        Array.from({ length: 24 }, () => runWorker(workerPath, cwd, lockPath, 800)),
      );

      expect(results.filter((result) => result.status === "acquired")).toHaveLength(1);
      expect(results.filter((result) => result.status === "rejected" && result.code === "RUN_LOCKED")).toHaveLength(23);
    });
  }, 30_000);

  it("does not let an expired owner release remove a replacement owner", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 60_000 });
      const lockPath = join(root, ".lock");
      const oldOwner = await filesystem.acquireLock(lockPath);
      const oldOwnerPath = join(lockPath, (await readdir(lockPath))[0]!);
      await writeFile(
        oldOwnerPath,
        JSON.stringify({ ownerToken: "old", pid: DEAD_PID, createdAt: "2020-01-01T00:00:00.000Z" }),
        "utf8",
      );

      const newOwner = await filesystem.acquireLock(lockPath);
      await oldOwner.release();
      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
      await newOwner.release();
    });
  });

  it("does not release a lock whose owner token file was replaced or corrupted", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort();
      const lockPath = join(root, ".lock");
      const owner = await filesystem.acquireLock(lockPath);
      const ownerPath = join(lockPath, (await readdir(lockPath))[0]!);
      await writeFile(ownerPath, JSON.stringify({ ownerToken: "different", pid: process.pid }), "utf8");

      await owner.release();
      expect((await stat(lockPath)).isDirectory()).toBe(true);
      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
    });
  });

  it("does not release a lock directory that was replaced by another owner", async () => {
    await withTemporaryRoot(async (root) => {
      const filesystem = new NodeFileSystemPort();
      const lockPath = join(root, ".lock");
      const oldOwner = await filesystem.acquireLock(lockPath);
      await rm(lockPath, { recursive: true, force: true });
      await seedOwner(lockPath, { ownerToken: "replacement", pid: process.pid, createdAt: new Date().toISOString() });

      await oldOwner.release();
      await expect(filesystem.acquireLock(lockPath)).rejects.toMatchObject({ code: "RUN_LOCKED" });
    });
  });
});

async function withTemporaryRoot<T>(operation: (root: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), TEST_ROOT_PREFIX));
  try {
    return await operation(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function seedOwner(
  lockPath: string,
  metadata: { readonly ownerToken: string; readonly pid: number; readonly createdAt: string },
): Promise<void> {
  await mkdir(lockPath, { recursive: true });
  await writeFile(join(lockPath, `.owner-${metadata.ownerToken}`), JSON.stringify(metadata), "utf8");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

interface WorkerResult {
  readonly status: string;
  readonly code?: unknown;
}

function runWorker(workerPath: string, cwd: string, lockPath: string, holdMs: number): Promise<WorkerResult> {
  return new Promise((resolveResult, rejectResult) => {
    const child = spawn(process.execPath, [workerPath, lockPath, String(holdMs)], { cwd });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", rejectResult);
    child.on("close", (exitCode) => {
      const line = stdout.trim().split("\n").at(-1);
      if (line === undefined || line.length === 0) {
        rejectResult(new Error(`lock worker produced no result: exitCode=${exitCode} stderr=${stderr}`));
        return;
      }
      try {
        resolveResult(JSON.parse(line) as WorkerResult);
      } catch (error) {
        rejectResult(new Error(`invalid lock worker result: ${line}; stderr=${stderr}`, { cause: error }));
      }
    });
  });
}
