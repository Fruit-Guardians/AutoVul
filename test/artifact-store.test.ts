import { describe, expect, it } from "vitest";
import { access, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LocalArtifactStore, NodeFileSystemPort } from "@pure-auto-codeql/codeql-runner";
import { DomainError, type RunManifest } from "@pure-auto-codeql/contracts";
import { RunStatusService } from "@pure-auto-codeql/core";

import { FixedClock, FixedIdGenerator } from "./helpers.js";

function manifest(runId: "run_store01" | "run_store02"): RunManifest {
  return {
    schemaVersion: "v2.contracts/1",
    runId,
    status: "created",
    verificationLevel: "generated",
    createdAt: "2026-08-23T00:00:00.000Z",
    updatedAt: "2026-08-23T00:00:00.000Z",
    artifactRoot: `/isolated/${runId}`,
  };
}

describe("LocalArtifactStore", () => {
  it("writes manifests atomically and restores a checkpoint from disk", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-"));
    try {
      const store = new LocalArtifactStore(root, new NodeFileSystemPort());
      const service = new RunStatusService(store, new FixedClock(), new FixedIdGenerator("run_store01"));
      const created = await service.create();
      await service.start(created.runId, "doctor");
      const checkpoint = await service.checkpoint(created.runId, "doctor", "generated");
      expect(checkpoint.status).toBe("checkpointed");
      await expect(access(join(root, created.runId, "manifest.json.tmp"))).rejects.toThrow();

      const reloaded = new RunStatusService(store, new FixedClock(), new FixedIdGenerator("run_store02"));
      expect((await reloaded.resume(created.runId)).status).toBe("running");
      expect((await store.findManifest(created.runId))?.checkpoint?.phase).toBe("doctor");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects corrupt and half-written manifests", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-corrupt-"));
    const store = new LocalArtifactStore(root, new NodeFileSystemPort());
    const runId = "run_store02" as const;
    const runRoot = join(root, runId);
    await mkdir(runRoot, { recursive: true });
    try {
      await writeFile(join(runRoot, "manifest.json"), "{not-json", "utf8");
      await expect(store.findManifest(runId)).rejects.toMatchObject({ code: "ARTIFACT_CORRUPT" });
      await rm(join(runRoot, "manifest.json"));
      await writeFile(join(runRoot, "manifest.json.tmp"), JSON.stringify(manifest(runId)), "utf8");
      await expect(store.findManifest(runId)).rejects.toMatchObject({ code: "ARTIFACT_CORRUPT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("prefers a stable manifest when an interrupted atomic write left a tmp file", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-fallback-"));
    const store = new LocalArtifactStore(root, new NodeFileSystemPort());
    const runId = "run_store02" as const;
    const runRoot = join(root, runId);
    try {
      await store.saveManifest(manifest(runId));
      await writeFile(join(runRoot, "manifest.json.tmp"), "{partial", "utf8");
      await expect(store.findManifest(runId)).resolves.toEqual(manifest(runId));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("enforces a per-run mutex", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-lock-"));
    try {
      const store = new LocalArtifactStore(root, new NodeFileSystemPort());
      const runId = "run_store01" as const;
      await store.withRunLock(runId, async () => {
        await expect(store.withRunLock(runId, async () => undefined)).rejects.toMatchObject({ code: "RUN_LOCKED" });
      });
      await expect(store.findManifest(runId)).resolves.toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("takes over a lock left by a dead process after the stale threshold", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-stale-lock-"));
    try {
      const filesystem = new NodeFileSystemPort({ lockStaleMs: 1_000 });
      const store = new LocalArtifactStore(root, filesystem);
      const runId = "run_store01" as const;
      const runRoot = join(root, runId);
      await mkdir(runRoot, { recursive: true });
      await mkdir(join(runRoot, ".lock"));
      await writeFile(
        join(runRoot, ".lock", ".owner-dead-process"),
        JSON.stringify({ ownerToken: "dead-process", pid: 99999999, createdAt: "2020-01-01T00:00:00.000Z" }),
        "utf8",
      );
      await expect(store.withRunLock(runId, async () => "recovered")).resolves.toBe("recovered");
      await expect(access(join(runRoot, ".lock"))).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("promotes a complete staged artifact bundle as one directory operation", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-stage-"));
    try {
      const store = new LocalArtifactStore(root, new NodeFileSystemPort());
      const bundle = await store.stageArtifactBundle("run_store01", "stage-one", "query-pack", [
        { relativePath: "query.ql", content: "select 1\n" },
        { relativePath: "query-pack-manifest.json", content: "{}\n" },
      ]);
      expect(await store.readArtifact("run_store01", "query-pack/query.ql")).toBeUndefined();
      expect(await store.readStagedArtifact("run_store01", bundle.operationId, "query.ql")).toBe("select 1\n");
      await store.promoteArtifactBundle("run_store01", bundle);
      expect(await store.readArtifact("run_store01", "query-pack/query.ql")).toBe("select 1\n");
      expect(await store.listStagedArtifactOperations("run_store01")).toEqual([]);
      await store.discardPromotedArtifactBundle("run_store01", "query-pack");
      expect(await store.readArtifact("run_store01", "query-pack/query.ql")).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a symlink escape before artifact writes", async () => {
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-symlink-"));
    const outside = await mkdtemp(join(tmpdir(), "pure-auto-codeql-artifact-outside-"));
    try {
      const store = new LocalArtifactStore(root, new NodeFileSystemPort());
      const runRoot = join(root, "run_store01");
      await mkdir(runRoot, { recursive: true });
      await symlink(outside, join(runRoot, "escape"));
      await expect(store.writeArtifact("run_store01", "escape/secret.txt", "secret")).rejects.toMatchObject({ code: "INVALID_INPUT" });
      await expect(access(join(outside, "secret.txt"))).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });
});
