import { describe, expect, it } from "vitest";
import { Value } from "typebox/value";

import {
  DomainError,
  DomainErrorSchema,
  RunManifestSchema,
  parseSchema,
  type RunManifest,
} from "@pure-auto-codeql/contracts";
import { Application, RunStatusService, assertTransition, canTransition } from "@pure-auto-codeql/core";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const initialManifest: RunManifest = {
  schemaVersion: "v2.contracts/1",
  runId: "run_test01",
  status: "created",
  verificationLevel: "generated",
  createdAt: "2026-08-23T00:00:00.000Z",
  updatedAt: "2026-08-23T00:00:00.000Z",
  artifactRoot: "/isolated/runs/run_test01",
};

describe("contracts", () => {
  it("validates versioned manifests and rejects malformed external input", () => {
    expect(Value.Check(RunManifestSchema, initialManifest)).toBe(true);
    expect(parseSchema(RunManifestSchema, initialManifest, "manifest")).toEqual(initialManifest);
    expect(() => parseSchema(RunManifestSchema, { ...initialManifest, status: "success" }, "manifest")).toThrow(
      DomainError,
    );
    expect(Value.Check(DomainErrorSchema, new DomainError("INVALID_INPUT", "input", "bad", false).toRecord())).toBe(true);
  });
});

describe("run state machine", () => {
  it("accepts only legal transitions", () => {
    expect(canTransition("created", "running")).toBe(true);
    expect(canTransition("running", "checkpointed")).toBe(true);
    expect(canTransition("failed", "completed")).toBe(false);
    expect(() => assertTransition("failed", "completed")).toThrowError(/Cannot transition/);
  });

  it("makes start and resume idempotent and never turns failure into success", async () => {
    const artifacts = new MemoryArtifactStore();
    const service = new RunStatusService(artifacts, new FixedClock(), new FixedIdGenerator());
    const created = await service.create();
    const started = await service.start(created.runId, "doctor");
    expect(await service.start(created.runId, "doctor")).toEqual(started);
    const checkpointed = await service.checkpoint(created.runId, "doctor", "generated");
    expect(checkpointed.status).toBe("checkpointed");
    expect((await service.resume(created.runId)).status).toBe("running");
    expect((await service.complete(created.runId)).status).toBe("completed");

    const failedArtifacts = new MemoryArtifactStore();
    const failedService = new RunStatusService(failedArtifacts, new FixedClock(), new FixedIdGenerator("run_fail01"));
    const failedRun = await failedService.create();
    await failedService.start(failedRun.runId, "doctor");
    const error = new DomainError("PROCESS_TIMEOUT", "process", "timed out", true).toRecord();
    expect((await failedService.fail(failedRun.runId, error)).status).toBe("failed");
    expect((await failedService.complete(failedRun.runId)).status).toBe("failed");
  });
});

describe("application controller", () => {
  it("uses the same deterministic workflow for doctor and persisted status", async () => {
    const artifacts = new MemoryArtifactStore();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator(),
    });
    const result = await app.doctor();
    expect(result.schemaVersion).toBe("v2.contracts/1");
    expect(result.run.status).toBe("completed");
    expect(await app.status(result.run.runId)).toEqual(result.run);
    await app.close();
  });

  it("checkpoints a failed run and preserves its classified error", async () => {
    const artifacts = new MemoryArtifactStore();
    const codeql = new FakeCodeqlPort();
    codeql.failure = new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "missing", false);
    const app = new Application({
      codeql,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_fail02"),
    });
    await expect(app.doctor()).rejects.toMatchObject({ code: "CODEQL_CLI_NOT_FOUND" });
    const failed = await app.status("run_fail02");
    expect(failed.status).toBe("failed");
    expect(failed.error?.code).toBe("CODEQL_CLI_NOT_FOUND");
    expect(failed.error?.details.runId).toBe("run_fail02");
  });

  it("persists cancellation as cancelled and exposes the run id", async () => {
    const artifacts = new MemoryArtifactStore();
    const codeql = new FakeCodeqlPort();
    codeql.failure = new DomainError("PROCESS_CANCELLED", "process", "cancelled", false);
    const app = new Application({
      codeql,
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_cancel01"),
    });
    await expect(app.doctor()).rejects.toMatchObject({ code: "PROCESS_CANCELLED", details: { runId: "run_cancel01" } });
    const cancelled = await app.status("run_cancel01");
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.error?.code).toBe("PROCESS_CANCELLED");
  });
});
