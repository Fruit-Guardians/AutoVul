import { describe, expect, it } from "vitest";

import {
  Application,
  CHANGE_OBSERVATION_RESULT_ARTIFACT,
  changeObservationRunIdForInput,
  resolveChangeObservationInput,
  type ChangeObservationPort,
  type ChangeObservationPortObservation,
  type ChangeObservationPortRequest,
} from "@autovul/core";
import { DomainError } from "@autovul/contracts";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const baseOid = "75b4c059b8405dfbd50884b773346a9946fabd20";
const headOid = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const treeOid = "0123456789abcdef0123456789abcdef01234567";
const sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function request(overrides: Record<string, unknown> = {}) {
  return {
    action: "execute" as const,
    service: "change_observation" as const,
    service_version: "autovul.change-observation/1" as const,
    input: {
      repository: { kind: "trusted_local_git_repository" as const, path: "/trusted/repository" },
      base_revision: baseOid,
      head_revision: headOid,
      path_filters: ["src"],
      budget: { max_hunks: 4 },
    },
    ...overrides,
  };
}

function observation(overrides: Record<string, unknown> = {}): ChangeObservationPortObservation {
  return {
    schema_version: "autovul.change-observation/1",
    revision_identity: {
      object_format: "sha1",
      base_oid: baseOid,
      head_oid: headOid,
      base_tree_oid: treeOid,
      head_tree_oid: treeOid,
    },
    completeness: "complete",
    changed_files: [{ path: "src/session.ts", change_kind: "modified", content_kind: "text" }],
    normalized_hunks: [{
      path: "src/session.ts",
      ordinal: 0,
      old_start: 2,
      old_line_count: 1,
      new_start: 2,
      new_line_count: 1,
      removed_line_count: 1,
      added_line_count: 1,
      normalized_removed_sha256: sha256,
      normalized_added_sha256: sha256,
      truncated: false,
    }],
    symbols: [],
    call_changes: [{
      change_kind: "added",
      callee_selector: ["session", "regenerate"],
      argument_change_kind: "none",
      new_argument_count: 0,
      new_location: { path: "src/session.ts", start_line: 2 },
    }],
    event_changes: [{ event_kind: "direct_call_added", selector: ["session", "regenerate"], location: { path: "src/session.ts", start_line: 2 } }],
    analysis_gaps: [],
    provenance: {
      service_version: "autovul.change-observation/1",
      source: "local_git_object_database",
      git_version: "git version 2.47.0",
      command_profile_version: "autovul.git-change-observation/1",
      parser_versions: [{ language: "typescript", version: "5.9.3" }],
    },
    ...overrides,
  } as ChangeObservationPortObservation;
}

class ScriptedChangeObservationPort implements ChangeObservationPort {
  readonly requests: ChangeObservationPortRequest[] = [];

  constructor(private readonly handler: (request: ChangeObservationPortRequest, options: { readonly signal?: AbortSignal }) => ChangeObservationPortObservation | Promise<ChangeObservationPortObservation>) {}

  async observe(requestValue: ChangeObservationPortRequest, options: { readonly signal?: AbortSignal }): Promise<ChangeObservationPortObservation> {
    this.requests.push(requestValue);
    return this.handler(requestValue, options);
  }
}

function application(port: ChangeObservationPort, artifacts = new MemoryArtifactStore()) {
  return {
    artifacts,
    app: new Application({
      codeql: new FakeCodeqlPort(),
      artifacts,
      clock: new FixedClock(),
      ids: new FixedIdGenerator(),
      changeObservation: port,
      defaultTimeoutMs: 5_000,
    }),
  };
}

describe("Change Observation runtime and replay", () => {
  it("commits an Analyzer Service route, remains generated, and replays without mutating source evidence", async () => {
    const port = new ScriptedChangeObservationPort(() => observation());
    const { app, artifacts } = application(port);
    const result = await app.research(request());
    if (!("service" in result)) throw new Error("expected Change Observation result");

    expect(result).toMatchObject({
      service: "change_observation",
      operation_status: "completed",
      allowed_next_actions: ["replay", "stop"],
    });
    expect(result).not.toHaveProperty("capability");
    expect(result).not.toHaveProperty("decision");
    expect(result).not.toHaveProperty("verification_level");
    const before = await artifacts.readArtifact(result.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT);
    expect(JSON.parse(await artifacts.readArtifact(result.run_id, "research/operation.json") ?? "null")).toEqual({
      schema_version: "v2.contracts/1",
      route_kind: "analyzer_service",
      service: "change_observation",
      service_version: "autovul.change-observation/1",
      result_artifact_ref: CHANGE_OBSERVATION_RESULT_ARTIFACT,
    });

    const replay = await app.manageRun({ action: "replay", run_id: result.run_id });
    expect(replay).toMatchObject({ service: "change_observation", status: "match" });
    expect(await artifacts.readArtifact(result.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT)).toBe(before);
    expect(await artifacts.listArtifactPaths(result.run_id, "research/change-observation-replay")).toEqual([
      "research/change-observation-replay/0/comparison.json",
    ]);
    expect(port.requests).toHaveLength(2);
    await app.close();
  });

  it("keeps semantic mutation distinct from a Decision because the service has none", async () => {
    let calls = 0;
    const port = new ScriptedChangeObservationPort(() => {
      calls += 1;
      return calls === 1
        ? observation()
        : observation({ event_changes: [{ event_kind: "direct_call_added", selector: ["session", "destroy"], location: { path: "src/session.ts", start_line: 3 } }] });
    });
    const { app } = application(port);
    const executed = await app.research(request());
    if (!("service" in executed)) throw new Error("expected Change Observation result");

    const replay = await app.manageRun({ action: "replay", run_id: executed.run_id });
    expect(replay).toMatchObject({ service: "change_observation", status: "semantic_mismatch" });
    expect(replay).not.toHaveProperty("decision");
    await app.close();
  });

  it("uses deterministic input identity and cancels the live adapter through autovul_run", async () => {
    let started: (() => void) | undefined;
    const observedStart = new Promise<void>((resolve) => { started = resolve; });
    const port = new ScriptedChangeObservationPort((_request, options) => new Promise<ChangeObservationPortObservation>((_resolve, reject) => {
      started?.();
      options.signal?.addEventListener("abort", () => reject(new DomainError("PROCESS_CANCELLED", "process", "cancelled", false)), { once: true });
    }));
    const { app } = application(port);
    const resolved = resolveChangeObservationInput(request().input);
    const runId = changeObservationRunIdForInput(resolved);
    const pending = app.research(request());
    await observedStart;

    await expect(app.manageRun({ action: "cancel", run_id: runId })).resolves.toMatchObject({ status: "cancelled" });
    await expect(pending).resolves.toMatchObject({ service: "change_observation", operation_status: "cancelled" });
    await app.close();
  });

  it("serializes concurrent replays for one run", async () => {
    let calls = 0;
    let signalReplayStarted: (() => void) | undefined;
    const replayObserved = new Promise<void>((resolve) => { signalReplayStarted = resolve; });
    let continueReplay: (() => void) | undefined;
    const replayContinues = new Promise<void>((resolve) => { continueReplay = resolve; });
    const port = new ScriptedChangeObservationPort(async () => {
      calls += 1;
      if (calls === 2) {
        signalReplayStarted?.();
        await replayContinues;
      }
      return observation();
    });
    const { app, artifacts } = application(port);
    const executed = await app.research(request());
    if (!("service" in executed)) throw new Error("expected Change Observation result");

    const first = app.manageRun({ action: "replay", run_id: executed.run_id });
    await replayObserved;
    const second = app.manageRun({ action: "replay", run_id: executed.run_id });
    continueReplay?.();
    await expect(first).resolves.toMatchObject({ status: "match" });
    await expect(second).resolves.toMatchObject({ status: "match" });
    expect(calls).toBe(3);
    expect(await artifacts.listArtifactPaths(executed.run_id, "research/change-observation-replay")).toEqual([
      "research/change-observation-replay/0/comparison.json",
      "research/change-observation-replay/1/comparison.json",
    ]);
    await app.close();
  });

  it("propagates Application shutdown to a live Change Observation adapter", async () => {
    let started: (() => void) | undefined;
    const observedStart = new Promise<void>((resolve) => { started = resolve; });
    const port = new ScriptedChangeObservationPort((_request, options) => new Promise<ChangeObservationPortObservation>((_resolve, reject) => {
      started?.();
      options.signal?.addEventListener("abort", () => reject(new DomainError("PROCESS_CANCELLED", "process", "shutdown", false)), { once: true });
    }));
    const { app } = application(port);
    const pending = app.research(request());
    await observedStart;

    await app.close();
    await expect(pending).resolves.toMatchObject({ service: "change_observation", operation_status: "cancelled" });
  });

  it("reports replay version changes without changing the original evidence", async () => {
    let calls = 0;
    const port = new ScriptedChangeObservationPort(() => {
      calls += 1;
      return calls === 1 ? observation() : observation({ provenance: { ...observation().provenance, git_version: "git version 2.48.0" } });
    });
    const { app, artifacts } = application(port);
    const executed = await app.research(request());
    if (!("service" in executed)) throw new Error("expected Change Observation result");
    const before = await artifacts.readArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT);

    await expect(app.manageRun({ action: "replay", run_id: executed.run_id })).resolves.toMatchObject({ status: "version_difference" });
    expect(await artifacts.readArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT)).toBe(before);
    await app.close();
  });

  it("keeps revision, request, and observation fingerprint mismatches distinct or semantic", async () => {
    const port = new ScriptedChangeObservationPort(() => observation());
    const { app, artifacts } = application(port);
    const executed = await app.research(request());
    if (!("service" in executed)) throw new Error("expected Change Observation result");
    const original = JSON.parse(await artifacts.readArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT) ?? "null") as Record<string, unknown>;
    const record = original.observation as Record<string, unknown>;

    await artifacts.writeArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT, JSON.stringify({
      ...original,
      observation: { ...record, revision_identity: { ...(record.revision_identity as Record<string, unknown>), head_tree_oid: "fedcba9876543210fedcba9876543210fedcba98" } },
    }));
    await expect(app.manageRun({ action: "replay", run_id: executed.run_id })).resolves.toMatchObject({ status: "revision_identity_difference" });

    await artifacts.writeArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT, JSON.stringify({
      ...original,
      observation: { ...record, request_fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
    }));
    await expect(app.manageRun({ action: "replay", run_id: executed.run_id })).resolves.toMatchObject({ status: "request_fingerprint_difference" });

    await artifacts.writeArtifact(executed.run_id, CHANGE_OBSERVATION_RESULT_ARTIFACT, JSON.stringify({
      ...original,
      observation: { ...record, observation_fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" },
    }));
    await expect(app.manageRun({ action: "replay", run_id: executed.run_id })).resolves.toMatchObject({ status: "semantic_mismatch" });
    await app.close();
  });
});
