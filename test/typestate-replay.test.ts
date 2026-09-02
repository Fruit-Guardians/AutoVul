import { describe, expect, it } from "vitest";

import {
  type TypestateAnalyzerObservation,
  type TypestateHypothesis,
} from "@autovul/contracts";
import {
  Application,
  RunCancellationService,
  RunStatusService,
  TypestateResearchService,
  TypestateReplayService,
  type TypestateEvidenceSnapshotPort,
  type TypestateExecutionPort,
} from "@autovul/core";
import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const scope = {
  kind: "single_file_named_function" as const,
  file: "fixture.js",
  entry: { kind: "named_function" as const, name: "login" },
  event_scope: "named_function_including_inline_callbacks" as const,
  alias_boundary: "direct_lexical_binding" as const,
};

const hypothesis: TypestateHypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-replay",
  language: "javascript",
  resource: { id: "login_session", kind: "local_binding", binding_name: "session", acquisition_event: "session_acquired", identity_model: "direct_lexical_binding" },
  initial_state: "preauth",
  states: ["preauth", "rekeyed", "authenticated"],
  events: [
    { id: "session_acquired", selector: { kind: "direct_call", name: "getSession" } },
    { id: "regenerate_request_session", selector: { kind: "direct_method", receiver: "req.session", name: "regenerate" } },
    { id: "assign_user", selector: { kind: "direct_call", name: "assignUserToSession", argument_property: "session" } },
  ],
  transitions: [
    { from_state: "preauth", event: "session_acquired", to_state: "preauth" },
    { from_state: "preauth", event: "regenerate_request_session", to_state: "rekeyed" },
    { from_state: "rekeyed", event: "assign_user", to_state: "authenticated" },
  ],
  violation: { kind: "prohibited_transition", from_state: "preauth", event: "assign_user", to_state: "authenticated", requires_same_identity: true },
  analysis_scope: scope,
};

const location = { file: "fixture.js", start_line: 10 };

function observation(overrides: Partial<TypestateAnalyzerObservation> = {}): TypestateAnalyzerObservation {
  return {
    schema_version: "autovul.typestate/1",
    compile_accepted: true,
    resource: { state: "observed", locations: [location], identity_evidence: ["direct_lexical_binding:login_session"] },
    events: [
      { event_id: "session_acquired", state: "observed", locations: [location] },
      { event_id: "regenerate_request_session", state: "not_found", locations: [] },
      { event_id: "assign_user", state: "observed", locations: [location] },
    ],
    traces: [{
      state: "violating_witness",
      resource_id: "login_session",
      events: [
        { event_id: "session_acquired", from_state: "preauth", to_state: "preauth", location },
        { event_id: "assign_user", from_state: "preauth", to_state: "authenticated", location },
      ],
      identity_evidence: [{ kind: "same_binding", resource_id: "login_session", event_ids: ["session_acquired", "assign_user"], locations: [location] }],
      violation_step: 1,
      evidence_ref: "typestate/tstate-replay/vulnerable/violation.sarif",
    }],
    completeness: { vulnerable: { status: "complete", scope, limitations: ["cross_file_aliases_excluded"] } },
    capability_gaps: [],
    evidence_refs: ["typestate/tstate-replay/vulnerable/violation.sarif"],
    analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "test_double", version: "CodeQL CLI 2.26.1", adapter_version: "autovul.codeql-typestate/1" },
    ...overrides,
  };
}

function requestFor(idempotencyKey: string): Record<string, unknown> {
  return {
    action: "execute",
    capability: "typestate",
    hypothesis_version: "autovul.typestate/1",
    hypothesis,
    target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } },
    analyzer_id: "codeql",
    mode: "reproduce",
    budget: { timeout_ms: 5_000 },
    idempotency_key: idempotencyKey,
  };
}

type TypestateReplayPort = TypestateExecutionPort & TypestateEvidenceSnapshotPort;

function replayPort(
  current: { value: TypestateAnalyzerObservation },
  overrides: Partial<TypestateReplayPort> = {},
): TypestateReplayPort {
  return {
    async execute(): Promise<TypestateAnalyzerObservation> { return current.value; },
    async snapshotEvidence(): Promise<readonly { readonly evidence_ref: string; readonly sha256: string }[]> {
      return [{ evidence_ref: "typestate/tstate-replay/observations.ql", sha256: "primary-evidence" }];
    },
    ...overrides,
  };
}

async function setup(current: { value: TypestateAnalyzerObservation }, idempotencyKey: string, execution = replayPort(current)): Promise<{
  readonly replay: TypestateReplayService;
  readonly codeql: FakeCodeqlPort;
  readonly artifacts: MemoryArtifactStore;
  readonly runId: `run_${string}`;
  readonly current: { value: TypestateAnalyzerObservation };
  readonly cancellations: RunCancellationService;
}> {
  const artifacts = new MemoryArtifactStore();
  const status = new RunStatusService(artifacts, new FixedClock(), new FixedIdGenerator());
  const codeql = new FakeCodeqlPort();
  const cancellations = new RunCancellationService();
  const research = new TypestateResearchService(status, codeql, execution, artifacts, cancellations);
  const result = await research.research(requestFor(idempotencyKey), { timeoutMs: 5_000 });
  if (!("run_id" in result)) throw new Error("expected execution result");
  return { replay: new TypestateReplayService(status, codeql, execution, execution, artifacts, cancellations), codeql, artifacts, runId: result.run_id, current, cancellations };
}

const route = {
  schema_version: "v2.contracts/1" as const,
  route_kind: "capability" as const,
  capability: "typestate" as const,
  hypothesis_version: "autovul.typestate/1" as const,
  result_artifact_ref: "research/typestate/result.json",
};

function deferred<T>(): { readonly promise: Promise<T>; resolve(value: T): void; reject(reason?: unknown): void } {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("TypestateReplayService", () => {
  it("routes research and replay through the aggregate Application API", async () => {
    const artifacts = new MemoryArtifactStore();
    const codeql = new FakeCodeqlPort();
    const execution = replayPort({ value: observation() });
    const app = new Application({ typestate: execution, codeql, artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_tstateapp") });
    try {
      const result = await app.research(requestFor("replay-aggregate"));
      if (!("run_id" in result)) throw new Error("expected aggregate execution result");
      expect(result).toMatchObject({ capability: "typestate", operation_status: "completed", decision: { outcome: "violation_observed" } });
      await expect(app.manageRun({ action: "replay", run_id: result.run_id })).resolves.toMatchObject({
        capability: "typestate",
        status: "match",
        replay_decision: { outcome: "violation_observed" },
      });
    } finally {
      await app.close();
    }
  });

  it("replays through the explicit Typestate route and matches the recorded policy result", async () => {
    const current = { value: observation() };
    const { replay, runId } = await setup(current, "replay-match");

    await expect(replay.replay(runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "match",
      recorded_decision: { outcome: "violation_observed" },
      replay_decision: { outcome: "violation_observed" },
    });
  });

  it("blocks when the target fingerprint changes and does not let an alternate route select another artifact", async () => {
    const current = { value: observation() };
    const target = await setup(current, "replay-fingerprint");
    target.codeql.database = { ...target.codeql.database, portableFingerprint: "fedcba9876543210" };

    await expect(target.replay.replay(target.runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "environment_blocked",
      observations: [{ code: "TSTATE_REPLAY_FINGERPRINT_DIFFERENCE" }],
    });
    await expect(target.replay.replay(target.runId, { ...route, result_artifact_ref: "research/other.json" }, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "environment_blocked",
      observations: [{ code: "TSTATE_REPLAY_ROUTE_ARTIFACT_MISMATCH" }],
    });
  });

  it("separates Analyzer and Decision Policy version differences from semantic mismatches", async () => {
    const current = { value: observation() };
    const analyzer = await setup(current, "replay-version");
    current.value = observation({ analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "test_double", version: "CodeQL CLI 2.27.0", adapter_version: "autovul.codeql-typestate/1" } });
    await expect(analyzer.replay.replay(analyzer.runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "version_difference",
      observations: [{ code: "TSTATE_REPLAY_ANALYZER_VERSION_DIFFERENCE" }],
    });

    const policy = await setup({ value: observation() }, "replay-policy");
    const key = `${policy.runId}/research/typestate/result.json`;
    const raw = policy.artifacts.artifacts.get(key);
    if (raw === undefined) throw new Error("expected committed Typestate artifact");
    const artifact = JSON.parse(raw) as Record<string, unknown>;
    delete artifact.decision_policy_version;
    policy.artifacts.artifacts.set(key, JSON.stringify(artifact));
    await expect(policy.replay.replay(policy.runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "version_difference",
      observations: [{ code: "TSTATE_REPLAY_POLICY_VERSION_UNRECORDED" }],
    });

    const semantic = await setup({ value: observation() }, "replay-semantic");
    const changed = { ...observation(), traces: [] };
    semantic.current.value = changed;
    const semanticResult = await semantic.replay.replay(semantic.runId, route, { timeoutMs: 5_000 });
    expect(semanticResult).toMatchObject({
      status: "semantic_mismatch",
      recorded_decision: { outcome: "violation_observed" },
      replay_decision: { outcome: "no_violation_observed" },
    });
    expect(semanticResult.observations).toEqual(expect.arrayContaining([{ code: "TSTATE_REPLAY_SEMANTIC_MISMATCH", evidence_ref: "research/typestate/result.json" }]));
  });

  it("compares the full Typestate observation while normalizing only replay evidence namespaces", async () => {
    const current = { value: observation() };
    const target = await setup(current, "replay-observation-semantics");
    const recordedTrace = observation().traces[0];
    if (recordedTrace === undefined) throw new Error("expected a recorded trace");
    current.value = observation({
      traces: [{
        ...recordedTrace,
        events: [...recordedTrace.events.slice(0, 1), { ...recordedTrace.events[1]!, location: { file: "fixture.js", start_line: 42 } }],
        identity_evidence: [{ ...recordedTrace.identity_evidence[0]!, locations: [{ file: "fixture.js", start_line: 41 }] }],
        evidence_ref: "typestate-replay/tstate-replay/vulnerable/violation.sarif",
      }],
      evidence_refs: ["typestate-replay/tstate-replay/vulnerable/violation.sarif"],
    });
    const semanticResult = await target.replay.replay(target.runId, route, { timeoutMs: 5_000 });
    expect(semanticResult).toMatchObject({
      status: "semantic_mismatch",
      recorded_decision: { outcome: "violation_observed" },
      replay_decision: { outcome: "violation_observed" },
    });
    expect(semanticResult.observations.some((item) => item.code === "TSTATE_REPLAY_OBSERVATION_SEMANTIC_MISMATCH")).toBe(true);

    const namespaceOnly = { value: observation() };
    const namespaceTarget = await setup(namespaceOnly, "replay-evidence-namespace");
    namespaceOnly.value = observation({
      traces: observation().traces.map((trace) => ({ ...trace, evidence_ref: trace.evidence_ref.replace("typestate/", "typestate-replay/") })),
      evidence_refs: observation().evidence_refs.map((ref) => ref.replace("typestate/", "typestate-replay/")),
    });
    await expect(namespaceTarget.replay.replay(namespaceTarget.runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({ status: "match" });
  });

  it("keeps the original evidence digest immutable across replay", async () => {
    const current = { value: observation() };
    let digest = "before";
    const primarySnapshots: string[] = [];
    const execution = replayPort(current, {
      async execute(request): Promise<TypestateAnalyzerObservation> {
        if (request.workspace === "replay") digest = "after";
        return current.value;
      },
      async snapshotEvidence(request): Promise<readonly { readonly evidence_ref: string; readonly sha256: string }[]> {
        if (request.workspace === "primary") primarySnapshots.push(digest);
        return [{ evidence_ref: "typestate/tstate-replay/observations.ql", sha256: digest }];
      },
    });
    const target = await setup(current, "replay-evidence-digest", execution);

    await expect(target.replay.replay(target.runId, route, { timeoutMs: 5_000 })).resolves.toMatchObject({
      status: "semantic_mismatch",
      observations: [{ code: "TSTATE_REPLAY_EVIDENCE_MUTATED" }],
    });
    expect(primarySnapshots).toEqual(["before", "after"]);
  });

  it("cancels replay through caller abort, autovul_run cancellation, and Application shutdown", async () => {
    const makeBlockingPort = (current: { value: TypestateAnalyzerObservation }) => {
      const started = deferred<void>();
      const execution: TypestateReplayPort = {
        async execute(request, options): Promise<TypestateAnalyzerObservation> {
          if (request.workspace !== "replay") return current.value;
          started.resolve();
          return new Promise<TypestateAnalyzerObservation>((_resolve, reject) => {
            options.signal?.addEventListener("abort", () => reject(options.signal?.reason), { once: true });
          });
        },
        async snapshotEvidence(): Promise<readonly { readonly evidence_ref: string; readonly sha256: string }[]> {
          return [{ evidence_ref: "typestate/tstate-replay/observations.ql", sha256: "stable" }];
        },
      };
      return { execution, started };
    };

    const callerCurrent = { value: observation() };
    const callerBlocking = makeBlockingPort(callerCurrent);
    const caller = await setup(callerCurrent, "replay-caller-cancel", callerBlocking.execution);
    const controller = new AbortController();
    const callerReplay = caller.replay.replay(caller.runId, route, { timeoutMs: 5_000, signal: controller.signal });
    await callerBlocking.started.promise;
    controller.abort(new Error("caller cancelled"));
    await expect(callerReplay).resolves.toMatchObject({ status: "cancelled", observations: [{ code: "TSTATE_REPLAY_CANCELLED" }] });

    const runCurrent = { value: observation() };
    const runBlocking = makeBlockingPort(runCurrent);
    const runArtifacts = new MemoryArtifactStore();
    const runApp = new Application({ typestate: runBlocking.execution, codeql: new FakeCodeqlPort(), artifacts: runArtifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_tstatecancel") });
    try {
      const result = await runApp.research(requestFor("replay-run-cancel"));
      if (!("run_id" in result)) throw new Error("expected Typestate execution");
      const replaying = runApp.manageRun({ action: "replay", run_id: result.run_id });
      await runBlocking.started.promise;
      await runApp.manageRun({ action: "cancel", run_id: result.run_id });
      await expect(replaying).resolves.toMatchObject({ status: "cancelled", observations: [{ code: "TSTATE_REPLAY_CANCELLED" }] });
    } finally {
      await runApp.close();
    }

    const shutdownCurrent = { value: observation() };
    const shutdownBlocking = makeBlockingPort(shutdownCurrent);
    const shutdownApp = new Application({ typestate: shutdownBlocking.execution, codeql: new FakeCodeqlPort(), artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_tstateshutdown") });
    const result = await shutdownApp.research(requestFor("replay-shutdown"));
    if (!("run_id" in result)) throw new Error("expected Typestate execution");
    const replaying = shutdownApp.manageRun({ action: "replay", run_id: result.run_id });
    await shutdownBlocking.started.promise;
    const closing = shutdownApp.close();
    await expect(replaying).resolves.toMatchObject({ status: "cancelled", observations: [{ code: "TSTATE_REPLAY_CANCELLED" }] });
    await closing;
  });

  it("serializes concurrent replay for the same run", async () => {
    const current = { value: observation() };
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    let replayCalls = 0;
    let active = 0;
    let maxActive = 0;
    const execution: TypestateReplayPort = {
      async execute(request): Promise<TypestateAnalyzerObservation> {
        if (request.workspace !== "replay") return current.value;
        replayCalls += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        if (replayCalls === 1) {
          firstStarted.resolve();
          await releaseFirst.promise;
        }
        active -= 1;
        return current.value;
      },
      async snapshotEvidence(): Promise<readonly { readonly evidence_ref: string; readonly sha256: string }[]> {
        return [{ evidence_ref: "typestate/tstate-replay/observations.ql", sha256: "stable" }];
      },
    };
    const target = await setup(current, "replay-concurrency", execution);
    const first = target.replay.replay(target.runId, route, { timeoutMs: 5_000 });
    await firstStarted.promise;
    const second = target.replay.replay(target.runId, route, { timeoutMs: 5_000 });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(maxActive).toBe(1);
    releaseFirst.resolve();
    await expect(Promise.all([first, second])).resolves.toEqual([expect.objectContaining({ status: "match" }), expect.objectContaining({ status: "match" })]);
    expect(maxActive).toBe(1);
  });
});
