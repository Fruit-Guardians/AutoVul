import { describe, expect, it, vi } from "vitest";

import { Application, type FlowExecutionPort, type FlowExecutionRequest, type QueryDraftExecutionPort } from "@autovul/core";
import type { FlowAnalyzerObservation, QueryDraftReport } from "@autovul/contracts";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const flowHypothesis = {
  schema_version: "autovul.flow/1",
  model_id: "shutdown-flow",
  language: "python",
  flow_mode: "taint",
  source: { kind: "environment", name: "USER_INPUT" },
  sink: { kind: "call_argument", name: "eval", argument_index: 0 },
};

class AbortableFlowPort implements FlowExecutionPort {
  private markStarted: (() => void) | undefined;
  readonly started = new Promise<void>((resolve) => { this.markStarted = resolve; });

  execute(_request: FlowExecutionRequest, options: { readonly signal?: AbortSignal }): Promise<FlowAnalyzerObservation> {
    this.markStarted?.();
    return new Promise((_resolve, reject) => {
      const abort = (): void => reject(new Error("shutdown reached Flow Adapter"));
      if (options.signal?.aborted) abort();
      else options.signal?.addEventListener("abort", abort, { once: true });
    });
  }
}

class CloseCountingDraftPort implements QueryDraftExecutionPort {
  closeCount = 0;

  executeDraft(): Promise<QueryDraftReport> {
    throw new Error("not used");
  }

  async close(): Promise<void> {
    this.closeCount += 1;
  }
}

function executeFlow(app: Application) {
  return app.research({
    action: "execute",
    capability: "flow",
    hypothesis_version: "autovul.flow/1",
    hypothesis: flowHypothesis,
    analyzer_id: "codeql",
    mode: "reproduce",
    target: { vulnerable: { kind: "codeql_database", path: "/isolated/db" } },
    expectation: { vulnerable: { min_paths: 1, max_paths: 1 } },
    budget: { timeout_ms: 5_000 },
    idempotency_key: "application-shutdown-flow",
  });
}

describe("Application shutdown", () => {
  it("cancels active Capability work, waits for settlement, closes resources once, and rejects new work", async () => {
    const flow = new AbortableFlowPort();
    const drafts = new CloseCountingDraftPort();
    const app = new Application({
      codeql: new FakeCodeqlPort(),
      artifacts: new MemoryArtifactStore(),
      clock: new FixedClock(),
      ids: new FixedIdGenerator("run_shutdown01"),
      flow,
      drafts,
    });

    const executing = executeFlow(app);
    await flow.started;
    const firstClose = app.close();
    const secondClose = app.close();

    await expect(executing).resolves.toMatchObject({
      operation_status: "cancelled",
      observations: [{ code: "FLOW_EXECUTION_CANCELLED" }],
    });
    await Promise.all([firstClose, secondClose]);
    expect(drafts.closeCount).toBe(1);
    await expect(app.doctor()).rejects.toMatchObject({
      code: "INVALID_STATE_TRANSITION",
      category: "state",
      details: { applicationState: "closed" },
    });
  });

  it("composes caller cancellation and shutdown cancellation for database operations", async () => {
    const callerCodeql = new FakeCodeqlPort();
    callerCodeql.inspectDelayMs = 10_000;
    const callerApp = new Application({ codeql: callerCodeql, artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_caller01") });
    const caller = new AbortController();
    const callerOperation = callerApp.databaseInspect("/isolated/db", { signal: caller.signal });
    while (callerCodeql.inspectedPaths.length === 0) await new Promise((resolve) => setTimeout(resolve, 1));
    caller.abort();
    await expect(callerOperation).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });
    await callerApp.close();

    const shutdownCodeql = new FakeCodeqlPort();
    shutdownCodeql.inspectDelayMs = 10_000;
    const shutdownApp = new Application({ codeql: shutdownCodeql, artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_shutdown02") });
    const shutdownOperation = shutdownApp.databaseInspect("/isolated/db");
    while (shutdownCodeql.inspectedPaths.length === 0) await new Promise((resolve) => setTimeout(resolve, 1));
    const closing = shutdownApp.close();
    await expect(shutdownOperation).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });
    await closing;
  });

  it("removes composed caller listeners after a normally completed operation", async () => {
    const app = new Application({ codeql: new FakeCodeqlPort(), artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_listener01") });
    const caller = new AbortController();
    const removeListener = vi.spyOn(caller.signal, "removeEventListener");
    await app.doctor({ signal: caller.signal });
    expect(removeListener).toHaveBeenCalledWith("abort", expect.any(Function));
    await app.close();
  });
});
