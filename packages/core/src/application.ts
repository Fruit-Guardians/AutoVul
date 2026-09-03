import type {
  CodeqlOperationOptions,
  CodeqlPort,
  ArtifactStorePort,
  ClockPort,
  QueryExecutionPort,
  QueryProbeExecutionPort,
  QueryDraftExecutionPort,
  IdGeneratorPort,
} from "./ports.js";
import { DoctorService } from "./doctor-service.js";
import { RunStatusService } from "./status-service.js";
import { WorkflowController } from "./workflow-controller.js";
import { DomainError, type ChangeObservationExecutionResult, type DatabaseResult, type DoctorResult, type ProbeEvidence, type QueryDraftReport, type QueryPackManifest, type QueryVerification, type QueryWorkflowStatus, type RunManifest } from "@autovul/contracts";
import { QueryWorkflowService } from "./query-workflow.js";
import type { FlowExecutionPort } from "./flow/port.js";
import { FlowReplayService } from "./flow/replay.js";
import { FlowResearchService, type ResearchResult } from "./flow/service.js";
import { MissingCheckResearchService, type MissingCheckResearchResult } from "./missing-check/service.js";
import type { MissingCheckExecutionPort } from "./missing-check/port.js";
import { MissingCheckReplayService } from "./missing-check/replay.js";
import { ResearchRunService, type RunManagementResult } from "./research-run.js";
import { RunCancellationService } from "./run-cancellation.js";
import { TypestateResearchService, type TypestateResearchResult } from "./typestate/service.js";
import type { TypestateEvidenceSnapshotPort, TypestateExecutionPort } from "./typestate/port.js";
import { TypestateReplayService } from "./typestate/replay.js";
import { ChangeObservationResearchService } from "./change-observation/service.js";
import { ChangeObservationReplayService } from "./change-observation/replay.js";
import type { ChangeObservationPort } from "./change-observation/port.js";

export interface ApplicationApi {
  doctor(options?: Partial<CodeqlOperationOptions>): Promise<DoctorResult>;
  databaseInspect(path: unknown, options?: Partial<CodeqlOperationOptions>): Promise<DatabaseResult>;
  databaseValidate(path: unknown, options?: Partial<CodeqlOperationOptions>): Promise<DatabaseResult>;
  status(runId: unknown): Promise<RunManifest>;
  resume(runId: unknown): Promise<RunManifest>;
  workflowStart(spec: unknown, options?: Partial<CodeqlOperationOptions>): Promise<QueryWorkflowStatus>;
  workflowStatus(runId: unknown): Promise<QueryWorkflowStatus>;
  queryVerify(runId: unknown, candidate: unknown, options?: Partial<CodeqlOperationOptions>): Promise<QueryVerification>;
  queryProbe(runId: unknown, intent: unknown, options?: Partial<CodeqlOperationOptions>): Promise<ProbeEvidence>;
  queryDraft(runId: unknown, candidate: unknown, options?: Partial<CodeqlOperationOptions>): Promise<QueryDraftReport>;
  workflowFinalize(runId: unknown, options?: Partial<CodeqlOperationOptions>): Promise<QueryPackManifest>;
  research(input: unknown, options?: Partial<CodeqlOperationOptions>): Promise<ResearchResult | MissingCheckResearchResult | TypestateResearchResult | ChangeObservationExecutionResult>;
  manageRun(input: unknown, options?: Partial<CodeqlOperationOptions>): Promise<RunManagementResult>;
  close(): Promise<void>;
}

export interface ApplicationDependencies {
  readonly codeql: CodeqlPort;
  readonly artifacts: ArtifactStorePort;
  readonly clock: ClockPort;
  readonly ids: IdGeneratorPort;
  readonly queries?: QueryExecutionPort;
  readonly probes?: QueryProbeExecutionPort;
  readonly drafts?: QueryDraftExecutionPort;
  readonly flow?: FlowExecutionPort;
  readonly missingCheck?: MissingCheckExecutionPort;
  readonly typestate?: TypestateExecutionPort & TypestateEvidenceSnapshotPort;
  readonly changeObservation?: ChangeObservationPort;
  readonly defaultTimeoutMs?: number;
}

export class Application implements ApplicationApi {
  private readonly controller: WorkflowController;
  private readonly queryWorkflow: QueryWorkflowService;
  private readonly flowResearch: FlowResearchService;
  private readonly missingCheckResearch: MissingCheckResearchService;
  private readonly typestateResearch: TypestateResearchService;
  private readonly changeObservationResearch: ChangeObservationResearchService;
  private readonly researchRuns: ResearchRunService;
  private readonly cancellations: RunCancellationService;
  private readonly defaultTimeoutMs: number;
  private readonly shutdown = new AbortController();
  private readonly activeOperations = new Set<Promise<unknown>>();
  private lifecycleState: "open" | "closing" | "closed" = "open";
  private closePromise: Promise<void> | undefined;

  constructor(dependencies: ApplicationDependencies) {
    this.defaultTimeoutMs = dependencies.defaultTimeoutMs ?? 30_000;
    const status = new RunStatusService(dependencies.artifacts, dependencies.clock, dependencies.ids);
    this.controller = new WorkflowController(new DoctorService(dependencies.codeql), status);
    this.queryWorkflow = new QueryWorkflowService(
      status,
      dependencies.codeql,
      dependencies.queries ?? unavailableQueryExecutionPort(),
      dependencies.probes ?? unavailableProbeExecutionPort(),
      dependencies.drafts ?? unavailableDraftExecutionPort(),
      dependencies.artifacts,
      dependencies.clock,
    );
    const flow = dependencies.flow ?? unavailableFlowExecutionPort();
    const missingCheck = dependencies.missingCheck ?? unavailableMissingCheckExecutionPort();
    const typestate = dependencies.typestate ?? unavailableTypestateExecutionPort();
    const changeObservation = dependencies.changeObservation ?? unavailableChangeObservationPort();
    this.cancellations = new RunCancellationService();
    this.flowResearch = new FlowResearchService(status, dependencies.codeql, flow, dependencies.artifacts, this.cancellations);
    this.missingCheckResearch = new MissingCheckResearchService(status, dependencies.codeql, missingCheck, dependencies.artifacts, this.cancellations);
    this.typestateResearch = new TypestateResearchService(status, dependencies.codeql, typestate, dependencies.artifacts, this.cancellations);
    this.changeObservationResearch = new ChangeObservationResearchService(status, changeObservation, dependencies.artifacts, this.cancellations);
    this.researchRuns = new ResearchRunService(
      status,
      dependencies.artifacts,
      new FlowReplayService(status, dependencies.codeql, flow, dependencies.artifacts, this.cancellations),
      new MissingCheckReplayService(status, dependencies.codeql, missingCheck, dependencies.artifacts, this.cancellations),
      new TypestateReplayService(status, dependencies.codeql, typestate, typestate, dependencies.artifacts, this.cancellations),
      new ChangeObservationReplayService(status, changeObservation, dependencies.artifacts, this.cancellations),
      this.cancellations,
    );
  }

  doctor(options: Partial<CodeqlOperationOptions> = {}): Promise<DoctorResult> {
    return this.admitWithOptions(options, (resolved) => this.controller.doctor(resolved));
  }

  databaseInspect(path: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<DatabaseResult> {
    return this.admitWithOptions(options, (resolved) => this.controller.inspectDatabase(path, resolved));
  }

  databaseValidate(path: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<DatabaseResult> {
    return this.admitWithOptions(options, (resolved) => this.controller.validateDatabase(path, resolved));
  }

  status(runId: unknown): Promise<RunManifest> {
    return this.admit(() => this.controller.status(runId));
  }

  resume(runId: unknown): Promise<RunManifest> {
    return this.admit(() => this.controller.resumeRun(runId));
  }

  workflowStart(spec: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryWorkflowStatus> {
    return this.admitWithOptions(options, (resolved) => this.queryWorkflow.start(spec, resolved));
  }

  workflowStatus(runId: unknown): Promise<QueryWorkflowStatus> {
    return this.admit(() => this.queryWorkflow.status(runId));
  }

  queryVerify(runId: unknown, candidate: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryVerification> {
    return this.admitWithOptions(options, (resolved) => this.queryWorkflow.verify(runId, candidate, resolved));
  }

  queryProbe(runId: unknown, intent: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<ProbeEvidence> {
    return this.admitWithOptions(options, (resolved) => this.queryWorkflow.probe(runId, intent, resolved));
  }

  queryDraft(runId: unknown, candidate: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryDraftReport> {
    return this.admitWithOptions(options, (resolved) => this.queryWorkflow.draft(runId, candidate, resolved));
  }

  workflowFinalize(runId: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryPackManifest> {
    return this.admitWithOptions(options, (resolved) => this.queryWorkflow.finalize(runId, resolved));
  }

  research(input: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<ResearchResult | MissingCheckResearchResult | TypestateResearchResult | ChangeObservationExecutionResult> {
    return this.admitWithOptions<ResearchResult | MissingCheckResearchResult | TypestateResearchResult | ChangeObservationExecutionResult>(options, (resolved) => {
      if (input !== null && typeof input === "object" && !Array.isArray(input)) {
        const record = input as Record<string, unknown>;
        if ("service" in record) {
          if (record.service === "change_observation") {
            return this.changeObservationResearch.research(input, resolved);
          }
          throw new DomainError("INVALID_INPUT", "input", `Unsupported analyzer service: ${String(record.service)}`, false);
        }
        if (record.capability === "typestate") {
          return this.typestateResearch.research(input, resolved);
        }
        if (record.capability === "missing_check") {
          return this.missingCheckResearch.research(input, resolved);
        }
        if (record.capability === "flow") {
          return this.flowResearch.research(input, resolved);
        }
        throw new DomainError(
          "INVALID_INPUT",
          "input",
          record.capability === undefined ? "Missing research capability or service" : `Unsupported research capability: ${String(record.capability)}`,
          false,
        );
      }
      throw new DomainError("INVALID_INPUT", "input", "Research request must be an object", false);
    });
  }

  manageRun(input: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<RunManagementResult> {
    return this.admitWithOptions(options, (resolved) => this.researchRuns.manage(input, resolved));
  }

  close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.lifecycleState = "closing";
    const reason = new Error("AutoVul Application is closing");
    this.shutdown.abort(reason);
    this.cancellations.cancelAll(reason);
    const admitted = [...this.activeOperations];
    const resourceClose = this.queryWorkflow.close();
    this.closePromise = (async (): Promise<void> => {
      try {
        const outcomes = await Promise.allSettled([...admitted, resourceClose]);
        const resourceOutcome = outcomes[outcomes.length - 1];
        if (resourceOutcome?.status === "rejected") throw resourceOutcome.reason;
      } finally {
        this.lifecycleState = "closed";
      }
    })();
    return this.closePromise;
  }

  private admitWithOptions<T>(options: Partial<CodeqlOperationOptions>, operation: (resolved: CodeqlOperationOptions) => Promise<T>): Promise<T> {
    return this.admit(() => {
      const composed = composeSignals(options.signal, this.shutdown.signal);
      let running: Promise<T>;
      try {
        running = operation({ timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs, signal: composed.signal });
      } catch (error: unknown) {
        composed.release();
        throw error;
      }
      return running.then(
        (value) => { composed.release(); return value; },
        (error: unknown) => { composed.release(); throw error; },
      );
    });
  }

  private admit<T>(operation: () => Promise<T>): Promise<T> {
    if (this.lifecycleState !== "open") {
      return Promise.reject(new DomainError(
        "INVALID_STATE_TRANSITION",
        "state",
        `AutoVul Application is ${this.lifecycleState}`,
        false,
        { applicationState: this.lifecycleState },
      ));
    }
    let admitted: Promise<T>;
    try {
      admitted = operation();
    } catch (error: unknown) {
      return Promise.reject(error);
    }
    this.activeOperations.add(admitted);
    const release = (): void => { this.activeOperations.delete(admitted); };
    void admitted.then(release, release);
    return admitted;
  }
}

function composeSignals(caller: AbortSignal | undefined, shutdown: AbortSignal): { readonly signal: AbortSignal; release(): void } {
  if (caller === undefined) return { signal: shutdown, release: () => undefined };
  const controller = new AbortController();
  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
    caller.removeEventListener("abort", abortFromCaller);
    shutdown.removeEventListener("abort", abortFromShutdown);
  };
  const abort = (reason: unknown): void => {
    release();
    if (!controller.signal.aborted) controller.abort(reason);
  };
  const abortFromCaller = (): void => abort(caller.reason);
  const abortFromShutdown = (): void => abort(shutdown.reason);
  if (caller.aborted) abortFromCaller();
  else if (shutdown.aborted) abortFromShutdown();
  else {
    caller.addEventListener("abort", abortFromCaller, { once: true });
    shutdown.addEventListener("abort", abortFromShutdown, { once: true });
  }
  return { signal: controller.signal, release };
}

function unavailableFlowExecutionPort(): FlowExecutionPort {
  return {
    async execute(): Promise<import("@autovul/contracts").FlowAnalyzerObservation> {
      return { schema_version: "autovul.flow/1", compile_accepted: "not_run", source: { state: "not_run", locations: [] }, sink: { state: "not_run", locations: [] }, path: { state: "not_run", path_count: 0 }, capability_gaps: [{ code: "FLOW_CODEQL_ADAPTER_UNAVAILABLE", path: "/" }], evidence_refs: [], analyzer: { analyzer_id: "codeql", available: false, evidence_kind: "test_double" } };
    },
  };
}

function unavailableMissingCheckExecutionPort(): MissingCheckExecutionPort {
  return {
    async execute(request): Promise<import("@autovul/contracts").MissingCheckAnalyzerObservation> {
      return { schema_version: "autovul.missing-check/1", compile_accepted: "not_run", operation: { state: "not_run", locations: [] }, required_check: { state: "not_run", locations: [] }, relation: { state: "not_run", unchecked_witnesses: [], checked_witnesses: [] }, completeness: { vulnerable: { status: "not_run", scope: request.hypothesis.scope, limitations: [] } }, capability_gaps: [{ code: "MCHECK_CODEQL_ADAPTER_UNAVAILABLE", path: "/" }], evidence_refs: [], analyzer: { analyzer_id: "codeql", available: false, evidence_kind: "real_analyzer" } };
    },
  };
}

function unavailableTypestateExecutionPort(): TypestateExecutionPort & TypestateEvidenceSnapshotPort {
  return {
    async execute(request): Promise<import("@autovul/contracts").TypestateAnalyzerObservation> {
      const events = request.hypothesis.events.map((event) => ({ event_id: event.id, state: "not_run" as const, locations: [] }));
      const boundary = { status: "not_run" as const, scope: request.hypothesis.analysis_scope, limitations: [] };
      return {
        schema_version: "autovul.typestate/1",
        compile_accepted: "not_run",
        resource: { state: "not_run", locations: [], identity_evidence: [] },
        events,
        traces: [],
        completeness: { vulnerable: boundary },
        capability_gaps: [{ code: "TSTATE_CODEQL_ADAPTER_UNAVAILABLE", path: "/" }],
        evidence_refs: [],
        analyzer: { analyzer_id: "codeql", available: false, evidence_kind: "real_analyzer" },
      };
    },
    async snapshotEvidence(): Promise<readonly import("./typestate/port.js").TypestateEvidenceDigest[]> {
      return [];
    },
  };
}

function unavailableChangeObservationPort(): ChangeObservationPort {
  return {
    async observe(): Promise<never> {
      throw new DomainError("CHANGE_OBSERVATION_GIT_FAILED", "process", "The Change Observation Git adapter is not configured", false);
    },
  };
}

function unavailableQueryExecutionPort(): QueryExecutionPort {
  return {
    async execute(): Promise<never> {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", "The query execution adapter is not configured", false);
    },
  };
}

function unavailableProbeExecutionPort(): QueryProbeExecutionPort {
  return {
    async executeProbe(): Promise<never> {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", "The query probe adapter is not configured", false);
    },
  };
}

function unavailableDraftExecutionPort(): QueryDraftExecutionPort {
  return {
    async executeDraft(request): Promise<QueryDraftReport> {
      return {
        schema_version: "v2.contracts/1",
        draft_id: `${request.runId}-${request.candidate.candidate_id}`,
        run_id: request.runId,
        candidate_id: request.candidate.candidate_id,
        revision: request.revision,
        draft_revision_budget: request.draftRevisionBudget,
        status: "degraded",
        lsp_available: false,
        diagnostics: [],
        definition_locations: [],
        hover_text: [],
        completion_labels: [],
        fallback_reason: "LSP draft adapter is not configured; continue to the authoritative CLI compile/analyze step",
        elapsed_ms: 0,
      };
    },
  };
}
