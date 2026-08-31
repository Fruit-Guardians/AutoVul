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
import { DomainError, type DatabaseResult, type DoctorResult, type ProbeEvidence, type QueryDraftReport, type QueryPackManifest, type QueryVerification, type QueryWorkflowStatus, type RunManifest } from "@autovul/contracts";
import { QueryWorkflowService } from "./query-workflow.js";
import type { FlowExecutionPort } from "./flow/port.js";
import { FlowReplayService } from "./flow/replay.js";
import { FlowResearchService, type ResearchResult } from "./flow/service.js";
import { MissingCheckResearchService, type MissingCheckResearchResult } from "./missing-check/service.js";
import type { MissingCheckExecutionPort } from "./missing-check/port.js";
import { MissingCheckReplayService } from "./missing-check/replay.js";
import { ResearchRunService, type RunManagementResult } from "./research-run.js";
import { RunCancellationService } from "./run-cancellation.js";

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
  research(input: unknown, options?: Partial<CodeqlOperationOptions>): Promise<ResearchResult | MissingCheckResearchResult>;
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
  readonly defaultTimeoutMs?: number;
}

export class Application implements ApplicationApi {
  private readonly controller: WorkflowController;
  private readonly queryWorkflow: QueryWorkflowService;
  private readonly flowResearch: FlowResearchService;
  private readonly missingCheckResearch: MissingCheckResearchService;
  private readonly researchRuns: ResearchRunService;
  private readonly defaultTimeoutMs: number;

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
    const cancellations = new RunCancellationService();
    this.flowResearch = new FlowResearchService(status, dependencies.codeql, flow, dependencies.artifacts, cancellations);
    this.missingCheckResearch = new MissingCheckResearchService(status, dependencies.codeql, missingCheck, dependencies.artifacts, cancellations);
    this.researchRuns = new ResearchRunService(status, dependencies.artifacts, new FlowReplayService(status, flow, dependencies.artifacts), new MissingCheckReplayService(status, dependencies.codeql, missingCheck, dependencies.artifacts), cancellations);
  }

  doctor(options: Partial<CodeqlOperationOptions> = {}): Promise<DoctorResult> {
    return this.controller.doctor(this.options(options));
  }

  databaseInspect(path: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<DatabaseResult> {
    return this.controller.inspectDatabase(path, this.options(options));
  }

  databaseValidate(path: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<DatabaseResult> {
    return this.controller.validateDatabase(path, this.options(options));
  }

  status(runId: unknown): Promise<RunManifest> {
    return this.controller.status(runId);
  }

  resume(runId: unknown): Promise<RunManifest> {
    return this.controller.resumeRun(runId);
  }

  workflowStart(spec: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryWorkflowStatus> {
    return this.queryWorkflow.start(spec, this.options(options));
  }

  workflowStatus(runId: unknown): Promise<QueryWorkflowStatus> {
    return this.queryWorkflow.status(runId);
  }

  queryVerify(runId: unknown, candidate: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryVerification> {
    return this.queryWorkflow.verify(runId, candidate, this.options(options));
  }

  queryProbe(runId: unknown, intent: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<ProbeEvidence> {
    return this.queryWorkflow.probe(runId, intent, this.options(options));
  }

  queryDraft(runId: unknown, candidate: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryDraftReport> {
    return this.queryWorkflow.draft(runId, candidate, this.options(options));
  }

  workflowFinalize(runId: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<QueryPackManifest> {
    return this.queryWorkflow.finalize(runId, this.options(options));
  }

  research(input: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<ResearchResult | MissingCheckResearchResult> {
    if (input !== null && typeof input === "object" && !Array.isArray(input) && (input as Record<string, unknown>).capability === "missing_check") {
      return this.missingCheckResearch.research(input, this.options(options));
    }
    return this.flowResearch.research(input, this.options(options));
  }

  manageRun(input: unknown, options: Partial<CodeqlOperationOptions> = {}): Promise<RunManagementResult> {
    return this.researchRuns.manage(input, this.options(options));
  }

  async close(): Promise<void> {
    await this.queryWorkflow.close();
  }

  private options(options: Partial<CodeqlOperationOptions>): CodeqlOperationOptions {
    const result: CodeqlOperationOptions = {
      timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
    };
    if (options.signal !== undefined) {
      return { ...result, signal: options.signal };
    }
    return result;
  }
}

function unavailableFlowExecutionPort(): FlowExecutionPort {
  return {
    async execute(): Promise<import("@autovul/contracts").FlowAnalyzerObservation> {
      return { schema_version: "autovul.flow/1", compile_accepted: "not_run", source: { state: "not_run", locations: [] }, sink: { state: "not_run", locations: [] }, path: { state: "not_run", path_count: 0 }, capability_gaps: [{ code: "FLOW_CODEQL_ADAPTER_UNAVAILABLE", path: "/" }], evidence_refs: [], analyzer: { analyzer_id: "codeql", available: false } };
    },
  };
}

function unavailableMissingCheckExecutionPort(): MissingCheckExecutionPort {
  return {
    async execute(): Promise<import("@autovul/contracts").MissingCheckAnalyzerObservation> {
      return { schema_version: "autovul.missing-check/1", compile_accepted: "not_run", operation: { state: "not_run", locations: [] }, required_check: { state: "not_run", locations: [] }, relation: { state: "not_run", unchecked_witnesses: [], checked_witnesses: [] }, capability_gaps: [{ code: "MCHECK_CODEQL_ADAPTER_UNAVAILABLE", path: "/" }], evidence_refs: [], analyzer: { analyzer_id: "codeql", available: false } };
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
