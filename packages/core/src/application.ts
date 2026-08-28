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
  readonly defaultTimeoutMs?: number;
}

export class Application implements ApplicationApi {
  private readonly controller: WorkflowController;
  private readonly queryWorkflow: QueryWorkflowService;
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
