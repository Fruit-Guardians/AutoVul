import type {
  QueryDraftReport,
  QueryPackManifest,
  QueryVerification,
  QueryWorkflowStatus,
  ProbeEvidence,
  RunId,
} from "@pure-auto-codeql/contracts";

import type {
  ArtifactStorePort,
  ClockPort,
  CodeqlOperationOptions,
  CodeqlPort,
  QueryDraftExecutionPort,
  QueryExecutionPort,
  QueryProbeExecutionPort,
} from "../ports.js";
import { RunStatusService } from "../status-service.js";
import { startWorkflow } from "./admission.js";
import { createWorkflowContext } from "./context.js";
import { draftQuery } from "./draft.js";
import { finalizeWorkflow } from "./finalize.js";
import { probeQuery } from "./probe.js";
import { readWorkflowStatus, reconcileWorkflowStatus } from "./status.js";
import { verifyQuery } from "./verify.js";

/** Public CodeQL workflow facade. Domain transactions live in command modules. */
export class QueryWorkflowService {
  private readonly context;

  constructor(
    status: RunStatusService,
    codeql: CodeqlPort,
    queries: QueryExecutionPort,
    probes: QueryProbeExecutionPort,
    drafts: QueryDraftExecutionPort,
    artifacts: ArtifactStorePort,
    clock: ClockPort,
  ) {
    this.context = createWorkflowContext(status, codeql, queries, probes, drafts, artifacts, clock);
  }

  close(): Promise<void> {
    return this.context.drafts.close?.() ?? Promise.resolve();
  }

  start(input: unknown, options: CodeqlOperationOptions = { timeoutMs: 30_000 }): Promise<QueryWorkflowStatus> {
    return startWorkflow(this.context, input, options, (runId: RunId) => this.status(runId));
  }

  status(input: unknown): Promise<QueryWorkflowStatus> {
    return reconcileWorkflowStatus(this.context, input).then(() => readWorkflowStatus(this.context, input));
  }

  probe(inputRunId: unknown, inputIntent: unknown, options: CodeqlOperationOptions): Promise<ProbeEvidence> {
    return probeQuery(this.context, inputRunId, inputIntent, options);
  }

  verify(inputRunId: unknown, inputCandidate: unknown, options: CodeqlOperationOptions): Promise<QueryVerification> {
    return verifyQuery(this.context, inputRunId, inputCandidate, options);
  }

  draft(inputRunId: unknown, inputCandidate: unknown, options: CodeqlOperationOptions): Promise<QueryDraftReport> {
    return draftQuery(this.context, inputRunId, inputCandidate, options);
  }

  finalize(input: unknown, options: CodeqlOperationOptions = { timeoutMs: 30_000 }): Promise<QueryPackManifest> {
    return finalizeWorkflow(this.context, input, options);
  }
}
