import type { ArtifactStorePort, ClockPort, CodeqlPort, QueryDraftExecutionPort, QueryExecutionPort, QueryProbeExecutionPort } from "../ports.js";
import type { RunStatusService } from "../status-service.js";
import { WorkflowRepository } from "./repository.js";

export interface CodeqlWorkflowContext {
  readonly codeql: CodeqlPort;
  readonly queries: QueryExecutionPort;
  readonly probes: QueryProbeExecutionPort;
  readonly drafts: QueryDraftExecutionPort;
  readonly artifacts: ArtifactStorePort;
  readonly clock: ClockPort;
  readonly repository: WorkflowRepository;
}

export function createWorkflowContext(
  status: RunStatusService,
  codeql: CodeqlPort,
  queries: QueryExecutionPort,
  probes: QueryProbeExecutionPort,
  drafts: QueryDraftExecutionPort,
  artifacts: ArtifactStorePort,
  clock: ClockPort,
): CodeqlWorkflowContext {
  return {
    codeql,
    queries,
    probes,
    drafts,
    artifacts,
    clock,
    repository: new WorkflowRepository(artifacts, status, clock),
  };
}
