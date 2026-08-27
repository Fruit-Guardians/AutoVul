import type { ArtifactStorePort, ClockPort, CodeqlPort, QueryDraftExecutionPort, QueryExecutionPort, QueryProbeExecutionPort } from "../ports.js";
import type { RunStatusService } from "../status-service.js";
import { CaseLedger } from "./case-ledger.js";
import { WorkflowRepository } from "./repository.js";

export interface CodeqlWorkflowContext {
  readonly status: RunStatusService;
  readonly codeql: CodeqlPort;
  readonly queries: QueryExecutionPort;
  readonly probes: QueryProbeExecutionPort;
  readonly drafts: QueryDraftExecutionPort;
  readonly artifacts: ArtifactStorePort;
  readonly clock: ClockPort;
  readonly repository: WorkflowRepository;
  readonly cases: CaseLedger;
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
    status,
    codeql,
    queries,
    probes,
    drafts,
    artifacts,
    clock,
    repository: new WorkflowRepository(artifacts),
    cases: new CaseLedger(artifacts, clock),
  };
}
