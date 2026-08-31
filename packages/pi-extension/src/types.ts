import type {
  DatabaseResult,
  DoctorResult,
  DomainErrorRecord,
  ProbeEvidence,
  QueryDraftReport,
  QueryPackManifest,
  QueryVerification,
  QueryWorkflowStatus,
  FlowValidationResult,
  MissingCheckExecutionResult,
  MissingCheckValidationResult,
  ResearchExecutionResult,
  RunManifest,
} from "@autovul/contracts";

export type ToolDetails = DoctorResult | DatabaseResult | ProbeEvidence | QueryDraftReport | QueryWorkflowStatus | QueryVerification | QueryPackManifest | FlowValidationResult | MissingCheckValidationResult | ResearchExecutionResult | MissingCheckExecutionResult | RunManifest | DomainErrorRecord;

export interface PiUiState {
  status: "ready" | "running" | "completed" | "failed" | "cancelled" | "budget_exhausted";
  phase: string;
  runId?: string;
  verificationLevel?: string;
  round?: number;
  compile?: string;
  vulnerableResults?: number;
  vulnerableFlows?: number;
  fixedResults?: number;
  fixedFlows?: number;
  passed?: boolean;
  diagnostics: string[];
  artifactRoot?: string;
  packId?: string;
}
