import type { EvidenceOperationMode, MissingCheckAnalyzerObservation, MissingCheckHypothesis, TargetRef } from "@autovul/contracts";
import type { CodeqlOperationOptions } from "../ports.js";

export interface MissingCheckExecutionRequest {
  readonly hypothesis: MissingCheckHypothesis;
  readonly target: { readonly vulnerable: TargetRef; readonly fixed?: TargetRef };
  readonly analyzer_id: "codeql" | "javascript_cfg";
  readonly mode: EvidenceOperationMode;
  readonly runId: string;
  readonly artifactRoot: string;
}

/** Adapter reports facts only; it never emits a domain decision. */
export interface MissingCheckExecutionPort {
  execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation>;
  validateTarget?(target: TargetRef, options: CodeqlOperationOptions): Promise<string>;
}
