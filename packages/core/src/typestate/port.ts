import type { EvidenceOperationMode, TargetRef, TypestateAnalyzerObservation, TypestateHypothesis } from "@autovul/contracts";

import type { CodeqlOperationOptions } from "../ports.js";

export interface TypestateExecutionRequest {
  readonly hypothesis: TypestateHypothesis;
  readonly target: {
    readonly vulnerable: TargetRef;
    readonly fixed?: TargetRef;
  };
  readonly analyzer_id: "codeql";
  readonly mode: EvidenceOperationMode;
  readonly runId: string;
  readonly artifactRoot: string;
}

/** Adapter reports analyzer facts only; Core remains the sole decision owner. */
export interface TypestateExecutionPort {
  execute(request: TypestateExecutionRequest, options: CodeqlOperationOptions): Promise<TypestateAnalyzerObservation>;
}
