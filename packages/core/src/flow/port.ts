import type {
  EvidenceOperationMode,
  FlowAnalyzerObservation,
  FlowExpectation,
  FlowModel,
  TargetRef,
} from "@autovul/contracts";

import type { CodeqlOperationOptions } from "../ports.js";

export interface FlowExecutionRequest {
  readonly model: FlowModel;
  readonly target: {
    readonly vulnerable: TargetRef;
    readonly fixed?: TargetRef;
  };
  readonly analyzer_id: "codeql";
  readonly mode: EvidenceOperationMode;
  readonly expectation?: FlowExpectation;
  readonly runId: string;
  readonly artifactRoot: string;
  readonly workspace?: "primary" | "replay";
}

export interface FlowExecutionPort {
  execute(request: FlowExecutionRequest, options: CodeqlOperationOptions): Promise<FlowAnalyzerObservation>;
}
