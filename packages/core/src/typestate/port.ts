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
  /** Primary evidence is immutable during replay; replay writes below its own namespace. */
  readonly workspace?: "primary" | "replay";
}

/** Adapter reports analyzer facts only; Core remains the sole decision owner. */
export interface TypestateExecutionPort {
  execute(request: TypestateExecutionRequest, options: CodeqlOperationOptions): Promise<TypestateAnalyzerObservation>;
}

/** A narrow Typestate-only integrity view over generated QL and SARIF evidence. */
export interface TypestateEvidenceDigest {
  readonly evidence_ref: string;
  readonly sha256: string;
}

export interface TypestateEvidenceSnapshotRequest {
  readonly hypothesis: TypestateHypothesis;
  readonly runId: string;
  readonly artifactRoot: string;
  readonly workspace: "primary" | "replay";
}

/**
 * Replay uses this sidecar solely to prove that the recorded QL/SARIF files
 * were not changed. It is deliberately not a generic observation comparer.
 */
export interface TypestateEvidenceSnapshotPort {
  snapshotEvidence(request: TypestateEvidenceSnapshotRequest): Promise<readonly TypestateEvidenceDigest[]>;
}
