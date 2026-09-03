import type {
  EvidenceOperationMode,
  MissingCheckAnalyzerObservation,
  MissingCheckHypothesis,
  MissingCheckTarget,
} from "@autovul/contracts";
import type { CodeqlOperationOptions } from "../ports.js";

export interface MissingCheckExecutionRequest {
  readonly hypothesis: MissingCheckHypothesis;
  readonly target: MissingCheckTarget;
  readonly analyzer_id: "codeql" | "javascript_cfg";
  readonly mode: EvidenceOperationMode;
  readonly runId: string;
  readonly artifactRoot: string;
  readonly workspace?: "primary" | "replay";
}

/** Adapter reports facts only; it never emits a domain decision. */
export interface MissingCheckExecutionPort {
  execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation>;
  validateTarget?(target: MissingCheckTarget["vulnerable"], options: CodeqlOperationOptions): Promise<string>;
}

export interface MissingCheckEvidenceDigest {
  readonly evidence_ref: string;
  readonly sha256: string;
}

export interface MissingCheckEvidenceSnapshotRequest {
  readonly hypothesis: MissingCheckHypothesis;
  readonly runId: string;
  readonly artifactRoot: string;
  readonly workspace: "primary" | "replay";
}

export interface MissingCheckEvidenceSnapshotPort {
  snapshotEvidence(request: MissingCheckEvidenceSnapshotRequest): Promise<readonly MissingCheckEvidenceDigest[]>;
}
