import { DomainError, parseSchema, RunIdSchema, type RunId } from "@pure-auto-codeql/contracts";

export const RECOVERY_SCHEMA_VERSION = "workflow.commit/v1" as const;
export const RECOVERY_DIRECTORY = "workflow/internal/commits";

export type CommitKind = "verification" | "finalization";
export type RecoveryPhase = "prepared" | "committed" | "projection_pending" | "reconciled" | "aborted";

export interface WorkflowCommitRecord {
  readonly schema_version: typeof RECOVERY_SCHEMA_VERSION;
  readonly operation_id: string;
  readonly idempotency_key: string;
  readonly run_id: RunId;
  readonly kind: CommitKind;
  readonly workflow_phase: "query_verify" | "workflow_finalize";
  readonly phase: RecoveryPhase;
  readonly state_digest: string;
  readonly artifact_paths: readonly string[];
  readonly staged_artifact_paths: readonly string[];
  readonly artifact_digests: Readonly<Record<string, string>>;
  readonly staged_operation_id?: string;
  readonly candidate_id?: string;
  readonly pack_id?: string;
  readonly diagnostics: readonly string[];
  readonly created_at: string;
  readonly updated_at: string;
}

export function recoveryPath(operationId: string): string {
  assertSafeIdentifier(operationId, "recovery operation id");
  return `${RECOVERY_DIRECTORY}/${operationId}.json`;
}

export function parseRecovery(value: unknown, source: string): WorkflowCommitRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw corruptRecovery(source, "record must be an object");
  }
  const record = value as Record<string, unknown>;
  if (record.schema_version !== RECOVERY_SCHEMA_VERSION) throw corruptRecovery(source, "unsupported schema version");
  const operationId = requiredString(record.operation_id, source, "operation_id");
  assertSafeIdentifier(operationId, "recovery operation id");
  const idempotencyKey = requiredString(record.idempotency_key, source, "idempotency_key");
  let runId: RunId;
  try {
    runId = parseSchema(RunIdSchema, record.run_id, "recovery run id");
  } catch {
    throw corruptRecovery(source, "run_id is invalid");
  }
  const kind = record.kind === "verification" || record.kind === "finalization" ? record.kind : undefined;
  if (kind === undefined) throw corruptRecovery(source, "kind is invalid");
  const workflowPhase = record.workflow_phase === "query_verify" || record.workflow_phase === "workflow_finalize" ? record.workflow_phase : undefined;
  if (workflowPhase === undefined) throw corruptRecovery(source, "workflow_phase is invalid");
  const phase = record.phase === "prepared" || record.phase === "committed" || record.phase === "projection_pending" || record.phase === "reconciled" || record.phase === "aborted" ? record.phase : undefined;
  if (phase === undefined) throw corruptRecovery(source, "phase is invalid");
  const stateDigest = requiredString(record.state_digest, source, "state_digest");
  if (!/^[a-f0-9]{16}$/.test(stateDigest)) throw corruptRecovery(source, "state_digest is invalid");
  const artifactPaths = boundedStringArray(record.artifact_paths, source, "artifact_paths", 64, 256);
  for (const path of artifactPaths) {
    if (path.startsWith("/") || path.includes("..") || path.includes("\\")) throw corruptRecovery(source, "artifact_paths contains an unsafe path");
  }
  const stagedArtifactPaths = boundedStringArray(record.staged_artifact_paths, source, "staged_artifact_paths", 64, 256);
  for (const path of stagedArtifactPaths) {
    if (path.startsWith("/") || path.includes("..") || path.includes("\\")) throw corruptRecovery(source, "staged_artifact_paths contains an unsafe path");
  }
  const artifactDigests = boundedDigestMap(record.artifact_digests, source);
  const diagnostics = boundedStringArray(record.diagnostics, source, "diagnostics", 8, 160);
  const createdAt = requiredString(record.created_at, source, "created_at");
  const updatedAt = requiredString(record.updated_at, source, "updated_at");
  const stagedOperationId = optionalString(record.staged_operation_id, source, "staged_operation_id");
  if (stagedOperationId !== undefined) assertSafeIdentifier(stagedOperationId, "staged operation id");
  const candidateId = optionalString(record.candidate_id, source, "candidate_id");
  const packId = optionalString(record.pack_id, source, "pack_id", 512);
  return {
    schema_version: RECOVERY_SCHEMA_VERSION,
    operation_id: operationId,
    idempotency_key: idempotencyKey,
    run_id: runId,
    kind,
    workflow_phase: workflowPhase,
    phase,
    state_digest: stateDigest,
    artifact_paths: artifactPaths,
    staged_artifact_paths: stagedArtifactPaths,
    artifact_digests: artifactDigests,
    ...(stagedOperationId === undefined ? {} : { staged_operation_id: stagedOperationId }),
    ...(candidateId === undefined ? {} : { candidate_id: candidateId }),
    ...(packId === undefined ? {} : { pack_id: packId }),
    diagnostics,
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

export function updateRecovery(record: WorkflowCommitRecord, phase: RecoveryPhase, updatedAt: string, diagnostics: readonly string[] = record.diagnostics): WorkflowCommitRecord {
  return {
    ...record,
    phase,
    diagnostics: diagnostics.slice(0, 8).map((item) => item.slice(0, 160)),
    updated_at: updatedAt,
  };
}

function requiredString(value: unknown, source: string, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) throw corruptRecovery(source, `${field} is invalid`);
  return value;
}

function optionalString(value: unknown, source: string, field: string, maxLength = 256): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) throw corruptRecovery(source, `${field} is invalid`);
  return value;
}

function boundedStringArray(value: unknown, source: string, field: string, maxItems: number, maxLength: number): string[] {
  if (!Array.isArray(value) || value.length > maxItems || value.some((item) => typeof item !== "string" || item.length === 0 || item.length > maxLength)) {
    throw corruptRecovery(source, `${field} is invalid`);
  }
  return value.slice() as string[];
}

function boundedDigestMap(value: unknown, source: string): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw corruptRecovery(source, "artifact_digests is invalid");
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 64) throw corruptRecovery(source, "artifact_digests is too large");
  const result: Record<string, string> = {};
  for (const [path, digest] of entries) {
    if (path.length === 0 || path.length > 256 || path.startsWith("/") || path.includes("..") || path.includes("\\") || typeof digest !== "string" || !/^[a-f0-9]{16}$/.test(digest)) {
      throw corruptRecovery(source, "artifact_digests contains an invalid entry");
    }
    result[path] = digest;
  }
  return result;
}

function assertSafeIdentifier(value: string, field: string): void {
  if (!/^[a-zA-Z0-9._-]{1,128}$/.test(value)) {
    throw new DomainError("ARTIFACT_CORRUPT", "artifact", `${field} is invalid`, false, { field });
  }
}

function corruptRecovery(source: string, reason: string): DomainError {
  return new DomainError("ARTIFACT_CORRUPT", "artifact", "Workflow recovery metadata is invalid", false, { source, reason });
}
