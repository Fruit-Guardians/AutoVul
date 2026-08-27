import { Type, type Static } from "typebox";

export const CONTRACTS_VERSION = "v2.contracts/1" as const;

export const ErrorCategorySchema = Type.Union([
  Type.Literal("input"),
  Type.Literal("state"),
  Type.Literal("environment"),
  Type.Literal("process"),
  Type.Literal("database"),
  Type.Literal("artifact"),
  Type.Literal("policy"),
]);
export type ErrorCategory = Static<typeof ErrorCategorySchema>;

export const DomainErrorCodeSchema = Type.Union([
  Type.Literal("INVALID_INPUT"),
  Type.Literal("INVALID_STATE_TRANSITION"),
  Type.Literal("ARTIFACT_NOT_FOUND"),
  Type.Literal("ARTIFACT_CORRUPT"),
  Type.Literal("RUN_LOCKED"),
  Type.Literal("WORKFLOW_BUSY"),
  Type.Literal("CODEQL_CLI_NOT_FOUND"),
  Type.Literal("CODEQL_RESOLVE_FAILED"),
  Type.Literal("CODEQL_EXTRACTOR_MISSING"),
  Type.Literal("DATABASE_NOT_FOUND"),
  Type.Literal("DATABASE_INVALID"),
  Type.Literal("DATABASE_PATH_OUTSIDE_WORKSPACE"),
  Type.Literal("PROCESS_EXITED"),
  Type.Literal("PROCESS_TIMEOUT"),
  Type.Literal("PROCESS_CANCELLED"),
  Type.Literal("PROCESS_CRASHED"),
  Type.Literal("PROCESS_OUTPUT_LIMIT"),
  Type.Literal("QUERY_BUDGET_EXCEEDED"),
  Type.Literal("QUERY_CASE_EXISTS"),
  Type.Literal("QUERY_INVALID_CANDIDATE"),
  Type.Literal("QUERY_RESULT_MISMATCH"),
  Type.Literal("SPEC_SEMANTIC_LOCATION_REQUIRED"),
  Type.Literal("QUERY_METADATA_INVALID"),
  Type.Literal("QUERY_DRAFT_INVALID"),
  Type.Literal("LANGUAGE_UNSUPPORTED"),
  Type.Literal("INTENT_INVALID"),
  Type.Literal("PROBE_FAILED"),
  Type.Literal("CAPABILITY_MISMATCH"),
]);
export type DomainErrorCode = Static<typeof DomainErrorCodeSchema>;

export const DomainErrorSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  code: DomainErrorCodeSchema,
  category: ErrorCategorySchema,
  retryable: Type.Boolean(),
  message: Type.String({ minLength: 1 }),
  details: Type.Record(Type.String(), Type.Unknown()),
});
export type DomainErrorRecord = Static<typeof DomainErrorSchema>;

export class DomainError extends Error {
  readonly schemaVersion = CONTRACTS_VERSION;
  readonly code: DomainErrorCode;
  readonly category: ErrorCategory;
  readonly retryable: boolean;
  readonly details: Record<string, unknown>;

  constructor(
    code: DomainErrorCode,
    category: ErrorCategory,
    message: string,
    retryable: boolean,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "DomainError";
    this.code = code;
    this.category = category;
    this.retryable = retryable;
    this.details = details;
  }

  toRecord(): DomainErrorRecord {
    return {
      schemaVersion: CONTRACTS_VERSION,
      code: this.code,
      category: this.category,
      retryable: this.retryable,
      message: this.message,
      details: this.details,
    };
  }
}

export function isDomainError(value: unknown): value is DomainError {
  return value instanceof DomainError;
}

export function asDomainError(value: unknown, fallbackMessage = "Unexpected error"): DomainError {
  if (isDomainError(value)) {
    return value;
  }
  const message = value instanceof Error ? value.message : fallbackMessage;
  return new DomainError("PROCESS_CRASHED", "process", message, false);
}

export function withRunId(error: DomainError, runId: string): DomainError {
  if (error.details.runId === runId) {
    return error;
  }
  return new DomainError(error.code, error.category, error.message, error.retryable, {
    ...error.details,
    runId,
  });
}
