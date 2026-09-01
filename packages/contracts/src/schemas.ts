import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION, DomainErrorSchema } from "./errors.js";

export const RunIdSchema = Type.String({ pattern: "^run_[a-z0-9][a-z0-9_-]{5,127}$" });
export type RunId = Static<typeof RunIdSchema>;

export const RunPhaseSchema = Type.Union([
  Type.Literal("doctor"),
  Type.Literal("inspect"),
  Type.Literal("validate"),
  Type.Literal("workflow_start"),
  Type.Literal("query_probe"),
  Type.Literal("query_draft"),
  Type.Literal("query_verify"),
  Type.Literal("workflow_finalize"),
  /** A Flow capability operation projected onto the shared run lifecycle. */
  Type.Literal("flow_execute"),
  Type.Literal("missing_check_execute"),
  /** A Typestate capability operation projected onto the shared run lifecycle. */
  Type.Literal("typestate_execute"),
]);
export type RunPhase = Static<typeof RunPhaseSchema>;

export const RunStatusSchema = Type.Union([
  Type.Literal("created"),
  Type.Literal("running"),
  Type.Literal("checkpointed"),
  Type.Literal("completed"),
  Type.Literal("failed"),
  Type.Literal("cancelled"),
  Type.Literal("budget_exhausted"),
]);
export type RunStatus = Static<typeof RunStatusSchema>;

export const VerificationLevelSchema = Type.Union([
  Type.Literal("generated"),
  Type.Literal("compiled"),
  Type.Literal("reproduced"),
  Type.Literal("differential"),
  Type.Literal("variant_validated"),
]);
export type VerificationLevel = Static<typeof VerificationLevelSchema>;

export const CodeqlEnvironmentSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  available: Type.Boolean(),
  cliPath: Type.Optional(Type.String()),
  version: Type.Optional(Type.String()),
  languages: Type.Array(Type.String()),
  checkedAt: Type.String({ minLength: 1 }),
  diagnostics: Type.Array(Type.String()),
});
export type CodeqlEnvironment = Static<typeof CodeqlEnvironmentSchema>;

export const CodeqlDiagnosticSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  code: Type.String({ minLength: 1 }),
  severity: Type.Union([Type.Literal("info"), Type.Literal("warning"), Type.Literal("error")]),
  message: Type.String({ minLength: 1 }),
  stream: Type.Optional(Type.Union([Type.Literal("stdout"), Type.Literal("stderr")])),
  truncated: Type.Boolean(),
});
export type CodeqlDiagnostic = Static<typeof CodeqlDiagnosticSchema>;

export const DatabaseManifestSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  path: Type.String({ minLength: 1 }),
  canonicalPath: Type.Optional(Type.String({ minLength: 1 })),
  exists: Type.Boolean(),
  isDirectory: Type.Boolean(),
  valid: Type.Boolean(),
  language: Type.Optional(Type.String({ minLength: 1 })),
  codeqlVersion: Type.Optional(Type.String({ minLength: 1 })),
  fingerprint: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
  portableFingerprint: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
  checkedAt: Type.String({ minLength: 1 }),
  diagnostics: Type.Array(CodeqlDiagnosticSchema),
});
export type DatabaseManifest = Static<typeof DatabaseManifestSchema>;

export const RunCheckpointSchema = Type.Object({
  phase: RunPhaseSchema,
  completedAt: Type.String({ minLength: 1 }),
  verificationLevel: VerificationLevelSchema,
});
export type RunCheckpoint = Static<typeof RunCheckpointSchema>;

export const RunManifestSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  runId: RunIdSchema,
  status: RunStatusSchema,
  phase: Type.Optional(RunPhaseSchema),
  verificationLevel: VerificationLevelSchema,
  createdAt: Type.String({ minLength: 1 }),
  updatedAt: Type.String({ minLength: 1 }),
  artifactRoot: Type.String({ minLength: 1 }),
  checkpoint: Type.Optional(RunCheckpointSchema),
  error: Type.Optional(DomainErrorSchema),
});
export type RunManifest = Static<typeof RunManifestSchema>;

export const CodeqlDatabaseActionSchema = Type.Union([
  Type.Literal("doctor"),
  Type.Literal("inspect"),
  Type.Literal("validate"),
]);
export type CodeqlDatabaseAction = Static<typeof CodeqlDatabaseActionSchema>;

export const CodeqlDatabaseToolInputSchema = Type.Object(
  {
    action: CodeqlDatabaseActionSchema,
    path: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type CodeqlDatabaseToolInput = Static<typeof CodeqlDatabaseToolInputSchema>;
