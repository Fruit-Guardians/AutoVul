import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import { CodeqlEnvironmentSchema, DatabaseManifestSchema, RunManifestSchema, RunIdSchema } from "./schemas.js";

export const DatabasePathSchema = Type.String({ minLength: 1 });
export type DatabasePath = Static<typeof DatabasePathSchema>;

export const DoctorResultSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  environment: CodeqlEnvironmentSchema,
  run: RunManifestSchema,
});
export type DoctorResult = Static<typeof DoctorResultSchema>;

export const DatabaseResultSchema = Type.Object({
  schemaVersion: Type.Literal(CONTRACTS_VERSION),
  database: DatabaseManifestSchema,
  run: RunManifestSchema,
});
export type DatabaseResult = Static<typeof DatabaseResultSchema>;

export const StatusRequestSchema = RunIdSchema;
export type StatusRequest = Static<typeof StatusRequestSchema>;
