import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import { RunIdSchema } from "./schemas.js";

export const DYNAMIC_REPRODUCTION_PORT_ID = "dynamic_reproduction" as const;
export const DYNAMIC_REPRODUCTION_CONTRACT_VERSION = "autovul.dynamic-reproduction/1" as const;

export const DYNAMIC_REPRODUCTION_LIMITS = {
  minTimeoutMs: 100,
  maxTimeoutMs: 120_000,
  defaultTimeoutMs: 10_000,
  maxOutputBytes: 1_048_576, // 1 MB
  defaultMaxOutputBytes: 262_144, // 256 KB
  maxWitnessBytes: 5_242_880, // 5 MB
  defaultMaxWitnessBytes: 524_288, // 512 KB
  maxArgs: 64,
  maxWitnessFiles: 32,
} as const;

export const DynamicReproductionCommandSchema = Type.Object(
  {
    executable: Type.String({ minLength: 1 }),
    args: Type.Array(Type.String(), { maxItems: DYNAMIC_REPRODUCTION_LIMITS.maxArgs }),
    cwd: Type.String({ minLength: 1 }),
    env: Type.Optional(Type.Record(Type.String(), Type.String())),
  },
  { additionalProperties: false },
);
export type DynamicReproductionCommand = Static<typeof DynamicReproductionCommandSchema>;

export const DynamicReproductionBudgetSchema = Type.Object(
  {
    timeout_ms: Type.Integer({
      minimum: DYNAMIC_REPRODUCTION_LIMITS.minTimeoutMs,
      maximum: DYNAMIC_REPRODUCTION_LIMITS.maxTimeoutMs,
      default: DYNAMIC_REPRODUCTION_LIMITS.defaultTimeoutMs,
    }),
    max_output_bytes: Type.Integer({
      minimum: 1024,
      maximum: DYNAMIC_REPRODUCTION_LIMITS.maxOutputBytes,
      default: DYNAMIC_REPRODUCTION_LIMITS.defaultMaxOutputBytes,
    }),
    max_witness_bytes: Type.Optional(
      Type.Integer({
        minimum: 1024,
        maximum: DYNAMIC_REPRODUCTION_LIMITS.maxWitnessBytes,
        default: DYNAMIC_REPRODUCTION_LIMITS.defaultMaxWitnessBytes,
      }),
    ),
  },
  { additionalProperties: false },
);
export type DynamicReproductionBudget = Static<typeof DynamicReproductionBudgetSchema>;

export const DynamicReproductionWitnessArtifactSchema = Type.Object(
  {
    path: Type.String({ minLength: 1 }),
    sha256: Type.String({ minLength: 64, maxLength: 64 }),
    size_bytes: Type.Integer({ minimum: 0 }),
    snippet: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);
export type DynamicReproductionWitnessArtifact = Static<typeof DynamicReproductionWitnessArtifactSchema>;

export const DynamicReproductionExecutionRequestSchema = Type.Object(
  {
    run_id: RunIdSchema,
    hypothesis_id: Type.String({ minLength: 1 }),
    command: DynamicReproductionCommandSchema,
    budget: DynamicReproductionBudgetSchema,
    witness_file_paths: Type.Optional(
      Type.Array(Type.String({ minLength: 1 }), {
        maxItems: DYNAMIC_REPRODUCTION_LIMITS.maxWitnessFiles,
      }),
    ),
    artifact_root: Type.String({ minLength: 1 }),
    workspace: Type.Optional(Type.Union([Type.Literal("primary"), Type.Literal("replay")])),
  },
  { additionalProperties: false },
);
export type DynamicReproductionExecutionRequest = Static<typeof DynamicReproductionExecutionRequestSchema>;

export const DynamicReproductionExecutionObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    contract_version: Type.Literal(DYNAMIC_REPRODUCTION_CONTRACT_VERSION),
    exit_code: Type.Union([Type.Integer(), Type.Null()]),
    signal: Type.Union([Type.String(), Type.Null()]),
    stdout: Type.String(),
    stderr: Type.String(),
    stdout_truncated: Type.Boolean(),
    stderr_truncated: Type.Boolean(),
    elapsed_ms: Type.Integer({ minimum: 0 }),
    timed_out: Type.Boolean(),
    cancelled: Type.Boolean(),
    witnesses: Type.Array(DynamicReproductionWitnessArtifactSchema),
    environment_digest: Type.String({ minLength: 64, maxLength: 64 }),
    evidence_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type DynamicReproductionExecutionObservation = Static<typeof DynamicReproductionExecutionObservationSchema>;

export const DynamicReproductionReplayVerificationSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    status: Type.Union([
      Type.Literal("identical"),
      Type.Literal("diverged"),
      Type.Literal("evidence_mutated"),
      Type.Literal("failed"),
    ]),
    original_evidence_ref: Type.String({ minLength: 1 }),
    original_environment_digest: Type.String({ minLength: 64, maxLength: 64 }),
    checked_witnesses_count: Type.Integer({ minimum: 0 }),
    detail: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);
export type DynamicReproductionReplayVerification = Static<typeof DynamicReproductionReplayVerificationSchema>;
