import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import { GitRevisionTargetRefSchema, RunIdSchema, VerificationLevelSchema } from "./schemas.js";

export const VARIANT_SEARCH_SERVICE = "variant_search" as const;
export const VARIANT_SEARCH_SERVICE_VERSION = "autovul.variant-search/1" as const;
export const VARIANT_SEARCH_STRATEGY_VERSION = "autovul.variant-strategy/1" as const;

export const VARIANT_SEARCH_LIMITS = {
  maxCorpusTargets: 32,
  maxCandidates: 500,
  maxFilesPerTarget: 2048,
  maxTimeoutMs: 300_000,
  defaultMaxCandidates: 50,
  defaultMaxFilesPerTarget: 500,
  defaultTimeoutMs: 60_000,
} as const;

export const VariantSearchGapReasonSchema = Type.Union([
  Type.Literal("candidate_budget_exhausted"),
  Type.Literal("file_budget_exhausted"),
  Type.Literal("timeout_exhausted"),
  Type.Literal("syntax_unsupported"),
  Type.Literal("parser_failed"),
  Type.Literal("object_unreadable"),
  Type.Literal("revision_unavailable"),
]);
export type VariantSearchGapReason = Static<typeof VariantSearchGapReasonSchema>;

export const VariantSearchGapSchema = Type.Object(
  {
    reason: VariantSearchGapReasonSchema,
    target_revision: Type.Optional(Type.String()),
    file: Type.Optional(Type.String()),
    detail: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type VariantSearchGap = Static<typeof VariantSearchGapSchema>;

export const VariantSearchStrategySchema = Type.Union([
  Type.Literal("symbol_call_pattern"),
  Type.Literal("enclosing_signature"),
]);
export type VariantSearchStrategy = Static<typeof VariantSearchStrategySchema>;

export const VariantSearchBudgetSchema = Type.Object(
  {
    max_candidates: Type.Integer({ minimum: 1, maximum: VARIANT_SEARCH_LIMITS.maxCandidates, default: VARIANT_SEARCH_LIMITS.defaultMaxCandidates }),
    max_files_per_target: Type.Integer({ minimum: 1, maximum: VARIANT_SEARCH_LIMITS.maxFilesPerTarget, default: VARIANT_SEARCH_LIMITS.defaultMaxFilesPerTarget }),
    timeout_ms: Type.Integer({ minimum: 1000, maximum: VARIANT_SEARCH_LIMITS.maxTimeoutMs, default: VARIANT_SEARCH_LIMITS.defaultTimeoutMs }),
  },
  { additionalProperties: false },
);
export type VariantSearchBudget = Static<typeof VariantSearchBudgetSchema>;

export const VariantSearchBudgetOverrideSchema = Type.Partial(VariantSearchBudgetSchema);
export type VariantSearchBudgetOverride = Static<typeof VariantSearchBudgetOverrideSchema>;

export const VariantSearchInputSchema = Type.Object(
  {
    seed_run_id: RunIdSchema,
    corpus: Type.Array(GitRevisionTargetRefSchema, {
      minItems: 1,
      maxItems: VARIANT_SEARCH_LIMITS.maxCorpusTargets,
    }),
    strategy: VariantSearchStrategySchema,
    budget: Type.Optional(VariantSearchBudgetOverrideSchema),
  },
  { additionalProperties: false },
);
export type VariantSearchInput = Static<typeof VariantSearchInputSchema>;

export const VariantSearchServiceRequestSchema = Type.Object(
  {
    action: Type.Literal("execute"),
    service: Type.Literal(VARIANT_SEARCH_SERVICE),
    service_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    input: VariantSearchInputSchema,
  },
  { additionalProperties: false },
);
export type VariantSearchServiceRequest = Static<typeof VariantSearchServiceRequestSchema>;

export const VariantCandidateLocationSchema = Type.Object(
  {
    file: Type.String({ minLength: 1, maxLength: 4096 }),
    start_line: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    end_line: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    enclosing_symbol: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type VariantCandidateLocation = Static<typeof VariantCandidateLocationSchema>;

export const VariantCandidateSchema = Type.Object(
  {
    candidate_id: Type.String({ pattern: "^(?:[a-f0-9]{16}|[a-f0-9]{64})$" }),
    target: GitRevisionTargetRefSchema,
    location: VariantCandidateLocationSchema,
    match_kind: Type.Union([Type.Literal("exact_symbol"), Type.Literal("pattern_match")]),
    matched_symbols: Type.Array(Type.String({ minLength: 1, maxLength: 256 }), { minItems: 1, maxItems: 32 }),
    evidence_ref: Type.String({ minLength: 1, maxLength: 1024 }),
    evidence_digest: Type.Optional(Type.String({ pattern: "^(?:[a-f0-9]{16}|[a-f0-9]{64})$" })),
  },
  { additionalProperties: false },
);
export type VariantCandidate = Static<typeof VariantCandidateSchema>;

export const VariantSearchObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    seed_run_id: RunIdSchema,
    seed_capability: Type.Literal("missing_check"),
    seed_digest: Type.String({ pattern: "^(?:[a-f0-9]{16}|[a-f0-9]{64})$" }),
    seed_verification_level: VerificationLevelSchema,
    strategy: VariantSearchStrategySchema,
    strategy_version: Type.Literal(VARIANT_SEARCH_STRATEGY_VERSION),
    completeness: Type.Union([Type.Literal("complete"), Type.Literal("partial")]),
    gaps: Type.Array(VariantSearchGapSchema),
    candidates: Type.Array(VariantCandidateSchema),
    budget_exhausted: Type.Boolean(),
    targets_inspected: Type.Integer({ minimum: 0 }),
    files_inspected: Type.Integer({ minimum: 0 }),
    evidence_refs: Type.Array(Type.String({ minLength: 1, maxLength: 1024 })),
    analyzer: Type.Object(
      {
        analyzer_id: Type.Literal("variant_search_git"),
        evidence_kind: Type.Literal("real_analyzer"),
        version: Type.String({ minLength: 1 }),
        adapter_version: Type.String({ minLength: 1 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type VariantSearchObservation = Static<typeof VariantSearchObservationSchema>;

export const VariantSearchResultArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    run_id: RunIdSchema,
    created_at: Type.String({ minLength: 1 }),
    service: Type.Literal(VARIANT_SEARCH_SERVICE),
    service_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    input: VariantSearchInputSchema,
    observation: VariantSearchObservationSchema,
    route: Type.Object(
      {
        schema_version: Type.Literal(CONTRACTS_VERSION),
        route_kind: Type.Literal("analyzer_service"),
        service: Type.Literal(VARIANT_SEARCH_SERVICE),
        service_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
        result_artifact_ref: Type.String({ minLength: 1 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type VariantSearchResultArtifact = Static<typeof VariantSearchResultArtifactSchema>;

export const VariantSearchExecutionResultSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    run_id: RunIdSchema,
    service: Type.Literal(VARIANT_SEARCH_SERVICE),
    service_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    operation_status: Type.Union([
      Type.Literal("completed"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
      Type.Literal("blocked"),
    ]),
    observation: Type.Optional(VariantSearchObservationSchema),
    allowed_next_actions: Type.Array(
      Type.Union([Type.Literal("execute"), Type.Literal("replay"), Type.Literal("stop")]),
      { maxItems: 3, uniqueItems: true },
    ),
    artifact_ref: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })),
  },
  { additionalProperties: false },
);
export type VariantSearchExecutionResult = Static<typeof VariantSearchExecutionResultSchema>;

export const VariantSearchReplayComparisonSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    run_id: RunIdSchema,
    service: Type.Literal(VARIANT_SEARCH_SERVICE),
    service_version: Type.Literal(VARIANT_SEARCH_SERVICE_VERSION),
    status: Type.Union([
      Type.Literal("identical"),
      Type.Literal("diverged"),
      Type.Literal("environment_blocked"),
      Type.Literal("evidence_mutated"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
    ]),
    replayed_observation: Type.Optional(VariantSearchObservationSchema),
    divergence_reasons: Type.Array(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type VariantSearchReplayComparison = Static<typeof VariantSearchReplayComparisonSchema>;
