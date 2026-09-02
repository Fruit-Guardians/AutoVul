import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import { RunIdSchema } from "./schemas.js";

export const CHANGE_OBSERVATION_SERVICE = "change_observation" as const;
export const CHANGE_OBSERVATION_SERVICE_VERSION = "autovul.change-observation/1" as const;

/** Fixed v1 protocol bounds; callers may only reduce these limits. */
export const CHANGE_OBSERVATION_LIMITS = {
  maxRepositoryPathLength: 4_096,
  maxPathFilterCount: 32,
  maxPathFilterLength: 1_024,
  maxChangedFiles: 512,
  maxDiffBytes: 4_194_304,
  maxHunks: 2_048,
  maxHunkLines: 256,
  maxSymbols: 4_096,
  maxCallChanges: 4_096,
  maxEventChanges: 4_096,
  maxSelectorSegments: 8,
  maxIdentifierLength: 128,
  maxSymbolNameLength: 256,
  maxDiagnosticCount: 32,
  maxParserVersions: 2,
  maxArtifactRefLength: 1_024,
  maxGitVersionLength: 256,
} as const;

const FULL_GIT_OID_PATTERN = "^(?:[a-f0-9]{40}|[a-f0-9]{64})$";
const SHA256_PATTERN = "^[a-f0-9]{64}$";
const IDENTIFIER_PATTERN = "^[A-Za-z_$][A-Za-z0-9_$]{0,127}$";
const PATH_PREFIX_PATTERN = "^(?!/)(?!.*\\\\)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\*\\?\\[\\]{}])[^\\u0000/](?:[^\\u0000]*[^\\u0000/])?$";

export const ChangeObservationRepositorySchema = Type.Object(
  {
    kind: Type.Literal("trusted_local_git_repository"),
    path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxRepositoryPathLength }),
  },
  { additionalProperties: false },
);
export type ChangeObservationRepository = Static<typeof ChangeObservationRepositorySchema>;

export const ChangeObservationRevisionSchema = Type.String({ pattern: FULL_GIT_OID_PATTERN });
export type ChangeObservationRevision = Static<typeof ChangeObservationRevisionSchema>;

/** Literal repository-relative prefix; semantic trusted-root checks remain Core-owned. */
export const ChangeObservationPathFilterSchema = Type.String({
  minLength: 1,
  maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength,
  pattern: PATH_PREFIX_PATTERN,
});
export type ChangeObservationPathFilter = Static<typeof ChangeObservationPathFilterSchema>;

export const ChangeObservationBudgetSchema = Type.Object(
  {
    timeout_ms: Type.Integer({ minimum: 1, maximum: 600_000, default: 600_000 }),
    max_changed_files: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxChangedFiles, default: CHANGE_OBSERVATION_LIMITS.maxChangedFiles }),
    max_diff_bytes: Type.Integer({ minimum: 1_024, maximum: CHANGE_OBSERVATION_LIMITS.maxDiffBytes, default: CHANGE_OBSERVATION_LIMITS.maxDiffBytes }),
    max_hunks: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxHunks, default: CHANGE_OBSERVATION_LIMITS.maxHunks }),
    max_hunk_lines: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxHunkLines, default: CHANGE_OBSERVATION_LIMITS.maxHunkLines }),
    max_symbols: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxSymbols, default: CHANGE_OBSERVATION_LIMITS.maxSymbols }),
    max_call_changes: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxCallChanges, default: CHANGE_OBSERVATION_LIMITS.maxCallChanges }),
    max_event_changes: Type.Integer({ minimum: 1, maximum: CHANGE_OBSERVATION_LIMITS.maxEventChanges, default: CHANGE_OBSERVATION_LIMITS.maxEventChanges }),
  },
  { additionalProperties: false },
);
export type ChangeObservationBudget = Static<typeof ChangeObservationBudgetSchema>;

/** Callers may supply only the dimensions they intend to lower; Core resolves every default. */
export const ChangeObservationBudgetOverrideSchema = Type.Partial(ChangeObservationBudgetSchema);
export type ChangeObservationBudgetOverride = Static<typeof ChangeObservationBudgetOverrideSchema>;

export const ChangeObservationInputSchema = Type.Object(
  {
    repository: ChangeObservationRepositorySchema,
    base_revision: ChangeObservationRevisionSchema,
    head_revision: ChangeObservationRevisionSchema,
    path_filters: Type.Optional(Type.Array(ChangeObservationPathFilterSchema, {
      minItems: 1,
      maxItems: CHANGE_OBSERVATION_LIMITS.maxPathFilterCount,
      uniqueItems: true,
    })),
    budget: Type.Optional(ChangeObservationBudgetOverrideSchema),
  },
  { additionalProperties: false },
);
export type ChangeObservationInput = Static<typeof ChangeObservationInputSchema>;

/** The sole non-Capability branch admitted by autovul_research in v1. */
export const ChangeObservationServiceRequestSchema = Type.Object(
  {
    action: Type.Literal("execute"),
    service: Type.Literal(CHANGE_OBSERVATION_SERVICE),
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    input: ChangeObservationInputSchema,
  },
  { additionalProperties: false },
);
export type ChangeObservationServiceRequest = Static<typeof ChangeObservationServiceRequestSchema>;

export const ChangeObservationLocationSchema = Type.Object(
  {
    path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength }),
    start_line: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    end_line: Type.Optional(Type.Integer({ minimum: 1, maximum: 2_147_483_647 })),
  },
  { additionalProperties: false },
);
export type ChangeObservationLocation = Static<typeof ChangeObservationLocationSchema>;

export const ChangeObservationObjectFormatSchema = Type.Union([Type.Literal("sha1"), Type.Literal("sha256")]);
export type ChangeObservationObjectFormat = Static<typeof ChangeObservationObjectFormatSchema>;

export const ChangeObservationRevisionIdentitySchema = Type.Object(
  {
    object_format: ChangeObservationObjectFormatSchema,
    base_oid: ChangeObservationRevisionSchema,
    head_oid: ChangeObservationRevisionSchema,
    base_tree_oid: ChangeObservationRevisionSchema,
    head_tree_oid: ChangeObservationRevisionSchema,
  },
  { additionalProperties: false },
);
export type ChangeObservationRevisionIdentity = Static<typeof ChangeObservationRevisionIdentitySchema>;

export const ChangeObservationScopeSchema = Type.Object(
  {
    path_filters: Type.Array(ChangeObservationPathFilterSchema, {
      maxItems: CHANGE_OBSERVATION_LIMITS.maxPathFilterCount,
      uniqueItems: true,
    }),
    submodules: Type.Literal("not_included"),
    dirty_worktree: Type.Literal("not_inspected"),
  },
  { additionalProperties: false },
);
export type ChangeObservationScope = Static<typeof ChangeObservationScopeSchema>;

export const ChangeObservationFileChangeKindSchema = Type.Union([
  Type.Literal("added"),
  Type.Literal("deleted"),
  Type.Literal("modified"),
  Type.Literal("renamed"),
  Type.Literal("type_changed"),
]);
export type ChangeObservationFileChangeKind = Static<typeof ChangeObservationFileChangeKindSchema>;

export const ChangeObservationContentKindSchema = Type.Union([
  Type.Literal("text"),
  Type.Literal("binary"),
  Type.Literal("unavailable"),
]);
export type ChangeObservationContentKind = Static<typeof ChangeObservationContentKindSchema>;

const ChangeObservationNonRenameFileSchema = Type.Object(
  {
    path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength }),
    change_kind: Type.Union([
      Type.Literal("added"),
      Type.Literal("deleted"),
      Type.Literal("modified"),
      Type.Literal("type_changed"),
    ]),
    content_kind: ChangeObservationContentKindSchema,
  },
  { additionalProperties: false },
);
const ChangeObservationRenameFileSchema = Type.Object(
  {
    path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength }),
    change_kind: Type.Literal("renamed"),
    content_kind: ChangeObservationContentKindSchema,
    previous_path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength }),
  },
  { additionalProperties: false },
);
export const ChangeObservationChangedFileSchema = Type.Union([
  ChangeObservationNonRenameFileSchema,
  ChangeObservationRenameFileSchema,
]);
export type ChangeObservationChangedFile = Static<typeof ChangeObservationChangedFileSchema>;

export const ChangeObservationNormalizedHunkSchema = Type.Object(
  {
    path: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength }),
    ordinal: Type.Integer({ minimum: 0, maximum: CHANGE_OBSERVATION_LIMITS.maxHunks - 1 }),
    old_start: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    old_line_count: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    new_start: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    new_line_count: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    removed_line_count: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    added_line_count: Type.Integer({ minimum: 0, maximum: 2_147_483_647 }),
    normalized_removed_sha256: Type.String({ pattern: SHA256_PATTERN }),
    normalized_added_sha256: Type.String({ pattern: SHA256_PATTERN }),
    truncated: Type.Boolean(),
  },
  { additionalProperties: false },
);
export type ChangeObservationNormalizedHunk = Static<typeof ChangeObservationNormalizedHunkSchema>;

export const ChangeObservationLanguageSchema = Type.Union([Type.Literal("javascript"), Type.Literal("typescript")]);
export type ChangeObservationLanguage = Static<typeof ChangeObservationLanguageSchema>;

export const ChangeObservationSymbolKindSchema = Type.Union([
  Type.Literal("function"),
  Type.Literal("method"),
  Type.Literal("class"),
  Type.Literal("variable"),
]);
export type ChangeObservationSymbolKind = Static<typeof ChangeObservationSymbolKindSchema>;

export const ChangeObservationStructuralChangeKindSchema = Type.Union([
  Type.Literal("added"),
  Type.Literal("removed"),
  Type.Literal("modified"),
]);
export type ChangeObservationStructuralChangeKind = Static<typeof ChangeObservationStructuralChangeKindSchema>;

export const ChangeObservationSymbolSchema = Type.Object(
  {
    change_kind: ChangeObservationStructuralChangeKindSchema,
    symbol_kind: ChangeObservationSymbolKindSchema,
    language: ChangeObservationLanguageSchema,
    name: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxSymbolNameLength }),
    old_location: Type.Optional(ChangeObservationLocationSchema),
    new_location: Type.Optional(ChangeObservationLocationSchema),
  },
  { additionalProperties: false },
);
export type ChangeObservationSymbol = Static<typeof ChangeObservationSymbolSchema>;

export const ChangeObservationSelectorSegmentSchema = Type.String({ pattern: IDENTIFIER_PATTERN, maxLength: CHANGE_OBSERVATION_LIMITS.maxIdentifierLength });
export type ChangeObservationSelectorSegment = Static<typeof ChangeObservationSelectorSegmentSchema>;

export const ChangeObservationSelectorSchema = Type.Array(ChangeObservationSelectorSegmentSchema, {
  minItems: 1,
  maxItems: CHANGE_OBSERVATION_LIMITS.maxSelectorSegments,
});
export type ChangeObservationSelector = Static<typeof ChangeObservationSelectorSchema>;

export const ChangeObservationArgumentChangeKindSchema = Type.Union([
  Type.Literal("none"),
  Type.Literal("count_changed"),
  Type.Literal("positions_changed"),
]);
export type ChangeObservationArgumentChangeKind = Static<typeof ChangeObservationArgumentChangeKindSchema>;

export const ChangeObservationCallChangeSchema = Type.Object(
  {
    change_kind: ChangeObservationStructuralChangeKindSchema,
    callee_selector: ChangeObservationSelectorSchema,
    argument_change_kind: ChangeObservationArgumentChangeKindSchema,
    old_argument_count: Type.Optional(Type.Integer({ minimum: 0, maximum: 256 })),
    new_argument_count: Type.Optional(Type.Integer({ minimum: 0, maximum: 256 })),
    old_location: Type.Optional(ChangeObservationLocationSchema),
    new_location: Type.Optional(ChangeObservationLocationSchema),
  },
  { additionalProperties: false },
);
export type ChangeObservationCallChange = Static<typeof ChangeObservationCallChangeSchema>;

export const ChangeObservationEventKindSchema = Type.Union([
  Type.Literal("direct_call_added"),
  Type.Literal("direct_call_removed"),
  Type.Literal("direct_call_modified"),
]);
export type ChangeObservationEventKind = Static<typeof ChangeObservationEventKindSchema>;

export const ChangeObservationEventChangeSchema = Type.Object(
  {
    event_kind: ChangeObservationEventKindSchema,
    selector: ChangeObservationSelectorSchema,
    location: ChangeObservationLocationSchema,
  },
  { additionalProperties: false },
);
export type ChangeObservationEventChange = Static<typeof ChangeObservationEventChangeSchema>;

export const ChangeObservationCompletenessSchema = Type.Union([
  Type.Literal("complete"),
  Type.Literal("partial"),
  Type.Literal("blocked"),
]);
export type ChangeObservationCompleteness = Static<typeof ChangeObservationCompletenessSchema>;

export const ChangeObservationGapCodeSchema = Type.Union([
  Type.Literal("BASE_REVISION_MISSING"),
  Type.Literal("HEAD_REVISION_MISSING"),
  Type.Literal("SHALLOW_HISTORY"),
  Type.Literal("BINARY_FILE_SKIPPED"),
  Type.Literal("UNDECODABLE_TEXT"),
  Type.Literal("RENAME_AMBIGUOUS"),
  Type.Literal("DIFF_TRUNCATED"),
  Type.Literal("HUNK_LINE_TRUNCATED"),
  Type.Literal("PARSER_UNAVAILABLE"),
  Type.Literal("PARSER_FAILED"),
  Type.Literal("SUBMODULE_SKIPPED"),
  Type.Literal("PATH_FILTER_NO_MATCH"),
]);
export type ChangeObservationGapCode = Static<typeof ChangeObservationGapCodeSchema>;

export const ChangeObservationGapSchema = Type.Object(
  {
    code: ChangeObservationGapCodeSchema,
    path: Type.Optional(Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength })),
    count: Type.Optional(Type.Integer({ minimum: 0, maximum: 2_147_483_647 })),
    parser_or_language: Type.Optional(Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxIdentifierLength })),
  },
  { additionalProperties: false },
);
export type ChangeObservationGap = Static<typeof ChangeObservationGapSchema>;

export const ChangeObservationParserProvenanceSchema = Type.Object(
  {
    language: ChangeObservationLanguageSchema,
    version: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxGitVersionLength }),
  },
  { additionalProperties: false },
);
export type ChangeObservationParserProvenance = Static<typeof ChangeObservationParserProvenanceSchema>;

export const ChangeObservationProvenanceSchema = Type.Object(
  {
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    source: Type.Literal("local_git_object_database"),
    git_version: Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxGitVersionLength }),
    command_profile_version: Type.Literal("autovul.git-change-observation/1"),
    parser_versions: Type.Array(ChangeObservationParserProvenanceSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxParserVersions }),
  },
  { additionalProperties: false },
);
export type ChangeObservationProvenance = Static<typeof ChangeObservationProvenanceSchema>;

export const ChangeObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    revision_identity: ChangeObservationRevisionIdentitySchema,
    scope: ChangeObservationScopeSchema,
    resolved_budget: ChangeObservationBudgetSchema,
    completeness: ChangeObservationCompletenessSchema,
    changed_files: Type.Array(ChangeObservationChangedFileSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxChangedFiles }),
    normalized_hunks: Type.Array(ChangeObservationNormalizedHunkSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxHunks }),
    symbols: Type.Array(ChangeObservationSymbolSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxSymbols }),
    call_changes: Type.Array(ChangeObservationCallChangeSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxCallChanges }),
    event_changes: Type.Array(ChangeObservationEventChangeSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxEventChanges }),
    analysis_gaps: Type.Array(ChangeObservationGapSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount }),
    provenance: ChangeObservationProvenanceSchema,
    request_fingerprint: Type.String({ pattern: SHA256_PATTERN }),
    observation_fingerprint: Type.String({ pattern: SHA256_PATTERN }),
  },
  { additionalProperties: false },
);
export type ChangeObservation = Static<typeof ChangeObservationSchema>;

export const ChangeObservationDiagnosticCodeSchema = Type.Union([
  Type.Literal("CHANGE_OBSERVATION_INVALID_REQUEST"),
  Type.Literal("CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED"),
  Type.Literal("CHANGE_OBSERVATION_REPOSITORY_INVALID"),
  Type.Literal("REVISION_OBJECT_MISSING"),
  Type.Literal("SHALLOW_HISTORY"),
  Type.Literal("CHANGE_OBSERVATION_PATH_FILTER_INVALID"),
  Type.Literal("CHANGE_OBSERVATION_GIT_FAILED"),
  Type.Literal("CHANGE_OBSERVATION_TIMEOUT"),
  Type.Literal("CHANGE_OBSERVATION_CANCELLED"),
  Type.Literal("CHANGE_OBSERVATION_ARTIFACT_MISSING"),
  Type.Literal("CHANGE_OBSERVATION_ARTIFACT_INVALID"),
  Type.Literal("CHANGE_OBSERVATION_ROUTE_UNSUPPORTED"),
  Type.Literal("CHANGE_OBSERVATION_APPLICATION_CLOSING"),
]);
export type ChangeObservationDiagnosticCode = Static<typeof ChangeObservationDiagnosticCodeSchema>;

export const ChangeObservationDiagnosticSchema = Type.Object(
  {
    code: ChangeObservationDiagnosticCodeSchema,
    path: Type.Optional(Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxPathFilterLength })),
    retryable: Type.Boolean(),
    count: Type.Optional(Type.Integer({ minimum: 0, maximum: 2_147_483_647 })),
  },
  { additionalProperties: false },
);
export type ChangeObservationDiagnostic = Static<typeof ChangeObservationDiagnosticSchema>;

export const ChangeObservationOperationStatusSchema = Type.Union([
  Type.Literal("completed"),
  Type.Literal("blocked"),
  Type.Literal("failed"),
  Type.Literal("cancelled"),
]);
export type ChangeObservationOperationStatus = Static<typeof ChangeObservationOperationStatusSchema>;

export const ChangeObservationAllowedNextActionSchema = Type.Union([Type.Literal("replay"), Type.Literal("stop")]);
export type ChangeObservationAllowedNextAction = Static<typeof ChangeObservationAllowedNextActionSchema>;

export const ChangeObservationExecutionResultSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    run_id: RunIdSchema,
    service: Type.Literal(CHANGE_OBSERVATION_SERVICE),
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    operation_status: ChangeObservationOperationStatusSchema,
    observation: Type.Optional(ChangeObservationSchema),
    diagnostics: Type.Array(ChangeObservationDiagnosticSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount }),
    allowed_next_actions: Type.Array(ChangeObservationAllowedNextActionSchema, { maxItems: 2, uniqueItems: true }),
    artifact_ref: Type.Optional(Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxArtifactRefLength })),
    replay_ref: Type.Optional(Type.String({ minLength: 1, maxLength: CHANGE_OBSERVATION_LIMITS.maxArtifactRefLength })),
  },
  { additionalProperties: false },
);
export type ChangeObservationExecutionResult = Static<typeof ChangeObservationExecutionResultSchema>;

export const ChangeObservationRunArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    service: Type.Literal(CHANGE_OBSERVATION_SERVICE),
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    input: ChangeObservationInputSchema,
    operation_status: ChangeObservationOperationStatusSchema,
    observation: Type.Optional(ChangeObservationSchema),
    diagnostics: Type.Array(ChangeObservationDiagnosticSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount }),
  },
  { additionalProperties: false },
);
export type ChangeObservationRunArtifact = Static<typeof ChangeObservationRunArtifactSchema>;

export const ChangeObservationReplayStatusSchema = Type.Union([
  Type.Literal("match"),
  Type.Literal("revision_identity_difference"),
  Type.Literal("request_fingerprint_difference"),
  Type.Literal("version_difference"),
  Type.Literal("semantic_mismatch"),
  Type.Literal("evidence_mutated"),
  Type.Literal("environment_blocked"),
  Type.Literal("cancelled"),
]);
export type ChangeObservationReplayStatus = Static<typeof ChangeObservationReplayStatusSchema>;

export const ChangeObservationReplayComparisonSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    service: Type.Literal(CHANGE_OBSERVATION_SERVICE),
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    status: ChangeObservationReplayStatusSchema,
    recorded_observation_fingerprint: Type.Optional(Type.String({ pattern: SHA256_PATTERN })),
    replay_observation_fingerprint: Type.Optional(Type.String({ pattern: SHA256_PATTERN })),
    diagnostics: Type.Array(ChangeObservationDiagnosticSchema, { maxItems: CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount }),
  },
  { additionalProperties: false },
);
export type ChangeObservationReplayComparison = Static<typeof ChangeObservationReplayComparisonSchema>;
