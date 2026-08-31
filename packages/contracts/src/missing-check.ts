import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import {
  EnvelopeActionSchema,
  EvidenceOperationModeSchema,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  OperationBudgetSchema,
  OperationStatusSchema,
  TargetRefSchema,
} from "./research.js";
import { RunIdSchema, VerificationLevelSchema } from "./schemas.js";

export { MISSING_CHECK_HYPOTHESIS_VERSION } from "./research.js";
export const MISSING_CHECK_DECISION_POLICY_VERSION = "autovul.missing-check.decision/1" as const;

export const MissingCheckSelectorSchema = Type.Object(
  { kind: Type.Literal("direct_call"), name: Type.String({ minLength: 1, maxLength: 160 }) },
  { additionalProperties: false },
);
export type MissingCheckSelector = Static<typeof MissingCheckSelectorSchema>;

export const MissingCheckRelationSchema = Type.Literal("same_callback_cfg_dominates_operation");
export type MissingCheckRelation = Static<typeof MissingCheckRelationSchema>;

export const MissingCheckScopeSchema = Type.Object(
  {
    kind: Type.Literal("single_file_named_entry_cfg"),
    file: Type.String({ minLength: 1, maxLength: 1_024 }),
    entry: Type.Object(
      {
        kind: Type.Literal("named_function"),
        name: Type.String({ minLength: 1, maxLength: 160 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type MissingCheckScope = Static<typeof MissingCheckScopeSchema>;

export const MissingCheckHypothesisSchema = Type.Object(
  {
    schema_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    hypothesis_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: Type.Literal("javascript"),
    operation: MissingCheckSelectorSchema,
    required_check: MissingCheckSelectorSchema,
    required_relation: MissingCheckRelationSchema,
    scope: MissingCheckScopeSchema,
  },
  { additionalProperties: false },
);
export type MissingCheckHypothesis = Static<typeof MissingCheckHypothesisSchema>;

export const MissingCheckValidationIssueSchema = Type.Object(
  {
    code: Type.String({ minLength: 1 }),
    path: Type.String({ minLength: 1 }),
    allowed_values: Type.Optional(Type.Array(Type.Unknown(), { maxItems: 32 })),
    expected_kind: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type MissingCheckValidationIssue = Static<typeof MissingCheckValidationIssueSchema>;

export const MissingCheckValidationResultSchema = Type.Object(
  {
    valid: Type.Boolean(),
    hypothesis: Type.Optional(MissingCheckHypothesisSchema),
    issues: Type.Array(MissingCheckValidationIssueSchema, { maxItems: 64 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }),
  },
  { additionalProperties: false },
);
export type MissingCheckValidationResult = Static<typeof MissingCheckValidationResultSchema>;

export const MissingCheckLocationRefSchema = Type.Object(
  {
    file: Type.String({ minLength: 1 }),
    start_line: Type.Integer({ minimum: 1 }),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type MissingCheckLocationRef = Static<typeof MissingCheckLocationRefSchema>;

export const MissingCheckObservationStateSchema = Type.Union([
  Type.Literal("observed"), Type.Literal("not_found"), Type.Literal("not_run"),
]);
export type MissingCheckObservationState = Static<typeof MissingCheckObservationStateSchema>;

export const MissingCheckSubjectObservationSchema = Type.Object(
  {
    state: MissingCheckObservationStateSchema,
    locations: Type.Array(MissingCheckLocationRefSchema, { maxItems: 16 }),
  },
  { additionalProperties: false },
);
export type MissingCheckSubjectObservation = Static<typeof MissingCheckSubjectObservationSchema>;

export const MissingCheckRelationStateSchema = Type.Union([
  Type.Literal("unchecked_witness"),
  Type.Literal("checked_witness"),
  Type.Literal("inconclusive"),
  Type.Literal("not_run"),
]);
export type MissingCheckRelationState = Static<typeof MissingCheckRelationStateSchema>;

export const MissingCheckWitnessSchema = Type.Object(
  {
    operation: MissingCheckLocationRefSchema,
    check: Type.Optional(MissingCheckLocationRefSchema),
    evidence_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type MissingCheckWitness = Static<typeof MissingCheckWitnessSchema>;

export const MissingCheckRelationObservationSchema = Type.Object(
  {
    state: MissingCheckRelationStateSchema,
    unchecked_witnesses: Type.Array(MissingCheckWitnessSchema, { maxItems: 16 }),
    checked_witnesses: Type.Array(MissingCheckWitnessSchema, { maxItems: 16 }),
  },
  { additionalProperties: false },
);
export type MissingCheckRelationObservation = Static<typeof MissingCheckRelationObservationSchema>;

export const MissingCheckCapabilityGapSchema = Type.Object(
  { code: Type.String({ minLength: 1 }), path: Type.String({ minLength: 1 }) },
  { additionalProperties: false },
);
export type MissingCheckCapabilityGap = Static<typeof MissingCheckCapabilityGapSchema>;

export const MissingCheckAnalyzerProvenanceSchema = Type.Object(
  {
    analyzer_id: Type.Literal("codeql"),
    available: Type.Boolean(),
    evidence_kind: Type.Union([Type.Literal("real_analyzer"), Type.Literal("test_double")]),
    version: Type.Optional(Type.String({ minLength: 1 })),
    adapter_version: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type MissingCheckAnalyzerProvenance = Static<typeof MissingCheckAnalyzerProvenanceSchema>;

export const MissingCheckCompletenessStatusSchema = Type.Union([
  Type.Literal("complete"), Type.Literal("incomplete"), Type.Literal("not_run"),
]);
export type MissingCheckCompletenessStatus = Static<typeof MissingCheckCompletenessStatusSchema>;

export const MissingCheckCompletenessBoundarySchema = Type.Object(
  {
    status: MissingCheckCompletenessStatusSchema,
    scope: MissingCheckScopeSchema,
    limitations: Type.Array(Type.Union([
      Type.Literal("cross_file_aliases_excluded"),
      Type.Literal("indirect_calls_excluded"),
      Type.Literal("dynamic_dispatch_excluded"),
      Type.Literal("helper_semantics_excluded"),
    ]), { maxItems: 8, uniqueItems: true }),
  },
  { additionalProperties: false },
);
export type MissingCheckCompletenessBoundary = Static<typeof MissingCheckCompletenessBoundarySchema>;

export const MissingCheckAnalyzerObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    compile_accepted: Type.Union([Type.Boolean(), Type.Literal("not_run")]),
    operation: MissingCheckSubjectObservationSchema,
    required_check: MissingCheckSubjectObservationSchema,
    relation: MissingCheckRelationObservationSchema,
    fixed_relation: Type.Optional(MissingCheckRelationObservationSchema),
    completeness: Type.Object(
      {
        vulnerable: MissingCheckCompletenessBoundarySchema,
        fixed: Type.Optional(MissingCheckCompletenessBoundarySchema),
      },
      { additionalProperties: false },
    ),
    capability_gaps: Type.Array(MissingCheckCapabilityGapSchema, { maxItems: 16 }),
    evidence_refs: Type.Array(Type.String({ minLength: 1 }), { maxItems: 32 }),
    analyzer: MissingCheckAnalyzerProvenanceSchema,
  },
  { additionalProperties: false },
);
export type MissingCheckAnalyzerObservation = Static<typeof MissingCheckAnalyzerObservationSchema>;

export const MissingCheckOutcomeSchema = Type.Union([
  Type.Literal("check_missing"), Type.Literal("check_present"), Type.Literal("unknown"),
]);
export type MissingCheckOutcome = Static<typeof MissingCheckOutcomeSchema>;

export const MissingCheckDecisionSchema = Type.Object(
  {
    capability: Type.Literal("missing_check"),
    outcome: MissingCheckOutcomeSchema,
    fixed_outcome: Type.Optional(MissingCheckOutcomeSchema),
    fixed_policy_satisfied: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type MissingCheckDecision = Static<typeof MissingCheckDecisionSchema>;

export const MissingCheckRevisionHintActionSchema = Type.Union([
  Type.Literal("revise_operation"), Type.Literal("revise_check"),
  Type.Literal("revise_relation"), Type.Literal("revise_scope"),
]);
export type MissingCheckRevisionHintAction = Static<typeof MissingCheckRevisionHintActionSchema>;

export const MissingCheckRevisionHintSchema = Type.Object(
  {
    action: MissingCheckRevisionHintActionSchema,
    path: Type.String({ minLength: 1 }),
    reason_code: Type.String({ minLength: 1 }),
    constraints: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
  },
  { additionalProperties: false },
);
export type MissingCheckRevisionHint = Static<typeof MissingCheckRevisionHintSchema>;

export const MissingCheckCompactObservationSchema = Type.Object(
  {
    code: Type.String({ minLength: 1 }),
    path: Type.Optional(Type.String({ minLength: 1 })),
    locations: Type.Optional(Type.Array(MissingCheckLocationRefSchema, { maxItems: 8 })),
    evidence_ref: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type MissingCheckCompactObservation = Static<typeof MissingCheckCompactObservationSchema>;

export const MissingCheckExecutionResultSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION), run_id: RunIdSchema,
    operation_status: OperationStatusSchema, capability: Type.Literal("missing_check"),
    decision: MissingCheckDecisionSchema, verification_level: VerificationLevelSchema,
    observations: Type.Array(MissingCheckCompactObservationSchema, { maxItems: 16 }),
    revision_hints: Type.Array(MissingCheckRevisionHintSchema, { maxItems: 8 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }),
    budget_remaining: Type.Optional(OperationBudgetSchema), artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type MissingCheckExecutionResult = Static<typeof MissingCheckExecutionResultSchema>;

export const MissingCheckRunArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION), capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION), hypothesis: MissingCheckHypothesisSchema,
    target: Type.Object({ vulnerable: TargetRefSchema, fixed: Type.Optional(TargetRefSchema) }, { additionalProperties: false }),
    mode: EvidenceOperationModeSchema, budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1 })), analyzer: MissingCheckAnalyzerProvenanceSchema,
    target_fingerprints: Type.Optional(Type.Object(
      {
        vulnerable: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        fixed: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
      },
      { additionalProperties: false },
    )),
    observation: Type.Optional(MissingCheckAnalyzerObservationSchema), decision_policy_version: Type.Optional(Type.String({ minLength: 1 })),
    operation_status: OperationStatusSchema, decision: MissingCheckDecisionSchema, verification_level: VerificationLevelSchema,
    observations: Type.Array(MissingCheckCompactObservationSchema, { maxItems: 16 }), revision_hints: Type.Array(MissingCheckRevisionHintSchema, { maxItems: 8 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }), budget_remaining: Type.Optional(OperationBudgetSchema),
  },
  { additionalProperties: false },
);
export type MissingCheckRunArtifact = Static<typeof MissingCheckRunArtifactSchema>;
