import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import {
  EnvelopeActionSchema,
  EvidenceOperationModeSchema,
  OperationBudgetSchema,
  OperationStatusSchema,
  TYPESTATE_HYPOTHESIS_VERSION,
  TargetRefSchema,
} from "./research.js";
import { RunIdSchema, VerificationLevelSchema } from "./schemas.js";

export const TYPESTATE_DECISION_POLICY_VERSION = "autovul.typestate.decision/1" as const;

/** Narrow v1 bounds. These are protocol limits, not shared-runtime budgets. */
export const TYPESTATE_LIMITS = {
  maxStates: 4,
  maxEvents: 4,
  maxTransitions: 8,
  maxTraceEvents: 8,
  maxLocationsPerItem: 4,
  maxIdentityEvidence: 8,
  maxCapabilityGaps: 16,
  maxEvidenceRefs: 32,
  maxAllowedValues: 32,
  maxLimitations: 8,
  maxIssueCount: 64,
  maxActions: 4,
  maxRevisionHints: 8,
  maxCompactObservations: 16,
  maxIdentifierLength: 128,
  maxSelectorTextLength: 160,
  maxFileLength: 1_024,
  maxIdempotencyKeyLength: 256,
} as const;

const ID_PATTERN = "^[a-z0-9][a-z0-9._-]{2,127}$";
const LIMITATION_VALUES = [
  "cross_file_aliases_excluded",
  "indirect_calls_excluded",
  "reflection_excluded",
  "dynamic_dispatch_excluded",
  "framework_callbacks_excluded",
  "concurrency_excluded",
  "helper_semantics_excluded",
] as const;

export const TypestateIdentifierSchema = Type.String({ pattern: ID_PATTERN, maxLength: TYPESTATE_LIMITS.maxIdentifierLength });
export type TypestateIdentifier = Static<typeof TypestateIdentifierSchema>;

export const TypestateLocationRefSchema = Type.Object(
  {
    file: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
    start_line: Type.Integer({ minimum: 1 }),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type TypestateLocationRef = Static<typeof TypestateLocationRefSchema>;

export const TypestateDirectCallSelectorSchema = Type.Object(
  {
    kind: Type.Literal("direct_call"),
    name: Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$.-]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    argument_property: Type.Optional(Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$-]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength })),
  },
  { additionalProperties: false },
);
export type TypestateDirectCallSelector = Static<typeof TypestateDirectCallSelectorSchema>;

export const TypestateDirectMethodSelectorSchema = Type.Object(
  {
    kind: Type.Literal("direct_method"),
    receiver: Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$.-]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    name: Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$.-]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
  },
  { additionalProperties: false },
);
export type TypestateDirectMethodSelector = Static<typeof TypestateDirectMethodSelectorSchema>;

export const TypestateEventSelectorSchema = Type.Union([
  TypestateDirectCallSelectorSchema,
  TypestateDirectMethodSelectorSchema,
]);
export type TypestateEventSelector = Static<typeof TypestateEventSelectorSchema>;

export const TypestateResourceSchema = Type.Object(
  {
    id: TypestateIdentifierSchema,
    kind: Type.Literal("local_binding"),
    binding_name: Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    acquisition_event: TypestateIdentifierSchema,
    identity_model: Type.Literal("direct_lexical_binding"),
  },
  { additionalProperties: false },
);
export type TypestateResource = Static<typeof TypestateResourceSchema>;

export const TypestateStateSchema = TypestateIdentifierSchema;
export type TypestateState = Static<typeof TypestateStateSchema>;

export const TypestateEventSchema = Type.Object(
  {
    id: TypestateIdentifierSchema,
    selector: TypestateEventSelectorSchema,
  },
  { additionalProperties: false },
);
export type TypestateEvent = Static<typeof TypestateEventSchema>;

export const TypestateTransitionSchema = Type.Object(
  {
    from_state: TypestateStateSchema,
    event: TypestateIdentifierSchema,
    to_state: TypestateStateSchema,
  },
  { additionalProperties: false },
);
export type TypestateTransition = Static<typeof TypestateTransitionSchema>;

export const TypestateViolationSchema = Type.Object(
  {
    kind: Type.Literal("prohibited_transition"),
    from_state: TypestateStateSchema,
    event: TypestateIdentifierSchema,
    to_state: TypestateStateSchema,
    requires_same_identity: Type.Literal(true),
  },
  { additionalProperties: false },
);
export type TypestateViolation = Static<typeof TypestateViolationSchema>;

export const TypestateAnalysisScopeSchema = Type.Object(
  {
    kind: Type.Literal("single_file_named_function"),
    file: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
    entry: Type.Object(
      {
        kind: Type.Literal("named_function"),
        name: Type.String({ pattern: "^[A-Za-z_$][A-Za-z0-9_$.-]{0,159}$", maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
      },
      { additionalProperties: false },
    ),
    event_scope: Type.Literal("named_function_including_inline_callbacks"),
    alias_boundary: Type.Literal("direct_lexical_binding"),
  },
  { additionalProperties: false },
);
export type TypestateAnalysisScope = Static<typeof TypestateAnalysisScopeSchema>;

export const TypestateHypothesisSchema = Type.Object(
  {
    schema_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    hypothesis_id: TypestateIdentifierSchema,
    language: Type.Literal("javascript"),
    resource: TypestateResourceSchema,
    initial_state: TypestateStateSchema,
    states: Type.Array(TypestateStateSchema, { minItems: 2, maxItems: TYPESTATE_LIMITS.maxStates, uniqueItems: true }),
    events: Type.Array(TypestateEventSchema, { minItems: 1, maxItems: TYPESTATE_LIMITS.maxEvents }),
    transitions: Type.Array(TypestateTransitionSchema, { minItems: 1, maxItems: TYPESTATE_LIMITS.maxTransitions }),
    violation: TypestateViolationSchema,
    analysis_scope: TypestateAnalysisScopeSchema,
  },
  { additionalProperties: false },
);
export type TypestateHypothesis = Static<typeof TypestateHypothesisSchema>;

export const TypestateValidationIssueSchema = Type.Object(
  {
    code: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    path: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
    allowed_values: Type.Optional(Type.Array(Type.Union([Type.String({ maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }), Type.Boolean()]), { maxItems: TYPESTATE_LIMITS.maxAllowedValues })),
    expected_kind: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxSelectorTextLength })),
  },
  { additionalProperties: false },
);
export type TypestateValidationIssue = Static<typeof TypestateValidationIssueSchema>;

export const TypestateValidationResultSchema = Type.Object(
  {
    valid: Type.Boolean(),
    hypothesis: Type.Optional(TypestateHypothesisSchema),
    issues: Type.Array(TypestateValidationIssueSchema, { maxItems: TYPESTATE_LIMITS.maxIssueCount }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: TYPESTATE_LIMITS.maxActions }),
  },
  { additionalProperties: false },
);
export type TypestateValidationResult = Static<typeof TypestateValidationResultSchema>;

export const TypestateObservationStateSchema = Type.Union([
  Type.Literal("observed"),
  Type.Literal("not_found"),
  Type.Literal("not_run"),
]);
export type TypestateObservationState = Static<typeof TypestateObservationStateSchema>;

export const TypestateResourceObservationSchema = Type.Object(
  {
    state: TypestateObservationStateSchema,
    locations: Type.Array(TypestateLocationRefSchema, { maxItems: TYPESTATE_LIMITS.maxLocationsPerItem }),
    identity_evidence: Type.Array(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }), { maxItems: TYPESTATE_LIMITS.maxIdentityEvidence }),
  },
  { additionalProperties: false },
);
export type TypestateResourceObservation = Static<typeof TypestateResourceObservationSchema>;

export const TypestateEventObservationSchema = Type.Object(
  {
    event_id: TypestateIdentifierSchema,
    state: TypestateObservationStateSchema,
    locations: Type.Array(TypestateLocationRefSchema, { maxItems: TYPESTATE_LIMITS.maxLocationsPerItem }),
  },
  { additionalProperties: false },
);
export type TypestateEventObservation = Static<typeof TypestateEventObservationSchema>;

export const TypestateIdentityEvidenceSchema = Type.Object(
  {
    kind: Type.Union([
      Type.Literal("same_binding"),
      Type.Literal("identity_change"),
      Type.Literal("direct_selector"),
    ]),
    resource_id: TypestateIdentifierSchema,
    event_ids: Type.Array(TypestateIdentifierSchema, { maxItems: TYPESTATE_LIMITS.maxTraceEvents }),
    locations: Type.Array(TypestateLocationRefSchema, { maxItems: TYPESTATE_LIMITS.maxLocationsPerItem }),
  },
  { additionalProperties: false },
);
export type TypestateIdentityEvidence = Static<typeof TypestateIdentityEvidenceSchema>;

export const TypestateTraceEventSchema = Type.Object(
  {
    event_id: TypestateIdentifierSchema,
    from_state: TypestateStateSchema,
    to_state: TypestateStateSchema,
    location: Type.Optional(TypestateLocationRefSchema),
  },
  { additionalProperties: false },
);
export type TypestateTraceEvent = Static<typeof TypestateTraceEventSchema>;

export const TypestateTraceStateSchema = Type.Union([
  Type.Literal("violating_witness"),
  Type.Literal("safe_trace"),
  Type.Literal("inconclusive"),
  Type.Literal("not_run"),
]);
export type TypestateTraceState = Static<typeof TypestateTraceStateSchema>;

export const TypestateTraceSchema = Type.Object(
  {
    state: TypestateTraceStateSchema,
    resource_id: TypestateIdentifierSchema,
    events: Type.Array(TypestateTraceEventSchema, { maxItems: TYPESTATE_LIMITS.maxTraceEvents }),
    identity_evidence: Type.Array(TypestateIdentityEvidenceSchema, { maxItems: TYPESTATE_LIMITS.maxIdentityEvidence }),
    violation_step: Type.Optional(Type.Integer({ minimum: 0, maximum: TYPESTATE_LIMITS.maxTraceEvents - 1 })),
    evidence_ref: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
  },
  { additionalProperties: false },
);
export type TypestateTrace = Static<typeof TypestateTraceSchema>;

export const TypestateCompletenessStatusSchema = Type.Union([
  Type.Literal("complete"),
  Type.Literal("incomplete"),
  Type.Literal("not_run"),
]);
export type TypestateCompletenessStatus = Static<typeof TypestateCompletenessStatusSchema>;

export const TypestateCompletenessBoundarySchema = Type.Object(
  {
    status: TypestateCompletenessStatusSchema,
    scope: TypestateAnalysisScopeSchema,
    limitations: Type.Array(Type.Union(LIMITATION_VALUES.map((value) => Type.Literal(value)) as [ReturnType<typeof Type.Literal>, ...ReturnType<typeof Type.Literal>[]]), { maxItems: TYPESTATE_LIMITS.maxLimitations, uniqueItems: true }),
  },
  { additionalProperties: false },
);
export type TypestateCompletenessBoundary = Static<typeof TypestateCompletenessBoundarySchema>;

export const TypestateCapabilityGapSchema = Type.Object(
  {
    code: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    path: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
  },
  { additionalProperties: false },
);
export type TypestateCapabilityGap = Static<typeof TypestateCapabilityGapSchema>;

export const TypestateAnalyzerProvenanceSchema = Type.Object(
  {
    analyzer_id: Type.Literal("codeql"),
    available: Type.Boolean(),
    evidence_kind: Type.Union([Type.Literal("real_analyzer"), Type.Literal("test_double")]),
    version: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength })),
    adapter_version: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength })),
  },
  { additionalProperties: false },
);
export type TypestateAnalyzerProvenance = Static<typeof TypestateAnalyzerProvenanceSchema>;

export const TypestateAnalyzerObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    compile_accepted: Type.Union([Type.Boolean(), Type.Literal("not_run")]),
    resource: TypestateResourceObservationSchema,
    events: Type.Array(TypestateEventObservationSchema, { maxItems: TYPESTATE_LIMITS.maxEvents }),
    traces: Type.Array(TypestateTraceSchema, { maxItems: TYPESTATE_LIMITS.maxTraceEvents }),
    fixed_resource: Type.Optional(TypestateResourceObservationSchema),
    fixed_events: Type.Optional(Type.Array(TypestateEventObservationSchema, { maxItems: TYPESTATE_LIMITS.maxEvents })),
    fixed_traces: Type.Optional(Type.Array(TypestateTraceSchema, { maxItems: TYPESTATE_LIMITS.maxTraceEvents })),
    completeness: Type.Object(
      {
        vulnerable: TypestateCompletenessBoundarySchema,
        fixed: Type.Optional(TypestateCompletenessBoundarySchema),
      },
      { additionalProperties: false },
    ),
    capability_gaps: Type.Array(TypestateCapabilityGapSchema, { maxItems: TYPESTATE_LIMITS.maxCapabilityGaps }),
    evidence_refs: Type.Array(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }), { maxItems: TYPESTATE_LIMITS.maxEvidenceRefs }),
    analyzer: TypestateAnalyzerProvenanceSchema,
  },
  { additionalProperties: false },
);
export type TypestateAnalyzerObservation = Static<typeof TypestateAnalyzerObservationSchema>;

export const TypestateOutcomeSchema = Type.Union([
  Type.Literal("violation_observed"),
  Type.Literal("no_violation_observed"),
  Type.Literal("unknown"),
]);
export type TypestateOutcome = Static<typeof TypestateOutcomeSchema>;

export const TypestateDecisionSchema = Type.Object(
  {
    capability: Type.Literal("typestate"),
    outcome: TypestateOutcomeSchema,
    fixed_outcome: Type.Optional(TypestateOutcomeSchema),
    fixed_policy_satisfied: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type TypestateDecision = Static<typeof TypestateDecisionSchema>;

export const TypestateRevisionHintActionSchema = Type.Union([
  Type.Literal("revise_resource"),
  Type.Literal("revise_event"),
  Type.Literal("revise_transition"),
  Type.Literal("revise_violation"),
  Type.Literal("revise_scope"),
]);
export type TypestateRevisionHintAction = Static<typeof TypestateRevisionHintActionSchema>;

export const TypestateRevisionHintSchema = Type.Object(
  {
    action: TypestateRevisionHintActionSchema,
    path: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
    reason_code: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
  },
  { additionalProperties: false },
);
export type TypestateRevisionHint = Static<typeof TypestateRevisionHintSchema>;

export const TypestateCompactObservationSchema = Type.Object(
  {
    code: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxSelectorTextLength }),
    path: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength })),
    locations: Type.Optional(Type.Array(TypestateLocationRefSchema, { maxItems: TYPESTATE_LIMITS.maxLocationsPerItem })),
    evidence_ref: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength })),
  },
  { additionalProperties: false },
);
export type TypestateCompactObservation = Static<typeof TypestateCompactObservationSchema>;

export const TypestateExecutionResultSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    run_id: RunIdSchema,
    operation_status: OperationStatusSchema,
    capability: Type.Literal("typestate"),
    decision: TypestateDecisionSchema,
    verification_level: VerificationLevelSchema,
    observations: Type.Array(TypestateCompactObservationSchema, { maxItems: TYPESTATE_LIMITS.maxCompactObservations }),
    revision_hints: Type.Array(TypestateRevisionHintSchema, { maxItems: TYPESTATE_LIMITS.maxRevisionHints }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: TYPESTATE_LIMITS.maxActions }),
    budget_remaining: Type.Optional(OperationBudgetSchema),
    artifact_ref: Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxFileLength }),
  },
  { additionalProperties: false },
);
export type TypestateExecutionResult = Static<typeof TypestateExecutionResultSchema>;

export const TypestateResearchToolInputSchema = Type.Object(
  {
    action: Type.Union([Type.Literal("validate"), Type.Literal("execute")]),
    capability: Type.Literal("typestate"),
    hypothesis_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
    target: Type.Optional(Type.Object({ vulnerable: TargetRefSchema, fixed: Type.Optional(TargetRefSchema) }, { additionalProperties: false })),
    analyzer_id: Type.Optional(Type.Literal("codeql")),
    mode: Type.Optional(EvidenceOperationModeSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxIdempotencyKeyLength })),
  },
  { additionalProperties: false },
);
export type TypestateResearchToolInput = Static<typeof TypestateResearchToolInputSchema>;

export const TypestateRunArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    capability: Type.Literal("typestate"),
    hypothesis_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    hypothesis: TypestateHypothesisSchema,
    target: Type.Object({ vulnerable: TargetRefSchema, fixed: Type.Optional(TargetRefSchema) }, { additionalProperties: false }),
    mode: EvidenceOperationModeSchema,
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: TYPESTATE_LIMITS.maxIdempotencyKeyLength })),
    analyzer: TypestateAnalyzerProvenanceSchema,
    target_fingerprints: Type.Optional(Type.Object(
      {
        vulnerable: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        fixed: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
      },
      { additionalProperties: false },
    )),
    observation: Type.Optional(TypestateAnalyzerObservationSchema),
    decision_policy_version: Type.Optional(Type.Literal(TYPESTATE_DECISION_POLICY_VERSION)),
    operation_status: OperationStatusSchema,
    decision: TypestateDecisionSchema,
    verification_level: VerificationLevelSchema,
    observations: Type.Array(TypestateCompactObservationSchema, { maxItems: TYPESTATE_LIMITS.maxCompactObservations }),
    revision_hints: Type.Array(TypestateRevisionHintSchema, { maxItems: TYPESTATE_LIMITS.maxRevisionHints }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: TYPESTATE_LIMITS.maxActions }),
    budget_remaining: Type.Optional(OperationBudgetSchema),
  },
  { additionalProperties: false },
);
export type TypestateRunArtifact = Static<typeof TypestateRunArtifactSchema>;

export const TypestateReplayComparisonSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    capability: Type.Literal("typestate"),
    status: Type.Union([
      Type.Literal("match"),
      Type.Literal("environment_blocked"),
      Type.Literal("version_difference"),
      Type.Literal("semantic_mismatch"),
      Type.Literal("cancelled"),
    ]),
    recorded_decision: TypestateDecisionSchema,
    replay_decision: Type.Optional(TypestateDecisionSchema),
    observations: Type.Array(TypestateCompactObservationSchema, { maxItems: TYPESTATE_LIMITS.maxCompactObservations }),
  },
  { additionalProperties: false },
);
export type TypestateReplayComparison = Static<typeof TypestateReplayComparisonSchema>;

export { LIMITATION_VALUES as TYPESTATE_COMPLETENESS_LIMITATION_VALUES };
