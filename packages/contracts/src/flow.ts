import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";
import { LanguageFamilySchema, TaintFlowModeSchema } from "./m3.js";
import {
  EnvelopeActionSchema,
  EvidenceOperationModeSchema,
  FLOW_HYPOTHESIS_VERSION,
  OperationBudgetSchema,
  OperationStatusSchema,
  ResearchActionSchema,
  ResearchCapabilitySchema,
  TargetRefSchema,
  type TargetRef,
} from "./research.js";
import { RunIdSchema, VerificationLevelSchema } from "./schemas.js";

export { FLOW_HYPOTHESIS_VERSION } from "./research.js";
export const FLOW_DECISION_POLICY_VERSION = "autovul.flow.decision/1" as const;

export const FlowRevisionHintActionSchema = Type.Union([
  Type.Literal("revise_source"),
  Type.Literal("revise_sink"),
  Type.Literal("revise_step"),
  Type.Literal("revise_barrier"),
  Type.Literal("probe_source"),
  Type.Literal("probe_sink"),
]);
export type FlowRevisionHintAction = Static<typeof FlowRevisionHintActionSchema>;

export const FlowOutcomeSchema = Type.Union([
  Type.Literal("connected"),
  Type.Literal("no_path"),
  Type.Literal("unknown"),
]);
export type FlowOutcome = Static<typeof FlowOutcomeSchema>;

export const ObservationRunStateSchema = Type.Union([
  Type.Literal("observed"),
  Type.Literal("not_found"),
  Type.Literal("not_run"),
]);
export type ObservationRunState = Static<typeof ObservationRunStateSchema>;

export const PathObservationStateSchema = Type.Union([
  Type.Literal("observed"),
  Type.Literal("not_observed"),
  Type.Literal("not_run"),
]);
export type PathObservationState = Static<typeof PathObservationStateSchema>;

const endpointSelectors = {
  module: Type.Optional(Type.String({ minLength: 1 })),
  type: Type.Optional(Type.String({ minLength: 1 })),
  member: Type.Optional(Type.String({ minLength: 1 })),
  name: Type.Optional(Type.String({ minLength: 1 })),
  argument_index: Type.Optional(Type.Integer({ minimum: 0 })),
  argument_name: Type.Optional(Type.String({ minLength: 1 })),
  keyword_name: Type.Optional(Type.String({ minLength: 1 })),
  keyword_value: Type.Optional(Type.Union([Type.Boolean(), Type.Number(), Type.String()])),
  property: Type.Optional(Type.String({ minLength: 1 })),
  file: Type.Optional(Type.String({ minLength: 1 })),
  symbol: Type.Optional(Type.String({ minLength: 1 })),
  line: Type.Optional(Type.Integer({ minimum: 1 })),
  start_line: Type.Optional(Type.Integer({ minimum: 1 })),
  end_line: Type.Optional(Type.Integer({ minimum: 1 })),
};

export const FlowEndpointSchema = Type.Union([
  Type.Object({ kind: Type.Literal("call"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("call_argument"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("constructor"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("function"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("parameter"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("environment"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("property"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("array_index"), ...endpointSelectors }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("array_element"), ...endpointSelectors }, { additionalProperties: false }),
]);
export type FlowEndpoint = Static<typeof FlowEndpointSchema>;

export const FlowStepSchema = Type.Object(
  { from: FlowEndpointSchema, to: FlowEndpointSchema },
  { additionalProperties: false },
);
export type FlowStep = Static<typeof FlowStepSchema>;

export const FlowBarrierSchema = Type.Object(
  { endpoint: FlowEndpointSchema },
  { additionalProperties: false },
);
export type FlowBarrier = Static<typeof FlowBarrierSchema>;

export const FlowModelSchema = Type.Object(
  {
    schema_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    model_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: LanguageFamilySchema,
    flow_mode: TaintFlowModeSchema,
    source: FlowEndpointSchema,
    sink: FlowEndpointSchema,
    steps: Type.Optional(Type.Array(FlowStepSchema, { maxItems: 16 })),
    barriers: Type.Optional(Type.Array(FlowBarrierSchema, { maxItems: 8 })),
  },
  { additionalProperties: false },
);
export type FlowModel = Static<typeof FlowModelSchema>;

export const FlowValidationIssueSchema = Type.Object(
  {
    code: Type.String({ minLength: 1 }),
    path: Type.String({ minLength: 1 }),
    allowed_values: Type.Optional(Type.Array(Type.Unknown(), { maxItems: 32 })),
    expected_kind: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type FlowValidationIssue = Static<typeof FlowValidationIssueSchema>;

export const FlowValidationResultSchema = Type.Object(
  {
    valid: Type.Boolean(),
    model: Type.Optional(FlowModelSchema),
    issues: Type.Array(FlowValidationIssueSchema, { maxItems: 64 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }),
  },
  { additionalProperties: false },
);
export type FlowValidationResult = Static<typeof FlowValidationResultSchema>;

export { TargetRefSchema } from "./research.js";
export type { TargetRef } from "./research.js";

const PathCountExpectationSchema = Type.Object(
  {
    min_paths: Type.Integer({ minimum: 0, maximum: 10_000 }),
    max_paths: Type.Integer({ minimum: 0, maximum: 10_000 }),
  },
  { additionalProperties: false },
);

export const FlowExpectationSchema = Type.Object(
  {
    vulnerable: Type.Object(
      {
        min_paths: Type.Integer({ minimum: 1, maximum: 10_000 }),
        max_paths: Type.Integer({ minimum: 1, maximum: 10_000 }),
      },
      { additionalProperties: false },
    ),
    fixed: Type.Optional(PathCountExpectationSchema),
  },
  { additionalProperties: false },
);
export type FlowExpectation = Static<typeof FlowExpectationSchema>;

export const FlowLocationRefSchema = Type.Object(
  {
    file: Type.String({ minLength: 1 }),
    start_line: Type.Integer({ minimum: 1 }),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type FlowLocationRef = Static<typeof FlowLocationRefSchema>;

export const EndpointObservationSchema = Type.Object(
  {
    state: ObservationRunStateSchema,
    locations: Type.Array(FlowLocationRefSchema, { maxItems: 16 }),
  },
  { additionalProperties: false },
);
export type EndpointObservation = Static<typeof EndpointObservationSchema>;

export const PathObservationSchema = Type.Object(
  {
    state: PathObservationStateSchema,
    path_count: Type.Integer({ minimum: 0, maximum: 10_000 }),
  },
  { additionalProperties: false },
);
export type PathObservation = Static<typeof PathObservationSchema>;

export const FlowCapabilityGapSchema = Type.Object(
  {
    code: Type.String({ minLength: 1 }),
    path: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type FlowCapabilityGap = Static<typeof FlowCapabilityGapSchema>;

export const FlowAnalyzerProvenanceSchema = Type.Object(
  {
    analyzer_id: Type.Literal("codeql"),
    available: Type.Boolean(),
    version: Type.Optional(Type.String({ minLength: 1 })),
    adapter_version: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type FlowAnalyzerProvenance = Static<typeof FlowAnalyzerProvenanceSchema>;

export const CompileAcceptanceSchema = Type.Union([Type.Boolean(), Type.Literal("not_run")]);
export type CompileAcceptance = Static<typeof CompileAcceptanceSchema>;

export const FlowAnalyzerObservationSchema = Type.Object(
  {
    schema_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    compile_accepted: CompileAcceptanceSchema,
    source: EndpointObservationSchema,
    sink: EndpointObservationSchema,
    path: PathObservationSchema,
    fixed_path: Type.Optional(PathObservationSchema),
    capability_gaps: Type.Array(FlowCapabilityGapSchema, { maxItems: 16 }),
    evidence_refs: Type.Array(Type.String({ minLength: 1 }), { maxItems: 32 }),
    analyzer: FlowAnalyzerProvenanceSchema,
  },
  { additionalProperties: false },
);
export type FlowAnalyzerObservation = Static<typeof FlowAnalyzerObservationSchema>;

export const FlowDecisionSchema = Type.Object(
  {
    capability: Type.Literal("flow"),
    outcome: FlowOutcomeSchema,
    fixed_outcome: Type.Optional(FlowOutcomeSchema),
    fixed_policy_satisfied: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type FlowDecision = Static<typeof FlowDecisionSchema>;

export const FlowRevisionHintSchema = Type.Object(
  {
    action: FlowRevisionHintActionSchema,
    path: Type.String({ minLength: 1 }),
    reason_code: Type.String({ minLength: 1 }),
    constraints: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
  },
  { additionalProperties: false },
);
export type FlowRevisionHint = Static<typeof FlowRevisionHintSchema>;

export const FlowCompactObservationSchema = Type.Object(
  {
    code: Type.String({ minLength: 1 }),
    path: Type.Optional(Type.String({ minLength: 1 })),
    locations: Type.Optional(Type.Array(FlowLocationRefSchema, { maxItems: 8 })),
    evidence_ref: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type FlowCompactObservation = Static<typeof FlowCompactObservationSchema>;

export const ResearchExecutionResultSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    run_id: RunIdSchema,
    operation_status: OperationStatusSchema,
    capability: Type.Literal("flow"),
    decision: FlowDecisionSchema,
    verification_level: VerificationLevelSchema,
    observations: Type.Array(FlowCompactObservationSchema, { maxItems: 16 }),
    revision_hints: Type.Array(FlowRevisionHintSchema, { maxItems: 8 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }),
    budget_remaining: Type.Optional(OperationBudgetSchema),
    artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type ResearchExecutionResult = Static<typeof ResearchExecutionResultSchema>;

/** Durable, replayable Flow evidence. This is distinct from the compact host result. */
export const FlowRunArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    capability: Type.Literal("flow"),
    hypothesis_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    model: FlowModelSchema,
    target: Type.Object(
      { vulnerable: TargetRefSchema, fixed: Type.Optional(TargetRefSchema) },
      { additionalProperties: false },
    ),
    mode: EvidenceOperationModeSchema,
    expectation: Type.Optional(FlowExpectationSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1 })),
    // Historical Flow artifacts recorded only the analyzer id. Keep those
    // readable so replay can return a precise unrecorded-version/fingerprint
    // result, while new writes persist full provenance.
    analyzer: Type.Object(
      {
        analyzer_id: Type.Literal("codeql"),
        available: Type.Optional(Type.Boolean()),
        version: Type.Optional(Type.String({ minLength: 1 })),
        adapter_version: Type.Optional(Type.String({ minLength: 1 })),
      },
      { additionalProperties: false },
    ),
    target_fingerprints: Type.Optional(Type.Object(
      {
        vulnerable: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        fixed: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
      },
      { additionalProperties: false },
    )),
    observation: Type.Optional(FlowAnalyzerObservationSchema),
    decision_policy_version: Type.Optional(Type.String({ minLength: 1 })),
    operation_status: OperationStatusSchema,
    decision: FlowDecisionSchema,
    verification_level: VerificationLevelSchema,
    observations: Type.Array(FlowCompactObservationSchema, { maxItems: 16 }),
    revision_hints: Type.Array(FlowRevisionHintSchema, { maxItems: 8 }),
    allowed_next_actions: Type.Array(EnvelopeActionSchema, { maxItems: 4 }),
    budget_remaining: Type.Optional(OperationBudgetSchema),
  },
  { additionalProperties: false },
);
export type FlowRunArtifact = Static<typeof FlowRunArtifactSchema>;

/**
 * Evidence-only projection emitted by the historical CodeQL compatibility
 * workflow. It preserves the legacy response contract while making the same
 * normalized Flow hypothesis, observation and Core decision auditable.
 */
export const LegacyFlowProjectionArtifactSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    projection_version: Type.Literal("autovul.flow.compatibility/1"),
    capability: Type.Literal("flow"),
    hypothesis_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    source_run_id: RunIdSchema,
    source_candidate_id: Type.String({ minLength: 1 }),
    model: FlowModelSchema,
    observation: FlowAnalyzerObservationSchema,
    decision_policy_version: Type.Literal(FLOW_DECISION_POLICY_VERSION),
    decision: FlowDecisionSchema,
    verification_level: VerificationLevelSchema,
  },
  { additionalProperties: false },
);
export type LegacyFlowProjectionArtifact = Static<typeof LegacyFlowProjectionArtifactSchema>;

export const FlowResearchToolInputSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: ResearchCapabilitySchema,
    hypothesis_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
    target: Type.Optional(
      Type.Object(
        {
          vulnerable: TargetRefSchema,
          fixed: Type.Optional(TargetRefSchema),
        },
        { additionalProperties: false },
      ),
    ),
    analyzer_id: Type.Optional(Type.Literal("codeql")),
    mode: Type.Optional(EvidenceOperationModeSchema),
    expectation: Type.Optional(FlowExpectationSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type FlowResearchToolInput = Static<typeof FlowResearchToolInputSchema>;
