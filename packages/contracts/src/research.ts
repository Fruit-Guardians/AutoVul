import { Type, type Static } from "typebox";

import {
  CHANGE_OBSERVATION_SERVICE,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  ChangeObservationServiceRequestSchema,
} from "./change-observation.js";
import { RunIdSchema } from "./schemas.js";

/** Versioned routing identities. Domain schemas remain capability-owned. */
export const FLOW_HYPOTHESIS_VERSION = "autovul.flow/1" as const;
export const MISSING_CHECK_HYPOTHESIS_VERSION = "autovul.missing-check/1" as const;
export const TYPESTATE_HYPOTHESIS_VERSION = "autovul.typestate/1" as const;

export const ResearchActionSchema = Type.Union([Type.Literal("validate"), Type.Literal("execute")]);
export type ResearchAction = Static<typeof ResearchActionSchema>;

export const ResearchCapabilitySchema = Type.Union([
  Type.Literal("flow"),
  Type.Literal("missing_check"),
  Type.Literal("typestate"),
]);
export type ResearchCapability = Static<typeof ResearchCapabilitySchema>;

export const ResearchHypothesisVersionSchema = Type.Union([
  Type.Literal(FLOW_HYPOTHESIS_VERSION),
  Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
  Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
]);
export type ResearchHypothesisVersion = Static<typeof ResearchHypothesisVersionSchema>;

export const EnvelopeActionSchema = Type.Union([
  Type.Literal("revise"),
  Type.Literal("execute"),
  Type.Literal("replay"),
  Type.Literal("stop"),
]);
export type EnvelopeAction = Static<typeof EnvelopeActionSchema>;

export const RunActionSchema = Type.Union([Type.Literal("status"), Type.Literal("cancel"), Type.Literal("replay")]);
export type RunAction = Static<typeof RunActionSchema>;

export const EvidenceOperationModeSchema = Type.Union([
  Type.Literal("probe"),
  Type.Literal("reproduce"),
  Type.Literal("differential"),
]);
export type EvidenceOperationMode = Static<typeof EvidenceOperationModeSchema>;

export const OperationStatusSchema = Type.Union([
  Type.Literal("completed"),
  Type.Literal("blocked"),
  Type.Literal("failed"),
  Type.Literal("cancelled"),
]);
export type OperationStatus = Static<typeof OperationStatusSchema>;

export const OperationBudgetSchema = Type.Object(
  {
    timeout_ms: Type.Integer({ minimum: 1, maximum: 3_600_000 }),
  },
  { additionalProperties: false },
);
export type OperationBudget = Static<typeof OperationBudgetSchema>;

/**
 * Minimal routing envelope. Capability domain fields belong in the selected
 * Hypothesis schema, not here.
 */
export const FlowCapabilityResearchRequestSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("flow"),
    hypothesis_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
  },
  { additionalProperties: false },
);
export type FlowCapabilityResearchRequest = Static<typeof FlowCapabilityResearchRequestSchema>;

export const MissingCheckCapabilityResearchRequestSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
  },
  { additionalProperties: false },
);
export type MissingCheckCapabilityResearchRequest = Static<typeof MissingCheckCapabilityResearchRequestSchema>;

export const TypestateCapabilityResearchRequestSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("typestate"),
    hypothesis_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
  },
  { additionalProperties: false },
);
export type TypestateCapabilityResearchRequest = Static<typeof TypestateCapabilityResearchRequestSchema>;

/** Capability-only routing shape is a closed discriminated union pairing capability and hypothesis_version. */
export const CapabilityResearchRequestSchema = Type.Union([
  FlowCapabilityResearchRequestSchema,
  MissingCheckCapabilityResearchRequestSchema,
  TypestateCapabilityResearchRequestSchema,
]);
export type CapabilityResearchRequest = Static<typeof CapabilityResearchRequestSchema>;

/** Aggregate routing is a closed Capability-or-Analyzer-Service union. */
export const ResearchRequestSchema = Type.Union([
  CapabilityResearchRequestSchema,
  ChangeObservationServiceRequestSchema,
]);
export type ResearchRequest = Static<typeof ResearchRequestSchema>;

export const CodeqlDatabaseTargetRefSchema = Type.Object(
  {
    kind: Type.Literal("codeql_database"),
    path: Type.String({ minLength: 1 }),
    expected_fingerprint: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16,64}$" })),
  },
  { additionalProperties: false },
);
export type CodeqlDatabaseTargetRef = Static<typeof CodeqlDatabaseTargetRefSchema>;

export const GitRevisionTargetRefSchema = Type.Object(
  {
    kind: Type.Literal("git_revision"),
    repository: Type.String({ minLength: 1, maxLength: 4096 }),
    revision: Type.String({ pattern: "^(?:[a-f0-9]{40}|[a-f0-9]{64})$" }),
    expected_fingerprint: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16,64}$" })),
  },
  { additionalProperties: false },
);
export type GitRevisionTargetRef = Static<typeof GitRevisionTargetRefSchema>;

/** Target identity for CodeQL-based capabilities (Flow, Typestate). */
export const TargetRefSchema = CodeqlDatabaseTargetRefSchema;
export type TargetRef = Static<typeof TargetRefSchema>;

export const TargetPairSchema = Type.Object(
  {
    vulnerable: TargetRefSchema,
    fixed: Type.Optional(TargetRefSchema),
  },
  { additionalProperties: false },
);
export type TargetPair = Static<typeof TargetPairSchema>;

export const GitRevisionTargetPairSchema = Type.Object(
  {
    vulnerable: GitRevisionTargetRefSchema,
    fixed: Type.Optional(GitRevisionTargetRefSchema),
  },
  { additionalProperties: false },
);
export type GitRevisionTargetPair = Static<typeof GitRevisionTargetPairSchema>;

export const AutovulRunToolInputSchema = Type.Object(
  {
    action: RunActionSchema,
    run_id: RunIdSchema,
  },
  { additionalProperties: false },
);
export type AutovulRunToolInput = Static<typeof AutovulRunToolInputSchema>;

export const FlowCapabilityResearchOperationRouteSchema = Type.Object(
  {
    schema_version: Type.Literal("v2.contracts/1"),
    route_kind: Type.Literal("capability"),
    capability: Type.Literal("flow"),
    hypothesis_version: Type.Literal(FLOW_HYPOTHESIS_VERSION),
    result_artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type FlowCapabilityResearchOperationRoute = Static<typeof FlowCapabilityResearchOperationRouteSchema>;

export const MissingCheckCapabilityResearchOperationRouteSchema = Type.Object(
  {
    schema_version: Type.Literal("v2.contracts/1"),
    route_kind: Type.Literal("capability"),
    capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    result_artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type MissingCheckCapabilityResearchOperationRoute = Static<typeof MissingCheckCapabilityResearchOperationRouteSchema>;

export const TypestateCapabilityResearchOperationRouteSchema = Type.Object(
  {
    schema_version: Type.Literal("v2.contracts/1"),
    route_kind: Type.Literal("capability"),
    capability: Type.Literal("typestate"),
    hypothesis_version: Type.Literal(TYPESTATE_HYPOTHESIS_VERSION),
    result_artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type TypestateCapabilityResearchOperationRoute = Static<typeof TypestateCapabilityResearchOperationRouteSchema>;

/**
 * Shared, persisted routing record for a deterministic research operation.
 * It deliberately records no Capability domain fields: replay selects the
 * explicit Capability branch from this route, then reads that Capability's
 * own artifact.
 */
export const CapabilityResearchOperationRouteSchema = Type.Union([
  FlowCapabilityResearchOperationRouteSchema,
  MissingCheckCapabilityResearchOperationRouteSchema,
  TypestateCapabilityResearchOperationRouteSchema,
]);
export type CapabilityResearchOperationRoute = Static<typeof CapabilityResearchOperationRouteSchema>;

export const AnalyzerServiceResearchOperationRouteSchema = Type.Object(
  {
    schema_version: Type.Literal("v2.contracts/1"),
    route_kind: Type.Literal("analyzer_service"),
    service: Type.Literal(CHANGE_OBSERVATION_SERVICE),
    service_version: Type.Literal(CHANGE_OBSERVATION_SERVICE_VERSION),
    result_artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type AnalyzerServiceResearchOperationRoute = Static<typeof AnalyzerServiceResearchOperationRouteSchema>;

/** Newly persisted routes are a closed static union, never artifact-name inferred. */
export const ResearchOperationRouteSchema = Type.Union([
  CapabilityResearchOperationRouteSchema,
  AnalyzerServiceResearchOperationRouteSchema,
]);
export type ResearchOperationRoute = Static<typeof ResearchOperationRouteSchema>;

/** Read-only schema for artifacts committed before route_kind was introduced. */
export const LegacyCapabilityResearchOperationRouteSchema = Type.Object(
  {
    schema_version: Type.Literal("v2.contracts/1"),
    capability: ResearchCapabilitySchema,
    hypothesis_version: ResearchHypothesisVersionSchema,
    result_artifact_ref: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type LegacyCapabilityResearchOperationRoute = Static<typeof LegacyCapabilityResearchOperationRouteSchema>;
