import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION } from "./errors.js";

/** Language families with an independently verified CodeQL Language Pack. */
export const LanguageFamilySchema = Type.Union([
  Type.Literal("python"),
  Type.Literal("javascript"),
  Type.Literal("typescript"),
  Type.Literal("java"),
  Type.Literal("kotlin"),
  Type.Literal("cpp"),
  Type.Literal("c"),
]);
export type LanguageFamily = Static<typeof LanguageFamilySchema>;

export const TaintFlowModeSchema = Type.Union([Type.Literal("value"), Type.Literal("taint")]);
export type TaintFlowMode = Static<typeof TaintFlowModeSchema>;

const MatcherBase = {
  module: Type.Optional(Type.String({ minLength: 1 })),
  type: Type.Optional(Type.String({ minLength: 1 })),
  member: Type.Optional(Type.String({ minLength: 1 })),
  name: Type.Optional(Type.String({ minLength: 1 })),
  argument_index: Type.Optional(Type.Integer({ minimum: 0 })),
  argument_name: Type.Optional(Type.String({ minLength: 1 })),
  /** A call-site keyword constraint, for example Python `shell=True`. */
  keyword_name: Type.Optional(Type.String({ minLength: 1 })),
  keyword_value: Type.Optional(Type.Union([Type.Boolean(), Type.Number(), Type.String()])),
  property: Type.Optional(Type.String({ minLength: 1 })),
  file: Type.Optional(Type.String({ minLength: 1 })),
  symbol: Type.Optional(Type.String({ minLength: 1 })),
  line: Type.Optional(Type.Integer({ minimum: 1 })),
};

export const TaintMatcherKindSchema = Type.Union([
  Type.Literal("call"),
  Type.Literal("call_argument"),
  Type.Literal("constructor"),
  Type.Literal("function"),
  Type.Literal("parameter"),
  Type.Literal("environment"),
  Type.Literal("property"),
  Type.Literal("array_index"),
  Type.Literal("array_element"),
]);
export type TaintMatcherKind = Static<typeof TaintMatcherKindSchema>;

export const TaintMatcherSchema = Type.Union([
  Type.Object({ kind: Type.Literal("call"), ...MatcherBase }, { additionalProperties: false }),
  /** A call-site argument node, useful for explicit wrapper/variadic flow edges. */
  Type.Object({ kind: Type.Literal("call_argument"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("constructor"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("function"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("parameter"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("environment"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("property"), ...MatcherBase }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("array_index"), ...MatcherBase }, { additionalProperties: false }),
  /** The value produced by an array subscript, distinct from the index expression. */
  Type.Object({ kind: Type.Literal("array_element"), ...MatcherBase }, { additionalProperties: false }),
]);
export type TaintMatcher = Static<typeof TaintMatcherSchema>;

/** An explicit directed edge for language-specific flow modeling. */
export const TaintFlowStepSchema = Type.Object(
  {
    from: TaintMatcherSchema,
    to: TaintMatcherSchema,
  },
  { additionalProperties: false },
);
export type TaintFlowStep = Static<typeof TaintFlowStepSchema>;

export const TaintLocationConstraintSchema = Type.Object(
  {
    file: Type.Optional(Type.String({ minLength: 1 })),
    symbol: Type.Optional(Type.String({ minLength: 1 })),
    start_line: Type.Optional(Type.Integer({ minimum: 1 })),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type TaintLocationConstraint = Static<typeof TaintLocationConstraintSchema>;

export const TaintQueryIntentSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    intent_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: LanguageFamilySchema,
    cwe: Type.String({ minLength: 1 }),
    query_kind: Type.Literal("path-problem"),
    flow_mode: TaintFlowModeSchema,
    source: TaintMatcherSchema,
    sink: TaintMatcherSchema,
    message: Type.String({ minLength: 1 }),
    description: Type.Optional(Type.String({ minLength: 1 })),
    source_location: Type.Optional(TaintLocationConstraintSchema),
    sink_location: Type.Optional(TaintLocationConstraintSchema),
    additional_flow: Type.Optional(Type.Array(TaintMatcherSchema, { maxItems: 16 })),
    additional_flow_steps: Type.Optional(Type.Array(TaintFlowStepSchema, { maxItems: 16 })),
    sanitizer: Type.Optional(Type.Array(TaintMatcherSchema, { maxItems: 8 })),
    variant: Type.Optional(Type.Union([Type.Literal("exact"), Type.Literal("semantic")])),
    evidence_refs: Type.Optional(Type.Array(Type.String({ minLength: 1 }), { maxItems: 32 })),
    rationale: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type TaintQueryIntent = Static<typeof TaintQueryIntentSchema>;

export const ProbeLocationSchema = Type.Object(
  {
    file: Type.String({ minLength: 1 }),
    start_line: Type.Integer({ minimum: 1 }),
    start_column: Type.Optional(Type.Integer({ minimum: 1 })),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
    end_column: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type ProbeLocation = Static<typeof ProbeLocationSchema>;

export const ProbeNodeEvidenceSchema = Type.Object(
  {
    role: Type.Union([Type.Literal("source"), Type.Literal("sink")]),
    node_type: Type.Optional(Type.String({ minLength: 1 })),
    label: Type.Optional(Type.String({ minLength: 1 })),
    locations: Type.Array(ProbeLocationSchema, { maxItems: 64 }),
  },
  { additionalProperties: false },
);
export type ProbeNodeEvidence = Static<typeof ProbeNodeEvidenceSchema>;

export const ProbeEvidenceSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    probe_id: Type.String({ minLength: 1 }),
    language: LanguageFamilySchema,
    intent_id: Type.String({ minLength: 1 }),
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed"), Type.Literal("not_run")]),
    source: ProbeNodeEvidenceSchema,
    sink: ProbeNodeEvidenceSchema,
    diagnostics: Type.Array(Type.String({ minLength: 1 })),
    query_artifact: Type.Optional(Type.String({ minLength: 1 })),
    codeql_cli_version: Type.Optional(Type.String({ minLength: 1 })),
    pack_version: Type.Optional(Type.String({ minLength: 1 })),
    elapsed_ms: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false },
);
export type ProbeEvidence = Static<typeof ProbeEvidenceSchema>;

export const LanguageCapabilitySchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    capability_id: Type.String({ minLength: 1 }),
    language: LanguageFamilySchema,
    pack_dependency: Type.String({ minLength: 1 }),
    pack_version_range: Type.String({ minLength: 1 }),
    matcher_kinds: Type.Array(Type.String({ minLength: 1 }), { minItems: 1 }),
    flow_modes: Type.Array(TaintFlowModeSchema, { minItems: 1 }),
    verified_at: Type.String({ minLength: 1 }),
    positive_fixture: Type.String({ minLength: 1 }),
    provenance: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type LanguageCapability = Static<typeof LanguageCapabilitySchema>;

export const LanguageSupportLevelSchema = Type.Union([
  Type.Literal("experimental"),
  Type.Literal("generated"),
  Type.Literal("differential"),
  Type.Literal("variant_validated"),
]);
export type LanguageSupportLevel = Static<typeof LanguageSupportLevelSchema>;

export const TaintQueryCandidateSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    candidate_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    query_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    spec_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: LanguageFamilySchema,
    intent: TaintQueryIntentSchema,
    probe_evidence: Type.Optional(ProbeEvidenceSchema),
    round: Type.Integer({ minimum: 1, maximum: 3 }),
    origin: Type.Union([
      Type.Literal("pi_generated"),
      Type.Literal("pi_revised"),
      Type.Literal("cli"),
      Type.Literal("test"),
    ]),
    parent_candidate_id: Type.Optional(Type.String({ minLength: 1 })),
    rationale: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type TaintQueryCandidate = Static<typeof TaintQueryCandidateSchema>;
