import { Type, type Static } from "typebox";

import { ChangeObservationServiceRequestSchema } from "./change-observation.js";
import { FlowResearchToolInputSchema } from "./flow.js";
import {
  EvidenceOperationModeSchema,
  GitRevisionTargetPairSchema,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  OperationBudgetSchema,
  ResearchActionSchema,
  TargetPairSchema,
} from "./research.js";
import { TypestateResearchToolInputSchema } from "./typestate.js";

export const CodeqlMissingCheckResearchToolInputSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
    target: Type.Optional(TargetPairSchema),
    analyzer_id: Type.Optional(Type.Literal("codeql")),
    mode: Type.Optional(EvidenceOperationModeSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type CodeqlMissingCheckResearchToolInput = Static<typeof CodeqlMissingCheckResearchToolInputSchema>;

export const JavascriptCfgMissingCheckResearchToolInputSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
    target: Type.Optional(GitRevisionTargetPairSchema),
    analyzer_id: Type.Literal("javascript_cfg"),
    mode: Type.Optional(EvidenceOperationModeSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type JavascriptCfgMissingCheckResearchToolInput = Static<typeof JavascriptCfgMissingCheckResearchToolInputSchema>;

/** The sole host-facing aggregate tool contract. Each branch owns its hypothesis and target pairing. */
export const MissingCheckResearchToolInputSchema = Type.Union([
  CodeqlMissingCheckResearchToolInputSchema,
  JavascriptCfgMissingCheckResearchToolInputSchema,
]);
export type MissingCheckResearchToolInput = Static<typeof MissingCheckResearchToolInputSchema>;

export const AutovulResearchToolInputSchema = Type.Union([
  FlowResearchToolInputSchema,
  MissingCheckResearchToolInputSchema,
  TypestateResearchToolInputSchema,
  ChangeObservationServiceRequestSchema,
]);
export type AutovulResearchToolInput = Static<typeof AutovulResearchToolInputSchema>;
