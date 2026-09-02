import { Type, type Static } from "typebox";

import { ChangeObservationServiceRequestSchema } from "./change-observation.js";
import { FlowExpectationSchema, FlowResearchToolInputSchema } from "./flow.js";
import { MissingCheckHypothesisSchema } from "./missing-check.js";
import {
  EvidenceOperationModeSchema,
  MISSING_CHECK_HYPOTHESIS_VERSION,
  OperationBudgetSchema,
  ResearchActionSchema,
  TargetRefSchema,
} from "./research.js";
import { TypestateResearchToolInputSchema } from "./typestate.js";

/** The sole host-facing aggregate tool contract. Each branch owns its hypothesis. */
export const MissingCheckResearchToolInputSchema = Type.Object(
  {
    action: ResearchActionSchema,
    capability: Type.Literal("missing_check"),
    hypothesis_version: Type.Literal(MISSING_CHECK_HYPOTHESIS_VERSION),
    hypothesis: Type.Unknown(),
    target: Type.Optional(Type.Object({ vulnerable: TargetRefSchema, fixed: Type.Optional(TargetRefSchema) }, { additionalProperties: false })),
    analyzer_id: Type.Optional(Type.Literal("codeql")),
    mode: Type.Optional(EvidenceOperationModeSchema),
    budget: Type.Optional(OperationBudgetSchema),
    idempotency_key: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type MissingCheckResearchToolInput = Static<typeof MissingCheckResearchToolInputSchema>;

export const AutovulResearchToolInputSchema = Type.Union([
  FlowResearchToolInputSchema,
  MissingCheckResearchToolInputSchema,
  TypestateResearchToolInputSchema,
  ChangeObservationServiceRequestSchema,
]);
export type AutovulResearchToolInput = Static<typeof AutovulResearchToolInputSchema>;

/** Keeps this file's Flow import intentional and gives docs a single aggregate shape. */
void FlowExpectationSchema;
