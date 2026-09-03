import {
  CONTRACTS_VERSION,
  LegacyCapabilityResearchOperationRouteSchema,
  parseSchema,
  ResearchOperationRouteSchema,
  type AnalyzerServiceResearchOperationRoute,
  type FlowCapabilityResearchOperationRoute,
  type MissingCheckCapabilityResearchOperationRoute,
  type ResearchOperationRoute,
  type RunId,
  type TypestateCapabilityResearchOperationRoute,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "./ports.js";

/** Shared runtime route; Capability payloads remain in Capability artifacts. */
const RESEARCH_OPERATION_ARTIFACT = "research/operation.json";

type ResearchOperationRouteWrite =
  | Omit<FlowCapabilityResearchOperationRoute, "schema_version" | "route_kind">
  | Omit<MissingCheckCapabilityResearchOperationRoute, "schema_version" | "route_kind">
  | Omit<TypestateCapabilityResearchOperationRoute, "schema_version" | "route_kind">
  | Omit<AnalyzerServiceResearchOperationRoute, "schema_version" | "route_kind">;

export function serializeResearchOperationRoute(
  route: ResearchOperationRouteWrite,
): string {
  const persisted: ResearchOperationRoute = "service" in route
    ? { schema_version: CONTRACTS_VERSION, route_kind: "analyzer_service", ...route }
    : route.capability === "flow"
      ? { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "flow", hypothesis_version: route.hypothesis_version, result_artifact_ref: route.result_artifact_ref }
      : route.capability === "missing_check"
        ? { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "missing_check", hypothesis_version: route.hypothesis_version, result_artifact_ref: route.result_artifact_ref }
        : { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "typestate", hypothesis_version: route.hypothesis_version, result_artifact_ref: route.result_artifact_ref };
  return JSON.stringify(parseSchema(
    ResearchOperationRouteSchema,
    persisted,
    "research operation route",
  ));
}

export async function readResearchOperationRoute(
  artifacts: ArtifactStorePort,
  runId: RunId,
): Promise<ResearchOperationRoute | undefined> {
  const raw = await artifacts.readArtifact(runId, RESEARCH_OPERATION_ARTIFACT);
  if (raw === undefined) return undefined;
  const parsed = JSON.parse(raw) as unknown;
  try {
    return parseSchema(ResearchOperationRouteSchema, parsed, "research operation route");
  } catch {
    const legacy = parseSchema(
      LegacyCapabilityResearchOperationRouteSchema,
      parsed,
      "legacy research operation route",
    );
    const persistedLegacy: ResearchOperationRoute = legacy.capability === "flow"
      ? { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "flow", hypothesis_version: legacy.hypothesis_version as "autovul.flow/1", result_artifact_ref: legacy.result_artifact_ref }
      : legacy.capability === "missing_check"
        ? { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "missing_check", hypothesis_version: legacy.hypothesis_version as "autovul.missing-check/1", result_artifact_ref: legacy.result_artifact_ref }
        : { schema_version: CONTRACTS_VERSION, route_kind: "capability", capability: "typestate", hypothesis_version: legacy.hypothesis_version as "autovul.typestate/1", result_artifact_ref: legacy.result_artifact_ref };
    return parseSchema(ResearchOperationRouteSchema, persistedLegacy, "legacy research operation route");
  }
}
