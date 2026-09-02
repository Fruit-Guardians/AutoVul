import {
  CONTRACTS_VERSION,
  LegacyCapabilityResearchOperationRouteSchema,
  parseSchema,
  ResearchOperationRouteSchema,
  type AnalyzerServiceResearchOperationRoute,
  type CapabilityResearchOperationRoute,
  type ResearchOperationRoute,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "./ports.js";

/** Shared runtime route; Capability payloads remain in Capability artifacts. */
export const RESEARCH_OPERATION_ARTIFACT = "research/operation.json";

type ResearchOperationRouteWrite =
  | Omit<CapabilityResearchOperationRoute, "schema_version" | "route_kind">
  | Omit<AnalyzerServiceResearchOperationRoute, "schema_version" | "route_kind">;

export function serializeResearchOperationRoute(
  route: ResearchOperationRouteWrite,
): string {
  const persisted: ResearchOperationRoute = "service" in route
    ? { schema_version: CONTRACTS_VERSION, route_kind: "analyzer_service", ...route }
    : { schema_version: CONTRACTS_VERSION, route_kind: "capability", ...route };
  return JSON.stringify(parseSchema(
    ResearchOperationRouteSchema,
    persisted,
    "research operation route",
  ));
}

export async function writeResearchOperationRoute(
  artifacts: ArtifactStorePort,
  runId: RunId,
  route: ResearchOperationRouteWrite,
): Promise<void> {
  await artifacts.writeArtifact(runId, RESEARCH_OPERATION_ARTIFACT, serializeResearchOperationRoute(route));
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
    return { ...legacy, route_kind: "capability" };
  }
}
