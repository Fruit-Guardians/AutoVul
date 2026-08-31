import {
  CONTRACTS_VERSION,
  parseSchema,
  ResearchOperationRouteSchema,
  type ResearchOperationRoute,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "./ports.js";

/** Shared runtime route; Capability payloads remain in Capability artifacts. */
export const RESEARCH_OPERATION_ARTIFACT = "research/operation.json";

export function serializeResearchOperationRoute(
  route: Omit<ResearchOperationRoute, "schema_version">,
): string {
  return JSON.stringify(parseSchema(
    ResearchOperationRouteSchema,
    { schema_version: CONTRACTS_VERSION, ...route },
    "research operation route",
  ));
}

export async function writeResearchOperationRoute(
  artifacts: ArtifactStorePort,
  runId: RunId,
  route: Omit<ResearchOperationRoute, "schema_version">,
): Promise<void> {
  await artifacts.writeArtifact(runId, RESEARCH_OPERATION_ARTIFACT, serializeResearchOperationRoute(route));
}

export async function readResearchOperationRoute(
  artifacts: ArtifactStorePort,
  runId: RunId,
): Promise<ResearchOperationRoute | undefined> {
  const raw = await artifacts.readArtifact(runId, RESEARCH_OPERATION_ARTIFACT);
  if (raw === undefined) return undefined;
  return parseSchema(
    ResearchOperationRouteSchema,
    JSON.parse(raw) as unknown,
    "research operation route",
  );
}
