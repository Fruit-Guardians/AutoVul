import {
  DomainError,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "../ports.js";
import { readResearchOperationRoute } from "../research-operation.js";
import type { VariantSeedPatternFacts } from "./port.js";

export async function extractSeedPatternFacts(
  artifacts: ArtifactStorePort,
  seedRunId: RunId,
): Promise<VariantSeedPatternFacts> {
  const manifest = await artifacts.findManifest(seedRunId);
  if (manifest === undefined) {
    throw new DomainError("INVALID_INPUT", "input", `Seed run does not exist: ${seedRunId}`, false);
  }
  if (manifest.status !== "completed") {
    throw new DomainError("INVALID_INPUT", "input", `Seed run is not completed (status: ${manifest.status}): ${seedRunId}`, false);
  }

  const route = await readResearchOperationRoute(artifacts, seedRunId);
  if (route === undefined) {
    throw new DomainError("INVALID_INPUT", "input", `Seed run has no committed route: ${seedRunId}`, false);
  }

  const rawArtifact = await artifacts.readArtifact(seedRunId, route.result_artifact_ref);
  if (rawArtifact === undefined) {
    throw new DomainError("INVALID_INPUT", "input", `Seed result artifact cannot be read: ${route.result_artifact_ref}`, false);
  }

  const parsed = JSON.parse(rawArtifact) as Record<string, unknown>;

  // 1. MissingCheck Seed
  if (parsed.hypothesis && typeof parsed.hypothesis === "object") {
    const hyp = parsed.hypothesis as Record<string, unknown>;
    const op = hyp.operation as { name?: string } | undefined;
    const check = hyp.required_check as { name?: string } | undefined;
    const scope = hyp.scope as { entry?: { name?: string } } | undefined;
    const matchedSymbols = [op?.name, check?.name].filter((s): s is string => typeof s === "string" && s.length > 0);
    if (matchedSymbols.length > 0) {
      return {
        capability: "missing_check",
        matchedSymbols,
        ...(op?.name !== undefined ? { primarySymbol: op.name } : {}),
        ...(check?.name !== undefined ? { checkSymbol: check.name } : {}),
        ...(scope?.entry?.name !== undefined ? { enclosingFunction: scope.entry.name } : {}),
      };
    }
  }

  // 2. Flow Seed
  if (parsed.query && typeof parsed.query === "object") {
    const q = parsed.query as Record<string, unknown>;
    const sink = q.sink as { name?: string } | undefined;
    if (sink?.name) {
      const sinkName = sink.name;
      return {
        capability: "flow",
        matchedSymbols: [sinkName],
        primarySymbol: sinkName,
      };
    }
  }

  // 3. Typestate Seed
  if (parsed.events && Array.isArray(parsed.events)) {
    const events = parsed.events as { id?: string; selector?: { name?: string } }[];
    const names = events.map((e) => e.selector?.name).filter((n): n is string => typeof n === "string" && n.length > 0);
    const primary = names[0];
    if (primary !== undefined) {
      return {
        capability: "typestate",
        matchedSymbols: names,
        primarySymbol: primary,
      };
    }
  }

  throw new DomainError(
    "INVALID_INPUT",
    "input",
    `Unable to extract pattern facts from seed run artifact: ${seedRunId}`,
    false,
  );
}
