import { Value } from "typebox/value";

import {
  DomainError,
  MissingCheckRunArtifactSchema,
  stableDigest,
  type MissingCheckRunArtifact,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "../ports.js";
import { readResearchOperationRoute } from "../research-operation.js";
import type { VariantSeedPatternFacts } from "./port.js";

const ACCEPTED_SEED_VERIFICATION_LEVELS = new Set([
  "reproduced",
  "differential",
  "variant_validated",
]);

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
  if (route.route_kind !== "capability" || route.capability !== "missing_check") {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      `Seed run ${seedRunId} is not a missing_check capability run (route_kind: ${route.route_kind}, capability: ${route.route_kind === "capability" ? route.capability : "none"}); Variant Search v1 only supports real MissingCheck seeds`,
      false,
    );
  }

  const rawArtifact = await artifacts.readArtifact(seedRunId, route.result_artifact_ref);
  if (rawArtifact === undefined) {
    throw new DomainError("INVALID_INPUT", "input", `Seed result artifact cannot be read: ${route.result_artifact_ref}`, false);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawArtifact);
  } catch {
    throw new DomainError("INVALID_INPUT", "input", `Seed result artifact is not valid JSON: ${route.result_artifact_ref}`, false);
  }

  if (!Value.Check(MissingCheckRunArtifactSchema, parsed)) {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      `Seed run artifact does not conform to MissingCheckRunArtifactSchema: ${seedRunId}`,
      false,
    );
  }

  const seedArtifact = Value.Parse(MissingCheckRunArtifactSchema, parsed) as MissingCheckRunArtifact;

  if (!ACCEPTED_SEED_VERIFICATION_LEVELS.has(seedArtifact.verification_level)) {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      `Seed run ${seedRunId} verification level is "${seedArtifact.verification_level}"; Variant Search v1 requires seed verification level to be at least reproduced: seed verification level must be at least reproduced (got: ${seedArtifact.verification_level})`,
      false,
    );
  }

  const primarySymbol = seedArtifact.hypothesis.operation.name;
  const checkSymbol = seedArtifact.hypothesis.required_check.name;
  const enclosingFunction = seedArtifact.hypothesis.scope.entry?.name;
  const matchedSymbols = [primarySymbol, checkSymbol].filter((s): s is string => typeof s === "string" && s.length > 0);

  if (matchedSymbols.length === 0) {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      `Seed run ${seedRunId} missing_check hypothesis has no extractable symbols`,
      false,
    );
  }

  const seedDigest = stableDigest(rawArtifact);

  return {
    capability: "missing_check",
    seedRunId,
    seedDigest,
    seedVerificationLevel: seedArtifact.verification_level,
    analyzerProvenance: seedArtifact.analyzer,
    primarySymbol,
    checkSymbol,
    matchedSymbols,
    ...(enclosingFunction !== undefined ? { enclosingFunction } : {}),
    ...(seedArtifact.target_fingerprints !== undefined ? { targetFingerprints: seedArtifact.target_fingerprints } : {}),
  };
}
