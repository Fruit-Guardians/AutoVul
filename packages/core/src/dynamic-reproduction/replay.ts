import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  DynamicReproductionExecutionObservationSchema,
  type DynamicReproductionReplayVerification,
  type RunId,
} from "@autovul/contracts";

import type { ArtifactStorePort } from "../ports.js";
import { sha256Utf8 } from "../change-observation/sha256.js";

export class DynamicReproductionReplayService {
  constructor(private readonly artifacts: ArtifactStorePort) {}

  async verifyReplay(
    runId: RunId,
    hypothesisId: string,
    options?: { signal?: AbortSignal },
  ): Promise<DynamicReproductionReplayVerification> {
    if (options?.signal?.aborted) {
      throw new DomainError("PROCESS_CANCELLED", "process", "Replay operation cancelled", false);
    }

    const observationPath = `reproduction/${hypothesisId}/observation.json`;
    const observationText = await this.artifacts.readArtifact(runId, observationPath);
    if (!observationText) {
      throw new DomainError(
        "ARTIFACT_NOT_FOUND",
        "artifact",
        `Reproduction observation artifact not found at ${observationPath}`,
        false,
        { runId, hypothesisId, path: observationPath },
      );
    }

    let rawObservation: unknown;
    try {
      rawObservation = JSON.parse(observationText);
    } catch {
      throw new DomainError(
        "ARTIFACT_CORRUPT",
        "artifact",
        `Reproduction observation artifact at ${observationPath} is not valid JSON`,
        false,
        { runId, hypothesisId },
      );
    }

    const observation = parseSchema(
      DynamicReproductionExecutionObservationSchema,
      rawObservation,
      "reproduction observation",
    );

    let checkedWitnessesCount = 0;
    for (const witness of observation.witnesses) {
      if (options?.signal?.aborted) {
        throw new DomainError("PROCESS_CANCELLED", "process", "Replay operation cancelled", false);
      }

      const witnessArtifactPath = `reproduction/${hypothesisId}/witnesses/${witness.path.replace(/^\/+/, "")}`;
      const content = await this.artifacts.readArtifact(runId, witnessArtifactPath);
      if (content === undefined) {
        return {
          schema_version: CONTRACTS_VERSION,
          status: "evidence_mutated",
          original_evidence_ref: observation.evidence_ref,
          original_environment_digest: observation.environment_digest,
          checked_witnesses_count: checkedWitnessesCount,
          detail: `Witness artifact missing during replay: ${witnessArtifactPath}`,
        };
      }

      const calculatedDigest = sha256Utf8(content);
      if (calculatedDigest !== witness.sha256) {
        return {
          schema_version: CONTRACTS_VERSION,
          status: "evidence_mutated",
          original_evidence_ref: observation.evidence_ref,
          original_environment_digest: observation.environment_digest,
          checked_witnesses_count: checkedWitnessesCount,
          detail: `Witness artifact digest mismatch for ${witness.path}: recorded=${witness.sha256}, calculated=${calculatedDigest}`,
        };
      }
      checkedWitnessesCount++;
    }

    return {
      schema_version: CONTRACTS_VERSION,
      status: "identical",
      original_evidence_ref: observation.evidence_ref,
      original_environment_digest: observation.environment_digest,
      checked_witnesses_count: checkedWitnessesCount,
    };
  }
}
