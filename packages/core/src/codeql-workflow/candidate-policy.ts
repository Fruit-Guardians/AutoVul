import {
  DomainError,
  stableDigest,
  type QueryCandidate,
  type VulnerabilitySpec,
} from "@autovul/contracts";

import { languagePackFor } from "../language-packs.js";

export function withCandidateDigest(candidate: QueryCandidate): QueryCandidate {
  return { ...candidate, candidate_digest: candidateDigest(candidate) };
}

export function candidateDigest(candidate: QueryCandidate): string {
  return stableDigest(
    JSON.stringify({
      schema_version: candidate.schema_version,
      candidate_id: candidate.candidate_id,
      query_id: candidate.query_id,
      spec_id: candidate.spec_id,
      language: candidate.language,
      ql_text: candidate.ql_text,
      intent: candidate.intent,
      probe_evidence: candidate.probe_evidence,
      round: candidate.round,
      origin: candidate.origin,
      parent_candidate_id: candidate.parent_candidate_id,
      rationale: candidate.rationale,
    }),
  );
}

export function assertCandidateProbeForUserCase(
  candidate: QueryCandidate,
  spec: VulnerabilitySpec,
): void {
  if (
    spec.input_provenance !== "user_provided" ||
    candidate.origin === "cli" ||
    candidate.origin === "test"
  ) {
    return;
  }
  if (candidate.intent === undefined) {
    throw new DomainError(
      "PROBE_FAILED",
      "input",
      "Pi candidates for user-provided cases must carry a structured intent and probe evidence",
      false,
      { candidateId: candidate.candidate_id },
    );
  }
  const evidence = candidate.probe_evidence;
  if (
    evidence === undefined ||
    evidence.status !== "passed" ||
    evidence.intent_id !== candidate.intent.intent_id ||
    evidence.source.locations.length === 0 ||
    evidence.sink.locations.length === 0
  ) {
    throw new DomainError(
      "PROBE_FAILED",
      "input",
      "Source/Sink probe evidence is required and must contain both matched node locations before CLI verification",
      false,
      {
        candidateId: candidate.candidate_id,
        intentId: candidate.intent.intent_id,
        probeStatus: evidence?.status ?? "missing",
        sourceLocations: evidence?.source.locations.length ?? 0,
        sinkLocations: evidence?.sink.locations.length ?? 0,
      },
    );
  }
}

export function compileRepairHint(
  spec: VulnerabilitySpec,
  candidate: QueryCandidate,
): string {
  if (candidate.intent !== undefined) {
    return `Revise only the structured ${spec.language} TaintQueryIntent (source/sink matchers, flow steps, or sanitizer); the language pack owns metadata, imports, module, PathGraph and select.`;
  }
  return spec.language === "python"
    ? "Revise only the structured PythonPathQueryDraft; Core owns metadata, imports, module, PathGraph and select."
    : `Revise the structured ${spec.language} candidate; the language pack owns metadata, imports, module, PathGraph and select.`;
}

export function assertCandidateLanguage(
  candidate: QueryCandidate,
  spec: VulnerabilitySpec,
): void {
  if (languagePackFor(candidate.language).language === languagePackFor(spec.language).language) {
    return;
  }
  throw new DomainError(
    "INVALID_INPUT",
    "input",
    "Query candidate language does not match the workflow Language Pack",
    false,
    {
      candidateLanguage: candidate.language,
      workflowLanguage: spec.language,
    },
  );
}
