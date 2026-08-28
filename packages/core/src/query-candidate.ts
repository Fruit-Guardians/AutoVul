import {
  CONTRACTS_VERSION,
  parseSchema,
  QueryCandidateInputSchema,
  QueryCandidateSchema,
  TaintQueryCandidateSchema,
  type QueryCandidate,
  type QueryCandidateInput,
  type VulnerabilitySpec,
} from "@autovul/contracts";

import { normalizePythonQueryCandidate } from "./python-query-renderer.js";
import { languagePackFor, normalizeTaintIntent, renderTaintQuery } from "./language-packs.js";

export function normalizeQueryCandidate(input: unknown, spec: VulnerabilitySpec): QueryCandidate {
  const candidateInput = parseSchema(QueryCandidateInputSchema, input, "query candidate input") as QueryCandidateInput;
  if ("ql_text" in candidateInput) {
    return parseSchema(QueryCandidateSchema, candidateInput, "query candidate");
  }
  if ("intent" in candidateInput) {
    const intent = normalizeTaintIntent(candidateInput.intent, spec.language);
    const pack = languagePackFor(candidateInput.language);
    return {
      schema_version: CONTRACTS_VERSION,
      candidate_id: candidateInput.candidate_id,
      query_id: candidateInput.query_id,
      spec_id: candidateInput.spec_id,
      language: candidateInput.language,
      ql_text: renderTaintQuery(candidateInput.query_id, intent),
      intent,
      ...(candidateInput.probe_evidence === undefined ? {} : { probe_evidence: candidateInput.probe_evidence }),
      qlpack_yml: pack.qlpackYml(),
      round: candidateInput.round,
      origin: candidateInput.origin,
      ...(candidateInput.parent_candidate_id === undefined ? {} : { parent_candidate_id: candidateInput.parent_candidate_id }),
      ...(candidateInput.rationale === undefined ? {} : { rationale: candidateInput.rationale }),
    };
  }
  return normalizePythonQueryCandidate(input, spec);
}
