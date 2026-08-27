import {
  parseSchema,
  ProbeEvidenceSchema,
  type QueryCandidate,
  type QueryWorkflowState,
  type RunId,
} from "@pure-auto-codeql/contracts";

import { normalizeQueryCandidate } from "../query-candidate.js";
import type { CodeqlWorkflowContext } from "./context.js";
import { withCandidateDigest } from "./candidate-policy.js";

export async function prepareCandidate(
  context: CodeqlWorkflowContext,
  runId: RunId,
  input: unknown,
  state: QueryWorkflowState,
): Promise<QueryCandidate> {
  let candidate = withCandidateDigest(normalizeQueryCandidate(input, state.spec));
  if (candidate.probe_evidence !== undefined || candidate.intent === undefined) return candidate;
  const artifact = await context.repository.readArtifact(runId, `probes/${candidate.intent.intent_id}/probe-evidence.json`);
  if (artifact === undefined) return candidate;
  const evidence = parseSchema(ProbeEvidenceSchema, JSON.parse(artifact) as unknown, "probe evidence");
  if (evidence.intent_id !== candidate.intent.intent_id) return candidate;
  return withCandidateDigest({ ...candidate, probe_evidence: evidence });
}
