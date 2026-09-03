import {
  CONTRACTS_VERSION,
  FLOW_DECISION_POLICY_VERSION,
  LegacyFlowProjectionArtifactSchema,
  parseSchema,
  type EndpointObservation,
  type FlowAnalyzerObservation,
  type LegacyFlowProjectionArtifact,
  type QueryCandidate,
  type QueryDatabaseObservation,
  type QueryVerification,
  type VulnerabilitySpec,
} from "@autovul/contracts";

import { projectTaintIntentToFlow } from "./compatibility.js";
import { decideFlow } from "./decision.js";

/**
 * Compatibility APIs retain their historical result shape, but this pure
 * projection records the Flow policy interpretation from the same committed
 * candidate, probe and analyzer observations.
 */
export function projectLegacyVerificationToFlow(
  candidate: QueryCandidate,
  spec: VulnerabilitySpec,
  verification: QueryVerification,
): LegacyFlowProjectionArtifact | undefined {
  if (candidate.intent === undefined || spec.validation.vulnerable_max_results < 1) return undefined;
  const { model } = projectTaintIntentToFlow(candidate.intent);
  const observation: FlowAnalyzerObservation = {
    schema_version: "autovul.flow/1",
    compile_accepted: verification.compile.status === "passed",
    source: endpointObservation(candidate, "source", verification),
    sink: endpointObservation(candidate, "sink", verification),
    path: pathObservation(verification.vulnerable),
    ...(spec.fixed_database === undefined ? {} : { fixed_path: pathObservation(verification.fixed) }),
    capability_gaps: [],
    evidence_refs: [`candidates/${candidate.candidate_id}/verification.json`],
    analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", ...(verification.codeql_cli_version === undefined ? {} : { version: verification.codeql_cli_version }) },
  };
  const mode = spec.fixed_database === undefined ? "reproduce" : "differential";
  const expectation = {
    vulnerable: { min_paths: Math.max(1, spec.validation.vulnerable_min_results), max_paths: spec.validation.vulnerable_max_results },
    ...(spec.fixed_database === undefined ? {} : { fixed: { min_paths: spec.validation.fixed_min_results, max_paths: spec.validation.fixed_max_results } }),
  };
  const decision = decideFlow(observation, mode, expectation);
  return parseSchema(LegacyFlowProjectionArtifactSchema, {
    schema_version: CONTRACTS_VERSION,
    projection_version: "autovul.flow.compatibility/1",
    capability: "flow",
    hypothesis_version: "autovul.flow/1",
    source_run_id: verification.run_id,
    source_candidate_id: candidate.candidate_id,
    model,
    observation,
    decision_policy_version: FLOW_DECISION_POLICY_VERSION,
    decision: decision.decision,
    verification_level: decision.verificationLevel,
  }, "legacy Flow projection");
}

function endpointObservation(candidate: QueryCandidate, role: "source" | "sink", verification: QueryVerification): EndpointObservation {
  const probe = candidate.probe_evidence;
  const locations = probe?.[role].locations ?? [];
  if (probe?.status === "passed") {
    return {
      state: locations.length === 0 ? "not_found" : "observed",
      locations: locations.slice(0, 16).map((location) => ({ file: location.file, start_line: location.start_line, ...(location.end_line === undefined ? {} : { end_line: location.end_line }) })),
    };
  }
  return { state: verification.compile.status === "passed" ? "not_run" : "not_run", locations: [] };
}

function pathObservation(observation: QueryDatabaseObservation): FlowAnalyzerObservation["path"] {
  if (observation.status !== "passed") return { state: "not_run", path_count: 0 };
  return { state: observation.code_flow_count > 0 ? "observed" : "not_observed", path_count: observation.code_flow_count };
}
