import type {
  EvidenceOperationMode,
  FlowAnalyzerObservation,
  FlowCompactObservation,
  FlowDecision,
  FlowExpectation,
  FlowRevisionHint,
  VerificationLevel,
} from "@autovul/contracts";

export interface FlowDecisionProjection {
  readonly decision: FlowDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly FlowCompactObservation[];
  readonly revisionHints: readonly FlowRevisionHint[];
  readonly allowedNextActions: readonly ("revise" | "execute" | "replay" | "stop")[];
}

/** Core-owned, deterministic interpretation of analyzer facts. */
export function decideFlow(
  observation: FlowAnalyzerObservation,
  mode: EvidenceOperationMode,
  expectation?: FlowExpectation,
): FlowDecisionProjection {
  const observations: FlowCompactObservation[] = [];
  const revisionHints: FlowRevisionHint[] = [];
  addEndpoint(observations, revisionHints, "SOURCE", "/source", observation.source, "source");
  addEndpoint(observations, revisionHints, "SINK", "/sink", observation.sink, "sink");
  observations.push({ code: pathCode(observation.path.state), ...(observation.evidence_refs[0] === undefined ? {} : { evidence_ref: observation.evidence_refs[0] }) });

  if (observation.capability_gaps.length > 0) {
    for (const gap of observation.capability_gaps) {
      observations.push({ code: "CAPABILITY_MISMATCH", path: gap.path });
      revisionHints.push({ action: hintAction(gap.path), path: gap.path, reason_code: gap.code });
    }
    return projection({ capability: "flow", outcome: "unknown" }, "generated", observations, revisionHints, ["revise", "stop"]);
  }
  // A probe may establish endpoint facts, but never runs the authoritative
  // path query. Keep even a malformed adapter's compile claim from inflating
  // the evidence grade or turning probe output into a path conclusion.
  if (mode === "probe") {
    return projection(
      { capability: "flow", outcome: "unknown" },
      "generated",
      observations,
      revisionHints,
      ["execute", "stop"],
    );
  }

  if (observation.compile_accepted !== true) {
    observations.push({ code: observation.compile_accepted === false ? "COMPILE_REJECTED" : "COMPILE_NOT_RUN" });
    return projection({ capability: "flow", outcome: "unknown" }, "generated", observations, revisionHints, ["revise", "stop"]);
  }

  const outcome = observation.path.state === "observed"
    ? "connected"
    : observation.path.state === "not_run"
      ? "unknown"
      : "no_path";
  if (outcome === "no_path" && observation.source.state === "observed" && observation.sink.state === "observed") {
    observations.push({ code: "ENDPOINTS_OBSERVED_WITHOUT_PATH" });
    revisionHints.push({ action: "revise_step", path: "/steps", reason_code: "ENDPOINTS_OBSERVED_WITHOUT_PATH" });
  }
  let decision: FlowDecision = { capability: "flow", outcome };
  let verificationLevel: VerificationLevel = "compiled";
  if (outcome === "connected" && expectation !== undefined && pathMatches(observation.path.path_count, expectation.vulnerable)) {
    verificationLevel = "reproduced";
  }
  if (mode === "differential" && expectation?.fixed !== undefined) {
    const fixed = observation.fixed_path;
    const fixedOutcome = fixed?.state === "observed" ? "connected" : fixed?.state === "not_observed" ? "no_path" : "unknown";
    const fixedPolicySatisfied = fixed !== undefined && fixed.state !== "not_run" && pathMatches(fixed.path_count, expectation.fixed);
    decision = { ...decision, fixed_outcome: fixedOutcome, fixed_policy_satisfied: fixedPolicySatisfied };
    if (verificationLevel === "reproduced" && fixedPolicySatisfied) verificationLevel = "differential";
  }
  if (observation.analyzer.evidence_kind === "test_double") verificationLevel = "generated";
  const nextActions = outcome === "connected" ? ["replay", "stop"] as const : ["revise", "execute", "stop"] as const;
  return projection(decision, verificationLevel, observations, revisionHints, nextActions);
}

function addEndpoint(
  observations: FlowCompactObservation[], hints: FlowRevisionHint[], prefix: "SOURCE" | "SINK", path: "/source" | "/sink",
  endpoint: FlowAnalyzerObservation["source"], role: "source" | "sink",
): void {
  const code = `${prefix}_${endpoint.state === "observed" ? "OBSERVED" : endpoint.state === "not_found" ? "NOT_FOUND" : "NOT_RUN"}`;
  observations.push({ code, path, ...(endpoint.locations.length === 0 ? {} : { locations: endpoint.locations.slice(0, 8) }) });
  if (endpoint.state === "not_found") hints.push({ action: role === "source" ? "revise_source" : "revise_sink", path, reason_code: code });
}

function pathCode(state: FlowAnalyzerObservation["path"]["state"]): string {
  return state === "observed" ? "PATH_OBSERVED" : state === "not_observed" ? "PATH_NOT_OBSERVED" : "PATH_NOT_RUN";
}

function hintAction(path: string): FlowRevisionHint["action"] {
  if (path.startsWith("/source")) return "revise_source";
  if (path.startsWith("/sink")) return "revise_sink";
  if (path.startsWith("/barriers")) return "revise_barrier";
  return "revise_step";
}

function pathMatches(count: number, expected: { min_paths: number; max_paths: number }): boolean {
  return count >= expected.min_paths && count <= expected.max_paths;
}

function projection(
  decision: FlowDecision, verificationLevel: VerificationLevel, observations: readonly FlowCompactObservation[],
  revisionHints: readonly FlowRevisionHint[], allowedNextActions: FlowDecisionProjection["allowedNextActions"],
): FlowDecisionProjection {
  return { decision, verificationLevel, observations: observations.slice(0, 16), revisionHints: revisionHints.slice(0, 8), allowedNextActions };
}
