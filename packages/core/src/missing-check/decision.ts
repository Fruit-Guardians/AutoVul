import type {
  EvidenceOperationMode,
  MissingCheckAnalyzerObservation,
  MissingCheckCompactObservation,
  MissingCheckDecision,
  MissingCheckRevisionHint,
  VerificationLevel,
} from "@autovul/contracts";

export interface MissingCheckDecisionProjection {
  readonly decision: MissingCheckDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly MissingCheckCompactObservation[];
  readonly revisionHints: readonly MissingCheckRevisionHint[];
  readonly allowedNextActions: readonly ("revise" | "execute" | "replay" | "stop")[];
}

/** Core is the sole interpreter of check/operation observations. */
export function decideMissingCheck(observation: MissingCheckAnalyzerObservation, mode: EvidenceOperationMode): MissingCheckDecisionProjection {
  const observations: MissingCheckCompactObservation[] = [];
  const hints: MissingCheckRevisionHint[] = [];
  subject(observations, hints, "OPERATION", "/operation", observation.operation, "revise_operation");
  subject(observations, hints, "CHECK", "/required_check", observation.required_check, "revise_check");
  observations.push({ code: relationCode(observation.relation.state), path: "/required_relation", ...(observation.evidence_refs[0] === undefined ? {} : { evidence_ref: observation.evidence_refs[0] }) });
  if (observation.capability_gaps.length > 0) {
    for (const gap of observation.capability_gaps) {
      observations.push({ code: "MCHECK_CAPABILITY_MISMATCH", path: gap.path });
      hints.push({ action: gap.path.startsWith("/operation") ? "revise_operation" : gap.path.startsWith("/required_check") ? "revise_check" : gap.path.startsWith("/scope") ? "revise_scope" : "revise_relation", path: gap.path, reason_code: gap.code });
    }
    return result({ capability: "missing_check", outcome: "unknown" }, "generated", observations, hints, ["revise", "stop"]);
  }
  if (mode === "probe") return result({ capability: "missing_check", outcome: "unknown" }, "generated", observations, hints, ["execute", "stop"]);
  if (observation.compile_accepted !== true) {
    observations.push({ code: observation.compile_accepted === false ? "MCHECK_COMPILE_REJECTED" : "MCHECK_COMPILE_NOT_RUN" });
    return result({ capability: "missing_check", outcome: "unknown" }, "generated", observations, hints, ["revise", "stop"]);
  }
  const outcome = outcomeFor(observation.relation);
  let decision: MissingCheckDecision = { capability: "missing_check", outcome };
  let verificationLevel: VerificationLevel = "compiled";
  if (outcome === "check_missing") verificationLevel = "reproduced";
  if (mode === "differential") {
    const fixedOutcome = observation.fixed_relation === undefined ? "unknown" : outcomeFor(observation.fixed_relation);
    const fixedPolicySatisfied = fixedOutcome === "check_present";
    decision = { ...decision, fixed_outcome: fixedOutcome, fixed_policy_satisfied: fixedPolicySatisfied };
    if (verificationLevel === "reproduced" && fixedPolicySatisfied) verificationLevel = "differential";
  }
  const actions = outcome === "check_missing" ? ["replay", "stop"] as const : ["revise", "execute", "stop"] as const;
  return result(decision, verificationLevel, observations, hints, actions);
}

function outcomeFor(relation: MissingCheckAnalyzerObservation["relation"]): MissingCheckDecision["outcome"] {
  if (relation.state === "unchecked_witness" && relation.unchecked_witnesses.length > 0) return "check_missing";
  if (relation.state === "checked_witness" && relation.checked_witnesses.length > 0) return "check_present";
  return "unknown";
}

function subject(
  observations: MissingCheckCompactObservation[], hints: MissingCheckRevisionHint[], prefix: "OPERATION" | "CHECK", path: "/operation" | "/required_check",
  value: MissingCheckAnalyzerObservation["operation"], action: "revise_operation" | "revise_check",
): void {
  const suffix = value.state === "observed" ? "OBSERVED" : value.state === "not_found" ? "NOT_FOUND" : "NOT_RUN";
  observations.push({ code: `MCHECK_${prefix}_${suffix}`, path, ...(value.locations.length === 0 ? {} : { locations: value.locations.slice(0, 8) }) });
  if (value.state === "not_found") hints.push({ action, path, reason_code: `MCHECK_${prefix}_NOT_FOUND` });
}

function relationCode(state: MissingCheckAnalyzerObservation["relation"]["state"]): string {
  return `MCHECK_RELATION_${state === "unchecked_witness" ? "UNCHECKED_WITNESS" : state === "checked_witness" ? "CHECKED_WITNESS" : state === "inconclusive" ? "INCONCLUSIVE" : "NOT_RUN"}`;
}

function result(
  decision: MissingCheckDecision, verificationLevel: VerificationLevel, observations: readonly MissingCheckCompactObservation[], revisionHints: readonly MissingCheckRevisionHint[], allowedNextActions: MissingCheckDecisionProjection["allowedNextActions"],
): MissingCheckDecisionProjection {
  return { decision, verificationLevel, observations: observations.slice(0, 16), revisionHints: revisionHints.slice(0, 8), allowedNextActions };
}
