import type {
  EvidenceOperationMode,
  MissingCheckAnalyzerObservation,
  MissingCheckCompactObservation,
  MissingCheckDecision,
  MissingCheckRevisionHint,
  MissingCheckScope,
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
export function decideMissingCheck(observation: MissingCheckAnalyzerObservation, mode: EvidenceOperationMode, declaredScope: MissingCheckScope): MissingCheckDecisionProjection {
  const observations: MissingCheckCompactObservation[] = [];
  const hints: MissingCheckRevisionHint[] = [];
  subject(observations, hints, "OPERATION", "/operation", observation.operation, "revise_operation");
  subject(observations, hints, "CHECK", "/required_check", observation.required_check, "revise_check");
  const vulnerableEvidenceRef = relationEvidence(observation.relation, observation.evidence_refs);
  observations.push({ code: relationCode(observation.relation.state), path: "/required_relation", ...(vulnerableEvidenceRef === undefined ? {} : { evidence_ref: vulnerableEvidenceRef }) });
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
  const vulnerableCompleteness = completenessIssue(observation.completeness.vulnerable, declaredScope, "/scope");
  if (vulnerableCompleteness !== undefined) {
    observations.push({ code: vulnerableCompleteness.code, path: "/scope" });
    hints.push({ action: "revise_scope", path: "/scope", reason_code: vulnerableCompleteness.code });
    return result({ capability: "missing_check", outcome: "unknown" }, observation.analyzer.evidence_kind === "test_double" ? "generated" : "compiled", observations, hints, ["revise", "stop"]);
  }
  const outcome = outcomeFor(observation.relation, observation.evidence_refs);
  if (observation.relation.state !== "inconclusive" && observation.relation.state !== "not_run" && outcome === "unknown") {
    observations.push({ code: "MCHECK_EVIDENCE_REF_INVALID", path: "/required_relation" });
    hints.push({ action: "revise_relation", path: "/required_relation", reason_code: "MCHECK_EVIDENCE_REF_INVALID" });
  }
  let decision: MissingCheckDecision = { capability: "missing_check", outcome };
  let verificationLevel: VerificationLevel = "compiled";
  if (outcome === "check_missing") verificationLevel = "reproduced";
  if (mode === "differential") {
    const fixedCompleteness = observation.completeness.fixed === undefined
      ? { code: "MCHECK_FIXED_COMPLETENESS_NOT_RUN" }
      : completenessIssue(observation.completeness.fixed, declaredScope, "/scope");
    const fixedOutcome = fixedCompleteness !== undefined || observation.fixed_relation === undefined
      ? "unknown"
      : outcomeFor(observation.fixed_relation, observation.evidence_refs);
    const fixedPolicySatisfied = fixedCompleteness === undefined && fixedOutcome === "check_present";
    if (fixedCompleteness !== undefined) observations.push({ code: fixedCompleteness.code, path: "/scope" });
    if (observation.fixed_relation !== undefined) {
      const fixedEvidenceRef = relationEvidence(observation.fixed_relation, observation.evidence_refs);
      observations.push({ code: `MCHECK_FIXED_${relationCode(observation.fixed_relation.state).slice("MCHECK_".length)}`, path: "/required_relation", ...(fixedEvidenceRef === undefined ? {} : { evidence_ref: fixedEvidenceRef }) });
    }
    decision = { ...decision, fixed_outcome: fixedOutcome, fixed_policy_satisfied: fixedPolicySatisfied };
    if (verificationLevel === "reproduced" && fixedPolicySatisfied) verificationLevel = "differential";
  }
  if (observation.analyzer.evidence_kind === "test_double") verificationLevel = "generated";
  const actions = outcome === "check_missing" ? ["replay", "stop"] as const : ["revise", "execute", "stop"] as const;
  return result(decision, verificationLevel, observations, hints, actions);
}

function outcomeFor(relation: MissingCheckAnalyzerObservation["relation"], evidenceRefs: readonly string[]): MissingCheckDecision["outcome"] {
  if (relation.state === "unchecked_witness" && relation.unchecked_witnesses.some((witness) => evidenceRefs.includes(witness.evidence_ref))) return "check_missing";
  if (relation.state === "checked_witness" && relation.checked_witnesses.some((witness) => evidenceRefs.includes(witness.evidence_ref))) return "check_present";
  return "unknown";
}

function relationEvidence(relation: MissingCheckAnalyzerObservation["relation"], evidenceRefs: readonly string[]): string | undefined {
  const witnesses = relation.state === "unchecked_witness" ? relation.unchecked_witnesses : relation.state === "checked_witness" ? relation.checked_witnesses : [];
  return witnesses.find((witness) => evidenceRefs.includes(witness.evidence_ref))?.evidence_ref;
}

function completenessIssue(
  completeness: MissingCheckAnalyzerObservation["completeness"]["vulnerable"],
  declaredScope: MissingCheckScope,
  _path: "/scope",
): { readonly code: string } | undefined {
  if (completeness.status === "not_run") return { code: "MCHECK_COMPLETENESS_NOT_RUN" };
  if (completeness.status === "incomplete") return { code: "MCHECK_COMPLETENESS_INCOMPLETE" };
  if (JSON.stringify(completeness.scope) !== JSON.stringify(declaredScope)) return { code: "MCHECK_COMPLETENESS_SCOPE_MISMATCH" };
  return undefined;
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
