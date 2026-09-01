import { TYPESTATE_LIMITS } from "@autovul/contracts";
import type {
  EvidenceOperationMode,
  TypestateAnalyzerObservation,
  TypestateCompactObservation,
  TypestateDecision,
  TypestateHypothesis,
  TypestateRevisionHint,
  TypestateTrace,
  TypestateOutcome,
  VerificationLevel,
} from "@autovul/contracts";

export interface TypestateDecisionProjection {
  readonly decision: TypestateDecision;
  readonly verificationLevel: VerificationLevel;
  readonly observations: readonly TypestateCompactObservation[];
  readonly revisionHints: readonly TypestateRevisionHint[];
  readonly allowedNextActions: readonly ("revise" | "execute" | "replay" | "stop")[];
}

/** Core-owned, deterministic interpretation of Typestate analyzer facts. */
export function decideTypestate(
  observation: TypestateAnalyzerObservation,
  mode: EvidenceOperationMode,
  hypothesis: TypestateHypothesis,
): TypestateDecisionProjection {
  const observations: TypestateCompactObservation[] = [];
  const revisionHints: TypestateRevisionHint[] = [];
  addResourceObservation(observations, revisionHints, observation.resource);
  addEventObservations(observations, observation.events);
  addTraceObservations(observations, observation.traces);

  if (observation.capability_gaps.length > 0) {
    for (const gap of observation.capability_gaps) {
      observations.push({ code: "TSTATE_CAPABILITY_MISMATCH", path: gap.path });
      revisionHints.push({ action: hintAction(gap.path), path: gap.path, reason_code: gap.code });
    }
    return projection({ capability: "typestate", outcome: "unknown" }, "generated", observations, revisionHints, ["revise", "stop"]);
  }
  if (mode === "probe") {
    return projection({ capability: "typestate", outcome: "unknown" }, "generated", observations, revisionHints, ["execute", "stop"]);
  }
  if (observation.compile_accepted !== true) {
    observations.push({ code: observation.compile_accepted === false ? "TSTATE_COMPILE_REJECTED" : "TSTATE_COMPILE_NOT_RUN" });
    return projection({ capability: "typestate", outcome: "unknown" }, "generated", observations, revisionHints, ["revise", "stop"]);
  }

  const vulnerableCompleteness = completenessIssue(observation.completeness.vulnerable, hypothesis);
  if (vulnerableCompleteness !== undefined) {
    observations.push({ code: vulnerableCompleteness.code, path: "/analysis_scope" });
    revisionHints.push({ action: "revise_scope", path: "/analysis_scope", reason_code: vulnerableCompleteness.code });
    return projection({ capability: "typestate", outcome: "unknown" }, evidenceLevel(observation, "compiled"), observations, revisionHints, ["revise", "stop"]);
  }

  const requiredObservationIssue = requiredEventIssue(observation, hypothesis);
  if (requiredObservationIssue !== undefined) {
    observations.push({ code: requiredObservationIssue.code, path: requiredObservationIssue.path });
    revisionHints.push({ action: requiredObservationIssue.action, path: requiredObservationIssue.path, reason_code: requiredObservationIssue.code });
    return projection({ capability: "typestate", outcome: "unknown" }, evidenceLevel(observation, "compiled"), observations, revisionHints, ["revise", "stop"]);
  }

  const vulnerableEvaluation = evaluateTraces(observation.traces, observation.evidence_refs, hypothesis);
  addTraceEvaluation(observations, revisionHints, vulnerableEvaluation);
  if (vulnerableEvaluation.inconclusiveCode !== undefined) {
    return projection({ capability: "typestate", outcome: "unknown" }, evidenceLevel(observation, "compiled"), observations, revisionHints, ["revise", "stop"]);
  }

  const vulnerableOutcome: TypestateOutcome = vulnerableEvaluation.violation ? "violation_observed" : "no_violation_observed";
  let decision: TypestateDecision = { capability: "typestate", outcome: vulnerableOutcome };
  let verificationLevel = evidenceLevel(observation, vulnerableOutcome === "violation_observed" ? "reproduced" : "compiled");

  if (mode === "differential") {
    const fixed = evaluateFixed(observation, hypothesis);
    if (fixed.completenessCode !== undefined) {
      observations.push({ code: fixed.completenessCode, path: "/analysis_scope" });
      revisionHints.push({ action: "revise_scope", path: "/analysis_scope", reason_code: fixed.completenessCode });
    }
    if (fixed.traceCode !== undefined) observations.push({ code: fixed.traceCode, path: "/fixed_traces" });
    const fixedOutcome: TypestateOutcome = fixed.violation
      ? "violation_observed"
      : fixed.unknown
        ? "unknown"
        : "no_violation_observed";
    const fixedPolicySatisfied = fixed.completenessCode === undefined
      && !fixed.violation
      && !fixed.unknown
      && fixed.safeTrace;
    decision = { ...decision, fixed_outcome: fixedOutcome, fixed_policy_satisfied: fixedPolicySatisfied };
    if (vulnerableOutcome === "violation_observed" && fixedPolicySatisfied) verificationLevel = evidenceLevel(observation, "differential");
    if (!fixedPolicySatisfied && fixedOutcome === "no_violation_observed") {
      observations.push({ code: "TSTATE_FIXED_POLICY_UNSATISFIED", path: "/fixed_traces" });
    }
  }

  const successful = vulnerableOutcome === "violation_observed" && (mode !== "differential" || decision.fixed_policy_satisfied === true);
  return projection(decision, verificationLevel, observations, revisionHints, successful ? ["replay", "stop"] : ["revise", "execute", "stop"]);
}

function addResourceObservation(
  observations: TypestateCompactObservation[],
  hints: TypestateRevisionHint[],
  resource: TypestateAnalyzerObservation["resource"],
): void {
  const suffix = resource.state === "observed" ? "OBSERVED" : resource.state === "not_found" ? "NOT_FOUND" : "NOT_RUN";
  observations.push({ code: `TSTATE_RESOURCE_${suffix}`, path: "/resource", ...(resource.locations.length === 0 ? {} : { locations: resource.locations }) });
  if (resource.state !== "observed") {
    hints.push({ action: "revise_resource", path: "/resource", reason_code: `TSTATE_RESOURCE_${suffix}` });
  }
  if (resource.identity_evidence.length === 0 && resource.state === "observed") {
    observations.push({ code: "TSTATE_IDENTITY_EVIDENCE_MISSING", path: "/resource" });
    hints.push({ action: "revise_resource", path: "/resource", reason_code: "TSTATE_IDENTITY_EVIDENCE_MISSING" });
  }
}

function addEventObservations(
  observations: TypestateCompactObservation[],
  events: TypestateAnalyzerObservation["events"],
): void {
  for (const event of events) {
    const suffix = event.state === "observed" ? "OBSERVED" : event.state === "not_found" ? "NOT_FOUND" : "NOT_RUN";
    observations.push({ code: `TSTATE_EVENT_${event.event_id}_${suffix}`, path: "/events", ...(event.locations.length === 0 ? {} : { locations: event.locations }) });
  }
}

function addTraceObservations(observations: TypestateCompactObservation[], traces: readonly TypestateTrace[]): void {
  for (const trace of traces) {
    const code = trace.state === "violating_witness"
      ? "TSTATE_TRACE_VIOLATING_WITNESS"
      : trace.state === "safe_trace"
        ? "TSTATE_TRACE_SAFE"
        : trace.state === "inconclusive"
          ? "TSTATE_TRACE_INCONCLUSIVE"
          : "TSTATE_TRACE_NOT_RUN";
    observations.push({ code, path: "/traces", evidence_ref: trace.evidence_ref });
  }
}

function requiredEventIssue(
  observation: TypestateAnalyzerObservation,
  hypothesis: TypestateHypothesis,
): { readonly code: string; readonly path: string; readonly action: "revise_resource" | "revise_event" } | undefined {
  if (observation.resource.state !== "observed") return { code: "TSTATE_RESOURCE_NOT_OBSERVED", path: "/resource", action: "revise_resource" };
  for (const eventId of [hypothesis.resource.acquisition_event, hypothesis.violation.event]) {
    const event = observation.events.find((candidate) => candidate.event_id === eventId);
    if (event === undefined || event.state === "not_run") return { code: "TSTATE_EVENT_NOT_RUN", path: "/events", action: "revise_event" };
    if (event.state === "not_found" && !isOptionalIdentityChangeEvent(hypothesis, eventId)) return { code: "TSTATE_EVENT_NOT_FOUND", path: "/events", action: "revise_event" };
  }
  return undefined;
}

function isOptionalIdentityChangeEvent(hypothesis: TypestateHypothesis, eventId: string): boolean {
  return identityChangeTransitionEventIds(hypothesis).has(eventId);
}

interface TraceEvaluation {
  readonly violation: boolean;
  readonly safeTrace: boolean;
  readonly inconclusiveCode?: string;
  readonly revision?: TypestateRevisionHint;
}

function evaluateTraces(
  traces: readonly TypestateTrace[],
  evidenceRefs: readonly string[],
  hypothesis: TypestateHypothesis,
): TraceEvaluation {
  let safeTrace = false;
  for (const trace of traces) {
    if (trace.state === "inconclusive" || trace.state === "not_run") {
      return { violation: false, safeTrace: false, inconclusiveCode: trace.state === "inconclusive" ? "TSTATE_TRACE_INCONCLUSIVE" : "TSTATE_TRACE_NOT_RUN" };
    }
    if (!evidenceRefs.includes(trace.evidence_ref)) {
      return { violation: false, safeTrace: false, inconclusiveCode: "TSTATE_TRACE_EVIDENCE_REF_INVALID", revision: { action: "revise_transition", path: "/traces", reason_code: "TSTATE_TRACE_EVIDENCE_REF_INVALID" } };
    }
    if (trace.state === "safe_trace") {
      const classification = classifySafeTrace(trace, hypothesis);
      if (classification === "valid") safeTrace = true;
      else {
        const reason = classification === "identity" ? "TSTATE_IDENTITY_EVIDENCE_INVALID" : "TSTATE_SAFE_TRACE_TRANSITION_MISMATCH";
        return {
          violation: false,
          safeTrace,
          inconclusiveCode: reason,
          revision: { action: classification === "identity" ? "revise_resource" : "revise_transition", path: classification === "identity" ? "/resource" : "/traces", reason_code: reason },
        };
      }
    }
    if (trace.state !== "violating_witness") continue;
    const classification = classifyViolatingTrace(trace, hypothesis);
    if (classification === "valid") return { violation: true, safeTrace };
    const reason = classification === "identity" ? "TSTATE_IDENTITY_EVIDENCE_INVALID" : "TSTATE_TRANSITION_MISMATCH";
    return {
      violation: false,
      safeTrace,
      inconclusiveCode: reason,
      revision: { action: classification === "identity" ? "revise_resource" : "revise_transition", path: classification === "identity" ? "/resource" : "/violation", reason_code: reason },
    };
  }
  return { violation: false, safeTrace };
}

function classifyViolatingTrace(trace: TypestateTrace, hypothesis: TypestateHypothesis): "valid" | "identity" | "transition" {
  if (trace.resource_id !== hypothesis.resource.id || !hasSameIdentityEvidence(trace, hypothesis)) return "identity";
  if (!hasContinuousStates(trace)) return "transition";
  const step = trace.violation_step;
  if (step === undefined || step >= trace.events.length) return "transition";
  const violationEvent = trace.events[step];
  if (violationEvent === undefined) return "transition";
  if (violationEvent.event_id !== hypothesis.violation.event
    || violationEvent.from_state !== hypothesis.violation.from_state
    || violationEvent.to_state !== hypothesis.violation.to_state) return "transition";
  const acquisitionIndex = trace.events.findIndex((event) => event.event_id === hypothesis.resource.acquisition_event);
  if (acquisitionIndex < 0 || acquisitionIndex >= step) return "transition";
  return trace.events.every((event, index) => index === step || isDeclaredTransition(event, hypothesis)) ? "valid" : "transition";
}

function classifySafeTrace(trace: TypestateTrace, hypothesis: TypestateHypothesis): "valid" | "identity" | "transition" {
  const acquisitionIndex = trace.events.findIndex((event) => event.event_id === hypothesis.resource.acquisition_event);
  const assignIndex = trace.events.findIndex((event) => event.event_id === hypothesis.violation.event);
  if (trace.resource_id !== hypothesis.resource.id) return "identity";
  if (!hasContinuousStates(trace)) return "transition";
  const identityChangeEvent = inferIdentityChangeEvent(trace, hypothesis, acquisitionIndex, assignIndex);
  if (identityChangeEvent === undefined) return "identity";
  const identityChangeIndex = trace.events.findIndex((event) => event.event_id === identityChangeEvent);
  if (acquisitionIndex < 0 || identityChangeIndex <= acquisitionIndex || assignIndex <= identityChangeIndex) return "transition";
  return trace.events.every((event) => isDeclaredTransition(event, hypothesis)) ? "valid" : "transition";
}

function hasSameIdentityEvidence(trace: TypestateTrace, hypothesis: TypestateHypothesis): boolean {
  return trace.identity_evidence.some((evidence) => evidence.kind === "same_binding"
    && evidence.resource_id === hypothesis.resource.id
    && evidence.event_ids.includes(hypothesis.resource.acquisition_event)
    && evidence.event_ids.includes(hypothesis.violation.event));
}

function inferIdentityChangeEvent(
  trace: TypestateTrace,
  hypothesis: TypestateHypothesis,
  acquisitionIndex: number,
  assignIndex: number,
): string | undefined {
  if (acquisitionIndex < 0 || assignIndex <= acquisitionIndex) return undefined;
  const evidence = trace.identity_evidence.find((candidate) => candidate.kind === "identity_change"
    && candidate.resource_id === hypothesis.resource.id
    && candidate.event_ids.includes(hypothesis.resource.acquisition_event)
    && candidate.event_ids.includes(hypothesis.violation.event));
  if (evidence === undefined) return undefined;
  const candidates = trace.events.filter((event, index) => index > acquisitionIndex
    && index < assignIndex
    && event.from_state !== event.to_state
    && identityChangeTransitionEventIds(hypothesis).has(event.event_id)
    && evidence.event_ids.includes(event.event_id)
    && isDeclaredTransition(event, hypothesis));
  return candidates.length === 1 ? candidates[0]?.event_id : undefined;
}

function identityChangeTransitionEventIds(hypothesis: TypestateHypothesis): Set<string> {
  return new Set(hypothesis.transitions
    .filter((transition) => transition.from_state === hypothesis.violation.from_state
      && transition.to_state !== transition.from_state
      && transition.event !== hypothesis.violation.event)
    .map((transition) => transition.event));
}

function hasContinuousStates(trace: TypestateTrace): boolean {
  return trace.events.every((event, index) => index === 0 || trace.events[index - 1]?.to_state === event.from_state);
}

function isDeclaredTransition(event: { readonly event_id: string; readonly from_state: string; readonly to_state: string }, hypothesis: TypestateHypothesis): boolean {
  return hypothesis.transitions.some((transition) => transition.event === event.event_id
    && transition.from_state === event.from_state
    && transition.to_state === event.to_state);
}

function evaluateFixed(
  observation: TypestateAnalyzerObservation,
  hypothesis: TypestateHypothesis,
): { readonly violation: boolean; readonly safeTrace: boolean; readonly unknown: boolean; readonly completenessCode?: string; readonly traceCode?: string } {
  const fixedCompleteness = observation.completeness.fixed;
  if (fixedCompleteness === undefined) return { violation: false, safeTrace: false, unknown: true, completenessCode: "TSTATE_FIXED_COMPLETENESS_NOT_RUN" };
  const completenessCode = completenessIssue(fixedCompleteness, hypothesis)?.code;
  if (completenessCode !== undefined) return { violation: false, safeTrace: false, unknown: true, completenessCode };
  if (observation.fixed_resource?.state !== "observed") return { violation: false, safeTrace: false, unknown: true, traceCode: "TSTATE_FIXED_RESOURCE_NOT_OBSERVED" };
  const traces = observation.fixed_traces;
  if (traces === undefined) return { violation: false, safeTrace: false, unknown: true, traceCode: "TSTATE_FIXED_TRACES_NOT_RUN" };
  const evaluation = evaluateTraces(traces, observation.evidence_refs, hypothesis);
  const result = {
    violation: evaluation.violation,
    safeTrace: evaluation.safeTrace,
    unknown: evaluation.inconclusiveCode !== undefined,
  };
  return evaluation.inconclusiveCode === undefined ? result : { ...result, traceCode: evaluation.inconclusiveCode };
}

function addTraceEvaluation(
  observations: TypestateCompactObservation[],
  hints: TypestateRevisionHint[],
  evaluation: TraceEvaluation,
): void {
  if (evaluation.inconclusiveCode !== undefined) observations.push({ code: evaluation.inconclusiveCode, path: "/traces" });
  if (evaluation.revision !== undefined) hints.push(evaluation.revision);
}

function completenessIssue(
  completeness: TypestateAnalyzerObservation["completeness"]["vulnerable"],
  hypothesis: TypestateHypothesis,
): { readonly code: string } | undefined {
  if (completeness.status === "not_run") return { code: "TSTATE_COMPLETENESS_NOT_RUN" };
  if (completeness.status === "incomplete") return { code: "TSTATE_COMPLETENESS_INCOMPLETE" };
  if (JSON.stringify(completeness.scope) !== JSON.stringify(hypothesis.analysis_scope)) return { code: "TSTATE_COMPLETENESS_SCOPE_MISMATCH" };
  return undefined;
}

function evidenceLevel(observation: TypestateAnalyzerObservation, desired: VerificationLevel): VerificationLevel {
  return observation.analyzer.evidence_kind === "test_double" ? "generated" : desired;
}

function hintAction(path: string): TypestateRevisionHintAction {
  if (path.startsWith("/resource")) return "revise_resource";
  if (path.startsWith("/events")) return "revise_event";
  if (path.startsWith("/violation")) return "revise_violation";
  if (path.startsWith("/transitions")) return "revise_transition";
  return "revise_scope";
}

type TypestateRevisionHintAction = TypestateRevisionHint["action"];

function projection(
  decision: TypestateDecision,
  verificationLevel: VerificationLevel,
  observations: readonly TypestateCompactObservation[],
  revisionHints: readonly TypestateRevisionHint[],
  allowedNextActions: TypestateDecisionProjection["allowedNextActions"],
): TypestateDecisionProjection {
  return {
    decision,
    verificationLevel,
    observations: observations.slice(0, TYPESTATE_LIMITS.maxCompactObservations),
    revisionHints: revisionHints.slice(0, TYPESTATE_LIMITS.maxRevisionHints),
    allowedNextActions,
  };
}
