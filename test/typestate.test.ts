import { describe, expect, it } from "vitest";
import { Value } from "typebox/value";

import {
  TYPESTATE_LIMITS,
  AutovulResearchToolInputSchema,
  ResearchCapabilitySchema,
  ResearchHypothesisVersionSchema,
  ResearchRequestSchema,
  TypestateAnalyzerObservationSchema,
  TypestateHypothesisSchema,
  TypestateResearchToolInputSchema,
  type TypestateAnalyzerObservation,
} from "@autovul/contracts";
import { decideTypestate, validateTypestateHypothesis } from "@autovul/core";

const scope = {
  kind: "single_file_named_function" as const,
  file: "ghost/core/core/server/services/auth/session/session-service.js",
  entry: { kind: "named_function" as const, name: "createSessionForUser" },
  event_scope: "named_function_including_inline_callbacks" as const,
  alias_boundary: "direct_lexical_binding" as const,
};

const hypothesis = {
  schema_version: "autovul.typestate/1" as const,
  hypothesis_id: "tstate-ghost",
  language: "javascript" as const,
  resource: {
    id: "login_session",
    kind: "local_binding" as const,
    binding_name: "session",
    acquisition_event: "session_acquired",
    identity_model: "direct_lexical_binding" as const,
  },
  initial_state: "preauth",
  states: ["preauth", "rekeyed", "authenticated"],
  events: [
    { id: "session_acquired", selector: { kind: "direct_call" as const, name: "getSession" } },
    { id: "regenerate_request_session", selector: { kind: "direct_method" as const, receiver: "req.session", name: "regenerate" } },
    { id: "assign_user", selector: { kind: "direct_call" as const, name: "assignUserToSession", argument_property: "session" } },
  ],
  transitions: [
    { from_state: "preauth", event: "session_acquired", to_state: "preauth" },
    { from_state: "preauth", event: "regenerate_request_session", to_state: "rekeyed" },
    { from_state: "rekeyed", event: "assign_user", to_state: "authenticated" },
  ],
  violation: {
    kind: "prohibited_transition" as const,
    from_state: "preauth",
    event: "assign_user",
    to_state: "authenticated",
    requires_same_identity: true as const,
  },
  analysis_scope: scope,
} as const;

const location = { file: scope.file, start_line: 10, end_line: 10 };

function vulnerableTrace(overrides: Partial<TypestateAnalyzerObservation["traces"][number]> = {}) {
  return {
    state: "violating_witness" as const,
    resource_id: "login_session",
    events: [
      { event_id: "session_acquired", from_state: "preauth", to_state: "preauth", location },
      { event_id: "assign_user", from_state: "preauth", to_state: "authenticated", location },
    ],
    identity_evidence: [{ kind: "same_binding" as const, resource_id: "login_session", event_ids: ["session_acquired", "assign_user"], locations: [location] }],
    violation_step: 1,
    evidence_ref: "vulnerable.sarif",
    ...overrides,
  };
}

function fixedTrace(overrides: Partial<TypestateAnalyzerObservation["traces"][number]> = {}) {
  return {
    state: "safe_trace" as const,
    resource_id: "login_session",
    events: [
      { event_id: "session_acquired", from_state: "preauth", to_state: "preauth", location },
      { event_id: "regenerate_request_session", from_state: "preauth", to_state: "rekeyed", location },
      { event_id: "assign_user", from_state: "rekeyed", to_state: "authenticated", location },
    ],
    identity_evidence: [{ kind: "identity_change" as const, resource_id: "login_session", event_ids: ["session_acquired", "regenerate_request_session", "assign_user"], locations: [location] }],
    evidence_ref: "fixed.sarif",
    ...overrides,
  };
}

function renameTraceEvent(trace: TypestateAnalyzerObservation["traces"][number], from: string, to: string) {
  return {
    ...trace,
    events: trace.events.map((event) => event.event_id === from ? { ...event, event_id: to } : event),
    identity_evidence: trace.identity_evidence.map((evidence) => ({
      ...evidence,
      event_ids: evidence.event_ids.map((eventId) => eventId === from ? to : eventId),
    })),
  };
}

function observation(overrides: Partial<TypestateAnalyzerObservation> = {}): TypestateAnalyzerObservation {
  return {
    schema_version: "autovul.typestate/1",
    compile_accepted: true,
    resource: { state: "observed", locations: [location], identity_evidence: ["binding:vulnerable"] },
    events: [
      { event_id: "session_acquired", state: "observed", locations: [location] },
      { event_id: "regenerate_request_session", state: "not_found", locations: [] },
      { event_id: "assign_user", state: "observed", locations: [location] },
    ],
    traces: [vulnerableTrace()],
    fixed_resource: { state: "observed", locations: [location], identity_evidence: ["binding:fixed"] },
    fixed_events: [
      { event_id: "session_acquired", state: "observed", locations: [location] },
      { event_id: "regenerate_request_session", state: "observed", locations: [location] },
      { event_id: "assign_user", state: "observed", locations: [location] },
    ],
    fixed_traces: [fixedTrace()],
    completeness: { vulnerable: { status: "complete", scope, limitations: ["cross_file_aliases_excluded"] }, fixed: { status: "complete", scope, limitations: ["cross_file_aliases_excluded"] } },
    capability_gaps: [],
    evidence_refs: ["vulnerable.sarif", "fixed.sarif"],
    analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", version: "CodeQL CLI 2.26.1", adapter_version: "autovul.codeql-typestate/1" },
    ...overrides,
  };
}

describe("Typestate v1 contracts and pure policy", () => {
  it("freezes the narrow schema limits and selector enums", () => {
    expect(Value.Check(TypestateHypothesisSchema, hypothesis)).toBe(true);
    expect(TYPESTATE_LIMITS).toMatchObject({ maxStates: 4, maxEvents: 4, maxTransitions: 8, maxTraceEvents: 8, maxLocationsPerItem: 4 });
    expect(Value.Check(TypestateHypothesisSchema, { ...hypothesis, states: [...hypothesis.states, "rekeyed_2", "rekeyed_3"] })).toBe(false);
    const invalidSelector = validateTypestateHypothesis({
      ...hypothesis,
      events: hypothesis.events.map((event, index) => index === 0
        ? { ...event, selector: { kind: "unknown", name: "getSession" } }
        : event),
    });
    expect(invalidSelector.issues.some((issue) => issue.code === "TSTATE_EVENT_SELECTOR_KIND_INVALID" && issue.path === "/events/0/selector/kind")).toBe(true);
    const unreachable = validateTypestateHypothesis({ ...hypothesis, states: [...hypothesis.states, "unreachable"] });
    expect(unreachable.issues.some((issue) => issue.code === "TSTATE_STATE_UNREACHABLE" && issue.path === "/states/3")).toBe(true);
  });

  it("routes the Typestate branch through the aggregate research contract", () => {
    expect(Value.Check(ResearchCapabilitySchema, "typestate")).toBe(true);
    expect(Value.Check(ResearchHypothesisVersionSchema, "autovul.typestate/1")).toBe(true);
    expect(Value.Check(ResearchRequestSchema, { action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis })).toBe(true);
    expect(Value.Check(TypestateResearchToolInputSchema, { action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis })).toBe(true);
    expect(Value.Check(AutovulResearchToolInputSchema, { action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis })).toBe(true);
  });

  it("rejects unknown fields, duplicate ids, bad endpoints, and bad identity requirements", () => {
    expect(validateTypestateHypothesis({ ...hypothesis, unexpected: true })).toMatchObject({ valid: false, issues: expect.arrayContaining([{ code: "TSTATE_UNKNOWN_PROPERTY", path: "/unexpected" }]) });
    expect(validateTypestateHypothesis({ ...hypothesis, events: [...hypothesis.events, hypothesis.events[0]] })).toMatchObject({ valid: false, issues: expect.arrayContaining([{ code: "TSTATE_DUPLICATE_EVENT_ID", path: "/events/3/id" }]) });
    const duplicateState = validateTypestateHypothesis({ ...hypothesis, states: ["preauth", "preauth", "rekeyed", "authenticated"] });
    expect(duplicateState.issues.some((issue) => issue.code === "TSTATE_DUPLICATE_STATE_ID" && issue.path === "/states/1")).toBe(true);
    const badEndpoint = validateTypestateHypothesis({ ...hypothesis, transitions: [{ ...hypothesis.transitions[0], to_state: "closed" }] });
    expect(badEndpoint.issues.some((issue) => issue.code === "TSTATE_TRANSITION_TO_STATE_UNKNOWN" && issue.path === "/transitions/0/to_state")).toBe(true);
    const badIdentity = validateTypestateHypothesis({ ...hypothesis, violation: { ...hypothesis.violation, requires_same_identity: false } });
    expect(badIdentity.issues.some((issue) => issue.code === "TSTATE_IDENTITY_REQUIREMENT_INVALID" && issue.path === "/violation/requires_same_identity")).toBe(true);
    const prohibitedAllowed = validateTypestateHypothesis({ ...hypothesis, transitions: [...hypothesis.transitions, { from_state: "preauth", event: "assign_user", to_state: "authenticated" }] });
    expect(prohibitedAllowed.issues.some((issue) => issue.code === "TSTATE_PROHIBITED_TRANSITION_ALLOWED" && issue.path === "/transitions/3")).toBe(true);
  });

  it("accepts only the declared finite protocol and returns field-level revision issues", () => {
    expect(validateTypestateHypothesis(hypothesis)).toMatchObject({ valid: true, allowed_next_actions: ["execute", "stop"] });
    expect(validateTypestateHypothesis({ ...hypothesis, resource: { ...hypothesis.resource, acquisition_event: "unknown_event" } })).toMatchObject({ valid: false, issues: [{ code: "TSTATE_RESOURCE_ACQUISITION_EVENT_UNKNOWN", path: "/resource/acquisition_event" }] });
    const badViolationEvent = validateTypestateHypothesis({ ...hypothesis, violation: { ...hypothesis.violation, event: "unknown_event" } });
    expect(badViolationEvent.issues.some((issue) => issue.code === "TSTATE_VIOLATION_EVENT_UNKNOWN" && issue.path === "/violation/event")).toBe(true);
  });

  it("requires an identity-backed ordered witness for violation_observed", () => {
    const result = decideTypestate(observation(), "reproduce", hypothesis);
    expect(result.decision).toEqual({ capability: "typestate", outcome: "violation_observed" });
    expect(result.verificationLevel).toBe("reproduced");
    expect(result.allowedNextActions).toEqual(["replay", "stop"]);
  });

  it("raises differential only with a complete fixed safe trace", () => {
    const result = decideTypestate(observation(), "differential", hypothesis);
    expect(result).toMatchObject({ verificationLevel: "differential", decision: { fixed_outcome: "no_violation_observed", fixed_policy_satisfied: true } });

    const fixedBoth = decideTypestate(observation({ fixed_traces: [fixedTrace(), vulnerableTrace({ evidence_ref: "fixed.sarif" })] }), "differential", hypothesis);
    expect(fixedBoth).toMatchObject({ verificationLevel: "reproduced", decision: { fixed_outcome: "violation_observed", fixed_policy_satisfied: false } });

    const incompleteFixed = decideTypestate(observation({ completeness: { vulnerable: { status: "complete", scope, limitations: [] }, fixed: { status: "incomplete", scope, limitations: [] } } }), "differential", hypothesis);
    expect(incompleteFixed).toMatchObject({ verificationLevel: "reproduced", decision: { fixed_outcome: "unknown", fixed_policy_satisfied: false }, observations: expect.arrayContaining([{ code: "TSTATE_COMPLETENESS_INCOMPLETE", path: "/analysis_scope" }]) });
  });

  it("rejects a different identity instead of trusting call order", () => {
    const differentIdentity = decideTypestate(observation({ traces: [vulnerableTrace({ resource_id: "other_session", identity_evidence: [{ kind: "same_binding", resource_id: "other_session", event_ids: ["session_acquired", "assign_user"], locations: [location] }] })] }), "reproduce", hypothesis);
    expect(differentIdentity).toMatchObject({ decision: { outcome: "unknown" }, revisionHints: [{ action: "revise_resource", path: "/resource", reason_code: "TSTATE_IDENTITY_EVIDENCE_INVALID" }] });
  });

  it("rejects an incorrect transition and does not invent a missing event", () => {
    const wrongTransition = decideTypestate(observation({ traces: [vulnerableTrace({ events: [vulnerableTrace().events[0], { event_id: "assign_user", from_state: "preauth", to_state: "rekeyed", location }] })] }), "reproduce", hypothesis);
    expect(wrongTransition).toMatchObject({ decision: { outcome: "unknown" }, revisionHints: [{ action: "revise_transition", path: "/violation", reason_code: "TSTATE_TRANSITION_MISMATCH" }] });

    const discontinuous = decideTypestate(observation({ traces: [vulnerableTrace({
      events: [
        { event_id: "session_acquired", from_state: "preauth", to_state: "preauth", location },
        { event_id: "regenerate_request_session", from_state: "preauth", to_state: "rekeyed", location },
        { event_id: "assign_user", from_state: "preauth", to_state: "authenticated", location },
      ],
      identity_evidence: [{ kind: "same_binding" as const, resource_id: "login_session", event_ids: ["session_acquired", "assign_user"], locations: [location] }],
      violation_step: 2,
    })] }), "reproduce", hypothesis);
    expect(discontinuous).toMatchObject({ decision: { outcome: "unknown" }, revisionHints: [{ action: "revise_transition", reason_code: "TSTATE_TRANSITION_MISMATCH" }] });

    const missingAssign = decideTypestate(observation({ events: observation().events.map((event) => event.event_id === "assign_user" ? { ...event, state: "not_found" as const, locations: [] } : event), traces: [] }), "reproduce", hypothesis);
    expect(missingAssign).toMatchObject({ decision: { outcome: "unknown" }, revisionHints: [{ action: "revise_event", path: "/events", reason_code: "TSTATE_EVENT_NOT_FOUND" }] });
  });

  it("derives the identity-change event from transitions and evidence", () => {
    const renamedEvent = "rotate_session";
    const renamedHypothesis = {
      ...hypothesis,
      events: hypothesis.events.map((event) => event.id === "regenerate_request_session" ? { ...event, id: renamedEvent } : event),
      transitions: hypothesis.transitions.map((transition) => transition.event === "regenerate_request_session" ? { ...transition, event: renamedEvent } : transition),
    };
    const renamed = observation({
      events: observation().events.map((event) => event.event_id === "regenerate_request_session" ? { ...event, event_id: renamedEvent } : event),
      fixed_events: observation().fixed_events?.map((event) => event.event_id === "regenerate_request_session" ? { ...event, event_id: renamedEvent } : event),
      fixed_traces: [renameTraceEvent(fixedTrace(), "regenerate_request_session", renamedEvent)],
    });
    expect(decideTypestate(renamed, "differential", renamedHypothesis)).toMatchObject({ verificationLevel: "differential", decision: { fixed_outcome: "no_violation_observed", fixed_policy_satisfied: true } });
  });

  it("keeps incomplete scope, probe facts, and test doubles from becoming completed evidence", () => {
    const incomplete = decideTypestate(observation({ completeness: { vulnerable: { status: "incomplete", scope, limitations: [] } } }), "reproduce", hypothesis);
    expect(incomplete).toMatchObject({ decision: { outcome: "unknown" }, verificationLevel: "compiled", revisionHints: [{ action: "revise_scope", path: "/analysis_scope" }] });

    const probe = decideTypestate(observation(), "probe", hypothesis);
    expect(probe).toMatchObject({ decision: { outcome: "unknown" }, verificationLevel: "generated" });

    const testDouble = decideTypestate(observation({ analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "test_double" } }), "reproduce", hypothesis);
    expect(testDouble.decision.outcome).toBe("violation_observed");
    expect(testDouble.verificationLevel).toBe("generated");
  });

  it("keeps the analyzer observation shape independent from the decision", () => {
    expect(Value.Check(TypestateAnalyzerObservationSchema, observation())).toBe(true);
    expect(Value.Check(TypestateAnalyzerObservationSchema, { ...observation(), decision: { capability: "typestate", outcome: "violation_observed" } })).toBe(false);
  });
});
