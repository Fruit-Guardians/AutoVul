import { Value } from "typebox/value";

import {
  TYPESTATE_LIMITS,
  TYPESTATE_HYPOTHESIS_VERSION,
  TypestateHypothesisSchema,
  type TypestateEvent,
  type TypestateHypothesis,
  type TypestateValidationIssue,
  type TypestateValidationResult,
} from "@autovul/contracts";

const EVENT_SELECTOR_KINDS = ["direct_call", "direct_method"] as const;
const RESOURCE_KINDS = ["local_binding"] as const;
const SCOPE_KINDS = ["single_file_named_function"] as const;
const EVENT_SCOPES = ["named_function_including_inline_callbacks"] as const;
const ALIAS_BOUNDARIES = ["direct_lexical_binding"] as const;
const VIOLATION_KINDS = ["prohibited_transition"] as const;

/** Pure structural and graph validation; it never reads a target or writes an artifact. */
export function validateTypestateHypothesis(input: unknown): TypestateValidationResult {
  const issues = unique([...schemaIssues(input), ...semanticIssues(input)]).slice(0, TYPESTATE_LIMITS.maxIssueCount);
  if (issues.length > 0) return { valid: false, issues, allowed_next_actions: ["revise", "stop"] };
  return {
    valid: true,
    hypothesis: Value.Parse(TypestateHypothesisSchema, input) as TypestateHypothesis,
    issues: [],
    allowed_next_actions: ["execute", "stop"],
  };
}

function schemaIssues(input: unknown): TypestateValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return [{ code: "TSTATE_HYPOTHESIS_OBJECT_REQUIRED", path: "/", expected_kind: "object" }];
  }
  const record = input as Record<string, unknown>;
  const issues: TypestateValidationIssue[] = [];
  if (record.schema_version !== TYPESTATE_HYPOTHESIS_VERSION) {
    issues.push({ code: "TSTATE_HYPOTHESIS_VERSION_INVALID", path: "/schema_version", allowed_values: [TYPESTATE_HYPOTHESIS_VERSION] });
  }
  if (!Value.Check(TypestateHypothesisSchema, input)) {
    for (const error of Value.Errors(TypestateHypothesisSchema, input)) {
      const path = errorPath(error);
      const keyword = errorKeyword(error);
      if (keyword === "anyOf" || keyword === "oneOf") continue;
      if (selectorUnionAlternativeNoise(input, path, keyword)) continue;
      if (path === "/" && /union|expected/i.test(error.message)) continue;
      issues.push(schemaIssue(path, error.message));
    }
  }
  return issues;
}

function semanticIssues(input: unknown): TypestateValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [];
  const record = input as Record<string, unknown>;
  const issues: TypestateValidationIssue[] = [];
  const states = stringArray(record.states);
  const events = eventArray(record.events);
  const transitions = transitionArray(record.transitions);

  events.forEach((event, index) => {
    const kind = objectRecord(event.selector)?.kind;
    if (typeof kind === "string" && !EVENT_SELECTOR_KINDS.includes(kind as (typeof EVENT_SELECTOR_KINDS)[number])) {
      issues.push({ code: "TSTATE_EVENT_SELECTOR_KIND_INVALID", path: `/events/${index}/selector/kind`, allowed_values: [...EVENT_SELECTOR_KINDS] });
    }
  });

  addDuplicateIssues(states, "/states", "TSTATE_DUPLICATE_STATE_ID", issues);
  addDuplicateIssues(events.map((event) => event.id), "/events", "TSTATE_DUPLICATE_EVENT_ID", issues);
  if (typeof record.initial_state === "string" && !states.includes(record.initial_state)) {
    issues.push({ code: "TSTATE_INITIAL_STATE_UNKNOWN", path: "/initial_state", allowed_values: states.slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
  }

  const resource = objectRecord(record.resource);
  const acquisitionEvent = resource?.acquisition_event;
  if (typeof acquisitionEvent === "string" && !events.some((event) => event.id === acquisitionEvent)) {
    issues.push({ code: "TSTATE_RESOURCE_ACQUISITION_EVENT_UNKNOWN", path: "/resource/acquisition_event", allowed_values: events.map((event) => event.id).slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
  }

  const eventIds = new Set(events.map((event) => event.id));
  const stateIds = new Set(states);
  const transitionKeys = new Set<string>();
  transitions.forEach((transition, index) => {
    if (!stateIds.has(transition.from_state)) issues.push({ code: "TSTATE_TRANSITION_FROM_STATE_UNKNOWN", path: `/transitions/${index}/from_state`, allowed_values: states.slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    if (!stateIds.has(transition.to_state)) issues.push({ code: "TSTATE_TRANSITION_TO_STATE_UNKNOWN", path: `/transitions/${index}/to_state`, allowed_values: states.slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    if (!eventIds.has(transition.event)) issues.push({ code: "TSTATE_TRANSITION_EVENT_UNKNOWN", path: `/transitions/${index}/event`, allowed_values: events.map((event) => event.id).slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    const key = `${transition.from_state}\u0000${transition.event}\u0000${transition.to_state}`;
    if (transitionKeys.has(key)) issues.push({ code: "TSTATE_DUPLICATE_TRANSITION", path: `/transitions/${index}` });
    transitionKeys.add(key);
  });

  const violation = objectRecord(record.violation);
  if (violation !== undefined) {
    if (typeof violation.from_state === "string" && !stateIds.has(violation.from_state)) issues.push({ code: "TSTATE_VIOLATION_FROM_STATE_UNKNOWN", path: "/violation/from_state", allowed_values: states.slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    if (typeof violation.to_state === "string" && !stateIds.has(violation.to_state)) issues.push({ code: "TSTATE_VIOLATION_TO_STATE_UNKNOWN", path: "/violation/to_state", allowed_values: states.slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    if (typeof violation.event === "string" && !eventIds.has(violation.event)) issues.push({ code: "TSTATE_VIOLATION_EVENT_UNKNOWN", path: "/violation/event", allowed_values: events.map((event) => event.id).slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    transitions.forEach((transition, index) => {
      if (transition.from_state === violation.from_state
        && transition.event === violation.event
        && transition.to_state === violation.to_state) {
        issues.push({ code: "TSTATE_PROHIBITED_TRANSITION_ALLOWED", path: `/transitions/${index}` });
      }
    });
  }

  if (typeof record.initial_state === "string" && stateIds.has(record.initial_state)) {
    const reachable = reachableStates(record.initial_state, transitions);
    states.forEach((state, index) => {
      if (!reachable.has(state)) issues.push({ code: "TSTATE_STATE_UNREACHABLE", path: `/states/${index}`, allowed_values: [...reachable].slice(0, TYPESTATE_LIMITS.maxAllowedValues) });
    });
  }

  return issues;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function eventArray(value: unknown): TypestateEvent[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is TypestateEvent => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return false;
    return typeof (item as Record<string, unknown>).id === "string";
  });
}

function transitionArray(value: unknown): Array<{ readonly from_state: string; readonly event: string; readonly to_state: string }> {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is { readonly from_state: string; readonly event: string; readonly to_state: string } => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return false;
    const record = item as Record<string, unknown>;
    return typeof record.from_state === "string" && typeof record.event === "string" && typeof record.to_state === "string";
  });
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function addDuplicateIssues(values: readonly string[], path: string, code: string, issues: TypestateValidationIssue[]): void {
  const seen = new Set<string>();
  values.forEach((value, index) => {
    if (seen.has(value)) issues.push({ code, path: path === "/states" ? `${path}/${index}` : `${path}/${index}/id` });
    seen.add(value);
  });
}

function reachableStates(initial: string, transitions: readonly { readonly from_state: string; readonly event: string; readonly to_state: string }[]): Set<string> {
  const reachable = new Set<string>([initial]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const transition of transitions) {
      if (reachable.has(transition.from_state) && !reachable.has(transition.to_state)) {
        reachable.add(transition.to_state);
        changed = true;
      }
    }
  }
  return reachable;
}

function schemaIssue(path: string, message: string): TypestateValidationIssue {
  const lower = message.toLowerCase();
  if (lower.includes("additional") || lower.includes("unexpected")) return { code: "TSTATE_UNKNOWN_PROPERTY", path };
  if (path === "/schema_version") return { code: "TSTATE_HYPOTHESIS_VERSION_INVALID", path, allowed_values: [TYPESTATE_HYPOTHESIS_VERSION] };
  if (path.endsWith("/selector/kind")) return { code: "TSTATE_EVENT_SELECTOR_KIND_INVALID", path, allowed_values: [...EVENT_SELECTOR_KINDS] };
  if (path === "/resource/kind") return { code: "TSTATE_RESOURCE_KIND_INVALID", path, allowed_values: [...RESOURCE_KINDS] };
  if (path === "/analysis_scope/kind") return { code: "TSTATE_SCOPE_KIND_INVALID", path, allowed_values: [...SCOPE_KINDS] };
  if (path === "/analysis_scope/event_scope") return { code: "TSTATE_EVENT_SCOPE_INVALID", path, allowed_values: [...EVENT_SCOPES] };
  if (path === "/analysis_scope/alias_boundary") return { code: "TSTATE_ALIAS_BOUNDARY_INVALID", path, allowed_values: [...ALIAS_BOUNDARIES] };
  if (path === "/violation/kind") return { code: "TSTATE_VIOLATION_KIND_INVALID", path, allowed_values: [...VIOLATION_KINDS] };
  if (path === "/violation/requires_same_identity") return { code: "TSTATE_IDENTITY_REQUIREMENT_INVALID", path, allowed_values: [true] };
  if (path === "/language") return { code: "TSTATE_LANGUAGE_INVALID", path, allowed_values: ["javascript"] };
  if (lower.includes("unique")) return { code: "TSTATE_DUPLICATE_ID", path };
  if (lower.includes("required")) return { code: "TSTATE_FIELD_REQUIRED", path };
  return { code: "TSTATE_INVALID_INPUT", path };
}

function errorKeyword(error: unknown): string | undefined {
  const record = objectRecord(error);
  return typeof record?.keyword === "string" ? record.keyword : undefined;
}

function errorPath(error: unknown): string {
  const record = objectRecord(error);
  const directPath = typeof record?.path === "string" ? record.path : undefined;
  if (directPath !== undefined && directPath !== "") return directPath;
  const instancePath = typeof record?.instancePath === "string" ? record.instancePath : undefined;
  if (instancePath !== undefined && instancePath !== "") return instancePath;
  const params = objectRecord(record?.params);
  const additionalProperties = params?.additionalProperties;
  if (Array.isArray(additionalProperties) && typeof additionalProperties[0] === "string") {
    return `/${escapeJsonPointer(additionalProperties[0])}`;
  }
  return "/";
}

function selectorUnionAlternativeNoise(input: unknown, path: string, keyword: string | undefined): boolean {
  if (keyword !== "const" && keyword !== "required") return false;
  const match = /^\/events\/(\d+)\/selector(?:\/|$)/.exec(path);
  if (match === null) return false;
  const events = objectRecord(input)?.events;
  if (!Array.isArray(events)) return false;
  const selector = objectRecord(objectRecord(events[Number(match[1])])?.selector);
  const kind = selector?.kind;
  return typeof kind === "string" && !EVENT_SELECTOR_KINDS.includes(kind as (typeof EVENT_SELECTOR_KINDS)[number]);
}

function escapeJsonPointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function unique(issues: readonly TypestateValidationIssue[]): TypestateValidationIssue[] {
  const seen = new Set<string>();
  const result: TypestateValidationIssue[] = [];
  for (const issue of issues) {
    const key = `${issue.code}:${issue.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(issue);
  }
  return result;
}
