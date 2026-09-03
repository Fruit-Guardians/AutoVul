import { Value } from "typebox/value";

import {
  FLOW_HYPOTHESIS_VERSION,
  FlowModelSchema,
  type FlowEndpoint,
  type FlowModel,
  type FlowValidationIssue,
  type FlowValidationResult,
} from "@autovul/contracts";

const ENDPOINT_KINDS = [
  "call",
  "call_argument",
  "constructor",
  "function",
  "parameter",
  "environment",
  "property",
  "array_index",
  "array_element",
] as const;

const IDENTIFYING_FIELDS = [
  "module",
  "type",
  "member",
  "name",
  "argument_index",
  "argument_name",
  "keyword_name",
  "property",
  "file",
  "symbol",
  "line",
] as const;

export function validateFlowModel(input: unknown): FlowValidationResult {
  const issues = [...schemaIssues(input), ...semanticIssues(input)];
  if (issues.length > 0) {
    return { valid: false, issues: issues.slice(0, 64), allowed_next_actions: ["revise", "stop"] };
  }
  const model = Value.Parse(FlowModelSchema, input) as FlowModel;
  return { valid: true, model, issues: [], allowed_next_actions: ["execute", "stop"] };
}

export function validateFlowExpectation(input: unknown, mode: "probe" | "reproduce" | "differential"): FlowValidationIssue[] {
  if (mode === "probe") return input === undefined ? [] : [{ code: "FLOW_EXPECTATION_NOT_ALLOWED", path: "/expectation" }];
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [{ code: "FLOW_EXPECTATION_REQUIRED", path: "/expectation", expected_kind: "object" }];
  const expectation = input as Record<string, unknown>;
  const issues: FlowValidationIssue[] = [];
  if (expectation.vulnerable === undefined) issues.push({ code: "FLOW_VULNERABLE_EXPECTATION_REQUIRED", path: "/expectation/vulnerable" });
  if (mode === "differential" && expectation.fixed === undefined) issues.push({ code: "FLOW_FIXED_EXPECTATION_REQUIRED", path: "/expectation/fixed" });
  for (const side of ["vulnerable", "fixed"] as const) {
    const range = expectation[side];
    if (range === undefined) continue;
    if (range === null || typeof range !== "object" || Array.isArray(range)) { issues.push({ code: "FLOW_PATH_EXPECTATION_INVALID", path: `/expectation/${side}`, expected_kind: "object" }); continue; }
    const values = range as Record<string, unknown>;
    if (typeof values.min_paths === "number" && typeof values.max_paths === "number" && values.max_paths < values.min_paths) issues.push({ code: "FLOW_PATH_RANGE_INVALID", path: `/expectation/${side}/max_paths` });
  }
  return issues;
}

function schemaIssues(input: unknown): FlowValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return [{ code: "FLOW_MODEL_OBJECT_REQUIRED", path: "/", expected_kind: "object" }];
  }
  const record = input as Record<string, unknown>;
  const issues: FlowValidationIssue[] = [];
  if (record.schema_version !== FLOW_HYPOTHESIS_VERSION) {
    issues.push({
      code: "FLOW_HYPOTHESIS_VERSION_INVALID",
      path: "/schema_version",
      allowed_values: [FLOW_HYPOTHESIS_VERSION],
    });
  }
  if (!Value.Check(FlowModelSchema, input)) {
    for (const error of Value.Errors(FlowModelSchema, input)) {
      // TypeBox's additional-properties diagnostic does not declare `path`,
      // although the runtime diagnostic still carries it when available.
      const errorPath = "path" in error && typeof error.path === "string" ? error.path : "";
      const path = errorPath === "" ? "/" : errorPath;
      const code = schemaIssueCode(error.message, path);
      issues.push(issueFromSchema(code, path, error.message));
    }
  }
  return uniqueIssues(issues);
}

function semanticIssues(input: unknown): FlowValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return [];
  }
  const record = input as Record<string, unknown>;
  return [
    ...endpointIssues("/source", record.source),
    ...endpointIssues("/sink", record.sink),
    ...stepIssues(record.steps),
    ...barrierIssues(record.barriers),
  ];
}

function endpointIssues(path: string, value: unknown): FlowValidationIssue[] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const endpoint = value as Partial<FlowEndpoint> & Record<string, unknown>;
  const issues: FlowValidationIssue[] = [];
  if (endpoint.kind === "call_argument" && endpoint.argument_index === undefined) {
    issues.push({
      code: "FLOW_ENDPOINT_POSITION_REQUIRED",
      path: `${path}/argument_index`,
      allowed_values: [0, 1, 2],
    });
  }
  if (endpoint.kind !== "array_index" && endpoint.kind !== "array_element" && !hasIdentifier(endpoint)) {
    issues.push({ code: "FLOW_ENDPOINT_SELECTOR_REQUIRED", path });
  }
  const start = endpoint.start_line ?? endpoint.line;
  if (start !== undefined && endpoint.end_line !== undefined && endpoint.end_line < start) {
    issues.push({ code: "FLOW_LOCATION_RANGE_INVALID", path: `${path}/end_line` });
  }
  return issues;
}

function stepIssues(value: unknown): FlowValidationIssue[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((step, index) => {
    if (step === null || typeof step !== "object") {
      return [];
    }
    const record = step as Record<string, unknown>;
    return [...endpointIssues(`/steps/${index}/from`, record.from), ...endpointIssues(`/steps/${index}/to`, record.to)];
  });
}

function barrierIssues(value: unknown): FlowValidationIssue[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((barrier, index) => {
    if (barrier === null || typeof barrier !== "object") {
      return [];
    }
    return endpointIssues(`/barriers/${index}/endpoint`, (barrier as Record<string, unknown>).endpoint);
  });
}

function hasIdentifier(endpoint: Record<string, unknown>): boolean {
  return IDENTIFYING_FIELDS.some((field) => endpoint[field] !== undefined);
}

function schemaIssueCode(message: string, path: string): string {
  const lower = message.toLowerCase();
  if (lower.includes("additional") || lower.includes("unexpected")) {
    return "FLOW_UNKNOWN_PROPERTY";
  }
  if (path.endsWith("/kind") || lower.includes("union") || lower.includes("literal")) {
    return "FLOW_INVALID_DISCRIMINANT";
  }
  if (lower.includes("required")) {
    return "FLOW_FIELD_REQUIRED";
  }
  return "FLOW_INVALID_INPUT";
}

function issueFromSchema(code: string, path: string, message: string): FlowValidationIssue {
  if (code === "FLOW_INVALID_DISCRIMINANT" && path.endsWith("/kind")) {
    return { code, path, allowed_values: [...ENDPOINT_KINDS] };
  }
  if (code === "FLOW_HYPOTHESIS_VERSION_INVALID") {
    return { code, path, allowed_values: [FLOW_HYPOTHESIS_VERSION] };
  }
  void message;
  return { code, path };
}

function uniqueIssues(issues: readonly FlowValidationIssue[]): FlowValidationIssue[] {
  const seen = new Set<string>();
  const unique: FlowValidationIssue[] = [];
  for (const issue of issues) {
    const key = `${issue.code}:${issue.path}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(issue);
  }
  return unique;
}
