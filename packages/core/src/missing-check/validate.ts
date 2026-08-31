import { Value } from "typebox/value";

import {
  MISSING_CHECK_HYPOTHESIS_VERSION,
  MissingCheckHypothesisSchema,
  type MissingCheckHypothesis,
  type MissingCheckValidationIssue,
  type MissingCheckValidationResult,
} from "@autovul/contracts";

const SELECTOR_KINDS = ["direct_call"] as const;
const RELATIONS = ["same_callback_cfg_dominates_operation"] as const;
const SCOPE_KINDS = ["single_file_cfg"] as const;

/** Pure validation; it never creates a run or reads a target. */
export function validateMissingCheckHypothesis(input: unknown): MissingCheckValidationResult {
  const issues = unique([...schemaIssues(input), ...semanticIssues(input)]);
  if (issues.length > 0) return { valid: false, issues: issues.slice(0, 64), allowed_next_actions: ["revise", "stop"] };
  return { valid: true, hypothesis: Value.Parse(MissingCheckHypothesisSchema, input) as MissingCheckHypothesis, issues: [], allowed_next_actions: ["execute", "stop"] };
}

function schemaIssues(input: unknown): MissingCheckValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [{ code: "MCHECK_HYPOTHESIS_OBJECT_REQUIRED", path: "/", expected_kind: "object" }];
  const record = input as Record<string, unknown>;
  const issues: MissingCheckValidationIssue[] = [];
  if (record.schema_version !== MISSING_CHECK_HYPOTHESIS_VERSION) issues.push({ code: "MCHECK_HYPOTHESIS_VERSION_INVALID", path: "/schema_version", allowed_values: [MISSING_CHECK_HYPOTHESIS_VERSION] });
  if (!Value.Check(MissingCheckHypothesisSchema, input)) {
    for (const error of Value.Errors(MissingCheckHypothesisSchema, input)) {
      const path = "path" in error && typeof error.path === "string" && error.path !== "" ? error.path : "/";
      // TypeBox emits a root union summary in addition to the actionable
      // literal/property diagnostic. Do not make the host revise `/` blindly.
      if (path === "/" && /union|expected/i.test(error.message)) continue;
      issues.push(schemaIssue(path, error.message));
    }
  }
  return issues;
}

function semanticIssues(input: unknown): MissingCheckValidationIssue[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [];
  const record = input as Record<string, unknown>;
  const issues: MissingCheckValidationIssue[] = [];
  for (const path of ["/operation", "/required_check"] as const) {
    const value = record[path.slice(1)];
    if (value !== null && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).kind !== "direct_call") {
      issues.push({ code: "MCHECK_SELECTOR_KIND_INVALID", path: `${path}/kind`, allowed_values: [...SELECTOR_KINDS] });
    }
  }
  if (record.required_relation !== undefined && record.required_relation !== "same_callback_cfg_dominates_operation") {
    issues.push({ code: "MCHECK_RELATION_INVALID", path: "/required_relation", allowed_values: [...RELATIONS] });
  }
  const scope = record.scope;
  if (scope !== null && typeof scope === "object" && !Array.isArray(scope) && (scope as Record<string, unknown>).kind !== "single_file_cfg") {
    issues.push({ code: "MCHECK_SCOPE_KIND_INVALID", path: "/scope/kind", allowed_values: [...SCOPE_KINDS] });
  }
  return issues;
}

function schemaIssue(path: string, message: string): MissingCheckValidationIssue {
  const lower = message.toLowerCase();
  if (lower.includes("additional") || lower.includes("unexpected")) return { code: "MCHECK_UNKNOWN_PROPERTY", path };
  if (path.endsWith("/kind")) return { code: "MCHECK_SELECTOR_KIND_INVALID", path, allowed_values: [...SELECTOR_KINDS] };
  if (path === "/required_relation") return { code: "MCHECK_RELATION_INVALID", path, allowed_values: [...RELATIONS] };
  if (path === "/scope/kind") return { code: "MCHECK_SCOPE_KIND_INVALID", path, allowed_values: [...SCOPE_KINDS] };
  if (lower.includes("required")) return { code: "MCHECK_FIELD_REQUIRED", path };
  return { code: "MCHECK_INVALID_INPUT", path };
}

function unique(issues: readonly MissingCheckValidationIssue[]): MissingCheckValidationIssue[] {
  const seen = new Set<string>();
  const result = issues.filter((issue) => !seen.has(`${issue.code}:${issue.path}`) && (seen.add(`${issue.code}:${issue.path}`), true));
  return result.some((issue) => issue.path !== "/")
    ? result.filter((issue) => !(issue.path === "/" && issue.code === "MCHECK_INVALID_INPUT"))
    : result;
}
