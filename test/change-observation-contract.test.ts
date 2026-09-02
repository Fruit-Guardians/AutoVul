import { describe, expect, it } from "vitest";
import { Value } from "typebox/value";

import {
  AutovulResearchToolInputSchema,
  CHANGE_OBSERVATION_LIMITS,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  ChangeObservationBudgetSchema,
  ChangeObservationChangedFileSchema,
  ChangeObservationExecutionResultSchema,
  ChangeObservationPathFilterSchema,
  ChangeObservationReplayComparisonSchema,
  ChangeObservationSchema,
  ChangeObservationServiceRequestSchema,
  LegacyCapabilityResearchOperationRouteSchema,
  ResearchOperationRouteSchema,
  ResearchRequestSchema,
} from "@autovul/contracts";

const baseOid = "75b4c059b8405dfbd50884b773346a9946fabd20";
const headOid = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const treeOid = "0123456789abcdef0123456789abcdef01234567";
const sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function request() {
  return {
    action: "execute" as const,
    service: "change_observation" as const,
    service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    input: {
      repository: { kind: "trusted_local_git_repository" as const, path: "/trusted/repository" },
      base_revision: baseOid,
      head_revision: headOid,
    },
  };
}

function observation() {
  return {
    schema_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    revision_identity: {
      object_format: "sha1" as const,
      base_oid: baseOid,
      head_oid: headOid,
      base_tree_oid: treeOid,
      head_tree_oid: treeOid,
    },
    scope: { path_filters: ["src/auth"], submodules: "not_included" as const, dirty_worktree: "not_inspected" as const },
    resolved_budget: {
      timeout_ms: 600_000,
      max_changed_files: 512,
      max_diff_bytes: 4_194_304,
      max_hunks: 2_048,
      max_hunk_lines: 256,
      max_symbols: 4_096,
      max_call_changes: 4_096,
      max_event_changes: 4_096,
    },
    completeness: "complete" as const,
    changed_files: [{ path: "src/auth/login.ts", change_kind: "modified" as const, content_kind: "text" as const }],
    normalized_hunks: [{
      path: "src/auth/login.ts",
      ordinal: 0,
      old_start: 1,
      old_line_count: 1,
      new_start: 1,
      new_line_count: 1,
      removed_line_count: 1,
      added_line_count: 1,
      normalized_removed_sha256: sha256,
      normalized_added_sha256: sha256,
      truncated: false,
    }],
    symbols: [{
      change_kind: "modified" as const,
      symbol_kind: "function" as const,
      language: "typescript" as const,
      name: "authenticate",
      old_location: { path: "src/auth/login.ts", start_line: 1 },
      new_location: { path: "src/auth/login.ts", start_line: 1 },
    }],
    call_changes: [{
      change_kind: "added" as const,
      callee_selector: ["isSigninInvokeAuthorized"],
      argument_change_kind: "count_changed" as const,
      new_argument_count: 1,
      new_location: { path: "src/auth/login.ts", start_line: 2 },
    }],
    event_changes: [{
      event_kind: "direct_call_added" as const,
      selector: ["req", "session", "regenerate"],
      location: { path: "src/auth/login.ts", start_line: 3 },
    }],
    analysis_gaps: [],
    provenance: {
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      source: "local_git_object_database" as const,
      git_version: "git version 2.47.0",
      command_profile_version: "autovul.git-change-observation/1" as const,
      parser_versions: [{ language: "typescript" as const, version: "1.0.0" }],
    },
    request_fingerprint: sha256,
    observation_fingerprint: sha256,
  };
}

describe("Change Observation Analyzer v1 contracts", () => {
  it("accepts only the static service request branch", () => {
    expect(Value.Check(ChangeObservationServiceRequestSchema, request())).toBe(true);
    expect(Value.Check(ResearchRequestSchema, request())).toBe(true);
    expect(Value.Check(AutovulResearchToolInputSchema, request())).toBe(true);

    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), action: "validate" })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), capability: "typestate" })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), hypothesis: {} })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), service: "delta" })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), service_version: "autovul.delta/1" })).toBe(false);
  });

  it("freezes full OIDs, literal path filters, and every numeric budget ceiling", () => {
    expect(Value.Check(ChangeObservationServiceRequestSchema, {
      ...request(),
      input: {
        ...request().input,
        path_filters: ["src/auth", "extensions/msteams"],
        budget: {
          timeout_ms: 1,
          max_changed_files: 1,
          max_diff_bytes: 1_024,
          max_hunks: 1,
          max_hunk_lines: 1,
          max_symbols: 1,
          max_call_changes: 1,
          max_event_changes: 1,
        },
      },
    })).toBe(true);
    expect(Value.Check(ChangeObservationServiceRequestSchema, {
      ...request(),
      input: { ...request().input, budget: { max_hunks: 1 } },
    })).toBe(true);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), input: { ...request().input, base_revision: baseOid.toUpperCase() } })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), input: { ...request().input, head_revision: "80b1" } })).toBe(false);
    expect(Value.Check(ChangeObservationServiceRequestSchema, { ...request(), input: { ...request().input, path_filters: ["src/auth", "src/auth"] } })).toBe(false);
    for (const invalid of ["/src/auth", "src/../auth", "src/auth/", "src/*.ts", "src\\auth", ".", "src//auth"]) {
      expect(Value.Check(ChangeObservationPathFilterSchema, invalid)).toBe(false);
    }
    expect(Value.Check(ChangeObservationPathFilterSchema, "src/auth")).toBe(true);
    expect(Value.Check(ChangeObservationBudgetSchema, {
      timeout_ms: 600_001,
      max_changed_files: CHANGE_OBSERVATION_LIMITS.maxChangedFiles,
      max_diff_bytes: CHANGE_OBSERVATION_LIMITS.maxDiffBytes,
      max_hunks: CHANGE_OBSERVATION_LIMITS.maxHunks,
      max_hunk_lines: CHANGE_OBSERVATION_LIMITS.maxHunkLines,
      max_symbols: CHANGE_OBSERVATION_LIMITS.maxSymbols,
      max_call_changes: CHANGE_OBSERVATION_LIMITS.maxCallChanges,
      max_event_changes: CHANGE_OBSERVATION_LIMITS.maxEventChanges,
    })).toBe(false);
    expect((ChangeObservationBudgetSchema.properties.timeout_ms as { readonly default?: number }).default).toBe(600_000);
    expect((ChangeObservationBudgetSchema.properties.max_diff_bytes as { readonly default?: number }).default).toBe(4_194_304);
  });

  it("keeps bounded structural facts and gaps free of verdict fields", () => {
    expect(Value.Check(ChangeObservationSchema, observation())).toBe(true);
    expect(Value.Check(ChangeObservationSchema, { ...observation(), decision: { outcome: "fixed" } })).toBe(false);
    expect(Value.Check(ChangeObservationChangedFileSchema, { path: "src/new.ts", change_kind: "renamed", content_kind: "text" })).toBe(false);
    expect(Value.Check(ChangeObservationChangedFileSchema, { path: "src/new.ts", previous_path: "src/old.ts", change_kind: "renamed", content_kind: "text" })).toBe(true);
    expect(Value.Check(ChangeObservationChangedFileSchema, { path: "src/new.ts", previous_path: "src/old.ts", change_kind: "added", content_kind: "text" })).toBe(false);
    expect(Value.Check(ChangeObservationSchema, {
      ...observation(),
      event_changes: [{ ...observation().event_changes[0], selector: ["a", "b", "c", "d", "e", "f", "g", "h", "i"] }],
    })).toBe(false);
    expect(Value.Check(ChangeObservationSchema, {
      ...observation(),
      analysis_gaps: [{ code: "PARSER_UNAVAILABLE", parser_or_language: "python" }],
      completeness: "partial",
    })).toBe(true);
  });

  it("separates service execution/replay results from Capability results and routes", () => {
    const result = {
      schema_version: "v2.contracts/1" as const,
      run_id: "run_changeobs01",
      service: "change_observation" as const,
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      operation_status: "completed" as const,
      observation: observation(),
      diagnostics: [],
      allowed_next_actions: ["replay", "stop"],
      artifact_ref: "research/change-observation/result.json",
      replay_ref: "research/change-observation/replay.json",
    };
    expect(Value.Check(ChangeObservationExecutionResultSchema, result)).toBe(true);
    expect(Value.Check(ChangeObservationExecutionResultSchema, { ...result, verification_level: "differential" })).toBe(false);

    const serviceRoute = {
      schema_version: "v2.contracts/1" as const,
      route_kind: "analyzer_service" as const,
      service: "change_observation" as const,
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      result_artifact_ref: "research/change-observation/result.json",
    };
    expect(Value.Check(ResearchOperationRouteSchema, serviceRoute)).toBe(true);
    expect(Value.Check(ResearchOperationRouteSchema, { ...serviceRoute, capability: "typestate" })).toBe(false);
    const legacyRoute = {
      schema_version: "v2.contracts/1" as const,
      capability: "flow" as const,
      hypothesis_version: "autovul.flow/1" as const,
      result_artifact_ref: "research/flow/result.json",
    };
    expect(Value.Check(ResearchOperationRouteSchema, legacyRoute)).toBe(false);
    expect(Value.Check(LegacyCapabilityResearchOperationRouteSchema, legacyRoute)).toBe(true);

    expect(Value.Check(ChangeObservationReplayComparisonSchema, {
      schema_version: "v2.contracts/1",
      service: "change_observation",
      service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      status: "request_fingerprint_difference",
      recorded_observation_fingerprint: sha256,
      replay_observation_fingerprint: sha256,
      diagnostics: [{ code: "CHANGE_OBSERVATION_ARTIFACT_INVALID", retryable: false }],
    })).toBe(true);
  });
});
