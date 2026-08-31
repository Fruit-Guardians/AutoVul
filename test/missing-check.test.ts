import { describe, expect, it } from "vitest";

import { DomainError, type MissingCheckAnalyzerObservation } from "@autovul/contracts";
import { Application, decideMissingCheck, validateMissingCheckHypothesis, type MissingCheckExecutionPort, type MissingCheckExecutionRequest } from "@autovul/core";
import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const hypothesis = {
  schema_version: "autovul.missing-check/1",
  hypothesis_id: "mcheck-openclaw",
  language: "javascript",
  operation: { kind: "direct_call", name: "handleSigninTokenExchangeInvoke" },
  required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" },
  required_relation: "same_callback_cfg_dominates_operation",
  scope: { kind: "single_file_named_entry_cfg", file: "extensions/msteams/src/monitor-handler.ts", entry: { kind: "named_function", name: "registerMSTeamsHandlers" } },
} as const;

function observation(overrides: Partial<MissingCheckAnalyzerObservation> = {}): MissingCheckAnalyzerObservation {
  return {
    schema_version: "autovul.missing-check/1", compile_accepted: true,
    operation: { state: "observed", locations: [{ file: "handler.ts", start_line: 10 }] },
    required_check: { state: "observed", locations: [{ file: "handler.ts", start_line: 5 }] },
    relation: { state: "inconclusive", unchecked_witnesses: [], checked_witnesses: [] },
    completeness: {
      vulnerable: { status: "complete", scope: hypothesis.scope, limitations: ["cross_file_aliases_excluded"] },
      fixed: { status: "complete", scope: hypothesis.scope, limitations: ["cross_file_aliases_excluded"] },
    },
    capability_gaps: [], evidence_refs: ["missing-check/vulnerable/unchecked.sarif", "witness.sarif", "v.sarif", "f.sarif"], analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-missing-check/1" }, ...overrides,
  };
}

describe("MissingCheck v1 contracts and policy", () => {
  it("accepts only the frozen one-operation one-check local-CFG hypothesis", () => {
    expect(validateMissingCheckHypothesis(hypothesis)).toMatchObject({ valid: true, allowed_next_actions: ["execute", "stop"] });
    expect(validateMissingCheckHypothesis({ ...hypothesis, required_relation: "all_paths" })).toMatchObject({ valid: false, issues: [{ code: "MCHECK_RELATION_INVALID", path: "/required_relation", allowed_values: ["same_callback_cfg_dominates_operation"] }] });
    expect(validateMissingCheckHypothesis({ ...hypothesis, scope: { kind: "single_file_cfg", file: hypothesis.scope.file, entry: "registerMSTeamsHandlers callback" } })).toMatchObject({ valid: false, issues: expect.arrayContaining([{ code: "MCHECK_SCOPE_KIND_INVALID", path: "/scope/kind", allowed_values: ["single_file_named_entry_cfg"] }]) });
  });

  it("requires a persisted unchecked witness before emitting check_missing", () => {
    const result = decideMissingCheck(observation({ relation: { state: "unchecked_witness", unchecked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "witness.sarif" }], checked_witnesses: [] } }), "reproduce", hypothesis.scope);
    expect(result.decision).toEqual({ capability: "missing_check", outcome: "check_missing" });
    expect(result.verificationLevel).toBe("reproduced");
    expect(result.revisionHints).toEqual([]);
    expect(result.allowedNextActions).toEqual(["replay", "stop"]);
  });

  it("does not turn a missing check selector into absence proof", () => {
    const result = decideMissingCheck(observation({ required_check: { state: "not_found", locations: [] } }), "reproduce", hypothesis.scope);
    expect(result.decision.outcome).toBe("unknown");
    expect(result.revisionHints).toContainEqual({ action: "revise_check", path: "/required_check", reason_code: "MCHECK_CHECK_NOT_FOUND" });
  });

  it("requires fixed checked evidence before raising differential", () => {
    const vulnerable = { state: "unchecked_witness" as const, unchecked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "v.sarif" }], checked_witnesses: [] };
    const noFixed = decideMissingCheck(observation({ relation: vulnerable, fixed_relation: { state: "not_run", unchecked_witnesses: [], checked_witnesses: [] }, completeness: { vulnerable: { status: "complete", scope: hypothesis.scope, limitations: [] }, fixed: { status: "not_run", scope: hypothesis.scope, limitations: [] } } }), "differential", hypothesis.scope);
    expect(noFixed.verificationLevel).toBe("reproduced");
    const fixed = decideMissingCheck(observation({ relation: vulnerable, fixed_relation: { state: "checked_witness", unchecked_witnesses: [], checked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "f.sarif" }] } }), "differential", hypothesis.scope);
    expect(fixed).toMatchObject({ verificationLevel: "differential", decision: { fixed_outcome: "check_present", fixed_policy_satisfied: true } });
  });

  it("keeps capability gaps distinct from a completed check decision", () => {
    const result = decideMissingCheck(observation({ capability_gaps: [{ code: "MCHECK_ALIASING_UNSUPPORTED", path: "/scope" }] }), "reproduce", hypothesis.scope);
    expect(result.decision.outcome).toBe("unknown");
    expect(result.revisionHints).toContainEqual({ action: "revise_scope", path: "/scope", reason_code: "MCHECK_ALIASING_UNSUPPORTED" });
  });

  it("requires an exact completed scope and a resolvable witness evidence ref", () => {
    const witness = { state: "unchecked_witness" as const, unchecked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "witness.sarif" }], checked_witnesses: [] };
    const incomplete = decideMissingCheck(observation({ relation: witness, completeness: { vulnerable: { status: "incomplete", scope: hypothesis.scope, limitations: [] } } }), "reproduce", hypothesis.scope);
    expect(incomplete).toMatchObject({ decision: { outcome: "unknown" }, verificationLevel: "compiled", observations: expect.arrayContaining([{ code: "MCHECK_COMPLETENESS_INCOMPLETE", path: "/scope" }]) });

    const wrongScope = { ...hypothesis.scope, entry: { kind: "named_function" as const, name: "otherEntry" } };
    const mismatch = decideMissingCheck(observation({ relation: witness, completeness: { vulnerable: { status: "complete", scope: wrongScope, limitations: [] } } }), "reproduce", hypothesis.scope);
    expect(mismatch.observations).toContainEqual({ code: "MCHECK_COMPLETENESS_SCOPE_MISMATCH", path: "/scope" });

    const dangling = decideMissingCheck(observation({ relation: witness, evidence_refs: ["other.sarif"] }), "reproduce", hypothesis.scope);
    expect(dangling).toMatchObject({ decision: { outcome: "unknown" }, verificationLevel: "compiled", observations: expect.arrayContaining([{ code: "MCHECK_EVIDENCE_REF_INVALID", path: "/required_relation" }]) });
  });

  it("uses the aggregate research and run APIs without Flow routing", async () => {
    const port: MissingCheckExecutionPort = { async execute(_request: MissingCheckExecutionRequest): Promise<MissingCheckAnalyzerObservation> {
      return observation({ relation: { state: "unchecked_witness", unchecked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "v.sarif" }], checked_witnesses: [] }, fixed_relation: { state: "checked_witness", unchecked_witnesses: [], checked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "f.sarif" }] }, analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "test_double", version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-missing-check/1" } });
    } };
    const artifacts = new MemoryArtifactStore();
    const codeql = new FakeCodeqlPort();
    const app = new Application({ codeql, artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_mcheck"), missingCheck: port });
    const result = await app.research({ action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis, analyzer_id: "codeql", mode: "differential", target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" }, fixed: { kind: "codeql_database", path: "/isolated/f" } }, budget: { timeout_ms: 5_000 }, idempotency_key: "mcheck-diff" });
    expect(result).toMatchObject({ capability: "missing_check", operation_status: "completed", verification_level: "generated", decision: { outcome: "check_missing", fixed_outcome: "check_present" } });
    if (!("run_id" in result)) throw new Error("expected execution result");
    expect(JSON.parse(await artifacts.readArtifact(result.run_id, "research/operation.json") ?? "null")).toMatchObject({ capability: "missing_check", result_artifact_ref: "research/missing-check/result.json" });
    expect(JSON.parse(await artifacts.readArtifact(result.run_id, "research/missing-check/result.json") ?? "null")).toMatchObject({ target_fingerprints: { vulnerable: "0123456789abcdef", fixed: "0123456789abcdef" }, analyzer: { analyzer_id: "codeql", version: "CodeQL CLI version 2.26.1", adapter_version: "autovul.codeql-missing-check/1" } });
    const replayed = await app.manageRun({ action: "replay", run_id: result.run_id });
    expect(replayed).toMatchObject({ capability: "missing_check", verification_level: "generated" });
    await app.close();
  });

  it("distinguishes replay fingerprint and analyzer-version differences", async () => {
    let current = observation({ relation: { state: "unchecked_witness", unchecked_witnesses: [{ operation: { file: "handler.ts", start_line: 10 }, evidence_ref: "v.sarif" }], checked_witnesses: [] } });
    const port: MissingCheckExecutionPort = { async execute(): Promise<MissingCheckAnalyzerObservation> { return current; } };
    const artifacts = new MemoryArtifactStore();
    const codeql = new FakeCodeqlPort();
    const app = new Application({ codeql, artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_mcheck_replay"), missingCheck: port });
    const execute = await app.research({ action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis, analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } }, budget: { timeout_ms: 5_000 }, idempotency_key: "mcheck-replay-comparison" });
    if (!("run_id" in execute)) throw new Error("expected execution result");

    current = observation({ ...current, analyzer: { ...current.analyzer, version: "CodeQL CLI version 2.27.0" } });
    const versionDifference = await app.manageRun({ action: "replay", run_id: execute.run_id });
    expect(versionDifference).toMatchObject({ operation_status: "completed", verification_level: "generated", observations: [{ code: "MCHECK_REPLAY_ANALYZER_VERSION_DIFFERENCE" }] });

    current = observation({ ...current, analyzer: { ...current.analyzer, version: "CodeQL CLI version 2.26.1" } });
    codeql.database = { ...codeql.database, fingerprint: "fedcba9876543210", portableFingerprint: "fedcba9876543210" };
    const fingerprintDifference = await app.manageRun({ action: "replay", run_id: execute.run_id });
    expect(fingerprintDifference).toMatchObject({ operation_status: "blocked", observations: [{ code: "MCHECK_REPLAY_FINGERPRINT_DIFFERENCE" }] });
    await app.close();
  });

  it("keeps analyzer timeouts out of completed unknown decisions", async () => {
    const artifacts = new MemoryArtifactStore();
    const port: MissingCheckExecutionPort = { async execute(): Promise<MissingCheckAnalyzerObservation> { throw new DomainError("PROCESS_TIMEOUT", "process", "timed out", true); } };
    const app = new Application({ codeql: new FakeCodeqlPort(), artifacts, clock: new FixedClock(), ids: new FixedIdGenerator("run_mcheck_timeout"), missingCheck: port });
    const result = await app.research({ action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis, analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } }, budget: { timeout_ms: 5_000 }, idempotency_key: "mcheck-timeout" });
    expect(result).toMatchObject({ operation_status: "failed", decision: { outcome: "unknown" }, observations: [{ code: "MCHECK_ANALYZER_TIMEOUT" }] });
    await app.close();
  });

  it("blocks real Analyzer observations without exact version provenance", async () => {
    const port: MissingCheckExecutionPort = { async execute(): Promise<MissingCheckAnalyzerObservation> {
      return observation({ analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", adapter_version: "autovul.codeql-missing-check/1" } });
    } };
    const app = new Application({ codeql: new FakeCodeqlPort(), artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_mcheck_version"), missingCheck: port });
    const result = await app.research({ action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis, analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } }, budget: { timeout_ms: 5_000 }, idempotency_key: "mcheck-version-gate" });
    expect(result).toMatchObject({ operation_status: "blocked", verification_level: "generated", decision: { outcome: "unknown" }, observations: [{ code: "MCHECK_ANALYZER_VERSION_UNAVAILABLE" }] });
    await app.close();
  });

  it("keeps Analyzer output parse failure distinct from completed unknown", async () => {
    const port: MissingCheckExecutionPort = { async execute(): Promise<MissingCheckAnalyzerObservation> {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "invalid SARIF", false);
    } };
    const app = new Application({ codeql: new FakeCodeqlPort(), artifacts: new MemoryArtifactStore(), clock: new FixedClock(), ids: new FixedIdGenerator("run_mcheck_parse"), missingCheck: port });
    const result = await app.research({ action: "execute", capability: "missing_check", hypothesis_version: "autovul.missing-check/1", hypothesis, analyzer_id: "codeql", mode: "reproduce", target: { vulnerable: { kind: "codeql_database", path: "/isolated/v" } }, budget: { timeout_ms: 5_000 }, idempotency_key: "mcheck-parse-failure" });
    expect(result).toMatchObject({ operation_status: "failed", verification_level: "generated", decision: { outcome: "unknown" }, observations: [{ code: "MCHECK_ANALYZER_OUTPUT_PARSE_FAILED" }] });
    await app.close();
  });
});
