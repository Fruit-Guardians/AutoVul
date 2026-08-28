import { describe, expect, it } from "vitest";

import { CONTRACTS_VERSION, type VulnerabilitySpec } from "@autovul/contracts";
import { normalizePythonQueryCandidate } from "@autovul/core";

const spec: VulnerabilitySpec = {
  schema_version: CONTRACTS_VERSION,
  spec_id: "python-renderer-case",
  language: "python",
  cwe: "CWE-078",
  vulnerability_description: "input reaches a shell sink",
  vulnerable_database: { path: "/db/vulnerable", language: "python" },
  fixed_database: { path: "/db/fixed", language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
  },
  max_rounds: 3,
  timeout_ms: 10_000,
  created_at: "2026-08-24T00:00:00.000Z",
  input_provenance: "golden_fixture",
  reference_query_excluded: true,
  provenance: { fixture: "test", license: "test", source: "test" },
};

describe("Python structured query renderer", () => {
  it("renders fixed metadata and QL structure around a model-owned draft", () => {
    const candidate = normalizePythonQueryCandidate({
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-renderer",
      query_id: "query-renderer",
      spec_id: spec.spec_id,
      language: "python",
      draft: {
        schema_version: CONTRACTS_VERSION,
        source_predicate: "exists(DataFlow::ParameterNode p | p = source and p.getParameter().getName() = \"value\")",
        sink_predicate: "exists(DataFlow::CallCfgNode call | sink = call.getArg(0))",
        message: "tainted value reaches the sink",
      },
      round: 1,
      origin: "pi_generated",
    }, spec);
    expect(candidate.draft?.source_predicate).toContain("ParameterNode");
    expect(candidate.ql_text).toContain("@kind path-problem");
    expect(candidate.ql_text).toContain("@id pure-auto-codeql/query-renderer");
    expect(candidate.ql_text).toContain("module Config implements DataFlow::ConfigSig");
    expect(candidate.ql_text).toContain("import Flow::PathGraph");
    expect(candidate.ql_text).toContain("select sink.getNode(), source, sink");
  });

  it("rejects fixed QL boilerplate smuggled into a draft field", () => {
    expect(() => normalizePythonQueryCandidate({
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-invalid-draft",
      query_id: "query-invalid-draft",
      spec_id: spec.spec_id,
      language: "python",
      draft: {
        schema_version: CONTRACTS_VERSION,
        source_predicate: "select 1",
        sink_predicate: "true",
        message: "invalid",
      },
      round: 1,
      origin: "pi_generated",
    }, spec)).toThrowError(expect.objectContaining({ code: "QUERY_DRAFT_INVALID" }));
  });
});
