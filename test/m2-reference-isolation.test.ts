import { describe, expect, it } from "vitest";

import {
  CONTRACTS_VERSION,
  QueryCandidateSchema,
  VulnerabilitySpecSchema,
  parseSchema,
} from "@pure-auto-codeql/contracts";

describe("M2 generator/reference isolation contract", () => {
  it("does not accept reference query content in the generator-facing spec", () => {
    const spec = {
      schema_version: CONTRACTS_VERSION,
      spec_id: "python-isolation",
      language: "python",
      cwe: "CWE-078",
      vulnerability_description: "input reaches a shell sink",
      vulnerable_database: { path: "/tmp/vulnerable", language: "python" },
      validation: {
        vulnerable_min_results: 1,
        vulnerable_max_results: 1,
        fixed_min_results: 0,
        fixed_max_results: 0,
        must_have_code_flow: true,
      },
      max_rounds: 3,
      timeout_ms: 1000,
      created_at: "2026-08-24T00:00:00.000Z",
      input_provenance: "golden_fixture",
      reference_query_excluded: true,
      provenance: { fixture: "redacted", license: "test", source: "test" },
      reference_query: "select secret reference answer",
    };
    expect(() => parseSchema(VulnerabilitySpecSchema, spec, "spec")).toThrow();
  });

  it("does not accept reference text or baseline fields in a candidate", () => {
    const candidate = {
      schema_version: CONTRACTS_VERSION,
      candidate_id: "candidate-isolation",
      query_id: "query-isolation",
      spec_id: "python-isolation",
      language: "python",
      ql_text: "import python\nselect 1, 'candidate'",
      round: 1,
      origin: "pi_generated",
      reference_query_text: "secret reference query",
    };
    expect(() => parseSchema(QueryCandidateSchema, candidate, "candidate")).toThrow();
  });
});
