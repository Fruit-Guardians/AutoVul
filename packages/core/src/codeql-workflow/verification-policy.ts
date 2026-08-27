import {
  CONTRACTS_VERSION,
  QueryVerificationSchema,
  parseSchema,
  type QueryCandidate,
  type QueryDiagnostic,
  type QueryVerification,
  type RunId,
  type VulnerabilitySpec,
} from "@pure-auto-codeql/contracts";

import type { QueryExecutionResult as ExecutionResult } from "../ports.js";
import { compileRepairHint } from "./candidate-policy.js";
import { locationMatches } from "./endpoint-policy.js";

export function evaluateVerification(
  runId: RunId,
  candidate: QueryCandidate,
  spec: VulnerabilitySpec,
  execution: ExecutionResult,
): QueryVerification {
  const fixedObservation = spec.fixed_database === undefined ? notRunFixedObservation() : execution.fixed;
  const diagnostics: QueryDiagnostic[] = deduplicateDiagnostics(execution.diagnostics);
  if (execution.compile.status !== "passed") {
    if (!diagnostics.some((item) => item.code === "QUERY_COMPILE_FAILED")) {
      diagnostics.push(diagnostic("QUERY_COMPILE_FAILED", "compile", "Query compilation failed", candidate, runId));
    }
    return buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, {
      stage: diagnostics.some((item) => item.stage === "preflight") ? "preflight" : "compile",
      root_causes: diagnostics.map((item) => item.code),
      hints: [compileRepairHint(spec, candidate)],
      next_action: "revise_candidate",
    });
  }
  if (execution.vulnerable.status !== "passed") {
    if (!diagnostics.some((item) => item.code === "QUERY_ANALYZE_FAILED" || item.code === "QUERY_PROCESS_TIMEOUT" || item.code === "QUERY_PROCESS_CANCELLED" || item.code === "QUERY_PROCESS_CRASHED")) {
      diagnostics.push(diagnostic("QUERY_ANALYZE_FAILED", "vulnerable", "Vulnerable database analysis failed", candidate, runId));
    }
    return buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, {
      stage: "vulnerable",
      root_causes: diagnostics.map((item) => item.code),
      hints: ["The fixed database was not run because vulnerable analysis failed. Repair the candidate and submit one replacement draft."],
      next_action: "revise_candidate",
    });
  }

  if (!within(execution.vulnerable.result_count, spec.validation.vulnerable_min_results, spec.validation.vulnerable_max_results)) {
    diagnostics.push(diagnostic("QUERY_RESULT_MISMATCH", "vulnerable", "Vulnerable database result count is outside the manifest policy", candidate, runId, {
      resultCount: execution.vulnerable.result_count,
      minimum: spec.validation.vulnerable_min_results,
      maximum: spec.validation.vulnerable_max_results,
    }));
  }
  if (spec.validation.must_have_code_flow && execution.vulnerable.code_flow_count < 1) {
    diagnostics.push(diagnostic("QUERY_CODE_FLOW_MISSING", "vulnerable", "Vulnerable database did not produce a source-to-sink code flow", candidate, runId));
  }
  if (spec.validation.expected_rule_ids !== undefined) {
    const observed = new Set(execution.vulnerable.rule_ids);
    const missing = spec.validation.expected_rule_ids.filter((ruleId) => !observed.has(ruleId));
    if (missing.length > 0) {
      diagnostics.push(diagnostic("QUERY_VULNERABLE_EXPECTATION_FAILED", "vulnerable", "Vulnerable result rule ids do not satisfy the manifest expectation", candidate, runId, {
        missingRuleIds: missing,
        observedRuleIds: execution.vulnerable.rule_ids,
      }));
    }
  }

  const semanticExpectations = [
    ...(spec.validation.source === undefined ? [] : [["source", spec.validation.source] as const]),
    ...(spec.validation.sink === undefined ? [] : [["sink", spec.validation.sink] as const]),
  ];
  if (semanticExpectations.length > 0) {
    const matchingFlow = execution.vulnerable.flow_evidence.find((flow) => semanticExpectations.every(([role, expectation]) => {
      const endpoint = role === "source" ? flow.source : flow.sink;
      const endpointLocations = endpoint === undefined ? flow.path : [endpoint];
      return endpointLocations.some((location) => locationMatches(expectation.file, expectation.line, location)) ||
        (expectation.file === undefined && expectation.line === undefined && execution.vulnerable.semantic_matches.some((match) => match.role === role && match.label.toLowerCase().includes(expectation.label.toLowerCase())));
    }));
    if (matchingFlow === undefined) {
      diagnostics.push(diagnostic("QUERY_SEMANTIC_MISMATCH", "vulnerable", "Vulnerable code flow does not match the manifest Source/Sink expectation", candidate, runId, {
        expected: semanticExpectations.map(([role, expectation]) => ({ role, file: expectation.file, line: expectation.line, label: expectation.label })),
        observedFlows: execution.vulnerable.flow_evidence,
        observedSemanticMatches: execution.vulnerable.semantic_matches,
      }));
    }
  }

  if (spec.input_provenance === "user_provided" && candidate.probe_evidence?.status === "passed") {
    const probeSource = candidate.probe_evidence.source.locations;
    const probeSink = candidate.probe_evidence.sink.locations;
    const matchingProbeFlow = execution.vulnerable.flow_evidence.find((flow) => {
      const sourceLocations = flow.source === undefined ? flow.path.slice(0, 1) : [flow.source];
      const sinkLocations = flow.sink === undefined ? flow.path.slice(-1) : [flow.sink];
      return sourceLocations.some((actual) => probeSource.some((expected) => locationMatches(expected.file, expected.start_line, actual))) &&
        sinkLocations.some((actual) => probeSink.some((expected) => locationMatches(expected.file, expected.start_line, actual)));
    });
    if (matchingProbeFlow === undefined) {
      diagnostics.push(diagnostic("QUERY_SEMANTIC_MISMATCH", "vulnerable", "Vulnerable code flow does not connect the probed Source and Sink", candidate, runId, {
        expectedProbeSource: probeSource,
        expectedProbeSink: probeSink,
        observedFlows: execution.vulnerable.flow_evidence,
      }));
    }
  }

  if (spec.fixed_database === undefined) {
    diagnostics.push({
      schema_version: CONTRACTS_VERSION,
      code: "QUERY_DIFFERENTIAL_NOT_RUN",
      severity: "warning",
      message: "No fixed database was provided; differential verification was not run",
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      stage: "fixed",
      details: { suggestion: "Provide a fixed database to obtain differential verification" },
    });
  } else if (execution.fixed.status === "passed") {
    if (!within(execution.fixed.result_count, spec.validation.fixed_min_results, spec.validation.fixed_max_results)) {
      diagnostics.push(diagnostic(execution.fixed.result_count > 0 ? "QUERY_FIXED_FALSE_POSITIVE" : "QUERY_FIXED_DATABASE_MISMATCH", "fixed", "Fixed database result count is outside the manifest policy", candidate, runId, {
        resultCount: execution.fixed.result_count,
        minimum: spec.validation.fixed_min_results,
        maximum: spec.validation.fixed_max_results,
      }));
    }
  } else if (execution.fixed.status === "failed") {
    diagnostics.push(diagnostic("QUERY_ANALYZE_FAILED", "fixed", "Fixed database analysis failed; no differential policy comparison was made", candidate, runId));
  }

  if (execution.vulnerable.result_count === 0 && spec.validation.vulnerable_min_results > 0) {
    diagnostics.push(diagnostic("QUERY_EMPTY_RESULT", "vulnerable", "Vulnerable database produced no result", candidate, runId));
  }
  const passed = (spec.fixed_database === undefined || fixedObservation.status === "passed") && diagnostics.every((item) => item.severity !== "error");
  const repairHints = ["Use the result and flow evidence above to revise the structured draft; do not regenerate fixed QL boilerplate."];
  if (diagnostics.some((item) => item.code === "QUERY_SEMANTIC_MISMATCH")) {
    repairHints.unshift("Keep the candidate Source/Sink aligned with the workflow validation Source/Sink frozen at start; use newly probed internal or intermediate endpoints only as directed additional_flow_steps.");
  }
  if (spec.language === "cpp" && candidate.probe_evidence?.status === "passed" && diagnostics.some((item) => item.code === "QUERY_CODE_FLOW_MISSING")) {
    repairHints.unshift("C/C++ probes can match a field/array/formal endpoint without the global flow graph bridging that node to a call argument. Preserve the frozen Source/Sink and add only probe-confirmed boundary edges as directed additional_flow_steps (for example property -> call_argument), then re-run vulnerable CLI verification.");
  }
  return buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, passed ? {
    stage: "policy",
    root_causes: [],
    hints: [],
    next_action: "stop",
  } : {
    stage: execution.fixed.status === "passed" ? "policy" : "fixed",
    root_causes: diagnostics.map((item) => item.code),
    hints: repairHints,
    next_action: "revise_candidate",
  });
}

export function notRunFixedObservation(): ExecutionResult["fixed"] {
  return {
    database: "fixed",
    status: "not_run",
    result_count: 0,
    code_flow_count: 0,
    rule_ids: [],
    locations: [],
    flow_evidence: [],
    semantic_matches: [],
    elapsed_ms: 0,
  };
}

function buildVerification(
  runId: RunId,
  candidate: QueryCandidate,
  spec: VulnerabilitySpec,
  execution: ExecutionResult,
  fixedObservation: ExecutionResult["fixed"],
  diagnostics: QueryDiagnostic[],
  repairBrief: {
    stage: "preflight" | "compile" | "vulnerable" | "fixed" | "policy";
    root_causes: string[];
    hints: string[];
    next_action: "revise_candidate" | "retry_operation" | "stop";
  },
): QueryVerification {
  const passed = execution.compile.status === "passed" && execution.vulnerable.status === "passed" && (spec.fixed_database === undefined || fixedObservation.status === "passed") && diagnostics.every((diagnostic) => diagnostic.severity !== "error");
  return parseSchema(QueryVerificationSchema, {
    schema_version: CONTRACTS_VERSION,
    verification_id: `verification-${runId}-${candidate.candidate_id}`,
    run_id: runId,
    spec_id: spec.spec_id,
    candidate_id: candidate.candidate_id,
    round: candidate.round,
    status: passed ? "passed" : "failed",
    passed,
    verification_level: passed ? spec.fixed_database === undefined ? "reproduced" : "differential" : execution.compile.status === "passed" ? "compiled" : "generated",
    compile: execution.compile,
    vulnerable: execution.vulnerable,
    fixed: fixedObservation,
    diagnostics,
    repair_brief: repairBrief,
    elapsed_ms: execution.elapsedMs,
    ...(execution.codeqlCliVersion === undefined ? {} : { codeql_cli_version: execution.codeqlCliVersion }),
    ...(execution.extractorInfo === undefined ? {} : { extractor_info: execution.extractorInfo }),
    cancelled: execution.cancelled ?? false,
    timed_out: execution.timedOut ?? false,
  }, "query verification");
}

function diagnostic(code: QueryDiagnostic["code"], stage: QueryDiagnostic["stage"], message: string, candidate: QueryCandidate, runId: RunId, details: Record<string, unknown> = {}): QueryDiagnostic {
  return {
    schema_version: CONTRACTS_VERSION,
    code,
    severity: "error",
    message,
    retryable: false,
    candidate_id: candidate.candidate_id,
    run_id: runId,
    ...(stage === undefined ? {} : { stage }),
    details,
  };
}

function deduplicateDiagnostics(diagnostics: readonly QueryDiagnostic[]): QueryDiagnostic[] {
  const seen = new Set<string>();
  return diagnostics.filter((item) => {
    const key = `${item.code}:${item.stage ?? ""}:${item.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function within(value: number, minimum: number, maximum: number): boolean {
  return value >= minimum && value <= maximum;
}
