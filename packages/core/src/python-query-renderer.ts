import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  PythonPathQueryCandidateSchema,
  QueryCandidateInputSchema,
  QueryCandidateSchema,
  type PythonPathQueryCandidate,
  type QueryCandidate,
  type QueryCandidateInput,
  type VulnerabilitySpec,
} from "@pure-auto-codeql/contracts";

const FORBIDDEN_DRAFT_TOKENS = /(^|\W)(?:import|module|select|from|@kind|@id)(?=\W|$)/i;

export function normalizePythonQueryCandidate(input: unknown, spec: VulnerabilitySpec): QueryCandidate {
  const candidateInput = parseSchema(QueryCandidateInputSchema, input, "query candidate input") as QueryCandidateInput;
  if ("ql_text" in candidateInput) {
    return parseSchema(QueryCandidateSchema, candidateInput, "query candidate");
  }
  const draftCandidate = parseSchema(PythonPathQueryCandidateSchema, candidateInput, "Python path query draft");
  return {
    schema_version: CONTRACTS_VERSION,
    candidate_id: draftCandidate.candidate_id,
    query_id: draftCandidate.query_id,
    spec_id: draftCandidate.spec_id,
    language: "python",
    ql_text: renderPythonPathQuery(draftCandidate, spec),
    draft: draftCandidate.draft,
    round: draftCandidate.round,
    origin: draftCandidate.origin,
    ...(draftCandidate.parent_candidate_id === undefined ? {} : { parent_candidate_id: draftCandidate.parent_candidate_id }),
    ...(draftCandidate.rationale === undefined ? {} : { rationale: draftCandidate.rationale }),
  };
}

export function renderPythonPathQuery(candidate: PythonPathQueryCandidate, spec: VulnerabilitySpec): string {
  const draft = candidate.draft;
  for (const [name, body] of Object.entries({
    source_predicate: draft.source_predicate,
    sink_predicate: draft.sink_predicate,
    additional_flow_step: draft.additional_flow_step,
    sanitizer_predicate: draft.sanitizer_predicate,
  })) {
    if (body !== undefined && FORBIDDEN_DRAFT_TOKENS.test(body)) {
      throw new DomainError("QUERY_DRAFT_INVALID", "input", `Python query draft ${name} contains fixed QL structure`, false, {
        field: name,
        forbidden: "import/module/select/from/@kind/@id",
      });
    }
  }
  const ruleId = `pure-auto-codeql/${candidate.query_id}`;
  const description = draft.description ?? spec.vulnerability_description ?? "Generated Python source-to-sink query.";
  const tags = `security external/cwe/${spec.cwe.toLowerCase().replaceAll("_", "-")}`;
  const additionalFlowStep = draft.additional_flow_step === undefined
    ? ""
    : [
        "",
        "",
        "  predicate isAdditionalFlowStep(DataFlow::Node source, DataFlow::Node sink) {",
        "    " + indent(draft.additional_flow_step),
        "  }",
      ].join("\n");
  const sanitizer = draft.sanitizer_predicate === undefined
    ? ""
    : [
        "",
        "",
        "  predicate isSanitizer(DataFlow::Node node) {",
        "    " + indent(draft.sanitizer_predicate),
        "  }",
      ].join("\n");
  const lines = [
    "/**",
    ` * @name ${qlDoc(description)}`,
    ` * @description ${qlDoc(description)}`,
    " * @kind path-problem",
    " * @problem.severity warning",
    " * @security-severity 7.5",
    " * @precision high",
    ` * @id ${ruleId}`,
    ` * @tags ${tags}`,
    " */",
    "",
    "import python",
    "import semmle.python.dataflow.new.DataFlow",
    "import semmle.python.dataflow.new.TaintTracking",
    "import semmle.python.ApiGraphs",
    "",
    "module Config implements DataFlow::ConfigSig {",
    "  predicate isSource(DataFlow::Node source) {",
    `    ${indent(draft.source_predicate)}`,
    "  }",
    "",
    "  predicate isSink(DataFlow::Node sink) {",
    `    ${indent(draft.sink_predicate)}`,
    `  }${additionalFlowStep}${sanitizer}`,
    "}",
    "",
    "module Flow = TaintTracking::Global<Config>;",
    "import Flow::PathGraph",
    "",
    "from Flow::PathNode source, Flow::PathNode sink",
    "where Flow::flowPath(source, sink)",
    `select sink.getNode(), source, sink, "${qlString(draft.message)}"`,
    "",
  ];
  return lines.join("\n");
}

function indent(value: string): string {
  return value.trim().split(/\r?\n/).map((line) => line.trim().length === 0 ? "" : "    " + line).join("\n    ");
}

function qlDoc(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\n", " ").replaceAll("*/", "* /");
}

function qlString(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", " ");
}
