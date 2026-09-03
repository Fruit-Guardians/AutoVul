import { DomainError, type FlowAnalyzerObservation, type FlowLocationRef, type QueryDatabaseObservation, type VulnerabilitySpec } from "@autovul/contracts";
import { projectFlowToTaintIntent, renderTaintQuery, type CodeqlOperationOptions, type FlowExecutionPort, type FlowExecutionRequest, type QueryExecutionPort, type QueryProbeExecutionPort } from "@autovul/core";

const CODEQL_FLOW_ADAPTER_VERSION = "autovul.codeql-flow/1";

/** CodeQL implementation of the single Flow v1 execution port. */
export class CodeqlFlowAdapter implements FlowExecutionPort {
  constructor(private readonly queries: QueryExecutionPort, private readonly probes: QueryProbeExecutionPort) {}

  async execute(request: FlowExecutionRequest, options: CodeqlOperationOptions): Promise<FlowAnalyzerObservation> {
    let intent;
    try {
      intent = projectFlowToTaintIntent(request.model);
      // Render before probes so an unsupported Flow semantic becomes an
      // explicit capability observation rather than a misleading no-match.
      renderTaintQuery(`flow-${request.model.model_id}`, intent);
    } catch (error: unknown) {
      if (error instanceof DomainError && (error.code === "CAPABILITY_MISMATCH" || error.code === "LANGUAGE_UNSUPPORTED" || error.code === "INTENT_INVALID")) {
        return unavailableObservation(error.code, typeof error.details.path === "string" ? error.details.path : "/");
      }
      throw error;
    }
    const spec: VulnerabilitySpec = {
      schema_version: "v2.contracts/1" as const, spec_id: request.model.model_id, language: request.model.language, cwe: intent.cwe,
      vulnerable_database: { path: request.target.vulnerable.path }, ...(request.target.fixed === undefined ? {} : { fixed_database: { path: request.target.fixed.path } }),
      validation: { vulnerable_min_results: 0, vulnerable_max_results: 10_000, fixed_min_results: 0, fixed_max_results: 10_000, must_have_code_flow: true },
      max_rounds: 1, timeout_ms: options.timeoutMs, created_at: new Date(0).toISOString(), input_provenance: "user_provided", reference_query_excluded: true,
      provenance: { fixture: "flow-v1", license: "internal", source: "autovul-flow" },
    };
    const probe = await this.probes.executeProbe({ runId: request.runId, intent, spec, artifactRoot: request.artifactRoot }, options);
    if (probe.status !== "passed") {
      throw new DomainError("PROBE_FAILED", "process", "Flow endpoint probe did not complete successfully", false, {
        model_id: request.model.model_id,
        probe_status: probe.status,
      });
    }
    const source = { state: probe.source.locations.length > 0 ? "observed" as const : "not_found" as const, locations: toLocations(probe.source.locations) };
    const sink = { state: probe.sink.locations.length > 0 ? "observed" as const : "not_found" as const, locations: toLocations(probe.sink.locations) };
    if (request.mode === "probe") {
      return {
        schema_version: "autovul.flow/1",
        compile_accepted: "not_run",
        source,
        sink,
        path: { state: "not_run", path_count: 0 },
        capability_gaps: [],
        evidence_refs: ["probes/" + request.model.model_id],
        analyzer: { analyzer_id: "codeql", available: true, adapter_version: CODEQL_FLOW_ADAPTER_VERSION, ...(probe.codeql_cli_version === undefined ? {} : { version: probe.codeql_cli_version }) },
      };
    }
    const candidate = {
      schema_version: "v2.contracts/1" as const, candidate_id: request.model.model_id, query_id: `flow-${request.model.model_id}`, spec_id: request.model.model_id,
      language: request.model.language, ql_text: renderTaintQuery(`flow-${request.model.model_id}`, intent), intent, probe_evidence: probe, round: 1, origin: "cli" as const,
    };
    const result = await this.queries.execute({ runId: request.runId, candidate, spec, artifactRoot: request.artifactRoot }, options);
    const analyzerVersion = result.codeqlCliVersion ?? probe.codeql_cli_version;
    return {
      schema_version: "autovul.flow/1", compile_accepted: result.compile.status === "passed",
      source,
      sink,
      path: toPath(result.vulnerable), ...(request.target.fixed === undefined ? {} : { fixed_path: toPath(result.fixed) }), capability_gaps: [],
      evidence_refs: ["probes/" + request.model.model_id, "candidates/" + request.model.model_id + "/vulnerable.sarif"], analyzer: { analyzer_id: "codeql", available: true, adapter_version: CODEQL_FLOW_ADAPTER_VERSION, ...(analyzerVersion === undefined ? {} : { version: analyzerVersion }) },
    };
  }
}

function unavailableObservation(code: string, path: string): FlowAnalyzerObservation {
  return { schema_version: "autovul.flow/1", compile_accepted: "not_run", source: { state: "not_run", locations: [] }, sink: { state: "not_run", locations: [] }, path: { state: "not_run", path_count: 0 }, capability_gaps: [{ code, path }], evidence_refs: [], analyzer: { analyzer_id: "codeql", available: true, adapter_version: CODEQL_FLOW_ADAPTER_VERSION } };
}

function toLocations(locations: readonly { file: string; start_line: number; end_line?: number }[]): FlowLocationRef[] {
  return locations.slice(0, 16).map((location) => ({ file: location.file, start_line: location.start_line, ...(location.end_line === undefined ? {} : { end_line: location.end_line }) }));
}
function toPath(observation: QueryDatabaseObservation): { state: "observed" | "not_observed" | "not_run"; path_count: number } {
  if (observation.status !== "passed") return { state: "not_run", path_count: 0 };
  return { state: observation.code_flow_count > 0 ? "observed" : "not_observed", path_count: observation.code_flow_count };
}
