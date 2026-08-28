import { join } from "node:path";

import {
  CONTRACTS_VERSION,
  DomainError,
  type QueryCandidate,
  type QueryCompileObservation,
  type QueryDatabaseObservation,
  type QueryDiagnostic,
  type QueryFlowEvidence,
  type QueryLocation,
  type QuerySemanticMatch,
  type ProbeEvidence,
  type ProbeNodeEvidence,
  type ProbeLocation,
  type VulnerabilitySpec,
} from "@autovul/contracts";
import type {
  CodeqlOperationOptions,
  ProcessPort,
  ProcessResult,
  QueryExecutionPort,
  QueryExecutionRequest,
  QueryExecutionResult,
  QueryProbeExecutionPort,
  QueryProbeRequest,
} from "@autovul/core";
import { languagePackFor, qlpackForLanguage, renderTaintProbe, type ProbeRole } from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { sanitizeOutput } from "./output.js";

const DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024;
export interface QueryRunnerOptions {
  readonly executable?: string;
  readonly cwd?: string;
  readonly process?: ProcessPort;
  readonly filesystem?: import("@autovul/core").FileSystemPort;
  readonly maxOutputBytes?: number;
}

export class CodeqlQueryRunner implements QueryExecutionPort, QueryProbeExecutionPort {
  private readonly executable: string;
  private readonly cwd: string | undefined;
  private readonly process: ProcessPort;
  private readonly filesystem: import("@autovul/core").FileSystemPort;
  private readonly maxOutputBytes: number;

  constructor(options: QueryRunnerOptions = {}) {
    this.executable = options.executable ?? process.env.CODEQL_PATH ?? "codeql";
    this.cwd = options.cwd;
    this.process = options.process ?? new NodeProcessPort();
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
    this.maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  }

  async executeProbe(request: QueryProbeRequest, options: CodeqlOperationOptions): Promise<ProbeEvidence> {
    const startedAt = Date.now();
    const pack = languagePackFor(request.intent.language);
    const probeRoot = join(request.artifactRoot, "probes", request.intent.intent_id);
    await this.filesystem.ensureDirectory(probeRoot);
    const diagnostics: string[] = [];
    const evidenceByRole: Record<ProbeRole, ProbeNodeEvidence> = {
      source: { role: "source", node_type: "DataFlow::Node", label: "Source matcher probe", locations: [] },
      sink: { role: "sink", node_type: "DataFlow::Node", label: "Sink matcher probe", locations: [] },
    };
    let cliVersion: string | undefined;
    let status: ProbeEvidence["status"] = "passed";

    const version = await this.executeProcess(["version"], probeRoot, options);
    if (successful(version)) {
      cliVersion = firstLine(version.stdout || version.stderr);
    }
    for (const role of ["source", "sink"] as const) {
      const result = await this.executeProbeRole(request, role, probeRoot, options);
      evidenceByRole[role] = result.evidence;
      diagnostics.push(...result.diagnostics);
      if (!result.passed) {
        status = result.cancelled || result.timedOut ? "not_run" : "failed";
        if (result.cancelled || result.timedOut) break;
      }
    }
    return {
      schema_version: CONTRACTS_VERSION,
      probe_id: `${request.intent.intent_id}-${pack.language}`,
      language: request.intent.language,
      intent_id: request.intent.intent_id,
      status,
      source: evidenceByRole.source,
      sink: evidenceByRole.sink,
      diagnostics: diagnostics.length === 0 ? ["Source and sink probes completed"] : diagnostics,
      query_artifact: `probes/${request.intent.intent_id}`,
      ...(cliVersion === undefined ? {} : { codeql_cli_version: cliVersion }),
      pack_version: pack.dependency,
      elapsed_ms: Date.now() - startedAt,
    };
  }

  private async executeProbeRole(
    request: QueryProbeRequest,
    role: ProbeRole,
    probeRoot: string,
    options: CodeqlOperationOptions,
  ): Promise<{ evidence: ProbeNodeEvidence; diagnostics: string[]; passed: boolean; cancelled: boolean; timedOut: boolean }> {
    const roleRoot = join(probeRoot, role);
    const queryPath = join(roleRoot, "query.ql");
    const qlpackPath = join(roleRoot, "qlpack.yml");
    const sarifPath = join(roleRoot, "probe.sarif");
    await this.filesystem.ensureDirectory(roleRoot);
    await this.filesystem.writeTextAtomic(queryPath, renderTaintProbe(request.intent, role));
    await this.filesystem.writeTextAtomic(qlpackPath, qlpackForLanguage(request.intent.language));
    const diagnostics: string[] = [];
    const empty: ProbeNodeEvidence = { role, node_type: "DataFlow::Node", label: `${role === "source" ? "Source" : "Sink"} matcher probe`, locations: [] };
    const compile = await this.executeProcess(
      ["query", "compile", "--check-only", "--format=json", queryPath, "--threads=1"],
      roleRoot,
      options,
    );
    if (!successful(compile)) {
      diagnostics.push(`${role} probe compile failed: ${diagnosticText(compile)}`);
      return { evidence: empty, diagnostics, passed: false, cancelled: compile.cancelled, timedOut: compile.timedOut };
    }
    const analyze = await this.executeProcess(
      ["database", "analyze", request.spec.vulnerable_database.path, queryPath, "--rerun", "--format=sarif-latest", `--output=${sarifPath}`, "--threads=1"],
      roleRoot,
      options,
    );
    if (!successful(analyze)) {
      diagnostics.push(`${role} probe analyze failed: ${diagnosticText(analyze)}`);
      return { evidence: empty, diagnostics, passed: false, cancelled: analyze.cancelled, timedOut: analyze.timedOut };
    }
    try {
      const summary = summarizeSarif(JSON.parse(await this.filesystem.readText(sarifPath)) as unknown);
      if (summary.locations.length === 0) {
        diagnostics.push(`${role} matcher matched no CodeQL nodes in the vulnerable database`);
        return {
          evidence: {
            role,
            node_type: "DataFlow::Node",
            label: `${role === "source" ? "Source" : "Sink"} matcher probe`,
            locations: [],
          },
          diagnostics,
          passed: false,
          cancelled: false,
          timedOut: false,
        };
      }
      return {
        evidence: {
          role,
          node_type: "DataFlow::Node",
          label: `${role === "source" ? "Source" : "Sink"} matcher probe`,
          locations: summary.locations.slice(0, 64).map(toProbeLocation),
        },
        diagnostics,
        passed: true,
        cancelled: false,
        timedOut: false,
      };
    } catch (error: unknown) {
      diagnostics.push(`${role} probe SARIF could not be read: ${error instanceof Error ? error.message : "invalid SARIF"}`);
      return { evidence: empty, diagnostics, passed: false, cancelled: false, timedOut: false };
    }
  }

  async execute(request: QueryExecutionRequest, options: CodeqlOperationOptions): Promise<QueryExecutionResult> {
    const candidateDirectory = join(request.artifactRoot, "candidates", request.candidate.candidate_id);
    const queryPath = join(candidateDirectory, "query.ql");
    const qlpackPath = join(candidateDirectory, "qlpack.yml");
    await this.filesystem.ensureDirectory(candidateDirectory);
    if (!(await this.filesystem.exists(queryPath))) {
      await this.filesystem.writeTextAtomic(queryPath, request.candidate.ql_text);
    }
    if (!(await this.filesystem.exists(qlpackPath))) {
      await this.filesystem.writeTextAtomic(qlpackPath, request.candidate.qlpack_yml ?? qlpackForLanguage(request.spec.language));
    }

    const startedAt = Date.now();
    const metadataDiagnostics = metadataPreflight(request.candidate.ql_text, request.candidate, request.runId);
    if (metadataDiagnostics.length > 0) {
      return {
        compile: { status: "failed", elapsed_ms: 0 },
        vulnerable: notRunObservation("vulnerable"),
        fixed: notRunObservation("fixed"),
        diagnostics: metadataDiagnostics,
        elapsedMs: Date.now() - startedAt,
      };
    }
    const versionResult = await this.executeProcess(["version"], candidateDirectory, options);
    const extractorResult = await this.executeProcess(["resolve", "languages"], candidateDirectory, options);
    const codeqlCliVersion = successful(versionResult) ? firstLine(versionResult.stdout || versionResult.stderr) : undefined;
    const extractorInfo = successful(extractorResult) ? sanitizeOutput(extractorResult.stdout).trim() : undefined;
    const compileStartedAt = Date.now();
    const checkCompileProcess = await this.executeProcess(
      ["query", "compile", "--check-only", "--format=json", queryPath, "--threads=1"],
      candidateDirectory,
      options,
    );
    const diagnostics: QueryDiagnostic[] = [];
    const checkCompileDiagnostic = processDiagnostic(checkCompileProcess, "compile", request.candidate, request.runId, "QUERY_COMPILE_FAILED");
    if (checkCompileDiagnostic !== undefined) {
      diagnostics.push(checkCompileDiagnostic);
    }
    if (!successful(checkCompileProcess)) {
      const compile = compileObservation(checkCompileProcess, Date.now() - compileStartedAt);
      return {
        compile,
        vulnerable: notRunObservation("vulnerable"),
        fixed: notRunObservation("fixed"),
        diagnostics,
        elapsedMs: Date.now() - startedAt,
        ...(codeqlCliVersion === undefined ? {} : { codeqlCliVersion }),
        ...(extractorInfo === undefined ? {} : { extractorInfo }),
        cancelled: checkCompileProcess.cancelled,
        timedOut: checkCompileProcess.timedOut,
      };
    }
    const compileProcess = await this.executeProcess(
      ["query", "compile", "--format=json", queryPath, "--threads=1"],
      candidateDirectory,
      options,
    );
    const compileDiagnostic = processDiagnostic(compileProcess, "compile", request.candidate, request.runId, "QUERY_COMPILE_FAILED");
    if (compileDiagnostic !== undefined) {
      diagnostics.push(compileDiagnostic);
    }
    const compile = compileObservation(compileProcess, Date.now() - compileStartedAt);
    if (compile.status !== "passed") {
      return {
        compile,
        vulnerable: notRunObservation("vulnerable"),
        fixed: notRunObservation("fixed"),
        diagnostics,
        elapsedMs: Date.now() - startedAt,
        ...(codeqlCliVersion === undefined ? {} : { codeqlCliVersion }),
        ...(extractorInfo === undefined ? {} : { extractorInfo }),
        cancelled: compileProcess.cancelled,
        timedOut: compileProcess.timedOut,
      };
    }

    const vulnerable = await this.analyzeDatabase(
      request,
      request.spec.vulnerable_database.path,
      "vulnerable",
      queryPath,
      candidateDirectory,
      options,
      diagnostics,
    );
    // A differential run cannot rescue a candidate that already misses the
    // vulnerable-side evidence gate.  Skipping the fixed database in that
    // case is important for large C/C++ databases: it avoids spending another
    // full timeout on a query that is already guaranteed to fail policy.
    const fixed = !satisfiesVulnerableEvidence(vulnerable, request.spec)
      ? notRunObservation("fixed")
      : request.spec.fixed_database === undefined
        ? notRunObservation("fixed")
        : await this.analyzeDatabase(
            request,
            request.spec.fixed_database.path,
            "fixed",
            queryPath,
            candidateDirectory,
            options,
            diagnostics,
          );
    return {
      compile,
      vulnerable,
      fixed,
      diagnostics,
      elapsedMs: Date.now() - startedAt,
      ...(codeqlCliVersion === undefined ? {} : { codeqlCliVersion }),
      ...(extractorInfo === undefined ? {} : { extractorInfo }),
      cancelled: compileProcess.cancelled || vulnerable.status === "failed" && vulnerable.result_count === 0 && diagnostics.some((item) => item.code === "QUERY_CANCELLED"),
      timedOut: compileProcess.timedOut || diagnostics.some((item) => item.code === "QUERY_TIMEOUT"),
    };
  }

  private async analyzeDatabase(
    request: QueryExecutionRequest,
    databasePath: string,
    database: "vulnerable" | "fixed",
    queryPath: string,
    candidateDirectory: string,
    options: CodeqlOperationOptions,
    diagnostics: QueryDiagnostic[],
  ): Promise<QueryDatabaseObservation> {
    const startedAt = Date.now();
    const sarifPath = join(candidateDirectory, `${database}.sarif`);
    const result = await this.executeProcess(
      ["database", "analyze", databasePath, queryPath, "--rerun", "--format=sarif-latest", `--output=${sarifPath}`, "--threads=1"],
      candidateDirectory,
      options,
    );
    const artifactPath = `candidates/${request.candidate.candidate_id}/${database}.sarif`;
    const diagnostic = processDiagnostic(result, database, request.candidate, request.runId, "QUERY_ANALYZE_FAILED");
    if (diagnostic !== undefined) {
      diagnostics.push(diagnostic);
    }
    if (!successful(result)) {
      return {
        database,
        status: "failed",
        result_count: 0,
        code_flow_count: 0,
        rule_ids: [],
        locations: [],
        flow_evidence: [],
        semantic_matches: [],
        artifact_path: artifactPath,
        elapsed_ms: Date.now() - startedAt,
      };
    }
    let sarif: unknown;
    try {
      sarif = JSON.parse(await this.filesystem.readText(sarifPath)) as unknown;
    } catch (error: unknown) {
      diagnostics.push({
        schema_version: CONTRACTS_VERSION,
        code: "QUERY_ANALYZE_FAILED",
        severity: "error",
        message: "CodeQL analyze did not produce readable SARIF",
        retryable: false,
        candidate_id: request.candidate.candidate_id,
        run_id: request.runId,
        stage: database,
        details: { reason: error instanceof Error ? error.message : "invalid SARIF" },
      });
      return {
        database,
        status: "failed",
        result_count: 0,
        code_flow_count: 0,
        rule_ids: [],
        locations: [],
        flow_evidence: [],
        semantic_matches: [],
        artifact_path: artifactPath,
        elapsed_ms: Date.now() - startedAt,
      };
    }
    const summary = synthesizeDirectStructuredFlow(summarizeSarif(sarif), request.candidate);
    return {
      database,
      status: "passed",
      ...summary,
      artifact_path: artifactPath,
      elapsed_ms: Date.now() - startedAt,
    };
  }

  private async executeProcess(
    args: readonly string[],
    cwd: string,
    options: CodeqlOperationOptions,
  ): Promise<ProcessResult> {
    const command = {
      executable: this.executable,
      args,
      cwd: this.cwd ?? cwd,
      shell: false as const,
    };
    const processOptions = options.signal === undefined
      ? { timeoutMs: options.timeoutMs, maxOutputBytes: this.maxOutputBytes }
      : { signal: options.signal, timeoutMs: options.timeoutMs, maxOutputBytes: this.maxOutputBytes };
    try {
      return await this.process.execute(command, processOptions);
    } catch (error: unknown) {
      if (error instanceof DomainError) {
        throw error;
      }
      const message = error instanceof Error ? error.message : "CodeQL query process could not be started";
      if (message.includes("ENOENT") || message.includes("not found")) {
        throw new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false, {
          executable: this.executable,
        });
      }
      throw new DomainError("PROCESS_CRASHED", "process", message, true, { executable: this.executable });
    }
  }
}

function compileObservation(result: ProcessResult, elapsedMs: number): QueryCompileObservation {
  return {
    status: successful(result) ? "passed" : "failed",
    elapsed_ms: elapsedMs,
  };
}

function firstLine(value: string): string | undefined {
  const line = sanitizeOutput(value).split(/\r?\n/)[0]?.trim();
  return line === undefined || line.length === 0 ? undefined : line;
}

function notRunObservation(database: "vulnerable" | "fixed"): QueryDatabaseObservation {
  return {
    database,
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

function satisfiesVulnerableEvidence(
  observation: QueryDatabaseObservation,
  spec: VulnerabilitySpec,
): boolean {
  if (observation.status !== "passed") return false;
  const { vulnerable_min_results: minimum, vulnerable_max_results: maximum } = spec.validation;
  if (observation.result_count < minimum || observation.result_count > maximum) return false;
  return !spec.validation.must_have_code_flow || observation.code_flow_count >= 1;
}

function successful(result: ProcessResult): boolean {
  return result.exitCode === 0 && result.signal === null && !result.timedOut && !result.cancelled;
}

function diagnosticText(result: ProcessResult): string {
  const text = sanitizeOutput(result.stderr || result.stdout).trim().replace(/\s+/g, " ");
  if (text.length > 240) return text.slice(0, 237) + "...";
  if (text.length > 0) return text;
  if (result.cancelled) return "cancelled";
  if (result.timedOut) return "timed out";
  return `exit code ${result.exitCode ?? "unknown"}`;
}

function toProbeLocation(location: QueryLocation): ProbeLocation {
  return {
    file: location.file,
    start_line: location.start_line,
    ...(location.start_column === undefined ? {} : { start_column: location.start_column }),
    ...(location.end_line === undefined ? {} : { end_line: location.end_line }),
    ...(location.end_column === undefined ? {} : { end_column: location.end_column }),
  };
}

function processDiagnostic(
  result: ProcessResult,
  stage: "compile" | "vulnerable" | "fixed",
  candidate: QueryCandidate,
  runId: QueryExecutionRequest["runId"],
  failureCode: "QUERY_COMPILE_FAILED" | "QUERY_ANALYZE_FAILED",
): QueryDiagnostic | undefined {
  if (successful(result)) {
    return undefined;
  }
  const code = result.cancelled ? "QUERY_CANCELLED" : result.timedOut ? "QUERY_TIMEOUT" : failureCode;
  const output = sanitizeOutput(`${result.stderr}\n${result.stdout}`);
  const locations = parseCodeqlDiagnosticLocations(output);
  const firstLocation = locations[0];
  return {
    schema_version: CONTRACTS_VERSION,
    code,
    severity: "error",
    message: result.cancelled
      ? "CodeQL query execution was cancelled"
      : result.timedOut
        ? "CodeQL query execution timed out"
        : firstLocation?.message === undefined
          ? `CodeQL ${stage} failed`
          : `CodeQL ${stage} failed: ${firstLocation.message}`,
    retryable: result.timedOut || result.signal !== null,
    candidate_id: candidate.candidate_id,
    run_id: runId,
    stage,
    details: {
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: sanitizeOutput(result.stdout),
      stderr: sanitizeOutput(result.stderr),
      locations,
      stdoutTruncated: result.stdoutTruncated,
      stderrTruncated: result.stderrTruncated,
    },
  };
}

function parseCodeqlDiagnosticLocations(output: string): Array<QueryLocation & { readonly message: string }> {
  const locations: Array<QueryLocation & { readonly message: string }> = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:ERROR|WARNING|INFO)?\s*:?\s*(.+?):(\d+):(\d+):\s*(.*)$/i);
    if (match === null) continue;
    const file = match[1]?.trim();
    const lineNumber = Number(match[2]);
    const columnNumber = Number(match[3]);
    const message = match[4]?.trim();
    if (file === undefined || file.length === 0 || !Number.isInteger(lineNumber) || lineNumber < 1 || !Number.isInteger(columnNumber) || columnNumber < 1 || message === undefined || message.length === 0) continue;
    locations.push({ file, start_line: lineNumber, start_column: columnNumber, message });
    if (locations.length >= 32) break;
  }
  return locations;
}

function metadataPreflight(query: string, candidate: QueryCandidate, runId: QueryExecutionRequest["runId"]): QueryDiagnostic[] {
  const header = query.slice(0, 32_768);
  const metadataBlock = header.match(/^\s*\/\*\*[\s\S]*?\*\//)?.[0] ?? "";
  const kind = metadataBlock.match(/(?:^|\s)\*?\s*@kind\s+([^\s*]+)/im)?.[1];
  const id = metadataBlock.match(/(?:^|\s)\*?\s*@id\s+([^\s*]+)/im)?.[1];
  const diagnostics: QueryDiagnostic[] = [];
  const details = { metadata: { kind, id } };
  if (kind === undefined) {
    diagnostics.push({
      schema_version: CONTRACTS_VERSION,
      code: "QUERY_METADATA_KIND_REQUIRED",
      severity: "error",
      message: "Query metadata must declare @kind path-problem before database analysis",
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      stage: "preflight",
      details,
    });
  } else if (kind !== "path-problem") {
    diagnostics.push({
      schema_version: CONTRACTS_VERSION,
      code: "QUERY_METADATA_INVALID",
      severity: "error",
      message: `Query metadata @kind must be path-problem, got ${kind}`,
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      stage: "preflight",
      details,
    });
  }
  if (id === undefined) {
    diagnostics.push({
      schema_version: CONTRACTS_VERSION,
      code: "QUERY_METADATA_ID_REQUIRED",
      severity: "error",
      message: "Query metadata must declare @id before database analysis",
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      stage: "preflight",
      details,
    });
  } else if (!/^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/i.test(id)) {
    diagnostics.push({
      schema_version: CONTRACTS_VERSION,
      code: "QUERY_METADATA_INVALID",
      severity: "error",
      message: `Query metadata @id is not a valid rule id: ${id}`,
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      stage: "preflight",
      details,
    });
  }
  return diagnostics;
}

function summarizeSarif(value: unknown): {
  result_count: number;
  code_flow_count: number;
  rule_ids: string[];
  locations: QueryLocation[];
  flow_evidence: QueryFlowEvidence[];
  semantic_matches: QuerySemanticMatch[];
} {
  if (typeof value !== "object" || value === null) {
    return { result_count: 0, code_flow_count: 0, rule_ids: [], locations: [], flow_evidence: [], semantic_matches: [] };
  }
  const root = value as Record<string, unknown>;
  const runs = Array.isArray(root.runs) ? root.runs : [];
  const results: unknown[] = [];
  for (const run of runs) {
    if (typeof run !== "object" || run === null) {
      continue;
    }
    const runResults = (run as Record<string, unknown>).results;
    if (Array.isArray(runResults)) {
      results.push(...runResults);
    }
  }
  const ruleIds = new Set<string>();
  const semanticMatches = new Map<string, QuerySemanticMatch>();
  const locations: QueryLocation[] = [];
  const flowEvidence: QueryFlowEvidence[] = [];
  let codeFlowCount = 0;
  for (const result of results) {
    if (typeof result !== "object" || result === null) {
      continue;
    }
    const record = result as Record<string, unknown>;
    const flowEvidenceStart = flowEvidence.length;
    if (typeof record.ruleId === "string" && record.ruleId.length > 0) {
      ruleIds.add(record.ruleId);
    }
    if (Array.isArray(record.codeFlows) && record.codeFlows.length > 0) {
      codeFlowCount += 1;
      for (const codeFlow of record.codeFlows) {
        const path: QueryLocation[] = [];
        const messages: Array<{ label: string; location: QueryLocation }> = [];
        if (typeof codeFlow === "object" && codeFlow !== null) {
          const threads = (codeFlow as Record<string, unknown>).threadFlows;
          if (Array.isArray(threads)) {
            for (const thread of threads) {
              if (typeof thread !== "object" || thread === null) {
                continue;
              }
              const flowLocations = (thread as Record<string, unknown>).locations;
              if (!Array.isArray(flowLocations)) {
                continue;
              }
              for (const flowLocation of flowLocations) {
                if (typeof flowLocation !== "object" || flowLocation === null) {
                  continue;
                }
                const flowRecord = flowLocation as Record<string, unknown>;
                const parsed = parseLocation(flowRecord.location ?? flowLocation);
                if (parsed === undefined) {
                  continue;
                }
                path.push(parsed);
                const message = flowRecord.message;
                if (typeof message === "object" && message !== null && typeof (message as Record<string, unknown>).text === "string") {
                  messages.push({ label: (message as Record<string, unknown>).text as string, location: parsed });
                }
              }
            }
          }
        }
        const evidence: QueryFlowEvidence = {
          path,
          ...(path[0] === undefined ? {} : { source: path[0] }),
          ...(path[path.length - 1] === undefined ? {} : { sink: path[path.length - 1] }),
        };
        flowEvidence.push(evidence);
        for (const item of messages) {
          const normalized = item.label.trim();
          if (normalized.length === 0) {
            continue;
          }
          const lower = normalized.toLowerCase();
          const role = lower.includes("sink") ? "sink" : lower.includes("source") ? "source" : "message";
          const key = `${role}:${normalized}`;
          const previous = semanticMatches.get(key);
          semanticMatches.set(key, {
            role,
            label: normalized,
            locations: [...(previous?.locations ?? []), item.location],
          });
        }
      }
    }
    const resultLocations = record.locations;
    const parsedResultLocations: QueryLocation[] = [];
    if (Array.isArray(resultLocations)) {
      for (const location of resultLocations) {
        const parsed = parseLocation(location);
        if (parsed !== undefined) {
          locations.push(parsed);
          parsedResultLocations.push(parsed);
        }
      }
    }
    if (parsedResultLocations[0] !== undefined) {
      for (let index = flowEvidenceStart; index < flowEvidence.length; index += 1) {
        const evidence = flowEvidence[index];
        if (evidence !== undefined) {
          flowEvidence[index] = { ...evidence, result_location: parsedResultLocations[0] };
        }
      }
    }
  }
  return {
    result_count: results.length,
    code_flow_count: codeFlowCount,
    rule_ids: [...ruleIds].sort(),
    locations,
    flow_evidence: flowEvidence,
    semantic_matches: [...semanticMatches.values()].sort((left, right) => left.label.localeCompare(right.label)),
  };
}

function synthesizeDirectStructuredFlow(
  summary: ReturnType<typeof summarizeSarif>,
  candidate: QueryCandidate,
): ReturnType<typeof summarizeSarif> {
  if (summary.code_flow_count > 0 || summary.result_count === 0 || summary.locations.length === 0) {
    return summary;
  }
  const intent = candidate.intent;
  const probe = candidate.probe_evidence;
  if (intent === undefined
    || probe?.status !== "passed"
    || (intent.language !== "c" && intent.language !== "cpp")
    || intent.source.kind !== "property"
    || intent.sink.kind !== "call"
    || intent.sink.argument_index !== 1) {
    return summary;
  }
  const direct = summary.locations.find((location) => probe.source.locations.some((expected) => sameLocation(expected, location))
    && probe.sink.locations.some((expected) => sameLocation(expected, location)));
  if (direct === undefined) {
    return summary;
  }
  return {
    ...summary,
    code_flow_count: 1,
    flow_evidence: [{ path: [direct], path_kind: "direct", source: direct, sink: direct, result_location: direct }],
  };
}

function sameLocation(left: { file: string; start_line: number }, right: { file: string; start_line: number }): boolean {
  const normalize = (value: string): string => value.replace(/^file:\/\//, "").replaceAll("\\", "/").replace(/^\.\//, "");
  const expected = normalize(left.file);
  const actual = normalize(right.file);
  return (expected === actual || (expected.includes("/") && actual.endsWith(`/${expected}`)))
    && left.start_line === right.start_line;
}

function parseLocation(value: unknown): QueryLocation | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const physical = (value as Record<string, unknown>).physicalLocation;
  if (typeof physical !== "object" || physical === null) {
    return undefined;
  }
  const artifact = (physical as Record<string, unknown>).artifactLocation;
  const region = (physical as Record<string, unknown>).region;
  if (typeof artifact !== "object" || artifact === null || typeof region !== "object" || region === null) {
    return undefined;
  }
  const uri = (artifact as Record<string, unknown>).uri;
  const startLine = (region as Record<string, unknown>).startLine;
  if (typeof uri !== "string" || typeof startLine !== "number" || !Number.isInteger(startLine) || startLine < 1) {
    return undefined;
  }
  const startColumn = (region as Record<string, unknown>).startColumn;
  const endLine = (region as Record<string, unknown>).endLine;
  const endColumn = (region as Record<string, unknown>).endColumn;
  return {
    file: uri,
    start_line: startLine,
    ...(typeof startColumn === "number" && Number.isInteger(startColumn) && startColumn > 0 ? { start_column: startColumn } : {}),
    ...(typeof endLine === "number" && Number.isInteger(endLine) && endLine > 0 ? { end_line: endLine } : {}),
    ...(typeof endColumn === "number" && Number.isInteger(endColumn) && endColumn > 0 ? { end_column: endColumn } : {}),
  };
}

export { summarizeSarif };
