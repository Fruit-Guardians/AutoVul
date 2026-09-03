import { join } from "node:path";

import {
  CONTRACTS_VERSION,
  DomainError,
  type QueryCandidate,
  type QueryCompileObservation,
  type QueryDatabaseObservation,
  type QueryDiagnostic,
  type QueryLocation,
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
import { summarizeSarif, synthesizeDirectStructuredFlow } from "./query-sarif.js";
import { firstSanitizedLine, processSucceeded } from "./process-result.js";

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
    if (processSucceeded(version)) {
      cliVersion = firstSanitizedLine(version.stdout || version.stderr);
    }
    for (const role of ["source", "sink"] as const) {
      const result = await this.executeProbeRole(request, role, probeRoot, options);
      if (result.cancelled) throw new DomainError("PROCESS_CANCELLED", "process", `CodeQL ${role} probe was cancelled`, false, { role });
      if (result.timedOut) throw new DomainError("PROCESS_TIMEOUT", "process", `CodeQL ${role} probe timed out`, true, { role });
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
    if (!processSucceeded(compile)) {
      diagnostics.push(`${role} probe compile failed: ${diagnosticText(compile)}`);
      return { evidence: empty, diagnostics, passed: false, cancelled: compile.cancelled, timedOut: compile.timedOut };
    }
    const analyze = await this.executeProcess(
      ["database", "analyze", request.spec.vulnerable_database.path, queryPath, "--rerun", "--format=sarif-latest", `--output=${sarifPath}`, "--threads=1"],
      roleRoot,
      options,
    );
    if (!processSucceeded(analyze)) {
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
    const codeqlCliVersion = processSucceeded(versionResult) ? firstSanitizedLine(versionResult.stdout || versionResult.stderr) : undefined;
    const extractorInfo = processSucceeded(extractorResult) ? sanitizeOutput(extractorResult.stdout).trim() : undefined;
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
    if (!processSucceeded(checkCompileProcess)) {
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
    if (!processSucceeded(result)) {
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
    status: processSucceeded(result) ? "passed" : "failed",
    elapsed_ms: elapsedMs,
  };
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
  if (processSucceeded(result)) {
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
