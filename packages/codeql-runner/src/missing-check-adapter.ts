import { join } from "node:path";

import { DomainError, type MissingCheckAnalyzerObservation, type MissingCheckLocationRef } from "@autovul/contracts";
import type { CodeqlOperationOptions, MissingCheckExecutionPort, MissingCheckExecutionRequest, ProcessPort, ProcessResult, FileSystemPort } from "@autovul/core";
import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { codeqlProcessFailure, firstSanitizedLine, processSucceeded } from "./process-result.js";
import { summarizeSarif } from "./query-sarif.js";

const MAX_OUTPUT = 256 * 1024;
const ADAPTER_VERSION = "autovul.codeql-missing-check/1";
const COMPLETENESS_LIMITATIONS = [
  "cross_file_aliases_excluded",
  "indirect_calls_excluded",
  "dynamic_dispatch_excluded",
  "helper_semantics_excluded",
] as const;

/** The one frozen CodeQL JavaScript adapter for MissingCheck v1. */
export class CodeqlMissingCheckAdapter implements MissingCheckExecutionPort {
  private readonly executable: string;
  private readonly cwd: string | undefined;
  private readonly process: ProcessPort;
  private readonly filesystem: FileSystemPort;

  constructor(options: { readonly executable?: string; readonly cwd?: string; readonly process?: ProcessPort; readonly filesystem?: FileSystemPort } = {}) {
    this.executable = options.executable ?? process.env.CODEQL_PATH ?? "codeql";
    this.cwd = options.cwd;
    this.process = options.process ?? new NodeProcessPort();
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
  }

  async execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation> {
    if (request.target.vulnerable.kind !== "codeql_database") {
      throw new DomainError("INVALID_INPUT", "input", "CodeqlMissingCheckAdapter requires codeql_database target", false);
    }
    const evidenceNamespace = request.workspace === "replay" ? "missing-check-replay" : "missing-check";
    const root = join(request.artifactRoot, evidenceNamespace, request.hypothesis.hypothesis_id);
    await this.filesystem.ensureDirectory(root);
    const query = renderQuery(
      request.hypothesis.operation.name,
      request.hypothesis.required_check.name,
      request.hypothesis.scope.file,
      request.hypothesis.scope.entry.name,
    );
    await this.filesystem.writeTextAtomic(join(root, "unchecked.ql"), query.unchecked);
    await this.filesystem.writeTextAtomic(join(root, "checked.ql"), query.checked);
    await this.filesystem.writeTextAtomic(join(root, "operations.ql"), query.operations);
    await this.filesystem.writeTextAtomic(join(root, "checks.ql"), query.checks);
    await this.filesystem.writeTextAtomic(join(root, "qlpack.yml"), "name: autovul/missing-check\nversion: 0.0.0\ndependencies:\n  codeql/javascript-all: \"*\"\n");
    const version = await this.run(["version"], root, options);
    if (!processSucceeded(version)) {
      const failure = codeqlProcessFailure(version, "version", "MissingCheck");
      if (failure.code === "PROCESS_CANCELLED" || failure.code === "PROCESS_TIMEOUT" || failure.code === "CODEQL_CLI_NOT_FOUND") throw failure;
      throw new DomainError("CODEQL_RESOLVE_FAILED", "environment", "MissingCheck could not resolve the CodeQL CLI version", false);
    }
    const cliVersion = firstSanitizedLine(version.stdout || version.stderr);
    if (cliVersion === undefined) throw new DomainError("CODEQL_RESOLVE_FAILED", "environment", "MissingCheck CodeQL CLI returned no version", false);
    const compile = await this.run(["query", "compile", "--check-only", "--format=json", join(root, "unchecked.ql"), "--threads=1"], root, options);
    if (!processSucceeded(compile)) throw codeqlProcessFailure(compile, "compile", "MissingCheck");
    const vulnerable = await this.observeSide(root, evidenceNamespace, request.hypothesis.hypothesis_id, request.target.vulnerable.path, "vulnerable", options);
    const fixed = request.mode === "differential" && request.target.fixed !== undefined && request.target.fixed.kind === "codeql_database"
      ? await this.observeSide(root, evidenceNamespace, request.hypothesis.hypothesis_id, request.target.fixed.path, "fixed", options)
      : undefined;
    return {
      schema_version: "autovul.missing-check/1", compile_accepted: true,
      operation: vulnerable.operations, required_check: vulnerable.checks, relation: vulnerable.relation,
      ...(fixed === undefined ? {} : { fixed_relation: fixed.relation }), capability_gaps: [],
      completeness: {
        vulnerable: { status: "complete", scope: request.hypothesis.scope, limitations: [...COMPLETENESS_LIMITATIONS] },
        ...(fixed === undefined ? {} : { fixed: { status: "complete", scope: request.hypothesis.scope, limitations: [...COMPLETENESS_LIMITATIONS] } }),
      },
      evidence_refs: [...vulnerable.evidenceRefs, ...(fixed === undefined ? [] : fixed.evidenceRefs)],
      analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", adapter_version: ADAPTER_VERSION, version: cliVersion },
    };
  }

  private async observeSide(root: string, evidenceNamespace: string, hypothesisId: string, database: string, side: "vulnerable" | "fixed", options: CodeqlOperationOptions): Promise<Side> {
    // CodeQL writes query-result state beneath the database. Keep these
    // observations serial so independent selectors cannot race that state.
    const operations = await this.analyze(root, database, side, "operations", options);
    const checks = await this.analyze(root, database, side, "checks", options);
    const unchecked = await this.analyze(root, database, side, "unchecked", options);
    const checked = await this.analyze(root, database, side, "checked", options);
    const operation = subject(operations); const check = subject(checks);
    const evidencePrefix = `${evidenceNamespace}/${hypothesisId}/${side}`;
    const uncheckedWitnesses = witnesses(unchecked, `${evidencePrefix}/unchecked.sarif`);
    const checkedWitnesses = witnesses(checked, `${evidencePrefix}/checked.sarif`);
    const relation = unchecked.ok && uncheckedWitnesses.length > 0
      ? { state: "unchecked_witness" as const, unchecked_witnesses: uncheckedWitnesses, checked_witnesses: [] }
      : checked.ok && checkedWitnesses.length > 0 && operations.ok
        ? { state: "checked_witness" as const, unchecked_witnesses: [], checked_witnesses: checkedWitnesses }
        : unchecked.ok && checked.ok && operations.ok
          ? { state: "inconclusive" as const, unchecked_witnesses: [], checked_witnesses: [] }
          : { state: "not_run" as const, unchecked_witnesses: [], checked_witnesses: [] };
    return { operations: operation, checks: check, relation, evidenceRefs: [`${evidencePrefix}/operations.sarif`, `${evidencePrefix}/checks.sarif`, `${evidencePrefix}/unchecked.sarif`, `${evidencePrefix}/checked.sarif`] };
  }

  private async analyze(root: string, database: string, side: "vulnerable" | "fixed", kind: "operations" | "checks" | "unchecked" | "checked", options: CodeqlOperationOptions): Promise<Analysis> {
    const output = join(root, side, `${kind}.sarif`);
    await this.filesystem.ensureDirectory(join(root, side));
    const result = await this.run(["database", "analyze", database, join(root, `${kind}.ql`), "--rerun", "--format=sarif-latest", `--output=${output}`, "--threads=1"], root, options);
    if (!processSucceeded(result)) throw codeqlProcessFailure(result, `${side}:${kind}`, "MissingCheck");
    try { return { ok: true, locations: summarizeSarif(JSON.parse(await this.filesystem.readText(output)) as unknown).locations.map((location) => ({ file: location.file, start_line: location.start_line, ...(location.end_line === undefined ? {} : { end_line: location.end_line }) })) }; }
    catch (error: unknown) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `MissingCheck CodeQL ${side}:${kind} produced unreadable SARIF`, false, { side, kind, output, reason: error instanceof Error ? error.message : "invalid SARIF" });
    }
  }

  private async run(args: readonly string[], cwd: string, options: CodeqlOperationOptions): Promise<ProcessResult> {
    try { return await this.process.execute({ executable: this.executable, args, cwd: this.cwd ?? cwd, shell: false }, options.signal === undefined ? { timeoutMs: options.timeoutMs, maxOutputBytes: MAX_OUTPUT } : { signal: options.signal, timeoutMs: options.timeoutMs, maxOutputBytes: MAX_OUTPUT }); }
    catch (error: unknown) {
      if (error instanceof DomainError) throw error;
      throw new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false, { executable: this.executable });
    }
  }
}

interface Analysis { readonly ok: boolean; readonly locations: readonly MissingCheckLocationRef[]; }
interface Side { readonly operations: MissingCheckAnalyzerObservation["operation"]; readonly checks: MissingCheckAnalyzerObservation["required_check"]; readonly relation: MissingCheckAnalyzerObservation["relation"]; readonly evidenceRefs: readonly string[]; }
function subject(result: Analysis): MissingCheckAnalyzerObservation["operation"] { return { state: result.ok ? result.locations.length > 0 ? "observed" : "not_found" : "not_run", locations: result.locations.slice(0, 16) }; }
function witnesses(result: Analysis, evidenceRef: string): MissingCheckAnalyzerObservation["relation"]["unchecked_witnesses"] { return result.locations.slice(0, 16).map((operation) => ({ operation, evidence_ref: evidenceRef })); }

function renderQuery(operation: string, check: string, file: string, entry: string): Record<"unchecked" | "checked" | "operations" | "checks", string> {
  const op = JSON.stringify(operation); const guard = JSON.stringify(check); const sourceFile = JSON.stringify(file); const entryName = JSON.stringify(entry);
  const header = "/**\n * @name AutoVul MissingCheck v1 observation\n * @id autovul/missing-check/observation\n * @kind problem\n * @problem.severity warning\n */\nimport javascript\n\npredicate inScope(CallExpr call) {\n  call.getLocation().getFile().getRelativePath() = " + sourceFile + " and\n  exists(Function entry |\n    entry.getName() = " + entryName + " and\n    entry.getLocation().getFile() = call.getLocation().getFile() and\n    entry.getLocation().getStartLine() <= call.getLocation().getStartLine() and\n    call.getLocation().getEndLine() <= entry.getLocation().getEndLine()\n  )\n}\npredicate isOperation(CallExpr call) { inScope(call) and call.getCallee().(VarAccess).getName() = " + op + " }\npredicate isCheck(CallExpr call) { inScope(call) and call.getCallee().(VarAccess).getName() = " + guard + " }\npredicate dominates(CallExpr check, CallExpr operation) { check.getEnclosingFunction() = operation.getEnclosingFunction() and check.getBasicBlock().(ReachableBasicBlock).dominates(operation.getBasicBlock()) }\n";
  return {
    operations: `${header}\nfrom CallExpr operation where isOperation(operation) select operation, "protected operation"\n`,
    checks: `${header}\nfrom CallExpr check where isCheck(check) select check, "required check"\n`,
    unchecked: `${header}\nfrom CallExpr operation where isOperation(operation) and not exists(CallExpr check | isCheck(check) and dominates(check, operation)) select operation, "unchecked protected operation"\n`,
    checked: `${header}\nfrom CallExpr operation, CallExpr check where isOperation(operation) and isCheck(check) and dominates(check, operation) select operation, "checked protected operation"\n`,
  };
}
