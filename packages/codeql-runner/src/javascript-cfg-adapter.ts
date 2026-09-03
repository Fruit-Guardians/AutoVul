import { createHash } from "node:crypto";
import { isAbsolute, join, relative, sep } from "node:path";
import ts from "typescript";

import {
  DomainError,
  type MissingCheckAnalyzerObservation,
  type MissingCheckLocationRef,
  type MissingCheckTarget,
  type MissingCheckWitness,
} from "@autovul/contracts";
import type {
  CodeqlOperationOptions,
  FileSystemPort,
  MissingCheckEvidenceDigest,
  MissingCheckEvidenceSnapshotPort,
  MissingCheckEvidenceSnapshotRequest,
  MissingCheckExecutionPort,
  MissingCheckExecutionRequest,
  ProcessPort,
} from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { processSucceeded } from "./process-result.js";

const ADAPTER_VERSION = "autovul.javascript-cfg/2";
const COMPLETENESS_LIMITATIONS = [
  "cross_file_aliases_excluded",
  "indirect_calls_excluded",
  "dynamic_dispatch_excluded",
  "helper_semantics_excluded",
] as const;

const GIT_ENVIRONMENT: Readonly<Record<string, string>> = {
  GIT_ATTR_NOSYSTEM: "1",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LC_ALL: "C",
};

export interface JavascriptCfgMissingCheckAdapterOptions {
  readonly trustedRoots?: readonly string[];
  readonly gitExecutable?: string;
  readonly filesystem?: FileSystemPort;
  readonly process?: ProcessPort;
}

interface AnalysisResult {
  readonly complete: boolean;
  readonly gaps: readonly { readonly code: string; readonly path: string }[];
  readonly operations: readonly MissingCheckLocationRef[];
  readonly checks: readonly MissingCheckLocationRef[];
  readonly uncheckedWitnesses: readonly MissingCheckWitness[];
  readonly checkedWitnesses: readonly MissingCheckWitness[];
}

interface PathState {
  readonly isGuarded: boolean;
  readonly isTerminated: boolean;
}

export class JavascriptCfgMissingCheckAdapter implements MissingCheckExecutionPort, MissingCheckEvidenceSnapshotPort {
  private readonly filesystem: FileSystemPort;
  private readonly process: ProcessPort;
  private readonly gitExecutable: string;
  private readonly trustedRoots: readonly string[];

  constructor(options: JavascriptCfgMissingCheckAdapterOptions = {}) {
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
    this.process = options.process ?? new NodeProcessPort();
    this.gitExecutable = options.gitExecutable ?? "git";
    this.trustedRoots = options.trustedRoots ? [...options.trustedRoots] : [process.cwd()];
  }

  async execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation> {
    if (options.signal?.aborted) {
      throw new DomainError("PROCESS_CANCELLED", "process", `Execution was cancelled: ${request.runId}`, false);
    }
    const target = request.target;
    if (target.vulnerable.kind !== "git_revision") {
      throw new DomainError("INVALID_INPUT", "input", "JavascriptCfgMissingCheckAdapter requires git_revision target", false);
    }
    const evidenceNamespace = request.workspace === "replay" ? "missing-check-replay" : "missing-check";
    const runArtifactRoot = request.artifactRoot;
    const evidenceRoot = join(runArtifactRoot, evidenceNamespace, request.hypothesis.hypothesis_id);
    await this.filesystem.ensureDirectory(evidenceRoot);

    const vulnerableWitnessRef = `${evidenceNamespace}/${request.hypothesis.hypothesis_id}/vulnerable/witnesses.json`;
    const vulnerableDir = join(evidenceRoot, "vulnerable");
    await this.filesystem.ensureDirectory(vulnerableDir);

    const vulnerableSource = await this.readGitFile(
      target.vulnerable.repository,
      target.vulnerable.revision,
      request.hypothesis.scope.file,
      options.signal,
    );

    const vulnerable = vulnerableSource === undefined
      ? {
          complete: false,
          gaps: [{ code: "MCHECK_FILE_NOT_FOUND", path: request.hypothesis.scope.file }],
          operations: [],
          checks: [],
          uncheckedWitnesses: [],
          checkedWitnesses: [],
        }
      : analyzeSource(
          vulnerableSource,
          request.hypothesis.scope.file,
          request.hypothesis.scope.entry.name,
          request.hypothesis.operation.name,
          request.hypothesis.required_check.name,
          vulnerableWitnessRef,
        );

    await this.filesystem.writeTextAtomic(
      join(vulnerableDir, "witnesses.json"),
      JSON.stringify(vulnerable, null, 2),
    );

    let fixed: AnalysisResult | undefined;
    let fixedWitnessRef: string | undefined;

    if (request.mode === "differential" && target.fixed !== undefined) {
      if (target.fixed.kind !== "git_revision") {
        throw new DomainError("INVALID_INPUT", "input", "JavascriptCfgMissingCheckAdapter requires git_revision target for fixed side", false);
      }
      fixedWitnessRef = `${evidenceNamespace}/${request.hypothesis.hypothesis_id}/fixed/witnesses.json`;
      const fixedDir = join(evidenceRoot, "fixed");
      await this.filesystem.ensureDirectory(fixedDir);

      const fixedSource = await this.readGitFile(
        target.fixed.repository,
        target.fixed.revision,
        request.hypothesis.scope.file,
        options.signal,
      );

      fixed = fixedSource === undefined
        ? {
            complete: false,
            gaps: [{ code: "MCHECK_FILE_NOT_FOUND", path: request.hypothesis.scope.file }],
            operations: [],
            checks: [],
            uncheckedWitnesses: [],
            checkedWitnesses: [],
          }
        : analyzeSource(
            fixedSource,
            request.hypothesis.scope.file,
            request.hypothesis.scope.entry.name,
            request.hypothesis.operation.name,
            request.hypothesis.required_check.name,
            fixedWitnessRef,
          );

      await this.filesystem.writeTextAtomic(
        join(fixedDir, "witnesses.json"),
        JSON.stringify(fixed, null, 2),
      );
    }

    const evidenceRefs = [
      vulnerableWitnessRef,
      ...(fixedWitnessRef === undefined ? [] : [fixedWitnessRef]),
    ];

    const isComplete = vulnerable.complete && (fixed === undefined || fixed.complete);
    const gaps = [...vulnerable.gaps, ...(fixed?.gaps ?? [])];

    return {
      schema_version: "autovul.missing-check/1",
      compile_accepted: isComplete,
      operation: {
        state: vulnerable.operations.length > 0 ? "observed" : "not_found",
        locations: [...vulnerable.operations],
      },
      required_check: {
        state: vulnerable.checks.length > 0 || (fixed !== undefined && fixed.checks.length > 0) ? "observed" : "not_found",
        locations: [...vulnerable.checks, ...(fixed?.checks ?? [])],
      },
      relation: {
        state: !vulnerable.complete
          ? "inconclusive"
          : vulnerable.uncheckedWitnesses.length > 0
            ? "unchecked_witness"
            : vulnerable.checkedWitnesses.length > 0
              ? "checked_witness"
              : "inconclusive",
        unchecked_witnesses: [...vulnerable.uncheckedWitnesses],
        checked_witnesses: [...vulnerable.checkedWitnesses],
      },
      ...(fixed === undefined
        ? {}
        : {
            fixed_relation: {
              state: !fixed.complete
                ? "inconclusive"
                : fixed.uncheckedWitnesses.length > 0
                  ? "unchecked_witness"
                  : fixed.checkedWitnesses.length > 0
                    ? "checked_witness"
                    : "inconclusive",
              unchecked_witnesses: [...fixed.uncheckedWitnesses],
              checked_witnesses: [...fixed.checkedWitnesses],
            },
          }),
      completeness: {
        vulnerable: {
          status: vulnerable.complete ? "complete" : "incomplete",
          scope: request.hypothesis.scope,
          limitations: [...COMPLETENESS_LIMITATIONS],
        },
        ...(fixed === undefined
          ? {}
          : {
              fixed: {
                status: fixed.complete ? "complete" : "incomplete",
                scope: request.hypothesis.scope,
                limitations: [...COMPLETENESS_LIMITATIONS],
              },
            }),
      },
      capability_gaps: gaps,
      evidence_refs: evidenceRefs,
      analyzer: {
        analyzer_id: "javascript_cfg",
        available: true,
        evidence_kind: "real_analyzer",
        version: ADAPTER_VERSION,
        adapter_version: ADAPTER_VERSION,
      },
    };
  }

  async validateTarget(target: MissingCheckTarget["vulnerable"], options: CodeqlOperationOptions): Promise<string> {
    if (target.kind !== "git_revision") {
      throw new DomainError("INVALID_INPUT", "input", "JavascriptCfgMissingCheckAdapter requires git_revision target", false);
    }
    const repository = await this.resolveTrustedRepository(target.repository);
    const result = await this.process.execute(
      {
        executable: this.gitExecutable,
        args: ["rev-parse", "--verify", `${target.revision}^{commit}`],
        cwd: repository,
        env: GIT_ENVIRONMENT,
        shell: false,
      },
      {
        timeoutMs: 10_000,
        maxOutputBytes: 1024 * 1024,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    );
    if (!processSucceeded(result)) {
      throw new DomainError(
        "DATABASE_FINGERPRINT_UNAVAILABLE",
        "database",
        `Revision is not a valid commit object in ${repository}: ${target.revision}`,
        false,
        { repository, revision: target.revision },
      );
    }
    const commitOid = result.stdout.trim();
    if (target.expected_fingerprint !== undefined && target.expected_fingerprint !== commitOid) {
      throw new DomainError(
        "DATABASE_FINGERPRINT_MISMATCH",
        "database",
        `Target fingerprint differs for revision ${target.revision}`,
        false,
        { repository, revision: target.revision, expected: target.expected_fingerprint, observed: commitOid },
      );
    }
    return commitOid;
  }

  async snapshotEvidence(request: MissingCheckEvidenceSnapshotRequest): Promise<readonly MissingCheckEvidenceDigest[]> {
    const root = join(request.artifactRoot, request.workspace === "replay" ? "missing-check-replay" : "missing-check", request.hypothesis.hypothesis_id);
    if (!await this.filesystem.exists(root)) return [];
    const files = await listEvidenceFiles(this.filesystem, root);
    const digests: MissingCheckEvidenceDigest[] = [];
    for (const file of files.filter((f) => f.endsWith(".json")).sort()) {
      const content = await this.filesystem.readText(file);
      const evidenceRef = relative(request.artifactRoot, file).split(sep).join("/");
      digests.push({
        evidence_ref: evidenceRef,
        sha256: createHash("sha256").update(content, "utf8").digest("hex"),
      });
    }
    return digests;
  }

  private async readGitFile(
    repositoryPath: string,
    revision: string,
    filePath: string,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    const repository = await this.resolveTrustedRepository(repositoryPath);
    const result = await this.process.execute(
      {
        executable: this.gitExecutable,
        args: ["cat-file", "-p", `${revision}:${filePath}`],
        cwd: repository,
        env: GIT_ENVIRONMENT,
        shell: false,
      },
      {
        timeoutMs: 10_000,
        maxOutputBytes: 10 * 1024 * 1024,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    if (!processSucceeded(result)) {
      return undefined;
    }
    return result.stdout;
  }

  private async resolveTrustedRepository(repoPath: string): Promise<string> {
    let canonical: string;
    try {
      canonical = await this.filesystem.canonicalize(repoPath);
    } catch {
      throw new DomainError("CHANGE_OBSERVATION_REPOSITORY_INVALID", "environment", "Repository path cannot be canonicalized", false, { path: repoPath });
    }
    const roots = await Promise.all(this.trustedRoots.map(async (root) => this.filesystem.canonicalize(root).catch(() => undefined)));
    if (!roots.some((root) => root !== undefined && isWithin(root, canonical))) {
      throw new DomainError("CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED", "policy", "Repository is outside configured trusted roots", false, { path: repoPath });
    }
    return canonical;
  }
}

function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

async function listEvidenceFiles(filesystem: FileSystemPort, directory: string): Promise<readonly string[]> {
  const entries = await filesystem.listDirectory(directory);
  const nested = await Promise.all(entries.map(async (entry) => entry.isDirectory
    ? listEvidenceFiles(filesystem, join(directory, entry.name))
    : [join(directory, entry.name)]));
  return nested.flat();
}

function analyzeSource(
  sourceText: string,
  filePath: string,
  entryName: string,
  opName: string,
  checkName: string,
  witnessRef: string,
): AnalysisResult {
  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const entryFunction = findEntryFunction(sourceFile, entryName);

  if (entryFunction === undefined) {
    return {
      complete: false,
      gaps: [{ code: "MCHECK_ENTRY_NOT_FOUND", path: entryName }],
      operations: [],
      checks: [],
      uncheckedWitnesses: [],
      checkedWitnesses: [],
    };
  }

  const unsupportedGaps = findUnsupportedConstructsGaps(entryFunction, opName, checkName);
  if (unsupportedGaps.length > 0) {
    return {
      complete: false,
      gaps: unsupportedGaps,
      operations: [],
      checks: [],
      uncheckedWitnesses: [],
      checkedWitnesses: [],
    };
  }

  const operations: MissingCheckLocationRef[] = [];
  const checks: MissingCheckLocationRef[] = [];
  const uncheckedWitnesses: MissingCheckWitness[] = [];
  const checkedWitnesses: MissingCheckWitness[] = [];

  const bodyStatements = getStatements(entryFunction);
  walkStatements(
    bodyStatements,
    [{ isGuarded: false, isTerminated: false }],
    sourceFile,
    filePath,
    opName,
    checkName,
    witnessRef,
    operations,
    checks,
    uncheckedWitnesses,
    checkedWitnesses,
  );

  return {
    complete: true,
    gaps: [],
    operations,
    checks,
    uncheckedWitnesses,
    checkedWitnesses,
  };
}

function findEntryFunction(sourceFile: ts.SourceFile, entryName: string): ts.FunctionLikeDeclaration | undefined {
  let matched: ts.FunctionLikeDeclaration | undefined;

  function visit(node: ts.Node): void {
    if (matched !== undefined) return;
    if (ts.isFunctionDeclaration(node) && node.name?.text === entryName) {
      matched = node;
      return;
    }
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.name.text === entryName) {
          if (decl.initializer && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) {
            matched = decl.initializer;
            return;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return matched;
}

function getStatements(fn: ts.FunctionLikeDeclaration): readonly ts.Statement[] {
  if (fn.body && ts.isBlock(fn.body)) {
    return fn.body.statements;
  }
  return [];
}

function findUnsupportedConstructsGaps(
  fn: ts.FunctionLikeDeclaration,
  opName: string,
  checkName: string,
): { readonly code: string; readonly path: string }[] {
  const gaps: { readonly code: string; readonly path: string }[] = [];

  function visit(node: ts.Node): void {
    if (node === fn) {
      ts.forEachChild(node, visit);
      return;
    }
    if (
      ts.isForStatement(node) ||
      ts.isForInStatement(node) ||
      ts.isForOfStatement(node) ||
      ts.isWhileStatement(node) ||
      ts.isDoStatement(node)
    ) {
      gaps.push({ code: "MCHECK_UNSUPPORTED_LOOP_CONSTRUCT", path: ts.SyntaxKind[node.kind] });
      return;
    }
    if (ts.isSwitchStatement(node)) {
      gaps.push({ code: "MCHECK_UNSUPPORTED_SWITCH_CONSTRUCT", path: "switch" });
      return;
    }
    if (ts.isTryStatement(node)) {
      gaps.push({ code: "MCHECK_UNSUPPORTED_TRY_CONSTRUCT", path: "try" });
      return;
    }
    if (ts.isBreakStatement(node) || ts.isContinueStatement(node) || ts.isLabeledStatement(node)) {
      gaps.push({ code: "MCHECK_UNSUPPORTED_JUMP_CONSTRUCT", path: ts.SyntaxKind[node.kind] });
      return;
    }
    if (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      let containsOpOrCheck = false;
      function checkNested(n: ts.Node): void {
        if (containsOpOrCheck) return;
        if (ts.isCallExpression(n)) {
          const callee = getCalleeName(n.expression);
          if (callee === opName || callee === checkName) {
            containsOpOrCheck = true;
            return;
          }
        }
        ts.forEachChild(n, checkNested);
      }
      checkNested(node);
      if (containsOpOrCheck) {
        gaps.push({ code: "MCHECK_UNSUPPORTED_NESTED_CALL", path: "nested_function" });
        return;
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(fn);
  return gaps;
}

function walkStatements(
  statements: readonly ts.Statement[],
  incomingPaths: readonly PathState[],
  sourceFile: ts.SourceFile,
  filePath: string,
  opName: string,
  checkName: string,
  witnessRef: string,
  operations: MissingCheckLocationRef[],
  checks: MissingCheckLocationRef[],
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): readonly PathState[] {
  let currentPaths: readonly PathState[] = incomingPaths.filter((p) => !p.isTerminated);

  for (const stmt of statements) {
    if (currentPaths.length === 0) break;

    if (ts.isIfStatement(stmt)) {
      currentPaths = walkIfStatement(
        stmt,
        currentPaths,
        sourceFile,
        filePath,
        opName,
        checkName,
        witnessRef,
        operations,
        checks,
        uncheckedWitnesses,
        checkedWitnesses,
      );
      continue;
    }

    if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt)) {
      checkForCalls(stmt, currentPaths, sourceFile, filePath, opName, checkName, witnessRef, operations, checks, uncheckedWitnesses, checkedWitnesses);
      currentPaths = [];
      break;
    }

    checkForCalls(stmt, currentPaths, sourceFile, filePath, opName, checkName, witnessRef, operations, checks, uncheckedWitnesses, checkedWitnesses);
  }

  return currentPaths;
}

function walkIfStatement(
  stmt: ts.IfStatement,
  incomingPaths: readonly PathState[],
  sourceFile: ts.SourceFile,
  filePath: string,
  opName: string,
  checkName: string,
  witnessRef: string,
  operations: MissingCheckLocationRef[],
  checks: MissingCheckLocationRef[],
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): readonly PathState[] {
  const polarity = evaluateConditionPolarity(stmt.expression, checkName, sourceFile, filePath, checks);

  let thenInitialPaths: PathState[];
  let elseInitialPaths: PathState[];

  if (polarity === "positive") {
    thenInitialPaths = incomingPaths.map((p) => ({ ...p, isGuarded: true }));
    elseInitialPaths = incomingPaths.map((p) => ({ ...p, isGuarded: false }));
  } else if (polarity === "negative") {
    thenInitialPaths = incomingPaths.map((p) => ({ ...p, isGuarded: false }));
    elseInitialPaths = incomingPaths.map((p) => ({ ...p, isGuarded: true }));
  } else {
    thenInitialPaths = incomingPaths.map((p) => ({ ...p }));
    elseInitialPaths = incomingPaths.map((p) => ({ ...p }));
  }

  const thenStatements = ts.isBlock(stmt.thenStatement) ? stmt.thenStatement.statements : [stmt.thenStatement];
  const thenExitingPaths = walkStatements(
    thenStatements,
    thenInitialPaths,
    sourceFile,
    filePath,
    opName,
    checkName,
    witnessRef,
    operations,
    checks,
    uncheckedWitnesses,
    checkedWitnesses,
  );

  let elseExitingPaths: readonly PathState[];
  if (stmt.elseStatement) {
    const elseStatements = ts.isBlock(stmt.elseStatement) ? stmt.elseStatement.statements : [stmt.elseStatement];
    elseExitingPaths = walkStatements(
      elseStatements,
      elseInitialPaths,
      sourceFile,
      filePath,
      opName,
      checkName,
      witnessRef,
      operations,
      checks,
      uncheckedWitnesses,
      checkedWitnesses,
    );
  } else {
    elseExitingPaths = elseInitialPaths;
  }

  return [...thenExitingPaths, ...elseExitingPaths];
}

function evaluateConditionPolarity(
  expr: ts.Expression,
  checkName: string,
  sourceFile: ts.SourceFile,
  filePath: string,
  checks: MissingCheckLocationRef[],
): "positive" | "negative" | "none" {
  if (ts.isCallExpression(expr)) {
    const callee = getCalleeName(expr.expression);
    if (callee === checkName) {
      checks.push(getLocation(expr, sourceFile, filePath));
      return "positive";
    }
  }

  if (
    ts.isPrefixUnaryExpression(expr) &&
    expr.operator === ts.SyntaxKind.ExclamationToken &&
    ts.isCallExpression(expr.operand)
  ) {
    const callee = getCalleeName(expr.operand.expression);
    if (callee === checkName) {
      checks.push(getLocation(expr.operand, sourceFile, filePath));
      return "negative";
    }
  }

  return "none";
}

function checkForCalls(
  node: ts.Node,
  activePaths: readonly PathState[],
  sourceFile: ts.SourceFile,
  filePath: string,
  opName: string,
  checkName: string,
  witnessRef: string,
  operations: MissingCheckLocationRef[],
  checks: MissingCheckLocationRef[],
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): void {
  function visit(n: ts.Node): void {
    if (ts.isCallExpression(n)) {
      const callee = getCalleeName(n.expression);
      if (callee === checkName) {
        checks.push(getLocation(n, sourceFile, filePath));
      }
      if (callee === opName) {
        const opLoc = getLocation(n, sourceFile, filePath);
        operations.push(opLoc);
        const allGuarded = activePaths.length > 0 && activePaths.every((p) => p.isGuarded);
        if (allGuarded) {
          const lastCheck = checks.at(-1);
          checkedWitnesses.push({
            operation: opLoc,
            ...(lastCheck === undefined ? {} : { check: lastCheck }),
            evidence_ref: witnessRef,
          });
        } else {
          uncheckedWitnesses.push({
            operation: opLoc,
            evidence_ref: witnessRef,
          });
        }
      }
    }
    ts.forEachChild(n, visit);
  }

  visit(node);
}

function getCalleeName(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  return undefined;
}

function getLocation(node: ts.Node, sourceFile: ts.SourceFile, filePath: string): MissingCheckLocationRef {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart());
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return {
    file: filePath,
    start_line: start.line + 1,
    end_line: end.line + 1,
  };
}
