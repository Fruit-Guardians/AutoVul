import { createHash } from "node:crypto";
import { join } from "node:path";
import ts from "typescript";

import {
  DomainError,
  type MissingCheckAnalyzerObservation,
  type MissingCheckLocationRef,
  type MissingCheckWitness,
  type TargetRef,
} from "@autovul/contracts";
import type {
  CodeqlOperationOptions,
  FileSystemPort,
  MissingCheckExecutionPort,
  MissingCheckExecutionRequest,
} from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";

const ADAPTER_VERSION = "autovul.javascript-cfg/1";
const COMPLETENESS_LIMITATIONS = [
  "cross_file_aliases_excluded",
  "indirect_calls_excluded",
  "dynamic_dispatch_excluded",
  "helper_semantics_excluded",
] as const;

interface AnalysisResult {
  readonly operations: readonly MissingCheckLocationRef[];
  readonly checks: readonly MissingCheckLocationRef[];
  readonly uncheckedWitnesses: readonly MissingCheckWitness[];
  readonly checkedWitnesses: readonly MissingCheckWitness[];
  readonly limitations: readonly (typeof COMPLETENESS_LIMITATIONS)[number][];
}

export class JavascriptCfgMissingCheckAdapter implements MissingCheckExecutionPort {
  private readonly filesystem: FileSystemPort;

  constructor(options: { readonly filesystem?: FileSystemPort } = {}) {
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
  }

  async execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation> {
    if (options.signal?.aborted) {
      throw new DomainError("PROCESS_CANCELLED", "process", `Execution was cancelled: ${request.runId}`, false);
    }
    const root = join(request.artifactRoot, "missing-check", request.hypothesis.hypothesis_id);
    await this.filesystem.ensureDirectory(root);

    const vulnerableWitnessRef = `missing-check/${request.hypothesis.hypothesis_id}/vulnerable/witnesses.json`;
    const vulnerableDir = join(root, "vulnerable");
    await this.filesystem.ensureDirectory(vulnerableDir);
    const vulnerablePath = join(request.target.vulnerable.path, request.hypothesis.scope.file);
    const vulnerable = await this.analyzeFile(
      vulnerablePath,
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

    if (request.mode === "differential" && request.target.fixed !== undefined) {
      fixedWitnessRef = `missing-check/${request.hypothesis.hypothesis_id}/fixed/witnesses.json`;
      const fixedDir = join(root, "fixed");
      await this.filesystem.ensureDirectory(fixedDir);
      const fixedPath = join(request.target.fixed.path, request.hypothesis.scope.file);
      fixed = await this.analyzeFile(
        fixedPath,
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

    const evidenceRefs = [vulnerableWitnessRef, ...(fixedWitnessRef === undefined ? [] : [fixedWitnessRef])];

    const isDominated = vulnerable.uncheckedWitnesses.length === 0 && vulnerable.checkedWitnesses.length > 0;
    const relationState = vulnerable.uncheckedWitnesses.length > 0
      ? "unchecked_witness" as const
      : isDominated
        ? "checked_witness" as const
        : "inconclusive" as const;

    const fixedRelationState = fixed === undefined
      ? undefined
      : fixed.uncheckedWitnesses.length > 0
        ? "unchecked_witness" as const
        : (fixed.checkedWitnesses.length > 0 && fixed.uncheckedWitnesses.length === 0)
          ? "checked_witness" as const
          : "inconclusive" as const;

    return {
      schema_version: "autovul.missing-check/1",
      compile_accepted: true,
      operation: {
        state: vulnerable.operations.length > 0 ? "observed" : "not_found",
        locations: [...vulnerable.operations],
      },
      required_check: {
        state: vulnerable.checks.length > 0 ? "observed" : "not_found",
        locations: [...vulnerable.checks],
      },
      relation: {
        state: relationState,
        unchecked_witnesses: [...vulnerable.uncheckedWitnesses],
        checked_witnesses: [...vulnerable.checkedWitnesses],
      },
      ...(fixed === undefined ? {} : {
        fixed_relation: {
          state: fixedRelationState!,
          unchecked_witnesses: [...fixed.uncheckedWitnesses],
          checked_witnesses: [...fixed.checkedWitnesses],
        },
      }),
      completeness: {
        vulnerable: {
          status: "complete",
          scope: request.hypothesis.scope,
          limitations: [...vulnerable.limitations],
        },
        ...(fixed === undefined ? {} : {
          fixed: {
            status: "complete",
            scope: request.hypothesis.scope,
            limitations: [...fixed.limitations],
          },
        }),
      },
      capability_gaps: [],
      evidence_refs: evidenceRefs,
      analyzer: {
        analyzer_id: "javascript_cfg",
        available: true,
        evidence_kind: "real_analyzer",
        version: `TypeScript AST ${ts.version}`,
        adapter_version: ADAPTER_VERSION,
      },
    };
  }

  async validateTarget(target: TargetRef, _options: CodeqlOperationOptions): Promise<string> {
    const exists = await this.filesystem.exists(target.path);
    if (!exists) {
      throw new DomainError(
        "DATABASE_FINGERPRINT_UNAVAILABLE",
        "database",
        `Target directory does not exist: ${target.path}`,
        false,
        { path: target.path },
      );
    }
    const stat = await this.filesystem.stat(target.path);
    let fingerprint: string;
    if (!stat.isDirectory) {
      const content = await this.filesystem.readText(target.path);
      fingerprint = createHash("sha256").update(content).digest("hex").slice(0, 16);
    } else {
      fingerprint = await this.computeDirectoryFingerprint(target.path);
    }
    if (target.expected_fingerprint !== undefined && target.expected_fingerprint !== fingerprint) {
      throw new DomainError(
        "DATABASE_FINGERPRINT_MISMATCH",
        "database",
        `Target fingerprint mismatch for ${target.path}`,
        false,
        {
          path: target.path,
          expected: target.expected_fingerprint,
          observed: fingerprint,
        },
      );
    }
    return fingerprint;
  }

  private async computeDirectoryFingerprint(dirPath: string): Promise<string> {
    const entries = await this.filesystem.listDirectory(dirPath);
    const hashes: string[] = [];
    for (const entry of entries) {
      const full = join(dirPath, entry.name);
      if (entry.isDirectory) {
        if (!entry.name.startsWith(".") && entry.name !== "node_modules") {
          hashes.push(`${entry.name}:${await this.computeDirectoryFingerprint(full)}`);
        }
      } else {
        const text = await this.filesystem.readText(full);
        const fileHash = createHash("sha256").update(text).digest("hex").slice(0, 16);
        hashes.push(`${entry.name}:${fileHash}`);
      }
    }
    hashes.sort();
    return createHash("sha256").update(hashes.join("\n")).digest("hex").slice(0, 16);
  }

  private async analyzeFile(
    fullPath: string,
    relativeFilePath: string,
    entryFunctionName: string,
    operationName: string,
    checkName: string,
    evidenceRef: string,
  ): Promise<AnalysisResult> {
    const exists = await this.filesystem.exists(fullPath);
    if (!exists) {
      return {
        operations: [],
        checks: [],
        uncheckedWitnesses: [],
        checkedWitnesses: [],
        limitations: [...COMPLETENESS_LIMITATIONS],
      };
    }
    const sourceText = await this.filesystem.readText(fullPath);
    const sourceFile = ts.createSourceFile(fullPath, sourceText, ts.ScriptTarget.Latest, true);

    const entryNode = findFunctionNode(sourceFile, entryFunctionName);
    if (entryNode === undefined || entryNode.body === undefined) {
      return {
        operations: [],
        checks: [],
        uncheckedWitnesses: [],
        checkedWitnesses: [],
        limitations: [...COMPLETENESS_LIMITATIONS],
      };
    }

    const operations: MissingCheckLocationRef[] = [];
    const checks: MissingCheckLocationRef[] = [];
    const uncheckedWitnesses: MissingCheckWitness[] = [];
    const checkedWitnesses: MissingCheckWitness[] = [];

    // Collect all call sites of operation and check in the function
    function collectCalls(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        const calledName = getCallName(node);
        if (calledName === operationName) {
          const loc = getNodeLocation(sourceFile, node, relativeFilePath);
          operations.push(loc);
        } else if (calledName === checkName) {
          const loc = getNodeLocation(sourceFile, node, relativeFilePath);
          checks.push(loc);
        }
      }
      ts.forEachChild(node, collectCalls);
    }
    collectCalls(entryNode.body);

    // Intra-procedural CFG walk analyzing paths to each operation call
    analyzeControlFlow(
      entryNode.body,
      operationName,
      checkName,
      relativeFilePath,
      sourceFile,
      evidenceRef,
      uncheckedWitnesses,
      checkedWitnesses,
    );

    return {
      operations,
      checks,
      uncheckedWitnesses,
      checkedWitnesses,
      limitations: [...COMPLETENESS_LIMITATIONS],
    };
  }
}

type FunctionLikeWithBody =
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration;

function findFunctionNode(sourceFile: ts.SourceFile, name: string): FunctionLikeWithBody | undefined {
  let matched: FunctionLikeWithBody | undefined;

  function visit(node: ts.Node) {
    if (matched !== undefined) return;
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) {
      matched = node;
      return;
    }
    if (ts.isMethodDeclaration(node) && node.name.getText(sourceFile) === name) {
      matched = node;
      return;
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer !== undefined) {
      if (ts.isFunctionExpression(node.initializer) || ts.isArrowFunction(node.initializer)) {
        matched = node.initializer;
        return;
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return matched;
}

function getCallName(node: ts.CallExpression): string | undefined {
  if (ts.isIdentifier(node.expression)) {
    return node.expression.text;
  }
  if (ts.isPropertyAccessExpression(node.expression)) {
    return node.expression.name.text;
  }
  return undefined;
}

function getNodeLocation(sourceFile: ts.SourceFile, node: ts.Node, relativeFilePath: string): MissingCheckLocationRef {
  const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
  return {
    file: relativeFilePath,
    start_line: line + 1,
  };
}

/** Check whether an expression contains a call to the required check function */
function containsCheckCall(expr: ts.Node, checkName: string): boolean {
  let found = false;
  function visit(n: ts.Node) {
    if (found) return;
    if (ts.isCallExpression(n) && getCallName(n) === checkName) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

/** Check whether a statement block definitely exits control flow (return or throw) */
function definitelyExits(stmt: ts.Statement): boolean {
  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt)) {
    return true;
  }
  if (ts.isBlock(stmt)) {
    return stmt.statements.some((s) => definitelyExits(s));
  }
  return false;
}

function analyzeControlFlow(
  body: ts.Node,
  operationName: string,
  checkName: string,
  relativeFilePath: string,
  sourceFile: ts.SourceFile,
  evidenceRef: string,
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): void {
  const statements: ts.Statement[] = ts.isBlock(body)
    ? [...body.statements]
    : ts.isExpression(body)
      ? [ts.factory.createExpressionStatement(body)]
      : [];

  let checkedOnCurrentPath = false;

  for (const stmt of statements) {
    // 1. Direct call to checkName in statement
    if (containsCheckCall(stmt, checkName)) {
      if (ts.isIfStatement(stmt)) {
        // Handle guard pattern: if (!check()) return/throw;
        const condition = stmt.expression;
        const conditionHasCheck = containsCheckCall(condition, checkName);

        if (conditionHasCheck) {
          // If thenStatement definitely exits, following statements are guarded!
          if (definitelyExits(stmt.thenStatement)) {
            checkedOnCurrentPath = true;
          }
          // Also analyze inside thenStatement
          analyzeBlock(
            stmt.thenStatement,
            operationName,
            checkName,
            relativeFilePath,
            sourceFile,
            evidenceRef,
            true, // Inside then branch where check passed
            uncheckedWitnesses,
            checkedWitnesses,
          );
          if (stmt.elseStatement !== undefined) {
            analyzeBlock(
              stmt.elseStatement,
              operationName,
              checkName,
              relativeFilePath,
              sourceFile,
              evidenceRef,
              false,
              uncheckedWitnesses,
              checkedWitnesses,
            );
          }
          continue;
        }
      } else {
        // Top-level call to checkName
        checkedOnCurrentPath = true;
      }
    }

    // 2. If statement without check in condition
    if (ts.isIfStatement(stmt)) {
      analyzeBlock(
        stmt.thenStatement,
        operationName,
        checkName,
        relativeFilePath,
        sourceFile,
        evidenceRef,
        checkedOnCurrentPath,
        uncheckedWitnesses,
        checkedWitnesses,
      );
      if (stmt.elseStatement !== undefined) {
        analyzeBlock(
          stmt.elseStatement,
          operationName,
          checkName,
          relativeFilePath,
          sourceFile,
          evidenceRef,
          checkedOnCurrentPath,
          uncheckedWitnesses,
          checkedWitnesses,
        );
      }
      continue;
    }

    // 3. Inspect operation calls in other statements
    findOperationsInNode(
      stmt,
      operationName,
      relativeFilePath,
      sourceFile,
      evidenceRef,
      checkedOnCurrentPath,
      uncheckedWitnesses,
      checkedWitnesses,
    );
  }
}

function analyzeBlock(
  blockNode: ts.Node,
  operationName: string,
  checkName: string,
  relativeFilePath: string,
  sourceFile: ts.SourceFile,
  evidenceRef: string,
  initialChecked: boolean,
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): void {
  const stmts = ts.isBlock(blockNode) ? blockNode.statements : [blockNode as ts.Statement];
  let checked = initialChecked;

  for (const s of stmts) {
    if (containsCheckCall(s, checkName)) {
      checked = true;
    }
    findOperationsInNode(
      s,
      operationName,
      relativeFilePath,
      sourceFile,
      evidenceRef,
      checked,
      uncheckedWitnesses,
      checkedWitnesses,
    );
  }
}

function findOperationsInNode(
  node: ts.Node,
  operationName: string,
  relativeFilePath: string,
  sourceFile: ts.SourceFile,
  evidenceRef: string,
  checked: boolean,
  uncheckedWitnesses: MissingCheckWitness[],
  checkedWitnesses: MissingCheckWitness[],
): void {
  function visit(n: ts.Node) {
    if (ts.isCallExpression(n) && getCallName(n) === operationName) {
      const loc = getNodeLocation(sourceFile, n, relativeFilePath);
      const witness: MissingCheckWitness = {
        operation: loc,
        evidence_ref: evidenceRef,
      };
      if (checked) {
        checkedWitnesses.push(witness);
      } else {
        uncheckedWitnesses.push(witness);
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(node);
}
