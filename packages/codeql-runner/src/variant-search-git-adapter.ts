import { createHash } from "node:crypto";
import { isAbsolute, relative } from "node:path";
import ts from "typescript";

import {
  DomainError,
  type GitRevisionTargetRef,
  type VariantCandidate,
  type VariantSearchStrategy,
} from "@autovul/contracts";
import type {
  FileSystemPort,
  ProcessPort,
  VariantSearchPort,
  VariantSearchPortObservation,
  VariantSearchPortRequest,
} from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { processSucceeded } from "./process-result.js";

const ADAPTER_VERSION = "autovul.variant-search-git/1";

const GIT_ENVIRONMENT: Readonly<Record<string, string>> = {
  GIT_ATTR_NOSYSTEM: "1",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LC_ALL: "C",
};

export interface GitVariantSearchAdapterOptions {
  readonly trustedRoots?: readonly string[];
  readonly gitExecutable?: string;
  readonly filesystem?: FileSystemPort;
  readonly process?: ProcessPort;
}

export class GitVariantSearchAdapter implements VariantSearchPort {
  private readonly filesystem: FileSystemPort;
  private readonly process: ProcessPort;
  private readonly gitExecutable: string;
  private readonly trustedRoots: readonly string[];

  constructor(options: GitVariantSearchAdapterOptions = {}) {
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
    this.process = options.process ?? new NodeProcessPort();
    this.gitExecutable = options.gitExecutable ?? "git";
    this.trustedRoots = options.trustedRoots ? [...options.trustedRoots] : [process.cwd()];
  }

  async search(
    request: VariantSearchPortRequest,
    options: { readonly signal?: AbortSignal },
  ): Promise<VariantSearchPortObservation> {
    if (options.signal?.aborted) {
      throw new DomainError("PROCESS_CANCELLED", "process", "Variant search was cancelled", false);
    }

    const matchedSymbols = new Set(request.seedFacts.matchedSymbols);
    const primarySymbol = request.seedFacts.primarySymbol;
    const candidates: VariantCandidate[] = [];
    const seenCandidateIds = new Set<string>();
    let budgetExhausted = false;
    let targetsInspected = 0;
    let filesInspected = 0;

    for (const target of request.input.corpus) {
      if (budgetExhausted) break;
      if (options.signal?.aborted) {
        throw new DomainError("PROCESS_CANCELLED", "process", "Variant search was cancelled", false);
      }

      const repository = await this.resolveTrustedRepository(target.repository);
      targetsInspected++;

      // Verify commit
      const revResult = await this.process.execute(
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
      if (!processSucceeded(revResult)) {
        throw new DomainError(
          "DATABASE_FINGERPRINT_UNAVAILABLE",
          "database",
          `Target revision is not a valid commit in ${repository}: ${target.revision}`,
          false,
          { repository, revision: target.revision },
        );
      }

      const commitOid = revResult.stdout.trim();
      if (target.expected_fingerprint !== undefined && target.expected_fingerprint !== commitOid) {
        throw new DomainError(
          "DATABASE_FINGERPRINT_MISMATCH",
          "database",
          `Target fingerprint mismatch for revision: ${target.revision}`,
          false,
          { repository, revision: target.revision, expected: target.expected_fingerprint, observed: commitOid },
        );
      }

      // List files
      const lsResult = await this.process.execute(
        {
          executable: this.gitExecutable,
          args: ["ls-tree", "-r", "--name-only", target.revision],
          cwd: repository,
          env: GIT_ENVIRONMENT,
          shell: false,
        },
        {
          timeoutMs: 15_000,
          maxOutputBytes: 10 * 1024 * 1024,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        },
      );
      if (!processSucceeded(lsResult)) continue;

      const sourceFiles = lsResult.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => isCandidateSourceFile(line))
        .slice(0, request.resolvedBudget.max_files_per_target);

      for (const filePath of sourceFiles) {
        if (options.signal?.aborted) {
          throw new DomainError("PROCESS_CANCELLED", "process", "Variant search was cancelled", false);
        }
        if (candidates.length >= request.resolvedBudget.max_candidates) {
          budgetExhausted = true;
          break;
        }

        filesInspected++;
        const sourceText = await this.readGitFile(repository, target.revision, filePath, options.signal);
        if (sourceText === undefined) continue;

        const fileCandidates = findCandidatesInSource(
          sourceText,
          filePath,
          target,
          matchedSymbols,
          primarySymbol,
          request.input.strategy,
        );

        for (const candidate of fileCandidates) {
          if (!seenCandidateIds.has(candidate.candidate_id)) {
            seenCandidateIds.add(candidate.candidate_id);
            candidates.push(candidate);
            if (candidates.length >= request.resolvedBudget.max_candidates) {
              budgetExhausted = true;
              break;
            }
          }
        }
      }
    }

    candidates.sort((a, b) => {
      const cmpTarget = a.target.revision.localeCompare(b.target.revision);
      if (cmpTarget !== 0) return cmpTarget;
      const cmpFile = a.location.file.localeCompare(b.location.file);
      if (cmpFile !== 0) return cmpFile;
      return a.location.start_line - b.location.start_line;
    });

    const evidenceRefs = candidates.map((c) => c.evidence_ref);

    return {
      candidates,
      budgetExhausted,
      targetsInspected,
      filesInspected,
      evidenceRefs,
      analyzer: {
        analyzer_id: "variant_search_git",
        evidence_kind: "real_analyzer",
        version: ADAPTER_VERSION,
        adapter_version: ADAPTER_VERSION,
      },
    };
  }

  private async readGitFile(
    repository: string,
    revision: string,
    filePath: string,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
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
    if (!processSucceeded(result)) return undefined;
    return result.stdout;
  }

  private async resolveTrustedRepository(repoPath: string): Promise<string> {
    let canonical: string;
    try {
      canonical = await this.filesystem.canonicalize(repoPath);
    } catch {
      throw new DomainError(
        "CHANGE_OBSERVATION_REPOSITORY_INVALID",
        "environment",
        "Repository path cannot be canonicalized",
        false,
        { path: repoPath },
      );
    }
    const roots = await Promise.all(
      this.trustedRoots.map(async (root) => this.filesystem.canonicalize(root).catch(() => undefined)),
    );
    if (!roots.some((root) => root !== undefined && isWithin(root, canonical))) {
      throw new DomainError(
        "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED",
        "policy",
        "Repository is outside configured trusted roots",
        false,
        { path: repoPath },
      );
    }
    return canonical;
  }
}

function isCandidateSourceFile(filePath: string): boolean {
  if (filePath.endsWith(".d.ts") || filePath.endsWith(".d.mts") || filePath.endsWith(".d.cts")) {
    return false;
  }
  return (
    filePath.endsWith(".js") ||
    filePath.endsWith(".mjs") ||
    filePath.endsWith(".cjs") ||
    filePath.endsWith(".jsx") ||
    filePath.endsWith(".ts") ||
    filePath.endsWith(".mts") ||
    filePath.endsWith(".cts") ||
    filePath.endsWith(".tsx")
  );
}

function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function findCandidatesInSource(
  sourceText: string,
  filePath: string,
  target: GitRevisionTargetRef,
  matchedSymbols: ReadonlySet<string>,
  primarySymbol?: string,
  strategy: VariantSearchStrategy = "symbol_call_pattern",
): readonly VariantCandidate[] {
  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const candidates: VariantCandidate[] = [];

  function visit(node: ts.Node, currentEnclosingFunction?: string): void {
    let nextEnclosing = currentEnclosingFunction;

    if (ts.isFunctionDeclaration(node) && node.name) {
      nextEnclosing = node.name.text;
    } else if (
      (ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node) || ts.isPropertyAssignment(node)) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      nextEnclosing = node.name.text;
    } else if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
      nextEnclosing = node.name.text;
    }

    if (strategy === "enclosing_signature" && nextEnclosing && nextEnclosing !== currentEnclosingFunction && matchedSymbols.has(nextEnclosing)) {
      const start = sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
      const startLine = start.line + 1;
      const endLine = end.line + 1;

      const candidateDigest = createHash("sha256")
        .update(`${target.repository}:${target.revision}:${filePath}:${startLine}:${nextEnclosing}`)
        .digest("hex");

      candidates.push({
        candidate_id: candidateDigest,
        target: { ...target },
        location: {
          file: filePath,
          start_line: startLine,
          end_line: endLine,
          enclosing_symbol: nextEnclosing,
        },
        match_kind: primarySymbol !== undefined && nextEnclosing === primarySymbol ? "exact_symbol" : "pattern_match",
        matched_symbols: [nextEnclosing],
        evidence_ref: `research/variant-search/candidates/${candidateDigest}.json`,
      });
    }

    if (ts.isCallExpression(node)) {
      const calleeName = getCalleeName(node.expression);
      if (calleeName && matchedSymbols.has(calleeName)) {
        const start = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
        const startLine = start.line + 1;
        const endLine = end.line + 1;

        const candidateDigest = createHash("sha256")
          .update(`${target.repository}:${target.revision}:${filePath}:${startLine}:${calleeName}`)
          .digest("hex");

        candidates.push({
          candidate_id: candidateDigest,
          target: { ...target },
          location: {
            file: filePath,
            start_line: startLine,
            end_line: endLine,
            ...(nextEnclosing !== undefined ? { enclosing_symbol: nextEnclosing } : {}),
          },
          match_kind: primarySymbol !== undefined && calleeName === primarySymbol ? "exact_symbol" : "pattern_match",
          matched_symbols: [calleeName],
          evidence_ref: `research/variant-search/candidates/${candidateDigest}.json`,
        });
      }
    }

    ts.forEachChild(node, (child) => visit(child, nextEnclosing));
  }

  visit(sourceFile);
  return candidates;
}

function getCalleeName(expr: ts.Expression): string | undefined {
  let unwrapped: ts.Expression = expr;
  while (ts.isParenthesizedExpression(unwrapped)) {
    unwrapped = unwrapped.expression;
  }
  if (ts.isIdentifier(unwrapped)) return unwrapped.text;
  if (ts.isPropertyAccessExpression(unwrapped)) return unwrapped.name.text;
  return undefined;
}
