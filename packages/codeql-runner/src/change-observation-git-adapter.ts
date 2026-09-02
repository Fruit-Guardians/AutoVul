import { createHash } from "node:crypto";
import { relative, sep } from "node:path";

import ts from "typescript";
import {
  CHANGE_OBSERVATION_LIMITS,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  DomainError,
  type ChangeObservationCallChange,
  type ChangeObservationChangedFile,
  type ChangeObservationEventChange,
  type ChangeObservationGap,
  type ChangeObservationLanguage,
  type ChangeObservationLocation,
  type ChangeObservationNormalizedHunk,
  type ChangeObservationSelector,
  type ChangeObservationStructuralChangeKind,
  type ChangeObservationSymbol,
  type ChangeObservationSymbolKind,
} from "@autovul/contracts";
import {
  type ChangeObservationPort,
  type ChangeObservationPortObservation,
  type ChangeObservationPortRequest,
  type FileSystemPort,
  type ProcessPort,
  type ProcessResult,
} from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";

const COMMAND_PROFILE_VERSION = "autovul.git-change-observation/1" as const;
const MAX_CONTROL_OUTPUT_BYTES = 4_096;
const GIT_ENVIRONMENT: Readonly<Record<string, string>> = {
  GIT_ATTR_NOSYSTEM: "1",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LC_ALL: "C",
};

export interface GitChangeObservationAdapterOptions {
  /** Roots are canonicalized before every object-database access. */
  readonly trustedRoots: readonly string[];
  readonly executable?: string;
  readonly process?: ProcessPort;
  readonly filesystem?: Pick<FileSystemPort, "canonicalize">;
}

interface GitInvocation {
  readonly repository: string;
  readonly request: ChangeObservationPortRequest;
  readonly signal?: AbortSignal;
}

interface StatusEntry {
  readonly path: string;
  readonly previousPath?: string;
  readonly changeKind: ChangeObservationChangedFile["change_kind"];
}

interface ParsedSymbol {
  readonly key: string;
  readonly symbolKind: ChangeObservationSymbolKind;
  readonly language: ChangeObservationLanguage;
  readonly name: string;
  readonly location: ChangeObservationLocation;
  readonly digest: string;
}

interface ParsedCall {
  readonly selector: ChangeObservationSelector;
  readonly key: string;
  readonly location: ChangeObservationLocation;
  readonly argumentDigests: readonly string[];
}

interface ParsedSource {
  readonly symbols: readonly ParsedSymbol[];
  readonly calls: readonly ParsedCall[];
}

/**
 * Fixed, object-addressed adapter for Change Observation v1. It owns only the
 * read-only Git and parser protocol; Core remains responsible for validation,
 * ordering, bounds, fingerprints, and all public result assembly.
 */
export class GitChangeObservationAdapter implements ChangeObservationPort {
  private readonly executable: string;
  private readonly process: ProcessPort;
  private readonly filesystem: Pick<FileSystemPort, "canonicalize">;
  private readonly trustedRoots: readonly string[];

  constructor(options: GitChangeObservationAdapterOptions) {
    this.executable = options.executable ?? "git";
    this.process = options.process ?? new NodeProcessPort();
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
    this.trustedRoots = [...options.trustedRoots];
  }

  async observe(
    request: ChangeObservationPortRequest,
    options: { readonly signal?: AbortSignal },
  ): Promise<ChangeObservationPortObservation> {
    const repository = await this.resolveTrustedRepository(request.input.repository.path);
    const invocation: GitInvocation = { repository, request, ...(options.signal === undefined ? {} : { signal: options.signal }) };
    const gaps: ChangeObservationGap[] = [];

    await this.assertRepository(invocation);
    const gitVersion = await this.gitVersion(invocation);
    const objectFormat = await this.objectFormat(invocation);
    this.assertRevisionFormat(request.input.base_revision, objectFormat, "base");
    this.assertRevisionFormat(request.input.head_revision, objectFormat, "head");
    await this.assertCommit(invocation, request.input.base_revision, "base");
    await this.assertCommit(invocation, request.input.head_revision, "head");
    const baseTree = await this.treeFor(invocation, request.input.base_revision);
    const headTree = await this.treeFor(invocation, request.input.head_revision);

    const shallow = await this.isShallow(invocation);
    if (shallow) gaps.push({ code: "SHALLOW_HISTORY" });

    const statuses = await this.statuses(invocation, gaps);
    const selectedStatuses = statuses.slice(0, CHANGE_OBSERVATION_LIMITS.maxChangedFiles);
    if (selectedStatuses.length !== statuses.length) {
      gaps.push({ code: "DIFF_TRUNCATED", count: statuses.length - selectedStatuses.length });
    }
    if (request.normalizedPathFilters.length > 0 && selectedStatuses.length === 0) {
      gaps.push({ code: "PATH_FILTER_NO_MATCH" });
    }

    const changedFiles: ChangeObservationChangedFile[] = [];
    const normalizedHunks: ChangeObservationNormalizedHunk[] = [];
    const symbols: ChangeObservationSymbol[] = [];
    const calls: ChangeObservationCallChange[] = [];
    const events: ChangeObservationEventChange[] = [];
    const parserLanguages = new Set<ChangeObservationLanguage>();

    for (const status of selectedStatuses) {
      const basePath = status.changeKind === "added" ? undefined : status.previousPath ?? status.path;
      const headPath = status.changeKind === "deleted" ? undefined : status.path;
      if (await this.isSubmodule(invocation, request.input.base_revision, basePath) || await this.isSubmodule(invocation, request.input.head_revision, headPath)) {
        changedFiles.push(fileForStatus(status, "unavailable"));
        gaps.push({ code: "SUBMODULE_SKIPPED", path: status.path });
        continue;
      }

      const contentKind = await this.contentKind(invocation, status.path, gaps);
      changedFiles.push(fileForStatus(status, contentKind));
      if (contentKind !== "text") continue;

      const diff = await this.diffForPath(invocation, status.path);
      const parsedHunks = parseNormalizedHunks(diff.stdout, status.path, request.resolvedBudget.max_hunk_lines);
      normalizedHunks.push(...parsedHunks.hunks);
      if (parsedHunks.truncatedCount > 0) {
        gaps.push({ code: "HUNK_LINE_TRUNCATED", path: status.path, count: parsedHunks.truncatedCount });
      }
      if (diff.stdoutTruncated || diff.stderrTruncated) {
        gaps.push({ code: "DIFF_TRUNCATED", path: status.path, count: 1 });
      }

      const language = languageForPath(status.path);
      if (language === undefined) {
        gaps.push({ code: "PARSER_UNAVAILABLE", path: status.path, parser_or_language: extensionForPath(status.path) });
        continue;
      }
      const oldSource = basePath === undefined ? undefined : await this.sourceForPath(invocation, request.input.base_revision, basePath, gaps);
      const newSource = headPath === undefined ? undefined : await this.sourceForPath(invocation, request.input.head_revision, headPath, gaps);
      if (oldSource === undefined && newSource === undefined) continue;
      parserLanguages.add(language);
      const oldParsed = oldSource === undefined ? undefined : parseSource(oldSource, basePath ?? status.path, language, gaps);
      const newParsed = newSource === undefined ? undefined : parseSource(newSource, headPath ?? status.path, language, gaps);
      if (oldParsed === undefined && newParsed === undefined) continue;
      symbols.push(...compareSymbols(oldParsed?.symbols ?? [], newParsed?.symbols ?? []));
      const callFacts = compareCalls(oldParsed?.calls ?? [], newParsed?.calls ?? []);
      calls.push(...callFacts);
      events.push(...eventsForCalls(callFacts));
    }

    const boundedHunks = boundFacts(normalizedHunks, CHANGE_OBSERVATION_LIMITS.maxHunks, gaps);
    const boundedSymbols = boundFacts(symbols, CHANGE_OBSERVATION_LIMITS.maxSymbols, gaps);
    const boundedCalls = boundFacts(calls, CHANGE_OBSERVATION_LIMITS.maxCallChanges, gaps);
    const boundedEvents = boundFacts(events, CHANGE_OBSERVATION_LIMITS.maxEventChanges, gaps);
    const boundedGaps = boundGaps(gaps);

    return {
      schema_version: CHANGE_OBSERVATION_SERVICE_VERSION,
      revision_identity: {
        object_format: objectFormat,
        base_oid: request.input.base_revision,
        head_oid: request.input.head_revision,
        base_tree_oid: baseTree,
        head_tree_oid: headTree,
      },
      completeness: boundedGaps.length === 0 ? "complete" : "partial",
      changed_files: changedFiles,
      normalized_hunks: boundedHunks,
      symbols: boundedSymbols,
      call_changes: boundedCalls,
      event_changes: boundedEvents,
      analysis_gaps: boundedGaps,
      provenance: {
        service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
        source: "local_git_object_database",
        git_version: gitVersion,
        command_profile_version: COMMAND_PROFILE_VERSION,
        parser_versions: [...parserLanguages]
          .sort(compareUtf8)
          .map((language) => ({ language, version: ts.version })),
      },
    };
  }

  private async resolveTrustedRepository(path: string): Promise<string> {
    let repository: string;
    try {
      repository = await this.filesystem.canonicalize(path);
    } catch {
      throw new DomainError("CHANGE_OBSERVATION_REPOSITORY_INVALID", "environment", "Repository path cannot be canonicalized", false);
    }
    const roots = await Promise.all(this.trustedRoots.map(async (root) => this.filesystem.canonicalize(root).catch(() => undefined)));
    if (!roots.some((root) => root !== undefined && isWithin(root, repository))) {
      throw new DomainError("CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED", "policy", "Repository is outside configured trusted roots", false);
    }
    return repository;
  }

  private async assertRepository(invocation: GitInvocation): Promise<void> {
    const result = await this.git(invocation, ["rev-parse", "--git-dir"], MAX_CONTROL_OUTPUT_BYTES);
    if (!successful(result)) {
      throwIfInterrupted(result, invocation.signal, "repository");
      throw new DomainError("CHANGE_OBSERVATION_REPOSITORY_INVALID", "environment", "Path is not a readable local Git repository", false);
    }
  }

  private async gitVersion(invocation: GitInvocation): Promise<string> {
    const result = await this.requireGit(invocation, ["--version"], "version", MAX_CONTROL_OUTPUT_BYTES);
    const version = sanitizeProvenance(result.stdout);
    if (version.length === 0) {
      throw new DomainError("CHANGE_OBSERVATION_GIT_FAILED", "process", "Git did not provide a usable version", false, { stage: "version" });
    }
    return version;
  }

  private async objectFormat(invocation: GitInvocation): Promise<"sha1" | "sha256"> {
    const result = await this.requireGit(invocation, ["rev-parse", "--show-object-format"], "object_format", MAX_CONTROL_OUTPUT_BYTES);
    const value = result.stdout.trim();
    if (value === "sha1" || value === "sha256") return value;
    throw new DomainError("CHANGE_OBSERVATION_GIT_FAILED", "process", "Git returned an unsupported object format", false, { stage: "object_format" });
  }

  private assertRevisionFormat(revision: string, objectFormat: "sha1" | "sha256", role: "base" | "head"): void {
    const expectedLength = objectFormat === "sha1" ? 40 : 64;
    if (revision.length !== expectedLength) {
      throw new DomainError("REVISION_OBJECT_MISSING", "environment", "Requested revision does not match repository object format", false, { revision: role });
    }
  }

  private async assertCommit(invocation: GitInvocation, revision: string, role: "base" | "head"): Promise<void> {
    const result = await this.git(invocation, ["cat-file", "-t", revision], MAX_CONTROL_OUTPUT_BYTES);
    if (!successful(result) || result.stdout.trim() !== "commit") {
      throwIfInterrupted(result, invocation.signal, "revision_identity");
      throw new DomainError("REVISION_OBJECT_MISSING", "environment", "Requested revision is not a local commit object", false, { revision: role });
    }
  }

  private async treeFor(invocation: GitInvocation, revision: string): Promise<string> {
    const result = await this.requireGit(invocation, ["rev-parse", `${revision}^{tree}`], "tree_identity", MAX_CONTROL_OUTPUT_BYTES);
    const tree = result.stdout.trim();
    if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(tree)) {
      throw new DomainError("CHANGE_OBSERVATION_GIT_FAILED", "process", "Git returned an invalid tree identity", false, { stage: "tree_identity" });
    }
    return tree;
  }

  private async isShallow(invocation: GitInvocation): Promise<boolean> {
    const result = await this.requireGit(invocation, ["rev-parse", "--is-shallow-repository"], "shallow", MAX_CONTROL_OUTPUT_BYTES);
    return result.stdout.trim() === "true";
  }

  private async statuses(invocation: GitInvocation, gaps: ChangeObservationGap[]): Promise<StatusEntry[]> {
    const result = await this.requireGit(
      invocation,
      ["diff", "--no-ext-diff", "--no-textconv", "--find-renames=50%", "--name-status", "-z", invocation.request.input.base_revision, invocation.request.input.head_revision, "--", ...invocation.request.normalizedPathFilters],
      "name_status",
      invocation.request.resolvedBudget.max_diff_bytes,
    );
    if (result.stdoutTruncated || result.stderrTruncated) gaps.push({ code: "DIFF_TRUNCATED", count: 1 });
    return parseStatuses(result.stdout, gaps);
  }

  private async isSubmodule(invocation: GitInvocation, revision: string, path: string | undefined): Promise<boolean> {
    if (path === undefined) return false;
    const result = await this.requireGit(invocation, ["ls-tree", "-z", revision, "--", path], "submodule", MAX_CONTROL_OUTPUT_BYTES);
    return result.stdout.split("\0").some((entry) => entry.startsWith("160000 "));
  }

  private async contentKind(
    invocation: GitInvocation,
    path: string,
    gaps: ChangeObservationGap[],
  ): Promise<ChangeObservationChangedFile["content_kind"]> {
    const result = await this.requireGit(
      invocation,
      ["diff", "--no-ext-diff", "--no-textconv", "--numstat", invocation.request.input.base_revision, invocation.request.input.head_revision, "--", path],
      "numstat",
      MAX_CONTROL_OUTPUT_BYTES,
    );
    if (result.stdoutTruncated || result.stderrTruncated) {
      gaps.push({ code: "DIFF_TRUNCATED", path, count: 1 });
      return "unavailable";
    }
    if (result.stdout.startsWith("-\t-\t")) {
      gaps.push({ code: "BINARY_FILE_SKIPPED", path });
      return "binary";
    }
    return "text";
  }

  private diffForPath(invocation: GitInvocation, path: string): Promise<ProcessResult> {
    return this.requireGit(
      invocation,
      ["diff", "--no-ext-diff", "--no-textconv", "--unified=0", invocation.request.input.base_revision, invocation.request.input.head_revision, "--", path],
      "hunks",
      invocation.request.resolvedBudget.max_diff_bytes,
      false,
    );
  }

  private async sourceForPath(
    invocation: GitInvocation,
    revision: string,
    path: string,
    gaps: ChangeObservationGap[],
  ): Promise<string | undefined> {
    const result = await this.requireGit(invocation, ["show", `${revision}:${path}`], "source", invocation.request.resolvedBudget.max_diff_bytes, false);
    if (result.stdoutTruncated || result.stderrTruncated) {
      gaps.push({ code: "DIFF_TRUNCATED", path, count: 1 });
      return undefined;
    }
    if (result.stdout.includes("\ufffd")) {
      gaps.push({ code: "UNDECODABLE_TEXT", path });
      return undefined;
    }
    return result.stdout;
  }

  private async requireGit(
    invocation: GitInvocation,
    args: readonly string[],
    stage: string,
    maxOutputBytes: number,
    redactOutput = true,
  ): Promise<ProcessResult> {
    const result = await this.git(invocation, args, maxOutputBytes, redactOutput);
    if (successful(result)) return result;
    throwIfInterrupted(result, invocation.signal, stage);
    throw new DomainError("CHANGE_OBSERVATION_GIT_FAILED", "process", "Change Observation Git command failed", true, { stage });
  }

  private git(invocation: GitInvocation, args: readonly string[], maxOutputBytes: number, redactOutput = true): Promise<ProcessResult> {
    return this.process.execute(
      {
        executable: this.executable,
        args: ["--no-pager", "-c", "diff.external=", "-c", "core.hooksPath=/dev/null", ...args],
        cwd: invocation.repository,
        env: GIT_ENVIRONMENT,
        shell: false,
      },
      {
        ...(invocation.signal === undefined ? {} : { signal: invocation.signal }),
        timeoutMs: invocation.request.resolvedBudget.timeout_ms,
        maxOutputBytes,
        redactOutput,
      },
    );
  }
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !path.includes(`..${sep}`) && !path.startsWith(".."));
}

function successful(result: ProcessResult): boolean {
  return result.exitCode === 0 && result.signal === null && !result.cancelled && !result.timedOut;
}

function throwIfInterrupted(result: ProcessResult, signal: AbortSignal | undefined, stage: string): void {
  if (result.cancelled || signal?.aborted) {
    throw new DomainError("PROCESS_CANCELLED", "process", "Change Observation Git command was cancelled", false, { stage });
  }
  if (result.timedOut) {
    throw new DomainError("PROCESS_TIMEOUT", "process", "Change Observation Git command timed out", true, { stage });
  }
}

function sanitizeProvenance(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, CHANGE_OBSERVATION_LIMITS.maxGitVersionLength);
}

function parseStatuses(value: string, gaps: ChangeObservationGap[]): StatusEntry[] {
  const fields = value.split("\0");
  if (fields.at(-1) === "") fields.pop();
  const entries: StatusEntry[] = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (status === undefined) break;
    const statusCode = status.charAt(0);
    const path = fields[index++];
    if (path === undefined || !isSafePath(path)) {
      gaps.push({ code: "RENAME_AMBIGUOUS" });
      continue;
    }
    if (statusCode === "R") {
      const destination = fields[index++];
      if (destination === undefined || !isSafePath(destination)) {
        gaps.push({ code: "RENAME_AMBIGUOUS", path });
        continue;
      }
      entries.push({ path: destination, previousPath: path, changeKind: "renamed" });
      continue;
    }
    const changeKind = statusCode === "A" ? "added"
      : statusCode === "D" ? "deleted"
        : statusCode === "M" ? "modified"
          : statusCode === "T" ? "type_changed"
            : undefined;
    if (changeKind === undefined) {
      gaps.push({ code: "RENAME_AMBIGUOUS", path });
      continue;
    }
    entries.push({ path, changeKind });
  }
  return entries;
}

function isSafePath(path: string): boolean {
  return path.length > 0
    && path.length <= CHANGE_OBSERVATION_LIMITS.maxPathFilterLength
    && !path.startsWith("/")
    && !path.includes("\\")
    && !path.includes("\0")
    && !path.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..");
}

function fileForStatus(status: StatusEntry, contentKind: ChangeObservationChangedFile["content_kind"]): ChangeObservationChangedFile {
  return status.previousPath === undefined
    ? { path: status.path, change_kind: status.changeKind as Exclude<ChangeObservationChangedFile["change_kind"], "renamed">, content_kind: contentKind }
    : { path: status.path, previous_path: status.previousPath, change_kind: "renamed", content_kind: contentKind };
}

function parseNormalizedHunks(
  patch: string,
  path: string,
  maxLines: number,
): { readonly hunks: readonly ChangeObservationNormalizedHunk[]; readonly truncatedCount: number } {
  const hunks: ChangeObservationNormalizedHunk[] = [];
  let current: { oldStart: number; oldCount: number; newStart: number; newCount: number; removed: string[]; added: string[] } | undefined;
  const finish = (): void => {
    if (current === undefined) return;
    const removed = current.removed.map(normalizeChangedLine);
    const added = current.added.map(normalizeChangedLine);
    const truncated = removed.length > maxLines || added.length > maxLines;
    hunks.push({
      path,
      ordinal: hunks.length,
      old_start: current.oldStart,
      old_line_count: current.oldCount,
      new_start: current.newStart,
      new_line_count: current.newCount,
      removed_line_count: removed.length,
      added_line_count: added.length,
      normalized_removed_sha256: digestLineStream(removed.slice(0, maxLines)),
      normalized_added_sha256: digestLineStream(added.slice(0, maxLines)),
      truncated,
    });
    current = undefined;
  };
  for (const line of patch.replace(/\r\n/g, "\n").split("\n")) {
    const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (match !== null) {
      finish();
      const oldCount = Number(match[2] ?? "1");
      const newCount = Number(match[4] ?? "1");
      current = {
        oldStart: oldCount === 0 ? 0 : Number(match[1]),
        oldCount,
        newStart: newCount === 0 ? 0 : Number(match[3]),
        newCount,
        removed: [],
        added: [],
      };
      continue;
    }
    if (current === undefined) continue;
    if (line.startsWith("-") && !line.startsWith("---")) current.removed.push(line.slice(1));
    if (line.startsWith("+") && !line.startsWith("+++")) current.added.push(line.slice(1));
  }
  finish();
  return { hunks, truncatedCount: hunks.filter((hunk) => hunk.truncated).length };
}

function normalizeChangedLine(line: string): string {
  return line.replace(/[ \t]+$/g, "");
}

function digestLineStream(lines: readonly string[]): string {
  return createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
}

function languageForPath(path: string): ChangeObservationLanguage | undefined {
  const extension = extensionForPath(path);
  if (["js", "jsx", "mjs", "cjs"].includes(extension)) return "javascript";
  if (["ts", "tsx", "mts", "cts"].includes(extension)) return "typescript";
  return undefined;
}

function extensionForPath(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const extension = name.lastIndexOf(".");
  return extension < 0 ? "unknown" : name.slice(extension + 1).toLowerCase().slice(0, CHANGE_OBSERVATION_LIMITS.maxIdentifierLength);
}

function parseSource(
  sourceText: string,
  path: string,
  language: ChangeObservationLanguage,
  gaps: ChangeObservationGap[],
): ParsedSource | undefined {
  const scriptKind = path.endsWith("x") ? ts.ScriptKind.TSX : language === "javascript" ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const source = ts.createSourceFile(path, sourceText, ts.ScriptTarget.Latest, true, scriptKind);
  const diagnostics = (source as ts.SourceFile & { readonly parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
  if (diagnostics.length > 0) {
    gaps.push({ code: "PARSER_FAILED", path, parser_or_language: language });
    return undefined;
  }
  const symbols: ParsedSymbol[] = [];
  const calls: ParsedCall[] = [];
  const visit = (node: ts.Node): void => {
    const symbol = symbolForNode(node, source, path, language);
    if (symbol !== undefined) symbols.push(symbol);
    if (ts.isCallExpression(node)) {
      const selector = selectorForExpression(node.expression);
      if (selector !== undefined && node.arguments.length <= 256) {
        calls.push({
          selector,
          key: selector.join("\0"),
          location: locationFor(node, source, path),
          argumentDigests: node.arguments.map((argument) => digestSyntax(argument.getText(source))),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { symbols: numberEntries(symbols), calls: numberEntries(calls) };
}

function symbolForNode(
  node: ts.Node,
  source: ts.SourceFile,
  path: string,
  language: ChangeObservationLanguage,
): ParsedSymbol | undefined {
  const candidate = ts.isFunctionDeclaration(node) ? { kind: "function" as const, name: node.name }
    : ts.isMethodDeclaration(node) ? { kind: "method" as const, name: node.name }
      : ts.isClassDeclaration(node) ? { kind: "class" as const, name: node.name }
        : ts.isVariableDeclaration(node) ? { kind: "variable" as const, name: node.name }
          : undefined;
  const name = candidate?.name;
  if (candidate === undefined || name === undefined || !ts.isIdentifier(name) || !isSafeSymbolName(name.text)) return undefined;
  return {
    key: `${candidate.kind}\0${name.text}`,
    symbolKind: candidate.kind,
    language,
    name: name.text,
    location: locationFor(node, source, path),
    digest: digestSyntax(node.getText(source)),
  };
}

function selectorForExpression(expression: ts.Expression): ChangeObservationSelector | undefined {
  if (ts.isIdentifier(expression)) return isSafeIdentifier(expression.text) ? [expression.text] : undefined;
  if (expression.kind === ts.SyntaxKind.ThisKeyword) return ["this"];
  if (ts.isPropertyAccessExpression(expression)) {
    const prefix = selectorForExpression(expression.expression);
    if (prefix === undefined || !isSafeIdentifier(expression.name.text) || prefix.length >= CHANGE_OBSERVATION_LIMITS.maxSelectorSegments) return undefined;
    return [...prefix, expression.name.text];
  }
  return undefined;
}

function isSafeIdentifier(value: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(value);
}

function isSafeSymbolName(value: string): boolean {
  return value.length > 0 && value.length <= CHANGE_OBSERVATION_LIMITS.maxSymbolNameLength;
}

function locationFor(node: ts.Node, source: ts.SourceFile, path: string): ChangeObservationLocation {
  const start = source.getLineAndCharacterOfPosition(node.getStart(source));
  const end = source.getLineAndCharacterOfPosition(node.getEnd());
  return { path, start_line: start.line + 1, end_line: Math.max(start.line + 1, end.line + 1) };
}

function digestSyntax(value: string): string {
  return createHash("sha256").update(value.replace(/\r\n/g, "\n").replace(/[ \t]+$/gm, ""), "utf8").digest("hex");
}

function numberEntries<T extends { readonly key: string }>(entries: readonly T[]): T[] {
  const positions = new Map<string, number>();
  return entries.map((entry) => {
    const ordinal = positions.get(entry.key) ?? 0;
    positions.set(entry.key, ordinal + 1);
    return { ...entry, key: `${entry.key}\0${ordinal}` };
  });
}

function compareSymbols(oldSymbols: readonly ParsedSymbol[], newSymbols: readonly ParsedSymbol[]): ChangeObservationSymbol[] {
  const oldByKey = new Map(oldSymbols.map((symbol) => [symbol.key, symbol]));
  const newByKey = new Map(newSymbols.map((symbol) => [symbol.key, symbol]));
  return [...new Set([...oldByKey.keys(), ...newByKey.keys()])]
    .sort(compareUtf8)
    .flatMap((key): ChangeObservationSymbol[] => {
      const oldSymbol = oldByKey.get(key);
      const newSymbol = newByKey.get(key);
      if (oldSymbol === undefined && newSymbol !== undefined) return [symbolChange("added", undefined, newSymbol)];
      if (oldSymbol !== undefined && newSymbol === undefined) return [symbolChange("removed", oldSymbol, undefined)];
      if (oldSymbol !== undefined && newSymbol !== undefined && oldSymbol.digest !== newSymbol.digest) return [symbolChange("modified", oldSymbol, newSymbol)];
      return [];
    });
}

function symbolChange(
  changeKind: ChangeObservationStructuralChangeKind,
  oldSymbol: ParsedSymbol | undefined,
  newSymbol: ParsedSymbol | undefined,
): ChangeObservationSymbol {
  const subject = newSymbol ?? oldSymbol;
  if (subject === undefined) throw new Error("Change Observation symbol change is missing both sides");
  return {
    change_kind: changeKind,
    symbol_kind: subject.symbolKind,
    language: subject.language,
    name: subject.name,
    ...(oldSymbol === undefined ? {} : { old_location: oldSymbol.location }),
    ...(newSymbol === undefined ? {} : { new_location: newSymbol.location }),
  };
}

function compareCalls(oldCalls: readonly ParsedCall[], newCalls: readonly ParsedCall[]): ChangeObservationCallChange[] {
  const oldByKey = new Map(oldCalls.map((call) => [call.key, call]));
  const newByKey = new Map(newCalls.map((call) => [call.key, call]));
  return [...new Set([...oldByKey.keys(), ...newByKey.keys()])]
    .sort(compareUtf8)
    .flatMap((key): ChangeObservationCallChange[] => {
      const oldCall = oldByKey.get(key);
      const newCall = newByKey.get(key);
      if (oldCall === undefined && newCall !== undefined) return [callChange("added", undefined, newCall, "none")];
      if (oldCall !== undefined && newCall === undefined) return [callChange("removed", oldCall, undefined, "none")];
      if (oldCall === undefined || newCall === undefined) return [];
      const argumentChange = oldCall.argumentDigests.length !== newCall.argumentDigests.length
        ? "count_changed"
        : sameArray(oldCall.argumentDigests, newCall.argumentDigests) ? "none" : "positions_changed";
      return argumentChange === "none" ? [] : [callChange("modified", oldCall, newCall, argumentChange)];
    });
}

function callChange(
  changeKind: ChangeObservationStructuralChangeKind,
  oldCall: ParsedCall | undefined,
  newCall: ParsedCall | undefined,
  argumentChangeKind: ChangeObservationCallChange["argument_change_kind"],
): ChangeObservationCallChange {
  const subject = newCall ?? oldCall;
  if (subject === undefined) throw new Error("Change Observation call change is missing both sides");
  return {
    change_kind: changeKind,
    callee_selector: subject.selector,
    argument_change_kind: argumentChangeKind,
    ...(oldCall === undefined ? {} : { old_argument_count: oldCall.argumentDigests.length, old_location: oldCall.location }),
    ...(newCall === undefined ? {} : { new_argument_count: newCall.argumentDigests.length, new_location: newCall.location }),
  };
}

function eventsForCalls(calls: readonly ChangeObservationCallChange[]): ChangeObservationEventChange[] {
  return calls.map((call) => ({
    event_kind: call.change_kind === "added" ? "direct_call_added" : call.change_kind === "removed" ? "direct_call_removed" : "direct_call_modified",
    selector: call.callee_selector,
    location: call.new_location ?? call.old_location ?? impossibleLocation(),
  }));
}

function impossibleLocation(): ChangeObservationLocation {
  throw new Error("Change Observation event requires a call location");
}

function sameArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function boundFacts<T>(facts: readonly T[], maximum: number, gaps: ChangeObservationGap[]): T[] {
  if (facts.length <= maximum) return [...facts];
  gaps.push({ code: "DIFF_TRUNCATED", count: facts.length - maximum });
  return facts.slice(0, maximum);
}

function boundGaps(gaps: readonly ChangeObservationGap[]): ChangeObservationGap[] {
  if (gaps.length <= CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount) return [...gaps];
  const retained = gaps.slice(0, CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount - 1);
  retained.push({ code: "DIFF_TRUNCATED", count: gaps.length - retained.length });
  return retained;
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
