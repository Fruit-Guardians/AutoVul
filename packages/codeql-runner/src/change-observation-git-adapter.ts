import { relative, sep } from "node:path";

import {
  CHANGE_OBSERVATION_LIMITS,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  DomainError,
  type ChangeObservationCallChange,
  type ChangeObservationChangedFile,
  type ChangeObservationEventChange,
  type ChangeObservationGap,
  type ChangeObservationLanguage,
  type ChangeObservationNormalizedHunk,
  type ChangeObservationSymbol,
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
import {
  compareUtf8,
  extensionForPath,
  languageForPath,
  parseNormalizedHunks,
  sourceChangeFacts,
  TYPESCRIPT_PARSER_VERSION,
} from "./change-observation-parser.js";
import { processSucceeded } from "./process-result.js";

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
      const facts = sourceChangeFacts(
        oldSource,
        basePath ?? status.path,
        newSource,
        headPath ?? status.path,
        language,
        gaps,
      );
      if (facts === undefined) continue;
      symbols.push(...facts.symbols);
      calls.push(...facts.calls);
      events.push(...facts.events);
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
          .map((language) => ({ language, version: TYPESCRIPT_PARSER_VERSION })),
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
    if (!processSucceeded(result)) {
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
    if (!processSucceeded(result) || result.stdout.trim() !== "commit") {
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
    if (processSucceeded(result)) return result;
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
