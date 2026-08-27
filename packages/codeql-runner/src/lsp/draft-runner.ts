import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  CONTRACTS_VERSION,
  type QueryDraftDiagnostic,
  type QueryDraftReport,
  type QueryLocation,
} from "@pure-auto-codeql/contracts";
import type {
  CodeqlOperationOptions,
  QueryDraftExecutionPort,
  QueryDraftRequest,
} from "@pure-auto-codeql/core";
import { allLanguagePacks, languagePackFor, qlpackForLanguage } from "@pure-auto-codeql/core";

import {
  CodeqlLspProtocolSpike,
  type L0DiagnosticItem,
  type L0ProtocolDocument,
  l0UriForPath,
} from "./protocol-spike.js";

const execFileAsync = promisify(execFile);

export interface LspDraftRunnerOptions {
  readonly executable?: string;
  readonly cwd?: string;
  readonly searchPaths?: readonly string[];
  readonly distributionRoot?: string;
  readonly initializationTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly diagnosticsTimeoutMs?: number;
  readonly diagnosticsQuietWindowMs?: number;
  readonly startupSettlingMs?: number;
  readonly synchronous?: boolean;
}

/**
 * Product adapter for the already-discovered CodeQL LSP protocol. It owns one
 * Application-scoped shared session and never decides whether a query is accepted; the
 * CLI QueryExecutionPort remains authoritative.
 */
export class CodeqlLspDraftRunner implements QueryDraftExecutionPort {
  private readonly executable: string;
  private session: CodeqlLspProtocolSpike | undefined;
  private workspacePromise: Promise<StableLspWorkspace> | undefined;
  private operation = Promise.resolve();
  private consecutiveFailures = 0;
  private circuitOpenUntil = 0;

  constructor(private readonly options: LspDraftRunnerOptions = {}) {
    this.executable = options.executable ?? process.env.CODEQL_PATH ?? "codeql";
  }

  async executeDraft(request: QueryDraftRequest, options: CodeqlOperationOptions): Promise<QueryDraftReport> {
    return this.serialized(() => this.executeDraftInternal(request, options));
  }

  async close(): Promise<void> {
    await this.operation.catch(() => undefined);
    await this.session?.close();
    this.session = undefined;
    const workspace = await this.workspacePromise?.catch(() => undefined);
    if (workspace !== undefined) {
      await rm(workspace.root, { recursive: true, force: true });
    }
    this.workspacePromise = undefined;
  }

  private async executeDraftInternal(request: QueryDraftRequest, options: CodeqlOperationOptions): Promise<QueryDraftReport> {
    const startedAt = Date.now();
    const draftRoot = join(request.artifactRoot, "drafts", request.candidate.candidate_id);
    const queryPath = join(draftRoot, "query.ql");
    const base = {
      schema_version: CONTRACTS_VERSION,
      draft_id: `${request.runId}-${request.candidate.candidate_id}`,
      run_id: request.runId,
      candidate_id: request.candidate.candidate_id,
      revision: request.revision,
      draft_revision_budget: request.draftRevisionBudget,
    } as const;
    if (Date.now() < this.circuitOpenUntil) {
      return {
        ...base,
        status: "degraded",
        lsp_available: false,
        diagnostics: [],
        definition_locations: [],
        hover_text: [],
        completion_labels: [],
        fallback_reason: "CodeQL LSP circuit breaker is open; continue with CLI compile/analyze",
        elapsed_ms: Date.now() - startedAt,
      };
    }
    try {
      const distributionRoot = await this.resolveDistributionRoot();
      const workspace = await this.ensureWorkspace();
      const pack = languagePackFor(request.spec.language);
      const packRoot = workspace.packRoots.get(pack.language);
      if (packRoot === undefined) throw new Error(`No stable LSP workspace for ${pack.language}`);
      const packFile = join(packRoot, "qlpack.yml");
      const packText = request.candidate.qlpack_yml ?? qlpackForLanguage(request.spec.language);
      if ((await readFile(packFile, "utf8")) !== packText) {
        await writeFile(packFile, packText, "utf8");
        await this.session?.notifyWorkspaceUpdate([{ watchedUri: l0UriForPath(packFile) }]);
      }
      const documentPath = join(packRoot, "documents", safePathSegment(request.candidate.candidate_id), `revision-${request.revision}.ql`);
      const document: L0ProtocolDocument = {
        language: request.spec.language,
        uri: l0UriForPath(documentPath),
        text: request.candidate.ql_text,
        invalidText: "this is deliberately invalid QL syntax",
        definitionToken: "DataFlow",
        completionToken: "DataFlow::",
      };
      const operationTimeoutMs = Math.max(1_000, options.timeoutMs);
      const session = await this.ensureSession(workspace, distributionRoot, operationTimeoutMs);
      const observed = await runWithDeadline(session, document, options);
      const diagnosticItems = observed?.valid.items ?? [];
      const diagnostics = diagnosticItems.map((item) => toDraftDiagnostic(item, queryPath, document.uri));
      const received = observed?.valid.received === true;
      const health = session.persistentHealth();
      const transportHealthy = health.errors.length === 0 && health.initialized && !health.closed;
      const degraded = !received || !transportHealthy;
      if (degraded) {
        this.consecutiveFailures += 1;
        if (this.consecutiveFailures >= 3) {
          this.circuitOpenUntil = Date.now() + 30_000;
          await this.resetFailedSession();
        }
      } else {
        this.consecutiveFailures = 0;
      }
      return {
        ...base,
        status: degraded ? "degraded" : diagnostics.length > 0 ? "errors" : "clean",
        lsp_available: transportHealthy,
        diagnostics,
        definition_locations: (observed?.definition.locations ?? []).map(toQueryLocation),
        hover_text: observed?.hover.hoverText === undefined || observed.hover.hoverText.length === 0 ? [] : [observed.hover.hoverText],
        completion_labels: [...(observed?.completion.completionLabels ?? [])],
        ...(degraded ? {
          fallback_reason: observed?.valid.received === false
            ? "CodeQL LSP did not publish diagnostics for the draft document; continue with CLI compile/analyze"
            : health.errors.join("; ") || "CodeQL LSP transport was not clean; continue with CLI compile/analyze",
        } : {}),
        elapsed_ms: Date.now() - startedAt,
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      const cancelled = options.signal?.aborted === true;
      await this.resetFailedSession();
      this.consecutiveFailures += 1;
      if (this.consecutiveFailures >= 3) {
        this.circuitOpenUntil = Date.now() + 30_000;
      }
      return {
        ...base,
        status: cancelled ? "cancelled" : "degraded",
        lsp_available: false,
        diagnostics: [{
          schema_version: CONTRACTS_VERSION,
          severity: "warning",
          message,
          source: "codeql-lsp",
          related_locations: [],
        }],
        definition_locations: [],
        hover_text: [],
        completion_labels: [],
        fallback_reason: cancelled
          ? "CodeQL LSP draft session was cancelled"
          : "CodeQL LSP draft session could not be started; continue with CLI compile/analyze",
        elapsed_ms: Date.now() - startedAt,
      };
    }
  }

  private async ensureWorkspace(): Promise<StableLspWorkspace> {
    if (this.workspacePromise === undefined) {
      this.workspacePromise = createStableWorkspace();
    }
    return this.workspacePromise;
  }

  private async ensureSession(workspace: StableLspWorkspace, distributionRoot: string | undefined, operationTimeoutMs: number): Promise<CodeqlLspProtocolSpike> {
    if (this.session !== undefined) return this.session;
    const session = new CodeqlLspProtocolSpike({
      codeqlPath: this.executable,
      searchPaths: uniquePaths([
        ...workspace.packRoots.values(),
        ...(this.options.searchPaths ?? []),
        ...(distributionRoot === undefined ? [] : [distributionRoot]),
      ]),
      workspaceFolders: workspace.workspaceFolders,
      documents: [],
      visibleFilesMode: "active-document",
      initializationTimeoutMs: Math.min(this.options.initializationTimeoutMs ?? 60_000, operationTimeoutMs),
      requestTimeoutMs: Math.min(this.options.requestTimeoutMs ?? 15_000, operationTimeoutMs),
      diagnosticsTimeoutMs: Math.min(this.options.diagnosticsTimeoutMs ?? 60_000, operationTimeoutMs),
      ...(this.options.diagnosticsQuietWindowMs === undefined ? {} : { diagnosticsQuietWindowMs: this.options.diagnosticsQuietWindowMs }),
      ...(this.options.startupSettlingMs === undefined ? {} : { startupSettlingMs: this.options.startupSettlingMs }),
      synchronous: this.options.synchronous ?? false,
      includeInvalidProbe: false,
      ...(this.options.cwd === undefined ? {} : { cwd: this.options.cwd }),
    });
    this.session = session;
    return session;
  }

  private async resetFailedSession(): Promise<void> {
    const session = this.session;
    this.session = undefined;
    await session?.close().catch(() => undefined);
  }

  private serialized<T>(task: () => Promise<T>): Promise<T> {
    const next = this.operation.then(task, task);
    this.operation = next.then(() => undefined, () => undefined);
    return next;
  }

  private async resolveDistributionRoot(): Promise<string | undefined> {
    if (this.options.distributionRoot !== undefined) return this.options.distributionRoot;
    if (process.env.CODEQL_DISTRIBUTION_ROOT !== undefined) return process.env.CODEQL_DISTRIBUTION_ROOT;
    if (isAbsolute(this.executable)) return dirname(this.executable);
    try {
      const result = await execFileAsync("which", [this.executable], { cwd: this.options.cwd ?? process.cwd() });
      const resolvedPath = String(result.stdout).trim().split(/\r?\n/)[0] ?? "";
      if (resolvedPath.length > 0) return dirname(resolvedPath);
    } catch {
      // The CLI will provide the authoritative failure if the executable is unavailable.
    }
    return undefined;
  }
}

interface StableLspWorkspace {
  readonly root: string;
  readonly packRoots: ReadonlyMap<string, string>;
  readonly workspaceFolders: readonly { readonly uri: string; readonly name: string }[];
}

async function createStableWorkspace(): Promise<StableLspWorkspace> {
  const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-lsp-session-"));
  try {
    const packRoots = new Map<string, string>();
    const workspaceFolders = [];
    for (const pack of allLanguagePacks()) {
      const packRoot = join(root, pack.language);
      await mkdir(packRoot, { recursive: true });
      await writeFile(join(packRoot, "qlpack.yml"), `name: pure-auto-codeql/lsp-${pack.language}\nversion: 0.0.1\ndependencies:\n  ${pack.dependency}: "*"\n`, "utf8");
      packRoots.set(pack.language, packRoot);
      workspaceFolders.push({ uri: l0UriForPath(packRoot), name: `pure-auto-codeql-lsp-${pack.language}` });
    }
    return { root, packRoots, workspaceFolders };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function runWithDeadline(
  session: CodeqlLspProtocolSpike,
  document: L0ProtocolDocument,
  options: CodeqlOperationOptions,
): Promise<Awaited<ReturnType<CodeqlLspProtocolSpike["diagnoseDocument"]>>> {
  let timer: NodeJS.Timeout | undefined;
  let abortHandler: (() => void) | undefined;
  let completed = false;
  const run = session.diagnoseDocument(document);
  void run.catch(() => undefined);
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("CodeQL LSP draft timed out")), Math.max(1_000, options.timeoutMs));
  });
  const cancellation = options.signal === undefined
    ? undefined
    : new Promise<never>((_resolve, reject) => {
      abortHandler = () => reject(new Error("CodeQL LSP draft cancelled"));
      if (options.signal?.aborted === true) abortHandler();
      else options.signal?.addEventListener("abort", abortHandler, { once: true });
    });
  try {
    const result = await Promise.race([run, deadline, ...(cancellation === undefined ? [] : [cancellation])]);
    completed = true;
    return result;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (abortHandler !== undefined && options.signal !== undefined) options.signal.removeEventListener("abort", abortHandler);
    if (!completed) await session.close();
  }
}

function toDraftDiagnostic(item: L0DiagnosticItem, draftPath: string, documentUri: string): QueryDraftDiagnostic {
  const file = item.uri === documentUri ? draftPath : fileForUri(item.uri);
  return {
    schema_version: CONTRACTS_VERSION,
    severity: item.severity === "error" ? "error" : item.severity === "warning" ? "warning" : "info",
    message: item.message,
    ...(item.code === undefined || item.code.length === 0 ? {} : { code: item.code }),
    ...(item.source === undefined || item.source.length === 0 ? {} : { source: item.source }),
    ...(item.range === undefined ? {} : {
      ...(file === undefined ? {} : { file }),
      start_line: item.range.start.line + 1,
      start_column: item.range.start.character + 1,
      end_line: item.range.end.line + 1,
      end_column: item.range.end.character + 1,
    }),
    related_locations: item.relatedLocations.map(toQueryLocation),
  };
}

function toQueryLocation(location: { readonly uri: string; readonly range?: { readonly start: { readonly line: number; readonly character: number }; readonly end: { readonly line: number; readonly character: number } } }): QueryLocation {
  const range = location.range ?? { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
  return {
    file: fileForUri(location.uri),
    start_line: range.start.line + 1,
    start_column: range.start.character + 1,
    end_line: range.end.line + 1,
    end_column: range.end.character + 1,
  };
}

function fileForUri(uri: string): string {
  try {
    return fileURLToPath(uri);
  } catch {
    return uri;
  }
}

function uniquePaths(paths: readonly string[]): string[] {
  return [...new Set(paths.map((path) => resolve(path)))];
}

function safePathSegment(value: string): string {
  const normalized = value.replaceAll(/[^A-Za-z0-9._-]/g, "_");
  return normalized.length === 0 ? "candidate" : normalized.slice(0, 120);
}
