import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFile } from "node:fs/promises";
import { delimiter } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

import {
  createMessageConnection,
  NotificationType,
  RequestType,
  type MessageConnection,
} from "vscode-jsonrpc";
import { StreamMessageReader, StreamMessageWriter } from "vscode-jsonrpc/node.js";
import {
  CompletionRequest,
  ConfigurationRequest,
  DefinitionRequest,
  DidChangeConfigurationNotification,
  DidChangeTextDocumentNotification,
  DidChangeWatchedFilesNotification,
  DidChangeWorkspaceFoldersNotification,
  DidCloseTextDocumentNotification,
  DidOpenTextDocumentNotification,
  ExitNotification,
  FileChangeType,
  HoverRequest,
  InitializeRequest,
  InitializedNotification,
  PublishDiagnosticsNotification,
  ShutdownRequest,
  WorkspaceFoldersRequest,
  WorkDoneProgressCreateRequest,
  type CompletionList,
  type CompletionItem,
  type ConfigurationParams,
  type Diagnostic,
  type Hover,
  type InitializeParams,
  type InitializeResult,
  type Location,
  type LocationLink,
  type Position,
  type PublishDiagnosticsParams,
  type WorkspaceFolder,
} from "vscode-languageserver-protocol";

const VisibleFilesNotification = new NotificationType<{ readonly visibleFiles: readonly string[] }>(
  "textDocument/codeQLDidChangeVisibleFiles",
);
const RegisterCapabilityRequest = new RequestType<unknown, null, void>("client/registerCapability");

const DEFAULT_INITIALIZATION_TIMEOUT_MS = 60_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_DIAGNOSTICS_TIMEOUT_MS = 60_000;
const DEFAULT_DIAGNOSTICS_QUIET_WINDOW_MS = 250;
const DEFAULT_STARTUP_SETTLING_MS = 1_500;
const MAX_STDERR_TAIL_LINES = 80;

export interface L0WorkspaceFolder {
  readonly uri: string;
  readonly name: string;
}

export interface L0ProtocolDocument {
  readonly language: string;
  readonly uri: string;
  readonly invalidUri?: string;
  readonly text: string;
  readonly invalidText: string;
  readonly definitionToken: string;
  readonly completionToken: string;
  readonly expectedDefinitionUriContains?: readonly string[];
}

export type L0VisibleFilesMode = "all" | "active-document" | "explicit";

export interface L0WorkspaceUpdate {
  readonly watchedUri: string;
  readonly type?: FileChangeType;
}

export interface CodeqlLspProtocolSpikeOptions {
  readonly codeqlPath: string;
  readonly searchPaths: readonly string[];
  readonly workspaceFolders: readonly L0WorkspaceFolder[];
  readonly dynamicWorkspaceFolder?: L0WorkspaceFolder;
  readonly dynamicWorkspaceFolders?: readonly L0WorkspaceFolder[];
  readonly dynamicWorkspaceAddMode?: "batch" | "one-by-one";
  readonly documents: readonly L0ProtocolDocument[];
  readonly visibleFiles?: readonly string[];
  readonly visibleFilesMode?: L0VisibleFilesMode;
  readonly workspaceUpdates?: readonly L0WorkspaceUpdate[];
  readonly workspaceUpdateHook?: () => Promise<void>;
  readonly commonCaches?: string;
  readonly cwd?: string;
  readonly initializationTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly diagnosticsTimeoutMs?: number;
  readonly diagnosticsQuietWindowMs?: number;
  readonly startupSettlingMs?: number;
  readonly synchronous?: boolean;
  readonly includeInvalidProbe?: boolean;
}

export interface L0DiagnosticObservation {
  readonly uri: string;
  readonly version?: number;
  readonly count: number;
  readonly severities: readonly string[];
  readonly messages: readonly string[];
  readonly received: boolean;
  readonly elapsedMs?: number;
  readonly items?: readonly L0DiagnosticItem[];
}

export interface L0DiagnosticItem {
  readonly uri: string;
  readonly severity?: string;
  readonly message: string;
  readonly code?: string;
  readonly source?: string;
  readonly range: { readonly start: Position; readonly end: Position };
  readonly relatedLocations: readonly L0SymbolLocation[];
}

export interface L0SymbolLocation {
  readonly uri: string;
  readonly range?: {
    readonly start: Position;
    readonly end: Position;
  };
  readonly targetSelectionRange?: {
    readonly start: Position;
    readonly end: Position;
  };
}

export interface L0DocumentObservation {
  readonly language: string;
  readonly uri: string;
  readonly valid: L0DiagnosticObservation;
  readonly invalid: L0DiagnosticObservation;
  readonly definition: L0RequestObservation;
  readonly hover: L0RequestObservation;
  readonly completion: L0RequestObservation;
}

export interface L0RequestObservation {
  readonly supportedByCapabilities: boolean;
  readonly completed: boolean;
  readonly resultKind: string;
  readonly resultCount?: number;
  readonly locations?: readonly L0SymbolLocation[];
  readonly hoverText?: string;
  readonly completionLabels?: readonly string[];
  readonly error?: string;
}

export interface L0ProtocolSnapshot {
  readonly schemaVersion: "v2.l0.codeql-lsp/1";
  readonly codeqlPath: string;
  readonly searchPaths: readonly string[];
  readonly workspaceFolders: readonly L0WorkspaceFolder[];
  readonly initialize: {
    readonly serverInfo?: { readonly name: string; readonly version?: string };
    readonly capabilities: InitializeResult["capabilities"];
    readonly observedServerRequests: Readonly<Record<string, number>>;
  };
  readonly capabilitySummary: {
    readonly diagnostics: boolean;
    readonly definition: boolean;
    readonly hover: boolean;
    readonly completion: boolean;
    readonly workspaceFolders: boolean;
    readonly dynamicWorkspaceFolders: boolean;
    readonly experimental: readonly string[];
  };
  readonly workspace: {
    readonly configurationNotificationSent: boolean;
    readonly dynamicWorkspaceFoldersNotificationSent: boolean;
    readonly watchedFilesNotificationSent: boolean;
    readonly visibleFilesNotificationSent: boolean;
    readonly visibleFilesUpdateCount: number;
    readonly initialWorkspaceFolders: readonly L0WorkspaceFolder[];
    readonly dynamicWorkspaceFolders: readonly L0WorkspaceFolder[];
    readonly workspaceUpdates: readonly L0WorkspaceUpdate[];
  };
  readonly documents: readonly L0DocumentObservation[];
  readonly timeline: readonly L0TimelineEvent[];
  readonly transport: {
    readonly errors: readonly string[];
    readonly stderrTail: readonly string[];
    readonly cleanShutdown: boolean;
  };
}

export interface L0TimelineEvent {
  readonly atMs: number;
  readonly direction: "client" | "server";
  readonly method: string;
  readonly uri?: string;
  readonly detail?: string;
}

interface DiagnosticWaiter {
  readonly afterSequence: number;
  readonly resolve: (event: DiagnosticEvent) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
  quietTimer?: NodeJS.Timeout;
  latestEvent?: DiagnosticEvent;
}

interface DiagnosticEvent extends PublishDiagnosticsParams {
  readonly sequence: number;
}

/**
 * L0 only: exercise the real CodeQL Language Server protocol before the V2
 * product contracts are frozen. This class intentionally returns a snapshot;
 * it is not the long-lived QL language-service adapter.
 */
export class CodeqlLspProtocolSpike {
  private readonly options: Required<Pick<CodeqlLspProtocolSpikeOptions, "initializationTimeoutMs" | "requestTimeoutMs" | "diagnosticsTimeoutMs" | "diagnosticsQuietWindowMs" | "startupSettlingMs" | "synchronous" | "includeInvalidProbe">>;
  private child: ChildProcessWithoutNullStreams | undefined;
  private connection: MessageConnection | undefined;
  private diagnosticsSequence = 0;
  private readonly diagnostics = new Map<string, DiagnosticEvent>();
  private readonly diagnosticWaiters = new Map<string, DiagnosticWaiter[]>();
  private readonly serverRequests = new Map<string, number>();
  private readonly transportErrors: string[] = [];
  private readonly stderrTail: string[] = [];
  private childExit: Promise<number | null> | undefined;
  private initialized = false;
  private closed = false;
  private persistentPrepared = false;
  private persistentCapabilities: ReturnType<typeof summarizeCapabilities> | undefined;
  private readonly startedAt = performance.now();
  private readonly timeline: L0TimelineEvent[] = [];
  private visibleFilesUpdateCount = 0;
  private currentWorkspaceFolders: L0WorkspaceFolder[];

  constructor(private readonly input: CodeqlLspProtocolSpikeOptions) {
    this.options = {
      initializationTimeoutMs: input.initializationTimeoutMs ?? DEFAULT_INITIALIZATION_TIMEOUT_MS,
      requestTimeoutMs: input.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      diagnosticsTimeoutMs: input.diagnosticsTimeoutMs ?? DEFAULT_DIAGNOSTICS_TIMEOUT_MS,
      diagnosticsQuietWindowMs: input.diagnosticsQuietWindowMs ?? DEFAULT_DIAGNOSTICS_QUIET_WINDOW_MS,
      startupSettlingMs: input.startupSettlingMs ?? DEFAULT_STARTUP_SETTLING_MS,
      synchronous: input.synchronous ?? true,
      includeInvalidProbe: input.includeInvalidProbe ?? true,
    };
    this.currentWorkspaceFolders = [...input.workspaceFolders];
  }

  async run(): Promise<L0ProtocolSnapshot> {
    let initialize: InitializeResult;
    try {
      initialize = await this.start();
    } catch (error: unknown) {
      await this.close();
      throw error;
    }
    const negotiatedCapabilities = summarizeCapabilities(initialize.capabilities);

    let configurationNotificationSent = false;
    let dynamicWorkspaceFoldersNotificationSent = false;
    let watchedFilesNotificationSent = false;
    let visibleFilesNotificationSent = false;
    let workspaceUpdates: readonly L0WorkspaceUpdate[] = [];
    const documents: L0DocumentObservation[] = [];
    const addedFolders = this.dynamicWorkspaceFolders();

    try {
      await this.sendNotification(DidChangeConfigurationNotification.method, { settings: {} });
      this.recordTimeline("client", DidChangeConfigurationNotification.method);
      configurationNotificationSent = true;

      if (addedFolders.length > 0) {
        const additions = this.input.dynamicWorkspaceAddMode === "one-by-one"
          ? addedFolders.map((folder) => [folder] as const)
          : [addedFolders];
        for (const addition of additions) {
          this.currentWorkspaceFolders.push(...addition);
          await this.sendNotification(DidChangeWorkspaceFoldersNotification.method, {
            event: { added: addition, removed: [] },
          });
          this.recordTimeline("client", DidChangeWorkspaceFoldersNotification.method, undefined, `added:${addition.map((folder) => folder.uri).join(",")}`);
        }
        dynamicWorkspaceFoldersNotificationSent = true;
      }

      const watchedUri = this.input.workspaceFolders[0]?.uri;
      if (watchedUri !== undefined) {
        await this.sendWatchedFiles([{ watchedUri: `${watchedUri}/qlpack.yml` }]);
        watchedFilesNotificationSent = true;
      }

      if (this.visibleFilesMode() !== "active-document") {
        await this.sendVisibleFiles(this.initialVisibleFiles());
      }
      visibleFilesNotificationSent = true;

      if (this.input.workspaceUpdateHook !== undefined) {
        await this.input.workspaceUpdateHook();
      }
      if (this.input.workspaceUpdates !== undefined && this.input.workspaceUpdates.length > 0) {
        workspaceUpdates = this.input.workspaceUpdates;
        await this.sendWatchedFiles(workspaceUpdates);
        watchedFilesNotificationSent = true;
      }

      await delay(this.options.startupSettlingMs);
      this.recordTimeline("client", "pure-auto-codeql/startup-settled", undefined, `${this.options.startupSettlingMs}ms`);

      for (const document of this.input.documents) {
        documents.push(await this.probeDocument(document, negotiatedCapabilities));
      }
      if (addedFolders.length > 0) {
        const removals = this.input.dynamicWorkspaceAddMode === "one-by-one"
          ? [...addedFolders].reverse().map((folder) => [folder] as const)
          : [addedFolders];
        for (const removal of removals) {
          this.currentWorkspaceFolders = this.currentWorkspaceFolders.filter((folder) => !removal.some((removed) => removed.uri === folder.uri));
          await this.sendNotification(DidChangeWorkspaceFoldersNotification.method, {
            event: { added: [], removed: removal },
          });
          this.recordTimeline("client", DidChangeWorkspaceFoldersNotification.method, undefined, `removed:${removal.map((folder) => folder.uri).join(",")}`);
        }
      }
    } finally {
      await this.close();
    }

    const capabilitySummary = {
      ...negotiatedCapabilities,
      diagnostics: documents.some((document) => document.valid.received || document.invalid.received),
    };

    return {
      schemaVersion: "v2.l0.codeql-lsp/1",
      codeqlPath: this.input.codeqlPath,
      searchPaths: this.input.searchPaths,
      workspaceFolders: this.input.workspaceFolders,
      initialize: {
        ...(initialize.serverInfo === undefined ? {} : { serverInfo: initialize.serverInfo }),
        capabilities: initialize.capabilities,
        observedServerRequests: Object.fromEntries(this.serverRequests.entries()),
      },
      capabilitySummary,
      workspace: {
        configurationNotificationSent,
        dynamicWorkspaceFoldersNotificationSent,
        watchedFilesNotificationSent,
        visibleFilesNotificationSent,
        visibleFilesUpdateCount: this.visibleFilesUpdateCount,
        initialWorkspaceFolders: this.input.workspaceFolders,
        dynamicWorkspaceFolders: addedFolders,
        workspaceUpdates,
      },
      documents,
      timeline: this.timeline,
      transport: {
        errors: this.transportErrors,
        stderrTail: this.stderrTail,
        cleanShutdown: this.closed
          && this.child !== undefined
          && this.child.exitCode === 0
          && !processGroupExists(this.child),
      },
    };
  }

  /**
   * Keep the same real protocol client alive for successive draft documents.
   * L0 uses `run()` as a finite experiment; the production draft adapter uses
   * this method so a session can serve multiple languages and revisions.
   */
  async diagnoseDocument(document: L0ProtocolDocument): Promise<L0DocumentObservation> {
    await this.preparePersistentSession();
    const capabilities = this.persistentCapabilities;
    if (capabilities === undefined) {
      throw new Error("CodeQL language server capabilities were not negotiated");
    }
    try {
      return await this.probeDocument(document, capabilities);
    } finally {
      await this.closeDocument(document.uri);
      if (this.visibleFilesMode() === "active-document") {
        await this.sendVisibleFiles([]);
      }
    }
  }

  async notifyWorkspaceUpdate(updates: readonly L0WorkspaceUpdate[]): Promise<void> {
    if (updates.length === 0) return;
    await this.preparePersistentSession();
    await this.sendWatchedFiles(updates);
  }

  persistentHealth(): { readonly initialized: boolean; readonly closed: boolean; readonly errors: readonly string[] } {
    return {
      initialized: this.initialized,
      closed: this.closed,
      errors: [...this.transportErrors],
    };
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    const connection = this.connection;
    const child = this.child;
    if (connection !== undefined) {
      try {
        await withTimeout(connection.sendRequest<void>(ShutdownRequest.method), this.options.requestTimeoutMs, "shutdown");
        this.recordTimeline("client", ShutdownRequest.method);
      } catch (error: unknown) {
        this.transportErrors.push(errorMessage(error));
      }
      try {
        await connection.sendNotification(ExitNotification.method);
        this.recordTimeline("client", ExitNotification.method);
        connection.end();
      } catch (error: unknown) {
        this.transportErrors.push(errorMessage(error));
      }
      connection.dispose();
      this.connection = undefined;
    }
    if (child !== undefined) {
      const exit = this.childExit ?? waitForExit(child);
      this.childExit = exit;
      await waitWithKill(exit, child, this.options.requestTimeoutMs);
    }
  }

  private async preparePersistentSession(): Promise<void> {
    if (this.closed) {
      throw new Error("CodeQL language server session is closed");
    }
    if (this.persistentPrepared) {
      return;
    }
    try {
      const initialize = await this.start();
      this.persistentCapabilities = summarizeCapabilities(initialize.capabilities);
      await this.sendNotification(DidChangeConfigurationNotification.method, { settings: {} });
      this.recordTimeline("client", DidChangeConfigurationNotification.method);
      await this.sendVisibleFiles([]);
      await delay(this.options.startupSettlingMs);
      this.recordTimeline("client", "pure-auto-codeql/startup-settled", undefined, `${this.options.startupSettlingMs}ms`);
      this.persistentPrepared = true;
    } catch (error: unknown) {
      await this.close();
      throw error;
    }
  }

  private async closeDocument(uri: string): Promise<void> {
    const connection = this.requireConnection();
    await connection.sendNotification(DidCloseTextDocumentNotification.method, { textDocument: { uri } });
    this.recordTimeline("client", DidCloseTextDocumentNotification.method, uri);
  }

  private async start(): Promise<InitializeResult> {
    if (this.initialized) {
      throw new Error("L0 CodeQL language server spike cannot be started twice");
    }
    const args = [
      "execute",
      "language-server",
      "--check-errors=ON_CHANGE",
      "--search-path",
      this.input.searchPaths.join(delimiter),
    ];
    if (this.input.commonCaches !== undefined) {
      args.push("--common-caches", this.input.commonCaches);
    }
    if (this.options.synchronous) {
      args.push("--synchronous");
    }
    const child = spawn(this.input.codeqlPath, args, {
      cwd: this.input.cwd,
      env: { ...process.env },
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    this.childExit = waitForExit(child);
    child.stderr.on("data", (chunk: Buffer | string) => this.captureStderr(chunk));
    child.on("error", (error: Error) => this.transportErrors.push(errorMessage(error)));

    const connection = createMessageConnection(
      new StreamMessageReader(child.stdout),
      new StreamMessageWriter(child.stdin),
    );
    this.connection = connection;
    this.registerServerHandlers(connection);
    connection.onError(([error]) => this.transportErrors.push(errorMessage(error)));
    connection.onClose(() => {
      if (!this.closed) {
        this.transportErrors.push("CodeQL language server transport closed before shutdown");
      }
    });
    connection.listen();

    const rootUri = this.input.workspaceFolders[0]?.uri ?? null;
    const params: InitializeParams = {
      processId: process.pid,
      clientInfo: { name: "pure-auto-codeql-l0-spike", version: "0.1.0" },
      rootUri,
      workspaceFolders: this.protocolWorkspaceFolders(),
      capabilities: {
        workspace: {
          configuration: true,
          workspaceFolders: true,
          didChangeWatchedFiles: { dynamicRegistration: true },
        },
        textDocument: {
          synchronization: { dynamicRegistration: false, willSave: false, didSave: false },
          publishDiagnostics: { relatedInformation: true },
          definition: { linkSupport: true },
          hover: { contentFormat: ["markdown", "plaintext"] },
          completion: { contextSupport: true, completionItem: { snippetSupport: false } },
        },
        window: { workDoneProgress: true },
      },
      trace: "off",
    };
    const result = await withTimeout(
      this.sendInitialize(connection, params),
      this.options.initializationTimeoutMs,
      "initialize",
    );
    this.initialized = true;
    await this.sendNotification(InitializedNotification.method, {});
    this.recordTimeline("client", InitializedNotification.method);
    return result;
  }

  private registerServerHandlers(connection: MessageConnection): void {
    connection.onNotification(PublishDiagnosticsNotification.method, (params: PublishDiagnosticsParams) => {
      this.recordTimeline("server", PublishDiagnosticsNotification.method, params.uri, `${params.diagnostics.length} diagnostics`);
      this.recordDiagnostics(params);
    });
    connection.onRequest(ConfigurationRequest.method, (params: ConfigurationParams) => {
      this.countServerRequest("workspace/configuration");
      return params.items.map(() => ({}));
    });
    connection.onRequest(WorkspaceFoldersRequest.method, () => {
      this.countServerRequest("workspace/workspaceFolders");
      return this.protocolWorkspaceFolders();
    });
    connection.onRequest(WorkDoneProgressCreateRequest.method, () => {
      this.countServerRequest("window/workDoneProgress/create");
      return null;
    });
    connection.onRequest(RegisterCapabilityRequest.method, () => {
      this.countServerRequest("client/registerCapability");
      return null;
    });
  }

  private async probeDocument(document: L0ProtocolDocument, capabilities: ReturnType<typeof summarizeCapabilities>): Promise<L0DocumentObservation> {
    const connection = this.requireConnection();
    const validSequence = this.diagnosticsSequence;
    const validStartedAt = performance.now();
    await connection.sendNotification(DidOpenTextDocumentNotification.method, {
      textDocument: { uri: document.uri, languageId: "ql", version: 1, text: document.text },
    });
    this.recordTimeline("client", DidOpenTextDocumentNotification.method, document.uri);
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([document.uri]);
    }
    const valid = await this.waitForDiagnosticsOrTimeout(document.uri, validSequence);
    const validWithTiming = { ...valid, elapsedMs: Math.round(performance.now() - validStartedAt) };

    const definition = await this.requestDefinition(connection, document, capabilities.definition);
    const hover = await this.requestHover(connection, document, capabilities.hover);
    const completion = await this.requestCompletion(connection, document, capabilities.completion);

    if (!this.options.includeInvalidProbe) {
      return {
        language: document.language,
        uri: document.uri,
        valid: validWithTiming,
        invalid: {
          uri: document.invalidUri ?? document.uri,
          count: 0,
          severities: [],
          messages: [],
          received: false,
        },
        definition,
        hover,
        completion,
      };
    }

    const invalidUri = document.invalidUri ?? document.uri;
    const invalidSequence = this.diagnosticsSequence;
    const invalidStartedAt = performance.now();
    if (invalidUri === document.uri) {
      await connection.sendNotification(DidChangeTextDocumentNotification.method, {
        textDocument: { uri: document.uri, version: 2 },
        contentChanges: [{ text: document.invalidText }],
      });
      this.recordTimeline("client", DidChangeTextDocumentNotification.method, document.uri);
    } else {
      await connection.sendNotification(DidCloseTextDocumentNotification.method, { textDocument: { uri: document.uri } });
      this.recordTimeline("client", DidCloseTextDocumentNotification.method, document.uri);
      await connection.sendNotification(DidOpenTextDocumentNotification.method, {
        textDocument: { uri: invalidUri, languageId: "ql", version: 1, text: document.invalidText },
      });
      this.recordTimeline("client", DidOpenTextDocumentNotification.method, invalidUri);
    }
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([invalidUri]);
    }
    const invalid = await this.waitForDiagnosticsOrTimeout(invalidUri, invalidSequence);
    const invalidWithTiming = { ...invalid, elapsedMs: Math.round(performance.now() - invalidStartedAt) };
    await connection.sendNotification(DidCloseTextDocumentNotification.method, { textDocument: { uri: invalidUri } });
    this.recordTimeline("client", DidCloseTextDocumentNotification.method, invalidUri);
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([]);
    }

    return { language: document.language, uri: document.uri, valid: validWithTiming, invalid: invalidWithTiming, definition, hover, completion };
  }

  private async requestDefinition(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean): Promise<L0RequestObservation> {
    if (!supported) {
      return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    }
    try {
      const result = await withTimeout(connection.sendRequest<Location[] | LocationLink[] | null>(DefinitionRequest.method, {
        textDocument: { uri: document.uri },
        position: positionAt(document.text, document.definitionToken),
      }), this.options.requestTimeoutMs, "textDocument/definition");
      const locations = normalizeLocations(result);
      return {
        supportedByCapabilities: true,
        completed: true,
        resultKind: result === null ? "null" : Array.isArray(result) ? "array" : "single",
        resultCount: locations.length,
        locations,
      };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private async requestHover(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean): Promise<L0RequestObservation> {
    if (!supported) {
      return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    }
    try {
      const result = await withTimeout(connection.sendRequest<Hover | null>(HoverRequest.method, {
        textDocument: { uri: document.uri },
        position: positionAt(document.text, document.definitionToken),
      }), this.options.requestTimeoutMs, "textDocument/hover");
      const hover = result as Hover | null;
      return {
        supportedByCapabilities: true,
        completed: true,
        resultKind: hover === null ? "null" : "hover",
        ...(hover === null ? {} : { hoverText: summarizeHover(hover) }),
      };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private async requestCompletion(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean): Promise<L0RequestObservation> {
    if (!supported) {
      return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    }
    try {
      const result = await withTimeout(connection.sendRequest<CompletionItem[] | CompletionList | null>(CompletionRequest.method, {
        textDocument: { uri: document.uri },
        position: positionAt(document.text, document.completionToken, true),
        context: { triggerKind: 1 },
      }), this.options.requestTimeoutMs, "textDocument/completion");
      const count = completionCount(result);
      const completionLabels = completionItems(result).slice(0, 20).map((item) => item.label);
      return {
        supportedByCapabilities: true,
        completed: true,
        resultKind: result === null ? "null" : isCompletionList(result) ? "list" : "array",
        resultCount: count,
        completionLabels,
      };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private waitForDiagnostics(uri: string, afterSequence: number): Promise<L0DiagnosticObservation> {
    const existing = this.diagnostics.get(uri);
    if (existing !== undefined && existing.sequence > afterSequence) {
      return Promise.resolve(toDiagnosticObservation(existing));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const waiters = this.diagnosticWaiters.get(uri) ?? [];
        this.diagnosticWaiters.set(uri, waiters.filter((waiter) => waiter.timer !== timer));
        reject(new Error(`Timed out waiting for publishDiagnostics for ${uri}`));
      }, this.options.diagnosticsTimeoutMs);
      const waiter: DiagnosticWaiter = {
        afterSequence,
        resolve: (event) => resolve(toDiagnosticObservation(event)),
        reject,
        timer,
      };
      const waiters = this.diagnosticWaiters.get(uri) ?? [];
      waiters.push(waiter);
      this.diagnosticWaiters.set(uri, waiters);
    });
  }

  private async waitForDiagnosticsOrTimeout(uri: string, afterSequence: number): Promise<L0DiagnosticObservation> {
    try {
      return await this.waitForDiagnostics(uri, afterSequence);
    } catch (error: unknown) {
      return {
        uri,
        count: 0,
        severities: [],
        messages: [errorMessage(error)],
        received: false,
      };
    }
  }

  private recordDiagnostics(params: PublishDiagnosticsParams): void {
    const event: DiagnosticEvent = { ...params, sequence: ++this.diagnosticsSequence };
    this.diagnostics.set(params.uri, event);
    const waiters = this.diagnosticWaiters.get(params.uri);
    if (waiters === undefined) {
      return;
    }
    const remaining: DiagnosticWaiter[] = [];
    for (const waiter of waiters) {
      if (event.sequence > waiter.afterSequence) {
        waiter.latestEvent = event;
        if (waiter.quietTimer !== undefined) {
          clearTimeout(waiter.quietTimer);
        }
        waiter.quietTimer = setTimeout(() => {
          clearTimeout(waiter.timer);
          const currentWaiters = this.diagnosticWaiters.get(params.uri) ?? [];
          const remainingWaiters = currentWaiters.filter((candidate) => candidate !== waiter);
          if (remainingWaiters.length === 0) {
            this.diagnosticWaiters.delete(params.uri);
          } else {
            this.diagnosticWaiters.set(params.uri, remainingWaiters);
          }
          if (waiter.latestEvent !== undefined) {
            waiter.resolve(waiter.latestEvent);
          }
        }, this.options.diagnosticsQuietWindowMs);
        remaining.push(waiter);
      } else {
        remaining.push(waiter);
      }
    }
    if (remaining.length === 0) {
      this.diagnosticWaiters.delete(params.uri);
    } else {
      this.diagnosticWaiters.set(params.uri, remaining);
    }
  }

  private sendNotification<P>(method: string, params: P): Promise<void> {
    return this.requireConnection().sendNotification(method, params);
  }

  private async sendVisibleFiles(visibleFiles: readonly string[]): Promise<void> {
    await this.sendNotification(VisibleFilesNotification.method, { visibleFiles });
    this.visibleFilesUpdateCount += 1;
    this.recordTimeline("client", VisibleFilesNotification.method, undefined, visibleFiles.join(","));
  }

  private async sendWatchedFiles(updates: readonly L0WorkspaceUpdate[]): Promise<void> {
    await this.sendNotification(DidChangeWatchedFilesNotification.method, {
      changes: updates.map((update) => ({ uri: update.watchedUri, type: update.type ?? FileChangeType.Changed })),
    });
    this.recordTimeline("client", DidChangeWatchedFilesNotification.method, undefined, updates.map((update) => update.watchedUri).join(","));
  }

  private recordTimeline(direction: "client" | "server", method: string, uri?: string, detail?: string): void {
    this.timeline.push({
      atMs: Math.round(performance.now() - this.startedAt),
      direction,
      method,
      ...(uri === undefined ? {} : { uri }),
      ...(detail === undefined ? {} : { detail }),
    });
  }

  private dynamicWorkspaceFolders(): readonly L0WorkspaceFolder[] {
    if (this.input.dynamicWorkspaceFolders !== undefined) {
      return this.input.dynamicWorkspaceFolders;
    }
    return this.input.dynamicWorkspaceFolder === undefined ? [] : [this.input.dynamicWorkspaceFolder];
  }

  private visibleFilesMode(): L0VisibleFilesMode {
    return this.input.visibleFilesMode ?? (this.input.visibleFiles === undefined ? "all" : "explicit");
  }

  private initialVisibleFiles(): readonly string[] {
    if (this.input.visibleFiles !== undefined) {
      return this.input.visibleFiles;
    }
    return this.input.documents.map((document) => document.uri);
  }

  private requireConnection(): MessageConnection {
    if (this.connection === undefined) {
      throw new Error("CodeQL language server connection is not available");
    }
    return this.connection;
  }

  private countServerRequest(method: string): void {
    this.serverRequests.set(method, (this.serverRequests.get(method) ?? 0) + 1);
    this.recordTimeline("server", method);
  }

  private async sendInitialize(connection: MessageConnection, params: InitializeParams): Promise<InitializeResult> {
    this.recordTimeline("client", InitializeRequest.method);
    const result = await connection.sendRequest<InitializeResult>(InitializeRequest.method, params);
    this.recordTimeline("server", "initialize:response");
    return result;
  }

  private protocolWorkspaceFolders(): WorkspaceFolder[] {
    return this.currentWorkspaceFolders.map((folder) => ({ uri: folder.uri, name: folder.name }));
  }

  private captureStderr(chunk: Buffer | string): void {
    const lines = String(chunk).replaceAll("\r\n", "\n").split("\n").map((line) => sanitize(line)).filter((line) => line.length > 0);
    this.stderrTail.push(...lines);
    while (this.stderrTail.length > MAX_STDERR_TAIL_LINES) {
      this.stderrTail.shift();
    }
  }
}

function summarizeCapabilities(capabilities: InitializeResult["capabilities"]): L0ProtocolSnapshot["capabilitySummary"] {
  const workspaceFolders = capabilities.workspace?.workspaceFolders;
  return {
    diagnostics: false,
    definition: Boolean(capabilities.definitionProvider),
    hover: Boolean(capabilities.hoverProvider),
    completion: Boolean(capabilities.completionProvider),
    workspaceFolders: Boolean(workspaceFolders),
    dynamicWorkspaceFolders: typeof workspaceFolders === "object" && workspaceFolders !== null && workspaceFolders.changeNotifications === true,
    experimental: capabilities.experimental !== undefined && typeof capabilities.experimental === "object" && capabilities.experimental !== null
      ? Object.keys(capabilities.experimental)
      : [],
  };
}

function toDiagnosticObservation(event: DiagnosticEvent): L0DiagnosticObservation {
  return {
    uri: event.uri,
    ...(event.version === undefined ? {} : { version: event.version }),
    count: event.diagnostics.length,
    severities: event.diagnostics.map((diagnostic) => severityName(diagnostic)),
    messages: event.diagnostics.map((diagnostic) => diagnostic.message),
    received: true,
    items: event.diagnostics.map((diagnostic) => ({
      uri: event.uri,
      ...(diagnostic.severity === undefined ? {} : { severity: severityName(diagnostic) }),
      message: diagnostic.message,
      ...(diagnostic.code === undefined ? {} : { code: String(diagnostic.code) }),
      ...(diagnostic.source === undefined ? {} : { source: diagnostic.source }),
      range: diagnostic.range,
      relatedLocations: (diagnostic.relatedInformation ?? []).map((related) => ({
        uri: related.location.uri,
        range: related.location.range,
      })),
    })),
  };
}

function severityName(diagnostic: Diagnostic): string {
  switch (diagnostic.severity) {
    case 1: return "error";
    case 2: return "warning";
    case 3: return "information";
    case 4: return "hint";
    default: return "unspecified";
  }
}

function positionAt(text: string, token: string, after = false): Position {
  const index = text.indexOf(token);
  if (index < 0) {
    return { line: 0, character: 0 };
  }
  const offset = after ? index + token.length : index;
  const prefix = text.slice(0, offset);
  const lines = prefix.split("\n");
  return { line: lines.length - 1, character: lines.at(-1)?.length ?? 0 };
}

function completionCount(result: CompletionItem[] | CompletionList | null): number {
  if (result === null) {
    return 0;
  }
  return Array.isArray(result) ? result.length : result.items.length;
}

function completionItems(result: CompletionItem[] | CompletionList | null): readonly CompletionItem[] {
  if (result === null) {
    return [];
  }
  return Array.isArray(result) ? result : result.items;
}

function isCompletionList(result: CompletionItem[] | CompletionList): result is CompletionList {
  return !Array.isArray(result) && "items" in result;
}

function normalizeLocations(result: Location[] | LocationLink[] | null): readonly L0SymbolLocation[] {
  if (result === null) {
    return [];
  }
  return result.map((location) => {
    if ("targetUri" in location) {
      return {
        uri: location.targetUri,
        range: location.targetRange,
        targetSelectionRange: location.targetSelectionRange,
      };
    }
    return { uri: location.uri, range: location.range };
  });
}

function summarizeHover(hover: Hover): string {
  const contents = Array.isArray(hover.contents) ? hover.contents : [hover.contents];
  const text = contents.map((content) => {
    if (typeof content === "string") {
      return content;
    }
    if ("value" in content) {
      return content.value;
    }
    return "";
  }).join("\n");
  return text.length > 2_000 ? `${text.slice(0, 2_000)}…` : text;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, operation: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

async function delay(timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null) {
    return Promise.resolve(child.exitCode);
  }
  return new Promise((resolve) => child.once("exit", (code) => resolve(code)));
}

async function waitWithKill(exit: Promise<number | null>, child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const outcome = await Promise.race([
    exit.then(() => "exited" as const),
    new Promise<"timed_out">((resolve) => {
      timer = setTimeout(() => resolve("timed_out"), timeoutMs);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);
  if (outcome === "timed_out") {
    terminateProcessTree(child, "SIGTERM");
    await delay(500);
  }

  // CodeQL is launched through a shell wrapper on some distributions. The
  // wrapper can exit successfully while its JVM is still alive, so a clean
  // parent exit is not sufficient evidence that the server is gone.
  terminateProcessTree(child, "SIGTERM");
  await waitForProcessGroupExit(child, 500);
  if (processGroupExists(child)) {
    terminateProcessTree(child, "SIGKILL");
  }
}

async function waitForProcessGroupExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(child) && Date.now() < deadline) {
    await delay(25);
  }
}

function processGroupExists(child: ChildProcessWithoutNullStreams): boolean {
  if (child.pid === undefined || process.platform === "win32") {
    return child.exitCode === null;
  }
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

function terminateProcessTree(child: ChildProcessWithoutNullStreams, signal: NodeJS.Signals): void {
  if (child.pid === undefined) {
    return;
  }
  try {
    if (process.platform === "win32") {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch {
    try {
      child.kill(signal);
    } catch {
      // The child exited between the checks; cleanup is complete.
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sanitize(value: string): string {
  return value
    .replaceAll(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replaceAll(/(token|password|secret|api[_-]?key)=\S+/gi, "$1=[REDACTED]")
    .trim();
}

export function l0UriForPath(path: string): string {
  return pathToFileURL(path).href;
}

export async function readL0Document(path: string, language: string, invalidText: string, definitionToken: string, completionToken: string): Promise<L0ProtocolDocument> {
  const text = await readFile(path, "utf8");
  return {
    language,
    uri: l0UriForPath(path),
    text,
    invalidText,
    definitionToken,
    completionToken,
  };
}
