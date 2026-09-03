import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { delimiter } from "node:path";
import { performance } from "node:perf_hooks";

import {
  createMessageConnection,
  NotificationType,
  RequestType,
  type MessageConnection,
} from "vscode-jsonrpc";
import {
  StreamMessageReader,
  StreamMessageWriter,
} from "vscode-jsonrpc/node.js";
import {
  delay,
  errorMessage,
  processGroupExists,
  sanitize,
  waitForExit,
  waitWithKill,
  withTimeout,
} from "../process-lifecycle.js";
import {
  ConfigurationRequest,
  DidChangeConfigurationNotification,
  DidChangeTextDocumentNotification,
  DidChangeWatchedFilesNotification,
  DidChangeWorkspaceFoldersNotification,
  DidCloseTextDocumentNotification,
  DidOpenTextDocumentNotification,
  ExitNotification,
  FileChangeType,
  InitializeRequest,
  InitializedNotification,
  PublishDiagnosticsNotification,
  ShutdownRequest,
  WorkspaceFoldersRequest,
  WorkDoneProgressCreateRequest,
  type ConfigurationParams,
  type InitializeParams,
  type InitializeResult,
  type PublishDiagnosticsParams,
  type WorkspaceFolder,
} from "vscode-languageserver-protocol";
import { summarizeCapabilities, toDiagnosticObservation } from "./protocol-helpers.js";
import { requestCompletion, requestDefinition, requestHover } from "./protocol-requests.js";
import type {
  CodeqlLspProtocolSpikeOptions,
  L0DiagnosticEvent as DiagnosticEvent,
  L0DiagnosticObservation,
  L0DiagnosticWaiter as DiagnosticWaiter,
  L0DocumentObservation,
  L0ProtocolDocument,
  L0ProtocolSnapshot,
  L0TimelineEvent,
  L0VisibleFilesMode,
  L0WorkspaceFolder,
  L0WorkspaceUpdate,
} from "./protocol-types.js";

export type {
  CodeqlLspProtocolSpikeOptions,
  L0DiagnosticItem,
  L0DiagnosticObservation,
  L0DocumentObservation,
  L0ProtocolDocument,
  L0ProtocolSnapshot,
  L0RequestObservation,
  L0SymbolLocation,
  L0TimelineEvent,
  L0VisibleFilesMode,
  L0WorkspaceFolder,
  L0WorkspaceUpdate,
} from "./protocol-types.js";
export { l0UriForPath, readL0Document } from "./protocol-helpers.js";

const VisibleFilesNotification = new NotificationType<{
  readonly visibleFiles: readonly string[];
}>("textDocument/codeQLDidChangeVisibleFiles");
const RegisterCapabilityRequest = new RequestType<unknown, null, void>(
  "client/registerCapability",
);

const DEFAULT_INITIALIZATION_TIMEOUT_MS = 60_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_DIAGNOSTICS_TIMEOUT_MS = 60_000;
const DEFAULT_DIAGNOSTICS_QUIET_WINDOW_MS = 250;
const DEFAULT_STARTUP_SETTLING_MS = 1_500;
const MAX_STDERR_TAIL_LINES = 80;

/**
 * L0 only: exercise the real CodeQL Language Server protocol before the V2
 * product contracts are frozen. This class intentionally returns a snapshot;
 * it is not the long-lived QL language-service adapter.
 */
export class CodeqlLspProtocolSpike {
  private readonly options: Required<
    Pick<
      CodeqlLspProtocolSpikeOptions,
      | "initializationTimeoutMs"
      | "requestTimeoutMs"
      | "diagnosticsTimeoutMs"
      | "diagnosticsQuietWindowMs"
      | "startupSettlingMs"
      | "synchronous"
      | "includeInvalidProbe"
    >
  >;
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
  private persistentCapabilities:
    | ReturnType<typeof summarizeCapabilities>
    | undefined;
  private readonly startedAt = performance.now();
  private readonly timeline: L0TimelineEvent[] = [];
  private visibleFilesUpdateCount = 0;
  private currentWorkspaceFolders: L0WorkspaceFolder[];

  constructor(private readonly input: CodeqlLspProtocolSpikeOptions) {
    this.options = {
      initializationTimeoutMs:
        input.initializationTimeoutMs ?? DEFAULT_INITIALIZATION_TIMEOUT_MS,
      requestTimeoutMs: input.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      diagnosticsTimeoutMs:
        input.diagnosticsTimeoutMs ?? DEFAULT_DIAGNOSTICS_TIMEOUT_MS,
      diagnosticsQuietWindowMs:
        input.diagnosticsQuietWindowMs ?? DEFAULT_DIAGNOSTICS_QUIET_WINDOW_MS,
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
    const negotiatedCapabilities = summarizeCapabilities(
      initialize.capabilities,
    );

    let configurationNotificationSent = false;
    let dynamicWorkspaceFoldersNotificationSent = false;
    let watchedFilesNotificationSent = false;
    let visibleFilesNotificationSent = false;
    let workspaceUpdates: readonly L0WorkspaceUpdate[] = [];
    const documents: L0DocumentObservation[] = [];
    const addedFolders = this.dynamicWorkspaceFolders();

    try {
      await this.sendNotification(DidChangeConfigurationNotification.method, {
        settings: {},
      });
      this.recordTimeline("client", DidChangeConfigurationNotification.method);
      configurationNotificationSent = true;

      if (addedFolders.length > 0) {
        const additions =
          this.input.dynamicWorkspaceAddMode === "one-by-one"
            ? addedFolders.map((folder) => [folder] as const)
            : [addedFolders];
        for (const addition of additions) {
          this.currentWorkspaceFolders.push(...addition);
          await this.sendNotification(
            DidChangeWorkspaceFoldersNotification.method,
            {
              event: { added: addition, removed: [] },
            },
          );
          this.recordTimeline(
            "client",
            DidChangeWorkspaceFoldersNotification.method,
            undefined,
            `added:${addition.map((folder) => folder.uri).join(",")}`,
          );
        }
        dynamicWorkspaceFoldersNotificationSent = true;
      }

      const watchedUri = this.input.workspaceFolders[0]?.uri;
      if (watchedUri !== undefined) {
        await this.sendWatchedFiles([
          { watchedUri: `${watchedUri}/qlpack.yml` },
        ]);
        watchedFilesNotificationSent = true;
      }

      if (this.visibleFilesMode() !== "active-document") {
        await this.sendVisibleFiles(this.initialVisibleFiles());
      }
      visibleFilesNotificationSent = true;

      if (this.input.workspaceUpdateHook !== undefined) {
        await this.input.workspaceUpdateHook();
      }
      if (
        this.input.workspaceUpdates !== undefined &&
        this.input.workspaceUpdates.length > 0
      ) {
        workspaceUpdates = this.input.workspaceUpdates;
        await this.sendWatchedFiles(workspaceUpdates);
        watchedFilesNotificationSent = true;
      }

      await delay(this.options.startupSettlingMs);
      this.recordTimeline(
        "client",
        "autovul/startup-settled",
        undefined,
        `${this.options.startupSettlingMs}ms`,
      );

      for (const document of this.input.documents) {
        documents.push(
          await this.probeDocument(document, negotiatedCapabilities),
        );
      }
      if (addedFolders.length > 0) {
        const removals =
          this.input.dynamicWorkspaceAddMode === "one-by-one"
            ? [...addedFolders].reverse().map((folder) => [folder] as const)
            : [addedFolders];
        for (const removal of removals) {
          this.currentWorkspaceFolders = this.currentWorkspaceFolders.filter(
            (folder) => !removal.some((removed) => removed.uri === folder.uri),
          );
          await this.sendNotification(
            DidChangeWorkspaceFoldersNotification.method,
            {
              event: { added: [], removed: removal },
            },
          );
          this.recordTimeline(
            "client",
            DidChangeWorkspaceFoldersNotification.method,
            undefined,
            `removed:${removal.map((folder) => folder.uri).join(",")}`,
          );
        }
      }
    } finally {
      await this.close();
    }

    const capabilitySummary = {
      ...negotiatedCapabilities,
      diagnostics: documents.some(
        (document) => document.valid.received || document.invalid.received,
      ),
    };

    return {
      schemaVersion: "v2.l0.codeql-lsp/1",
      codeqlPath: this.input.codeqlPath,
      searchPaths: this.input.searchPaths,
      workspaceFolders: this.input.workspaceFolders,
      initialize: {
        ...(initialize.serverInfo === undefined
          ? {}
          : { serverInfo: initialize.serverInfo }),
        capabilities: initialize.capabilities,
        observedServerRequests: Object.fromEntries(
          this.serverRequests.entries(),
        ),
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
        cleanShutdown:
          this.closed &&
          this.child !== undefined &&
          this.child.exitCode === 0 &&
          !processGroupExists(this.child),
      },
    };
  }

  /**
   * Keep the same real protocol client alive for successive draft documents.
   * L0 uses `run()` as a finite experiment; the production draft adapter uses
   * this method so a session can serve multiple languages and revisions.
   */
  async diagnoseDocument(
    document: L0ProtocolDocument,
  ): Promise<L0DocumentObservation> {
    await this.preparePersistentSession();
    const capabilities = this.persistentCapabilities;
    if (capabilities === undefined) {
      throw new Error(
        "CodeQL language server capabilities were not negotiated",
      );
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

  async notifyWorkspaceUpdate(
    updates: readonly L0WorkspaceUpdate[],
  ): Promise<void> {
    if (updates.length === 0) return;
    await this.preparePersistentSession();
    await this.sendWatchedFiles(updates);
  }

  persistentHealth(): {
    readonly initialized: boolean;
    readonly closed: boolean;
    readonly errors: readonly string[];
  } {
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
        await withTimeout(
          connection.sendRequest<void>(ShutdownRequest.method),
          this.options.requestTimeoutMs,
          "shutdown",
        );
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
      this.persistentCapabilities = summarizeCapabilities(
        initialize.capabilities,
      );
      await this.sendNotification(DidChangeConfigurationNotification.method, {
        settings: {},
      });
      this.recordTimeline("client", DidChangeConfigurationNotification.method);
      await this.sendVisibleFiles([]);
      await delay(this.options.startupSettlingMs);
      this.recordTimeline(
        "client",
        "autovul/startup-settled",
        undefined,
        `${this.options.startupSettlingMs}ms`,
      );
      this.persistentPrepared = true;
    } catch (error: unknown) {
      await this.close();
      throw error;
    }
  }

  private async closeDocument(uri: string): Promise<void> {
    const connection = this.requireConnection();
    await connection.sendNotification(DidCloseTextDocumentNotification.method, {
      textDocument: { uri },
    });
    this.recordTimeline("client", DidCloseTextDocumentNotification.method, uri);
  }

  private async start(): Promise<InitializeResult> {
    if (this.initialized) {
      throw new Error(
        "L0 CodeQL language server spike cannot be started twice",
      );
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
    child.stderr.on("data", (chunk: Buffer | string) =>
      this.captureStderr(chunk),
    );
    child.on("error", (error: Error) =>
      this.transportErrors.push(errorMessage(error)),
    );

    const connection = createMessageConnection(
      new StreamMessageReader(child.stdout),
      new StreamMessageWriter(child.stdin),
    );
    this.connection = connection;
    this.registerServerHandlers(connection);
    connection.onError(([error]) =>
      this.transportErrors.push(errorMessage(error)),
    );
    connection.onClose(() => {
      if (!this.closed) {
        this.transportErrors.push(
          "CodeQL language server transport closed before shutdown",
        );
      }
    });
    connection.listen();

    const rootUri = this.input.workspaceFolders[0]?.uri ?? null;
    const params: InitializeParams = {
      processId: process.pid,
      clientInfo: { name: "autovul-l0-spike", version: "0.1.0" },
      rootUri,
      workspaceFolders: this.protocolWorkspaceFolders(),
      capabilities: {
        workspace: {
          configuration: true,
          workspaceFolders: true,
          didChangeWatchedFiles: { dynamicRegistration: true },
        },
        textDocument: {
          synchronization: {
            dynamicRegistration: false,
            willSave: false,
            didSave: false,
          },
          publishDiagnostics: { relatedInformation: true },
          definition: { linkSupport: true },
          hover: { contentFormat: ["markdown", "plaintext"] },
          completion: {
            contextSupport: true,
            completionItem: { snippetSupport: false },
          },
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
    connection.onNotification(
      PublishDiagnosticsNotification.method,
      (params: PublishDiagnosticsParams) => {
        this.recordTimeline(
          "server",
          PublishDiagnosticsNotification.method,
          params.uri,
          `${params.diagnostics.length} diagnostics`,
        );
        this.recordDiagnostics(params);
      },
    );
    connection.onRequest(
      ConfigurationRequest.method,
      (params: ConfigurationParams) => {
        this.countServerRequest("workspace/configuration");
        return params.items.map(() => ({}));
      },
    );
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

  private async probeDocument(
    document: L0ProtocolDocument,
    capabilities: ReturnType<typeof summarizeCapabilities>,
  ): Promise<L0DocumentObservation> {
    const connection = this.requireConnection();
    const validSequence = this.diagnosticsSequence;
    const validStartedAt = performance.now();
    await connection.sendNotification(DidOpenTextDocumentNotification.method, {
      textDocument: {
        uri: document.uri,
        languageId: "ql",
        version: 1,
        text: document.text,
      },
    });
    this.recordTimeline(
      "client",
      DidOpenTextDocumentNotification.method,
      document.uri,
    );
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([document.uri]);
    }
    const valid = await this.waitForDiagnosticsOrTimeout(
      document.uri,
      validSequence,
    );
    const validWithTiming = {
      ...valid,
      elapsedMs: Math.round(performance.now() - validStartedAt),
    };

    const definition = await requestDefinition(
      connection,
      document,
      capabilities.definition,
      this.options.requestTimeoutMs,
    );
    const hover = await requestHover(
      connection,
      document,
      capabilities.hover,
      this.options.requestTimeoutMs,
    );
    const completion = await requestCompletion(
      connection,
      document,
      capabilities.completion,
      this.options.requestTimeoutMs,
    );

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
      await connection.sendNotification(
        DidChangeTextDocumentNotification.method,
        {
          textDocument: { uri: document.uri, version: 2 },
          contentChanges: [{ text: document.invalidText }],
        },
      );
      this.recordTimeline(
        "client",
        DidChangeTextDocumentNotification.method,
        document.uri,
      );
    } else {
      await connection.sendNotification(
        DidCloseTextDocumentNotification.method,
        { textDocument: { uri: document.uri } },
      );
      this.recordTimeline(
        "client",
        DidCloseTextDocumentNotification.method,
        document.uri,
      );
      await connection.sendNotification(
        DidOpenTextDocumentNotification.method,
        {
          textDocument: {
            uri: invalidUri,
            languageId: "ql",
            version: 1,
            text: document.invalidText,
          },
        },
      );
      this.recordTimeline(
        "client",
        DidOpenTextDocumentNotification.method,
        invalidUri,
      );
    }
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([invalidUri]);
    }
    const invalid = await this.waitForDiagnosticsOrTimeout(
      invalidUri,
      invalidSequence,
    );
    const invalidWithTiming = {
      ...invalid,
      elapsedMs: Math.round(performance.now() - invalidStartedAt),
    };
    await connection.sendNotification(DidCloseTextDocumentNotification.method, {
      textDocument: { uri: invalidUri },
    });
    this.recordTimeline(
      "client",
      DidCloseTextDocumentNotification.method,
      invalidUri,
    );
    if (this.visibleFilesMode() === "active-document") {
      await this.sendVisibleFiles([]);
    }

    return {
      language: document.language,
      uri: document.uri,
      valid: validWithTiming,
      invalid: invalidWithTiming,
      definition,
      hover,
      completion,
    };
  }

  private waitForDiagnostics(
    uri: string,
    afterSequence: number,
  ): Promise<L0DiagnosticObservation> {
    const existing = this.diagnostics.get(uri);
    if (existing !== undefined && existing.sequence > afterSequence) {
      return Promise.resolve(toDiagnosticObservation(existing));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const waiters = this.diagnosticWaiters.get(uri) ?? [];
        this.diagnosticWaiters.set(
          uri,
          waiters.filter((waiter) => waiter.timer !== timer),
        );
        reject(
          new Error(`Timed out waiting for publishDiagnostics for ${uri}`),
        );
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

  private async waitForDiagnosticsOrTimeout(
    uri: string,
    afterSequence: number,
  ): Promise<L0DiagnosticObservation> {
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
    const event: DiagnosticEvent = {
      ...params,
      sequence: ++this.diagnosticsSequence,
    };
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
          const remainingWaiters = currentWaiters.filter(
            (candidate) => candidate !== waiter,
          );
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

  private async sendVisibleFiles(
    visibleFiles: readonly string[],
  ): Promise<void> {
    await this.sendNotification(VisibleFilesNotification.method, {
      visibleFiles,
    });
    this.visibleFilesUpdateCount += 1;
    this.recordTimeline(
      "client",
      VisibleFilesNotification.method,
      undefined,
      visibleFiles.join(","),
    );
  }

  private async sendWatchedFiles(
    updates: readonly L0WorkspaceUpdate[],
  ): Promise<void> {
    await this.sendNotification(DidChangeWatchedFilesNotification.method, {
      changes: updates.map((update) => ({
        uri: update.watchedUri,
        type: update.type ?? FileChangeType.Changed,
      })),
    });
    this.recordTimeline(
      "client",
      DidChangeWatchedFilesNotification.method,
      undefined,
      updates.map((update) => update.watchedUri).join(","),
    );
  }

  private recordTimeline(
    direction: "client" | "server",
    method: string,
    uri?: string,
    detail?: string,
  ): void {
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
    return this.input.dynamicWorkspaceFolder === undefined
      ? []
      : [this.input.dynamicWorkspaceFolder];
  }

  private visibleFilesMode(): L0VisibleFilesMode {
    return (
      this.input.visibleFilesMode ??
      (this.input.visibleFiles === undefined ? "all" : "explicit")
    );
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

  private async sendInitialize(
    connection: MessageConnection,
    params: InitializeParams,
  ): Promise<InitializeResult> {
    this.recordTimeline("client", InitializeRequest.method);
    const result = await connection.sendRequest<InitializeResult>(
      InitializeRequest.method,
      params,
    );
    this.recordTimeline("server", "initialize:response");
    return result;
  }

  private protocolWorkspaceFolders(): WorkspaceFolder[] {
    return this.currentWorkspaceFolders.map((folder) => ({
      uri: folder.uri,
      name: folder.name,
    }));
  }

  private captureStderr(chunk: Buffer | string): void {
    const lines = String(chunk)
      .replaceAll("\r\n", "\n")
      .split("\n")
      .map((line) => sanitize(line))
      .filter((line) => line.length > 0);
    this.stderrTail.push(...lines);
    while (this.stderrTail.length > MAX_STDERR_TAIL_LINES) {
      this.stderrTail.shift();
    }
  }
}
