import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { delimiter } from "node:path";

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
  DidCloseTextDocumentNotification,
  DidOpenTextDocumentNotification,
  DidChangeWatchedFilesNotification,
  ExitNotification,
  HoverRequest,
  InitializeRequest,
  InitializedNotification,
  PublishDiagnosticsNotification,
  ShutdownRequest,
  WorkspaceFoldersRequest,
  WorkDoneProgressCreateRequest,
  type CompletionItem,
  type CompletionList,
  type ConfigurationParams,
  type Diagnostic,
  type Hover,
  type InitializeParams,
  type InitializeResult,
  type Location,
  type LocationLink,
  type Position,
  type PublishDiagnosticsParams,
} from "vscode-languageserver-protocol";

import { errorMessage, waitForExit, waitWithKill, withTimeout } from "./process-lifecycle.js";

const VisibleFilesNotification = new NotificationType<{ readonly visibleFiles: readonly string[] }>("textDocument/codeQLDidChangeVisibleFiles");
const RegisterCapabilityRequest = new RequestType<unknown, null, void>("client/registerCapability");

export interface LspSessionOptions {
  readonly codeqlPath: string;
  readonly searchPaths: readonly string[];
  readonly workspaceFolders: readonly LspWorkspaceFolder[];
  readonly commonCaches?: string;
  readonly cwd?: string;
  readonly initializationTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly diagnosticsTimeoutMs?: number;
  readonly diagnosticsQuietWindowMs?: number;
  readonly startupSettlingMs?: number;
  readonly synchronous?: boolean;
}

export interface LspWorkspaceFolder {
  readonly uri: string;
  readonly name: string;
}

export interface LspDocument {
  readonly language: string;
  readonly uri: string;
  readonly text: string;
  readonly definitionToken: string;
  readonly completionToken: string;
}

export interface LspDocumentObservation {
  readonly valid: LspDiagnosticObservation;
  readonly definition: LspRequestObservation;
  readonly hover: LspRequestObservation;
  readonly completion: LspRequestObservation;
}

export interface LspDiagnosticObservation {
  readonly uri: string;
  readonly count: number;
  readonly messages: readonly string[];
  readonly received: boolean;
  readonly items?: readonly LspDiagnosticItem[];
}

export interface LspDiagnosticItem {
  readonly uri: string;
  readonly severity?: string;
  readonly message: string;
  readonly code?: string;
  readonly source?: string;
  readonly range: { readonly start: Position; readonly end: Position };
  readonly relatedLocations: readonly LspSymbolLocation[];
}

export interface LspSymbolLocation {
  readonly uri: string;
  readonly range?: { readonly start: Position; readonly end: Position };
  readonly targetSelectionRange?: { readonly start: Position; readonly end: Position };
}

export interface LspRequestObservation {
  readonly supportedByCapabilities: boolean;
  readonly completed: boolean;
  readonly resultKind: string;
  readonly locations?: readonly LspSymbolLocation[];
  readonly hoverText?: string;
  readonly completionLabels?: readonly string[];
  readonly error?: string;
}

interface DiagnosticEvent extends PublishDiagnosticsParams {
  readonly sequence: number;
}

interface DiagnosticWaiter {
  readonly afterSequence: number;
  readonly resolve: (event: DiagnosticEvent) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
  quietTimer?: NodeJS.Timeout;
}

export class CodeqlLspSession {
  private readonly initializationTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly diagnosticsTimeoutMs: number;
  private readonly diagnosticsQuietWindowMs: number;
  private readonly startupSettlingMs: number;
  private readonly synchronous: boolean;
  private child: ChildProcessWithoutNullStreams | undefined;
  private childExit: Promise<number | null> | undefined;
  private connection: MessageConnection | undefined;
  private initialized = false;
  private closed = false;
  private diagnosticsSequence = 0;
  private readonly diagnostics = new Map<string, DiagnosticEvent>();
  private readonly diagnosticWaiters = new Map<string, DiagnosticWaiter[]>();
  private readonly errors: string[] = [];
  private prepared = false;

  constructor(private readonly input: LspSessionOptions) {
    this.initializationTimeoutMs = input.initializationTimeoutMs ?? 60_000;
    this.requestTimeoutMs = input.requestTimeoutMs ?? 15_000;
    this.diagnosticsTimeoutMs = input.diagnosticsTimeoutMs ?? 60_000;
    this.diagnosticsQuietWindowMs = input.diagnosticsQuietWindowMs ?? 250;
    this.startupSettlingMs = input.startupSettlingMs ?? 1_500;
    this.synchronous = input.synchronous ?? false;
  }

  async diagnose(document: LspDocument): Promise<LspDocumentObservation> {
    await this.prepare();
    const connection = this.requireConnection();
    const sequence = this.diagnosticsSequence;
    await connection.sendNotification(DidOpenTextDocumentNotification.method, {
      textDocument: { uri: document.uri, languageId: "ql", version: 1, text: document.text },
    });
    await this.sendVisibleFiles([document.uri]);
    try {
      const valid = await this.waitForDiagnosticsOrTimeout(document.uri, sequence);
      const capabilities = this.capabilities;
      return {
        valid,
        definition: await this.requestDefinition(connection, document, capabilities.definition),
        hover: await this.requestHover(connection, document, capabilities.hover),
        completion: await this.requestCompletion(connection, document, capabilities.completion),
      };
    } finally {
      await connection.sendNotification(DidCloseTextDocumentNotification.method, { textDocument: { uri: document.uri } });
      await this.sendVisibleFiles([]);
    }
  }

  async notifyWorkspaceUpdate(updates: readonly { readonly watchedUri: string }[]): Promise<void> {
    if (updates.length === 0) return;
    await this.prepare();
    await this.requireConnection().sendNotification(DidChangeWatchedFilesNotification.method, {
      changes: updates.map((update) => ({ uri: update.watchedUri, type: 2 })),
    });
  }

  persistentHealth(): { readonly initialized: boolean; readonly closed: boolean; readonly errors: readonly string[] } {
    return { initialized: this.initialized, closed: this.closed, errors: [...this.errors] };
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const connection = this.connection;
    const child = this.child;
    if (connection !== undefined) {
      try {
        await withTimeout(connection.sendRequest<void>(ShutdownRequest.method), this.requestTimeoutMs, "shutdown");
      } catch (error: unknown) {
        this.errors.push(errorMessage(error));
      }
      try {
        await connection.sendNotification(ExitNotification.method);
        connection.end();
      } catch (error: unknown) {
        this.errors.push(errorMessage(error));
      }
      connection.dispose();
      this.connection = undefined;
    }
    if (child !== undefined) {
      const exit = this.childExit ?? waitForExit(child);
      this.childExit = exit;
      await waitWithKill(exit, child, this.requestTimeoutMs);
    }
  }

  private get capabilities(): { readonly definition: boolean; readonly hover: boolean; readonly completion: boolean } {
    return this.negotiatedCapabilities ?? { definition: false, hover: false, completion: false };
  }

  private negotiatedCapabilities: { readonly definition: boolean; readonly hover: boolean; readonly completion: boolean } | undefined;

  private async prepare(): Promise<void> {
    if (this.closed) throw new Error("CodeQL language server session is closed");
    if (this.prepared) return;
    try {
      const initialize = await this.start();
      this.negotiatedCapabilities = {
        definition: Boolean(initialize.capabilities.definitionProvider),
        hover: Boolean(initialize.capabilities.hoverProvider),
        completion: Boolean(initialize.capabilities.completionProvider),
      };
      await this.requireConnection().sendNotification(DidChangeConfigurationNotification.method, { settings: {} });
      await this.sendVisibleFiles([]);
      await delay(this.startupSettlingMs);
      this.prepared = true;
    } catch (error: unknown) {
      await this.close();
      throw error;
    }
  }

  private async start(): Promise<InitializeResult> {
    const args = ["execute", "language-server", "--check-errors=ON_CHANGE", "--search-path", this.input.searchPaths.join(delimiter)];
    if (this.input.commonCaches !== undefined) args.push("--common-caches", this.input.commonCaches);
    if (this.synchronous) args.push("--synchronous");
    const child = spawn(this.input.codeqlPath, args, {
      cwd: this.input.cwd,
      env: { ...process.env },
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    this.childExit = waitForExit(child);
    child.on("error", (error: Error) => this.errors.push(errorMessage(error)));
    const connection = createMessageConnection(new StreamMessageReader(child.stdout), new StreamMessageWriter(child.stdin));
    this.connection = connection;
    this.registerServerHandlers(connection);
    connection.onError(([error]) => this.errors.push(errorMessage(error)));
    connection.onClose(() => {
      if (!this.closed) this.errors.push("CodeQL language server transport closed before shutdown");
    });
    connection.listen();
    const params: InitializeParams = {
      processId: process.pid,
      clientInfo: { name: "autovul-lsp", version: "0.1.0" },
      rootUri: this.input.workspaceFolders[0]?.uri ?? null,
      workspaceFolders: [...this.input.workspaceFolders],
      capabilities: {
        workspace: { configuration: true, workspaceFolders: true, didChangeWatchedFiles: { dynamicRegistration: true } },
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
    const result = await withTimeout(connection.sendRequest<InitializeResult>(InitializeRequest.method, params), this.initializationTimeoutMs, "initialize");
    this.initialized = true;
    await connection.sendNotification(InitializedNotification.method, {});
    return result;
  }

  private registerServerHandlers(connection: MessageConnection): void {
    connection.onNotification(PublishDiagnosticsNotification.method, (params: PublishDiagnosticsParams) => this.recordDiagnostics(params));
    connection.onRequest(ConfigurationRequest.method, (params: ConfigurationParams) => params.items.map(() => ({})));
    connection.onRequest(WorkspaceFoldersRequest.method, () => [...this.input.workspaceFolders]);
    connection.onRequest(WorkDoneProgressCreateRequest.method, () => null);
    connection.onRequest(RegisterCapabilityRequest.method, () => null);
  }

  private async sendVisibleFiles(visibleFiles: readonly string[]): Promise<void> {
    await this.requireConnection().sendNotification(VisibleFilesNotification.method, { visibleFiles });
  }

  private async requestDefinition(connection: MessageConnection, document: LspDocument, supported: boolean): Promise<LspRequestObservation> {
    if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    try {
      const result = await withTimeout(connection.sendRequest<Location[] | LocationLink[] | null>(DefinitionRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.definitionToken) }), this.requestTimeoutMs, "textDocument/definition");
      const locations = normalizeLocations(result);
      return { supportedByCapabilities: true, completed: true, resultKind: result === null ? "null" : Array.isArray(result) ? "array" : "single", locations };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private async requestHover(connection: MessageConnection, document: LspDocument, supported: boolean): Promise<LspRequestObservation> {
    if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    try {
      const result = await withTimeout(connection.sendRequest<Hover | null>(HoverRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.definitionToken) }), this.requestTimeoutMs, "textDocument/hover");
      return { supportedByCapabilities: true, completed: true, resultKind: result === null ? "null" : "hover", ...(result === null ? {} : { hoverText: summarizeHover(result) }) };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private async requestCompletion(connection: MessageConnection, document: LspDocument, supported: boolean): Promise<LspRequestObservation> {
    if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
    try {
      const result = await withTimeout(connection.sendRequest<CompletionItem[] | CompletionList | null>(CompletionRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.completionToken, true), context: { triggerKind: 1 } }), this.requestTimeoutMs, "textDocument/completion");
      const items = result === null ? [] : Array.isArray(result) ? result : result.items;
      return { supportedByCapabilities: true, completed: true, resultKind: result === null ? "null" : Array.isArray(result) ? "array" : "list", completionLabels: items.slice(0, 20).map((item) => item.label) };
    } catch (error: unknown) {
      return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
    }
  }

  private waitForDiagnosticsOrTimeout(uri: string, afterSequence: number): Promise<LspDiagnosticObservation> {
    const existing = this.diagnostics.get(uri);
    if (existing !== undefined && existing.sequence > afterSequence) return Promise.resolve(toDiagnosticObservation(existing));
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({ uri, count: 0, messages: ["Timed out waiting for publishDiagnostics"], received: false }), this.diagnosticsTimeoutMs);
      const waiter: DiagnosticWaiter = {
        afterSequence,
        resolve: (event) => resolve(toDiagnosticObservation(event)),
        reject: () => resolve({ uri, count: 0, messages: ["Diagnostic wait failed"], received: false }),
        timer,
      };
      const waiters = this.diagnosticWaiters.get(uri) ?? [];
      waiters.push(waiter);
      this.diagnosticWaiters.set(uri, waiters);
    });
  }

  private recordDiagnostics(params: PublishDiagnosticsParams): void {
    const event: DiagnosticEvent = { ...params, sequence: ++this.diagnosticsSequence };
    this.diagnostics.set(params.uri, event);
    const waiters = this.diagnosticWaiters.get(params.uri) ?? [];
    for (const waiter of waiters) {
      if (event.sequence <= waiter.afterSequence) continue;
      if (waiter.quietTimer !== undefined) clearTimeout(waiter.quietTimer);
      waiter.quietTimer = setTimeout(() => {
        clearTimeout(waiter.timer);
        waiter.resolve(event);
        this.diagnosticWaiters.delete(params.uri);
      }, this.diagnosticsQuietWindowMs);
    }
  }

  private requireConnection(): MessageConnection {
    if (this.connection === undefined) throw new Error("CodeQL language server connection is not available");
    return this.connection;
  }
}

async function delay(timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));
}

function toDiagnosticObservation(event: DiagnosticEvent): LspDiagnosticObservation {
  return { uri: event.uri, count: event.diagnostics.length, messages: event.diagnostics.map((item) => item.message), received: true, items: event.diagnostics.map((item) => toDiagnosticItem(event.uri, item)) };
}

function toDiagnosticItem(uri: string, diagnostic: Diagnostic): LspDiagnosticItem {
  return {
    uri,
    ...(diagnostic.severity === undefined ? {} : { severity: severityName(diagnostic.severity) }),
    message: diagnostic.message,
    ...(diagnostic.code === undefined ? {} : { code: String(diagnostic.code) }),
    ...(diagnostic.source === undefined ? {} : { source: diagnostic.source }),
    range: diagnostic.range,
    relatedLocations: (diagnostic.relatedInformation ?? []).map((related) => ({ uri: related.location.uri, range: related.location.range })),
  };
}

function severityName(severity: number): string {
  return severity === 1 ? "error" : severity === 2 ? "warning" : severity === 3 ? "information" : severity === 4 ? "hint" : "unspecified";
}

function normalizeLocations(result: Location[] | LocationLink[] | null): LspSymbolLocation[] {
  if (result === null) return [];
  return result.map((location) => "targetUri" in location
    ? { uri: location.targetUri, range: location.targetRange, targetSelectionRange: location.targetSelectionRange }
    : { uri: location.uri, range: location.range });
}

function summarizeHover(hover: Hover): string {
  const contents = Array.isArray(hover.contents) ? hover.contents : [hover.contents];
  const text = contents.map((content) => typeof content === "string" ? content : "value" in content ? content.value : "").join("\n");
  return text.length > 2_000 ? `${text.slice(0, 2_000)}…` : text;
}

function positionAt(text: string, token: string, after = false): Position {
  const index = after ? text.lastIndexOf(token) + token.length : text.indexOf(token);
  if (index < 0) return { line: 0, character: 0 };
  const lines = text.slice(0, index).split("\n");
  return { line: lines.length - 1, character: lines.at(-1)?.length ?? 0 };
}
