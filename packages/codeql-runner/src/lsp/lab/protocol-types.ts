import type {
  Diagnostic,
  FileChangeType,
  InitializeResult,
  Position,
  PublishDiagnosticsParams,
} from "vscode-languageserver-protocol";

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
  readonly range?: { readonly start: Position; readonly end: Position };
  readonly targetSelectionRange?: { readonly start: Position; readonly end: Position };
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

export interface L0DiagnosticEvent extends PublishDiagnosticsParams {
  readonly sequence: number;
}

export interface L0DiagnosticWaiter {
  readonly afterSequence: number;
  readonly resolve: (event: L0DiagnosticEvent) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
  quietTimer?: NodeJS.Timeout;
  latestEvent?: L0DiagnosticEvent;
}

export type L0Diagnostic = Diagnostic;
