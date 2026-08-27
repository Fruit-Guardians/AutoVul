import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import type {
  CompletionItem,
  CompletionList,
  Diagnostic,
  Hover,
  InitializeResult,
  Location,
  LocationLink,
  Position,
} from "vscode-languageserver-protocol";

import { errorMessage } from "../process-lifecycle.js";
import type {
  L0DiagnosticEvent,
  L0DiagnosticObservation,
  L0ProtocolDocument,
  L0ProtocolSnapshot,
  L0SymbolLocation,
} from "./protocol-types.js";

export function summarizeCapabilities(capabilities: InitializeResult["capabilities"]): L0ProtocolSnapshot["capabilitySummary"] {
  const workspaceFolders = capabilities.workspace?.workspaceFolders;
  return {
    diagnostics: false,
    definition: Boolean(capabilities.definitionProvider),
    hover: Boolean(capabilities.hoverProvider),
    completion: Boolean(capabilities.completionProvider),
    workspaceFolders: Boolean(workspaceFolders),
    dynamicWorkspaceFolders: typeof workspaceFolders === "object" && workspaceFolders !== null && workspaceFolders.changeNotifications === true,
    experimental: capabilities.experimental !== undefined && typeof capabilities.experimental === "object" && capabilities.experimental !== null ? Object.keys(capabilities.experimental) : [],
  };
}

export function toDiagnosticObservation(event: L0DiagnosticEvent): L0DiagnosticObservation {
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
      relatedLocations: (diagnostic.relatedInformation ?? []).map((related) => ({ uri: related.location.uri, range: related.location.range })),
    })),
  };
}

export function severityName(diagnostic: Diagnostic): string {
  switch (diagnostic.severity) {
    case 1: return "error";
    case 2: return "warning";
    case 3: return "information";
    case 4: return "hint";
    default: return "unspecified";
  }
}

export function positionAt(text: string, token: string, after = false): Position {
  const index = text.indexOf(token);
  if (index < 0) return { line: 0, character: 0 };
  const prefix = text.slice(0, after ? index + token.length : index);
  const lines = prefix.split("\n");
  return { line: lines.length - 1, character: lines.at(-1)?.length ?? 0 };
}

export function completionCount(result: CompletionItem[] | CompletionList | null): number {
  if (result === null) return 0;
  return Array.isArray(result) ? result.length : result.items.length;
}

export function completionItems(result: CompletionItem[] | CompletionList | null): readonly CompletionItem[] {
  if (result === null) return [];
  return Array.isArray(result) ? result : result.items;
}

export function isCompletionList(result: CompletionItem[] | CompletionList): result is CompletionList {
  return !Array.isArray(result) && "items" in result;
}

export function normalizeLocations(result: Location[] | LocationLink[] | null): readonly L0SymbolLocation[] {
  if (result === null) return [];
  return result.map((location) => "targetUri" in location
    ? { uri: location.targetUri, range: location.targetRange, targetSelectionRange: location.targetSelectionRange }
    : { uri: location.uri, range: location.range });
}

export function summarizeHover(hover: Hover): string {
  const contents = Array.isArray(hover.contents) ? hover.contents : [hover.contents];
  const text = contents.map((content) => {
    if (typeof content === "string") return content;
    if ("value" in content) return content.value;
    return "";
  }).join("\n");
  return text.length > 2_000 ? `${text.slice(0, 2_000)}…` : text;
}

export function l0UriForPath(path: string): string {
  return pathToFileURL(path).href;
}

export async function readL0Document(path: string, language: string, invalidText: string, definitionToken: string, completionToken: string): Promise<L0ProtocolDocument> {
  const text = await readFile(path, "utf8");
  return { language, uri: l0UriForPath(path), text, invalidText, definitionToken, completionToken };
}

export { errorMessage };
