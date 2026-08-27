import {
  CompletionRequest,
  DefinitionRequest,
  HoverRequest,
  type CompletionItem,
  type CompletionList,
  type Hover,
  type Location,
  type LocationLink,
  type MessageConnection,
} from "vscode-languageserver-protocol";
import { withTimeout, errorMessage } from "../process-lifecycle.js";
import {
  completionCount,
  completionItems,
  isCompletionList,
  normalizeLocations,
  positionAt,
  summarizeHover,
} from "./protocol-helpers.js";
import type { L0ProtocolDocument, L0RequestObservation } from "./protocol-types.js";

export async function requestDefinition(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean, timeoutMs: number): Promise<L0RequestObservation> {
  if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
  try {
    const result = await withTimeout(connection.sendRequest<Location[] | LocationLink[] | null>(DefinitionRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.definitionToken) }), timeoutMs, "textDocument/definition");
    const locations = normalizeLocations(result);
    return { supportedByCapabilities: true, completed: true, resultKind: result === null ? "null" : Array.isArray(result) ? "array" : "single", resultCount: locations.length, locations };
  } catch (error: unknown) {
    return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
  }
}

export async function requestHover(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean, timeoutMs: number): Promise<L0RequestObservation> {
  if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
  try {
    const result = await withTimeout(connection.sendRequest<Hover | null>(HoverRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.definitionToken) }), timeoutMs, "textDocument/hover");
    const hover = result as Hover | null;
    return { supportedByCapabilities: true, completed: true, resultKind: hover === null ? "null" : "hover", ...(hover === null ? {} : { hoverText: summarizeHover(hover) }) };
  } catch (error: unknown) {
    return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
  }
}

export async function requestCompletion(connection: MessageConnection, document: L0ProtocolDocument, supported: boolean, timeoutMs: number): Promise<L0RequestObservation> {
  if (!supported) return { supportedByCapabilities: false, completed: false, resultKind: "unsupported" };
  try {
    const result = await withTimeout(connection.sendRequest<CompletionItem[] | CompletionList | null>(CompletionRequest.method, { textDocument: { uri: document.uri }, position: positionAt(document.text, document.completionToken, true), context: { triggerKind: 1 } }), timeoutMs, "textDocument/completion");
    return { supportedByCapabilities: true, completed: true, resultKind: result === null ? "null" : isCompletionList(result) ? "list" : "array", resultCount: completionCount(result), completionLabels: completionItems(result).slice(0, 20).map((item) => item.label) };
  } catch (error: unknown) {
    return { supportedByCapabilities: true, completed: false, resultKind: "error", error: errorMessage(error) };
  }
}
