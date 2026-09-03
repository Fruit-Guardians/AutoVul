import { createHash } from "node:crypto";

import ts from "typescript";
import {
  CHANGE_OBSERVATION_LIMITS,
  type ChangeObservationCallChange,
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

export const TYPESCRIPT_PARSER_VERSION = ts.version;

export interface SourceChangeFacts {
  readonly symbols: readonly ChangeObservationSymbol[];
  readonly calls: readonly ChangeObservationCallChange[];
  readonly events: readonly ChangeObservationEventChange[];
}

export function parseNormalizedHunks(
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

export function languageForPath(path: string): ChangeObservationLanguage | undefined {
  const extension = extensionForPath(path);
  if (["js", "jsx", "mjs", "cjs"].includes(extension)) return "javascript";
  if (["ts", "tsx", "mts", "cts"].includes(extension)) return "typescript";
  return undefined;
}

export function extensionForPath(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const extension = name.lastIndexOf(".");
  return extension < 0 ? "unknown" : name.slice(extension + 1).toLowerCase().slice(0, CHANGE_OBSERVATION_LIMITS.maxIdentifierLength);
}

/** Parse both immutable source sides and return only structural change facts. */
export function sourceChangeFacts(
  oldSource: string | undefined,
  oldPath: string,
  newSource: string | undefined,
  newPath: string,
  language: ChangeObservationLanguage,
  gaps: ChangeObservationGap[],
): SourceChangeFacts | undefined {
  const oldParsed = oldSource === undefined ? undefined : parseSource(oldSource, oldPath, language, gaps);
  const newParsed = newSource === undefined ? undefined : parseSource(newSource, newPath, language, gaps);
  if (oldParsed === undefined && newParsed === undefined) return undefined;
  const symbols = compareSymbols(oldParsed?.symbols ?? [], newParsed?.symbols ?? []);
  const calls = compareCalls(oldParsed?.calls ?? [], newParsed?.calls ?? []);
  return { symbols, calls, events: eventsForCalls(calls) };
}

export function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function normalizeChangedLine(line: string): string {
  return line.replace(/[ \t]+$/g, "");
}

function digestLineStream(lines: readonly string[]): string {
  return createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
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
