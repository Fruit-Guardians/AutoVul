import { createHash } from "node:crypto";

import { Type } from "typebox";
import {
  CHANGE_OBSERVATION_LIMITS,
  CHANGE_OBSERVATION_SERVICE_VERSION,
  ChangeObservationBudgetSchema,
  ChangeObservationInputSchema,
  ChangeObservationSchema,
  parseSchema,
  type ChangeObservation,
  type ChangeObservationBudget,
  type ChangeObservationGap,
  type ChangeObservationInput,
} from "@autovul/contracts";

import {
  sameRequestedRevision,
  type ChangeObservationPortObservation,
  type ChangeObservationPortRequest,
} from "./port.js";

const ChangeObservationPortObservationSchema = Type.Object(
  {
    schema_version: ChangeObservationSchema.properties.schema_version,
    revision_identity: ChangeObservationSchema.properties.revision_identity,
    completeness: ChangeObservationSchema.properties.completeness,
    changed_files: ChangeObservationSchema.properties.changed_files,
    normalized_hunks: ChangeObservationSchema.properties.normalized_hunks,
    symbols: ChangeObservationSchema.properties.symbols,
    call_changes: ChangeObservationSchema.properties.call_changes,
    event_changes: ChangeObservationSchema.properties.event_changes,
    analysis_gaps: ChangeObservationSchema.properties.analysis_gaps,
    provenance: ChangeObservationSchema.properties.provenance,
  },
  { additionalProperties: false },
);

const DEFAULT_BUDGET: ChangeObservationBudget = {
  timeout_ms: 600_000,
  max_changed_files: CHANGE_OBSERVATION_LIMITS.maxChangedFiles,
  max_diff_bytes: CHANGE_OBSERVATION_LIMITS.maxDiffBytes,
  max_hunks: CHANGE_OBSERVATION_LIMITS.maxHunks,
  max_hunk_lines: CHANGE_OBSERVATION_LIMITS.maxHunkLines,
  max_symbols: CHANGE_OBSERVATION_LIMITS.maxSymbols,
  max_call_changes: CHANGE_OBSERVATION_LIMITS.maxCallChanges,
  max_event_changes: CHANGE_OBSERVATION_LIMITS.maxEventChanges,
};

export interface ResolvedChangeObservationInput {
  readonly input: ChangeObservationInput;
  readonly resolvedBudget: ChangeObservationBudget;
  readonly normalizedPathFilters: readonly string[];
}

/**
 * Side-effect-free request parsing. Trusted-root and Git-object checks belong
 * to the later runtime/adapter boundary; this function never reads a path.
 */
export function resolveChangeObservationInput(input: unknown): ResolvedChangeObservationInput {
  const parsed = parseSchema(ChangeObservationInputSchema, input, "Change Observation input");
  const normalizedPathFilters = [...(parsed.path_filters ?? [])].sort(compareUtf8);
  const resolvedBudget = parseSchema(
    ChangeObservationBudgetSchema,
    { ...DEFAULT_BUDGET, ...(parsed.budget ?? {}) },
    "resolved Change Observation budget",
  );
  return {
    input: {
      repository: { ...parsed.repository },
      base_revision: parsed.base_revision,
      head_revision: parsed.head_revision,
      ...(normalizedPathFilters.length === 0 ? {} : { path_filters: normalizedPathFilters }),
      ...(parsed.budget === undefined ? {} : { budget: { ...parsed.budget } }),
    },
    resolvedBudget,
    normalizedPathFilters,
  };
}

export function toChangeObservationPortRequest(input: ResolvedChangeObservationInput): ChangeObservationPortRequest {
  return {
    input: input.input,
    resolvedBudget: input.resolvedBudget,
    normalizedPathFilters: input.normalizedPathFilters,
  };
}

/**
 * Converts bounded adapter facts into the public deterministic observation.
 * It intentionally has no execution, artifact, routing, or Decision behavior.
 */
export function normalizeChangeObservation(
  resolved: ResolvedChangeObservationInput,
  raw: unknown,
): ChangeObservation {
  const bounded = boundRawObservation(raw);
  const parsed = parseSchema(
    ChangeObservationPortObservationSchema,
    bounded.value,
    "Change Observation adapter output",
  ) as ChangeObservationPortObservation;

  if (!sameRequestedRevision(resolved.input, parsed.revision_identity)) {
    throw new Error("Change Observation adapter revision identity differs from the requested immutable revisions");
  }
  if (parsed.revision_identity.object_format === "sha1" && (parsed.revision_identity.base_oid.length !== 40 || parsed.revision_identity.head_oid.length !== 40)) {
    throw new Error("Change Observation sha1 revision identity must use 40-hex OIDs");
  }
  if (parsed.revision_identity.object_format === "sha256" && (parsed.revision_identity.base_oid.length !== 64 || parsed.revision_identity.head_oid.length !== 64)) {
    throw new Error("Change Observation sha256 revision identity must use 64-hex OIDs");
  }
  assertPortObservationSemantics(parsed);

  const changedFiles = sortBy(parsed.changed_files, (item) => [item.path, "previous_path" in item ? item.previous_path : "", item.change_kind])
    .slice(0, resolved.resolvedBudget.max_changed_files);
  const hunks = sortBy(parsed.normalized_hunks, (item) => [item.path, numericKey(item.ordinal), numericKey(item.new_start), numericKey(item.old_start)])
    .slice(0, resolved.resolvedBudget.max_hunks)
    .map((item) => ({
      ...item,
      truncated: item.truncated
        || item.added_line_count > resolved.resolvedBudget.max_hunk_lines
        || item.removed_line_count > resolved.resolvedBudget.max_hunk_lines,
    }));
  const symbols = sortBy(parsed.symbols, (item) => [
    item.language,
    item.name,
    item.symbol_kind,
    item.change_kind,
    locationKey(item.new_location),
    locationKey(item.old_location),
  ]).slice(0, resolved.resolvedBudget.max_symbols);
  const calls = sortBy(parsed.call_changes, (item) => [
    item.callee_selector.join("\u0000"),
    item.change_kind,
    item.argument_change_kind,
    locationKey(item.new_location),
    locationKey(item.old_location),
  ]).slice(0, resolved.resolvedBudget.max_call_changes);
  const events = sortBy(parsed.event_changes, (item) => [
    item.selector.join("\u0000"),
    item.event_kind,
    locationKey(item.location),
  ]).slice(0, resolved.resolvedBudget.max_event_changes);

  const droppedFactCount = bounded.droppedFactCount
    + (parsed.changed_files.length - changedFiles.length)
    + (parsed.normalized_hunks.length - hunks.length)
    + (parsed.symbols.length - symbols.length)
    + (parsed.call_changes.length - calls.length)
    + (parsed.event_changes.length - events.length);
  const hunkLineTruncationCount = hunks.filter((item) => item.truncated).length;
  const gaps = normalizeGaps([
    ...parsed.analysis_gaps,
    ...(droppedFactCount === 0 ? [] : [{ code: "DIFF_TRUNCATED" as const, count: droppedFactCount }]),
    ...(hunkLineTruncationCount === 0 ? [] : [{ code: "HUNK_LINE_TRUNCATED" as const, count: hunkLineTruncationCount }]),
  ]);
  const completeness = parsed.completeness === "blocked"
    ? "blocked"
    : gaps.length === 0 ? "complete" : "partial";
  const parserVersions = sortBy(parsed.provenance.parser_versions, (item) => [item.language, item.version]);
  const requestFingerprint = sha256(canonicalJson({
    service_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    input: {
      repository: resolved.input.repository,
      base_revision: resolved.input.base_revision,
      head_revision: resolved.input.head_revision,
      path_filters: resolved.normalizedPathFilters,
      budget: resolved.resolvedBudget,
    },
    revision_identity: parsed.revision_identity,
  }));
  const withoutFingerprints = {
    schema_version: CHANGE_OBSERVATION_SERVICE_VERSION,
    revision_identity: parsed.revision_identity,
    scope: {
      path_filters: resolved.normalizedPathFilters,
      submodules: "not_included" as const,
      dirty_worktree: "not_inspected" as const,
    },
    resolved_budget: resolved.resolvedBudget,
    completeness,
    changed_files: changedFiles,
    normalized_hunks: hunks,
    symbols,
    call_changes: calls,
    event_changes: events,
    analysis_gaps: gaps,
    provenance: { ...parsed.provenance, parser_versions: parserVersions },
  };
  const observationFingerprint = sha256(canonicalJson(withoutFingerprints));
  return parseSchema(ChangeObservationSchema, {
    ...withoutFingerprints,
    request_fingerprint: requestFingerprint,
    observation_fingerprint: observationFingerprint,
  }, "normalized Change Observation");
}

function boundRawObservation(raw: unknown): { readonly value: unknown; readonly droppedFactCount: number } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return { value: raw, droppedFactCount: 0 };
  const record = raw as Record<string, unknown>;
  const files = boundedArray(record.changed_files, CHANGE_OBSERVATION_LIMITS.maxChangedFiles);
  const hunks = boundedArray(record.normalized_hunks, CHANGE_OBSERVATION_LIMITS.maxHunks);
  const symbols = boundedArray(record.symbols, CHANGE_OBSERVATION_LIMITS.maxSymbols);
  const calls = boundedArray(record.call_changes, CHANGE_OBSERVATION_LIMITS.maxCallChanges);
  const events = boundedArray(record.event_changes, CHANGE_OBSERVATION_LIMITS.maxEventChanges);
  const gaps = boundedArray(record.analysis_gaps, CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount);
  const provenance = record.provenance !== null && typeof record.provenance === "object" && !Array.isArray(record.provenance)
    ? { ...(record.provenance as Record<string, unknown>), parser_versions: boundedArray((record.provenance as Record<string, unknown>).parser_versions, CHANGE_OBSERVATION_LIMITS.maxParserVersions).values }
    : record.provenance;
  return {
    value: {
      ...record,
      changed_files: files.values,
      normalized_hunks: hunks.values,
      symbols: symbols.values,
      call_changes: calls.values,
      event_changes: events.values,
      analysis_gaps: gaps.values,
      provenance,
    },
    droppedFactCount: files.dropped + hunks.dropped + symbols.dropped + calls.dropped + events.dropped + gaps.dropped,
  };
}

function boundedArray(value: unknown, maximum: number): { readonly values: unknown; readonly dropped: number } {
  if (!Array.isArray(value)) return { values: value, dropped: 0 };
  return { values: value.slice(0, maximum), dropped: Math.max(0, value.length - maximum) };
}

function normalizeGaps(gaps: readonly ChangeObservationGap[]): ChangeObservationGap[] {
  const deduplicated = new Map<string, ChangeObservationGap>();
  for (const gap of gaps) {
    const key = canonicalJson(gap);
    if (!deduplicated.has(key)) deduplicated.set(key, gap);
  }
  const sorted = sortBy([...deduplicated.values()], (gap) => [
    gap.code,
    gap.path ?? "",
    numericKey(gap.count ?? 0),
    gap.parser_or_language ?? "",
  ]);
  if (sorted.length <= CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount) return sorted;
  const dropped = sorted.length - (CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount - 1);
  return [
    ...sorted.slice(0, CHANGE_OBSERVATION_LIMITS.maxDiagnosticCount - 1),
    { code: "DIFF_TRUNCATED", count: dropped },
  ];
}

function assertPortObservationSemantics(observation: ChangeObservationPortObservation): void {
  const expectedOidLength = observation.revision_identity.object_format === "sha1" ? 40 : 64;
  for (const oid of [
    observation.revision_identity.base_oid,
    observation.revision_identity.head_oid,
    observation.revision_identity.base_tree_oid,
    observation.revision_identity.head_tree_oid,
  ]) {
    if (oid.length !== expectedOidLength) {
      throw new Error(`Change Observation ${observation.revision_identity.object_format} revision identity has an invalid OID length`);
    }
  }
  for (const file of observation.changed_files) {
    assertRepositoryRelativePath(file.path);
    if ("previous_path" in file) assertRepositoryRelativePath(file.previous_path);
  }
  for (const hunk of observation.normalized_hunks) {
    assertRepositoryRelativePath(hunk.path);
    assertHunkRange(hunk.old_start, hunk.old_line_count, "old");
    assertHunkRange(hunk.new_start, hunk.new_line_count, "new");
  }
  for (const symbol of observation.symbols) {
    if (symbol.old_location === undefined && symbol.new_location === undefined) {
      throw new Error("Change Observation symbol requires an old or new location");
    }
    assertOptionalLocationPath(symbol.old_location?.path);
    assertOptionalLocationPath(symbol.new_location?.path);
  }
  for (const call of observation.call_changes) {
    if (call.old_location === undefined && call.new_location === undefined) {
      throw new Error("Change Observation call requires an old or new location");
    }
    assertOptionalLocationPath(call.old_location?.path);
    assertOptionalLocationPath(call.new_location?.path);
  }
  for (const event of observation.event_changes) assertRepositoryRelativePath(event.location.path);
  for (const gap of observation.analysis_gaps) assertOptionalLocationPath(gap.path);
}

function assertHunkRange(start: number, count: number, label: string): void {
  if ((count === 0 && start !== 0) || (count > 0 && start < 1)) {
    throw new Error(`Change Observation ${label} hunk range has inconsistent start/count`);
  }
}

function assertOptionalLocationPath(path: string | undefined): void {
  if (path !== undefined) assertRepositoryRelativePath(path);
}

function assertRepositoryRelativePath(path: string): void {
  if (
    path.length === 0
    || path.startsWith("/")
    || path.includes("\\")
    || path.includes("\u0000")
    || path.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    throw new Error("Change Observation path must be normalized and repository-relative");
  }
}

function sortBy<T>(values: readonly T[], keys: (value: T) => readonly string[]): T[] {
  return [...values].sort((left, right) => compareTuple(keys(left), keys(right)));
}

function compareTuple(left: readonly string[], right: readonly string[]): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const compared = compareUtf8(left[index] ?? "", right[index] ?? "");
    if (compared !== 0) return compared;
  }
  return 0;
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function numericKey(value: number): string {
  return value.toString().padStart(10, "0");
}

function locationKey(location: { readonly path: string; readonly start_line: number; readonly end_line?: number } | undefined): string {
  if (location === undefined) return "";
  return `${location.path}\u0000${numericKey(location.start_line)}\u0000${numericKey(location.end_line ?? location.start_line)}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort(compareUtf8).map((key) => [key, canonicalize(record[key])]));
  }
  return value;
}
