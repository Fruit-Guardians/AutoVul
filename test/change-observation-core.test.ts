import { describe, expect, it } from "vitest";

import {
  normalizeChangeObservation,
  resolveChangeObservationInput,
  sameRequestedRevision,
  toChangeObservationPortRequest,
} from "@autovul/core";

const baseOid = "75b4c059b8405dfbd50884b773346a9946fabd20";
const headOid = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const treeOid = "0123456789abcdef0123456789abcdef01234567";
const sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function input(overrides: Record<string, unknown> = {}) {
  return {
    repository: { kind: "trusted_local_git_repository", path: "/trusted/repository" },
    base_revision: baseOid,
    head_revision: headOid,
    path_filters: ["src/z", "src/a"],
    budget: {
      max_changed_files: 4,
      max_hunks: 4,
      max_hunk_lines: 3,
      max_symbols: 4,
      max_call_changes: 4,
      max_event_changes: 4,
    },
    ...overrides,
  };
}

function rawObservation(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "autovul.change-observation/1",
    revision_identity: {
      object_format: "sha1",
      base_oid: baseOid,
      head_oid: headOid,
      base_tree_oid: treeOid,
      head_tree_oid: treeOid,
    },
    completeness: "complete",
    changed_files: [
      { path: "src/z.ts", change_kind: "modified", content_kind: "text" },
      { path: "src/a.ts", change_kind: "renamed", content_kind: "text", previous_path: "src/old.ts" },
    ],
    normalized_hunks: [
      {
        path: "src/z.ts",
        ordinal: 1,
        old_start: 3,
        old_line_count: 1,
        new_start: 3,
        new_line_count: 1,
        removed_line_count: 1,
        added_line_count: 1,
        normalized_removed_sha256: sha256,
        normalized_added_sha256: sha256,
        truncated: false,
      },
      {
        path: "src/a.ts",
        ordinal: 0,
        old_start: 1,
        old_line_count: 1,
        new_start: 1,
        new_line_count: 1,
        removed_line_count: 4,
        added_line_count: 1,
        normalized_removed_sha256: sha256,
        normalized_added_sha256: sha256,
        truncated: false,
      },
    ],
    symbols: [
      { change_kind: "added", symbol_kind: "function", language: "typescript", name: "zeta", new_location: { path: "src/z.ts", start_line: 1 } },
      { change_kind: "added", symbol_kind: "function", language: "typescript", name: "alpha", new_location: { path: "src/a.ts", start_line: 1 } },
    ],
    call_changes: [
      { change_kind: "added", callee_selector: ["zeta"], argument_change_kind: "none", new_location: { path: "src/z.ts", start_line: 2 } },
      { change_kind: "added", callee_selector: ["alpha"], argument_change_kind: "none", new_location: { path: "src/a.ts", start_line: 2 } },
    ],
    event_changes: [
      { event_kind: "direct_call_added", selector: ["zeta"], location: { path: "src/z.ts", start_line: 3 } },
      { event_kind: "direct_call_added", selector: ["alpha"], location: { path: "src/a.ts", start_line: 3 } },
    ],
    analysis_gaps: [],
    provenance: {
      service_version: "autovul.change-observation/1",
      source: "local_git_object_database",
      git_version: "git version 2.47.0",
      command_profile_version: "autovul.git-change-observation/1",
      parser_versions: [
        { language: "typescript", version: "2.0.0" },
        { language: "javascript", version: "1.0.0" },
      ],
    },
    ...overrides,
  };
}

describe("Change Observation Core normalization", () => {
  it("resolves defaults and canonicalizes only protocol input", () => {
    const resolved = resolveChangeObservationInput(input());
    expect(resolved.normalizedPathFilters).toEqual(["src/a", "src/z"]);
    expect(resolved.input.path_filters).toEqual(["src/a", "src/z"]);
    expect(resolved.resolvedBudget).toMatchObject({
      timeout_ms: 600_000,
      max_diff_bytes: 4_194_304,
      max_changed_files: 4,
      max_hunks: 4,
      max_hunk_lines: 3,
    });
    expect(toChangeObservationPortRequest(resolved)).toEqual({
      input: resolved.input,
      resolvedBudget: resolved.resolvedBudget,
      normalizedPathFilters: ["src/a", "src/z"],
    });
  });

  it("sorts structural facts and fingerprints independent of adapter iteration order", () => {
    const resolved = resolveChangeObservationInput(input());
    const first = normalizeChangeObservation(resolved, rawObservation());
    const second = normalizeChangeObservation(resolved, rawObservation({
      changed_files: [...rawObservation().changed_files].reverse(),
      normalized_hunks: [...rawObservation().normalized_hunks].reverse(),
      symbols: [...rawObservation().symbols].reverse(),
      call_changes: [...rawObservation().call_changes].reverse(),
      event_changes: [...rawObservation().event_changes].reverse(),
      provenance: { ...rawObservation().provenance, parser_versions: [...rawObservation().provenance.parser_versions].reverse() },
    }));
    expect(first.changed_files.map((item) => item.path)).toEqual(["src/a.ts", "src/z.ts"]);
    expect(first.normalized_hunks.map((item) => item.path)).toEqual(["src/a.ts", "src/z.ts"]);
    expect(first.symbols.map((item) => item.name)).toEqual(["alpha", "zeta"]);
    expect(first.call_changes.map((item) => item.callee_selector.join("."))).toEqual(["alpha", "zeta"]);
    expect(first.event_changes.map((item) => item.selector.join("."))).toEqual(["alpha", "zeta"]);
    expect(first.provenance.parser_versions.map((item) => item.language)).toEqual(["javascript", "typescript"]);
    expect(first.request_fingerprint).toBe(second.request_fingerprint);
    expect(first.observation_fingerprint).toBe(second.observation_fingerprint);
  });

  it("adds explicit partial gaps when Core applies caller or hard protocol bounds", () => {
    const resolved = resolveChangeObservationInput(input({ budget: {
      timeout_ms: 1,
      max_changed_files: 1,
      max_diff_bytes: 1_024,
      max_hunks: 1,
      max_hunk_lines: 2,
      max_symbols: 1,
      max_call_changes: 1,
      max_event_changes: 1,
    } }));
    const manyFiles = Array.from({ length: 513 }, (_, index) => ({
      path: `src/${index.toString().padStart(3, "0")}.ts`,
      change_kind: "modified",
      content_kind: "text",
    }));
    const normalized = normalizeChangeObservation(resolved, rawObservation({ changed_files: manyFiles }));
    expect(normalized.completeness).toBe("partial");
    expect(normalized.changed_files).toHaveLength(1);
    expect(normalized.normalized_hunks).toHaveLength(1);
    expect(normalized.normalized_hunks[0]?.truncated).toBe(true);
    expect(normalized.symbols).toHaveLength(1);
    expect(normalized.call_changes).toHaveLength(1);
    expect(normalized.event_changes).toHaveLength(1);
    expect(normalized.analysis_gaps).toEqual(expect.arrayContaining([
      { code: "DIFF_TRUNCATED", count: 516 },
      { code: "HUNK_LINE_TRUNCATED", count: 1 },
    ]));
  });

  it("rejects adapter output that cannot honestly bind to the requested revisions", () => {
    const resolved = resolveChangeObservationInput(input());
    expect(sameRequestedRevision(resolved.input, rawObservation().revision_identity)).toBe(true);
    expect(() => normalizeChangeObservation(resolved, rawObservation({
      revision_identity: { ...rawObservation().revision_identity, head_oid: baseOid },
    }))).toThrow("revision identity differs");
    expect(() => normalizeChangeObservation(resolved, { ...rawObservation(), changed_files: undefined })).toThrow("Invalid Change Observation adapter output");
    expect(() => normalizeChangeObservation(resolved, rawObservation({ capability: "typestate" }))).toThrow("Invalid Change Observation adapter output");
    expect(() => normalizeChangeObservation(resolved, rawObservation({
      normalized_hunks: [{ ...rawObservation().normalized_hunks[0], old_start: 1, old_line_count: 0 }],
    }))).toThrow("old hunk range has inconsistent start/count");
    expect(() => normalizeChangeObservation(resolved, rawObservation({
      changed_files: [{ path: "../outside.ts", change_kind: "modified", content_kind: "text" }],
    }))).toThrow("path must be normalized and repository-relative");
  });
});
