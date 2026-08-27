import {
  DomainError,
  type DatabaseManifest,
  type QueryCandidate,
  type VulnerabilitySpec,
} from "@pure-auto-codeql/contracts";

import { languagePackFor } from "../language-packs.js";

export function assertStrictSemanticLocations(spec: VulnerabilitySpec): void {
  const strict = spec.validation.strict_semantics === true || spec.input_provenance === "user_provided";
  if (!strict) return;
  const missing: string[] = [];
  if (spec.validation.source?.file === undefined || spec.validation.source.line === undefined) {
    missing.push("source.file/source.line");
  }
  if (spec.validation.sink?.file === undefined || spec.validation.sink.line === undefined) {
    missing.push("sink.file/sink.line");
  }
  if (spec.validation.strict_semantics === true && spec.validation.source?.kind === undefined) {
    missing.push("source.kind");
  }
  if (spec.validation.strict_semantics === true && spec.validation.sink?.kind === undefined) {
    missing.push("sink.kind");
  }
  if (missing.length > 0) {
    throw new DomainError(
      "SPEC_SEMANTIC_LOCATION_REQUIRED",
      "input",
      "Strict differential verification requires exact Source/Sink file and line locations",
      false,
      { specId: spec.spec_id, missing },
    );
  }
}

export function assertSupportedSemanticKinds(spec: VulnerabilitySpec): void {
  const pack = languagePackFor(spec.language);
  const supported = new Set(pack.capabilities.flatMap((capability) => capability.matcher_kinds));
  const unsupported = (["source", "sink"] as const)
    .map((role) => {
      const kind = spec.validation[role]?.kind;
      return kind !== undefined && !supported.has(kind) ? { role, kind } : undefined;
    })
    .filter((item) => item !== undefined);
  if (unsupported.length > 0) {
    throw new DomainError(
      "CAPABILITY_MISMATCH",
      "input",
      "Workflow Source/Sink endpoint kinds are not supported by the selected Language Pack",
      false,
      {
        language: spec.language,
        unsupported,
        supported: [...supported],
        hint: "Choose a supported endpoint kind before starting the workflow; JavaScript/TypeScript and Java/Kotlin currently use call for a whole call, while Python and C/C++ also support call_argument.",
      },
    );
  }
}

export function assertCandidateSemanticKinds(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  if (candidate.intent === undefined) return;
  const mismatches: Record<string, unknown> = {};
  if (spec.validation.source?.kind !== undefined && candidate.intent.source.kind !== spec.validation.source.kind) {
    mismatches.source = { expected: spec.validation.source.kind, actual: candidate.intent.source.kind };
  }
  if (spec.validation.sink?.kind !== undefined && candidate.intent.sink.kind !== spec.validation.sink.kind) {
    mismatches.sink = { expected: spec.validation.sink.kind, actual: candidate.intent.sink.kind };
  }
  if (Object.keys(mismatches).length > 0) {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      "Candidate Source/Sink matcher kinds must match the frozen workflow endpoint kinds",
      true,
      {
        mismatches,
        hint: "Keep the candidate endpoint kind aligned with validation.kind; use a different line only when it is the endpoint of that same matcher kind.",
      },
    );
  }
}

export function assertCandidateSemanticLocations(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  if (candidate.intent === undefined) return;
  const mismatches: Record<string, unknown> = {};
  for (const role of ["source", "sink"] as const) {
    const expected = spec.validation[role];
    const actual = candidate.intent[role];
    const roleMismatches: Record<string, unknown> = {};
    if (actual.file !== undefined && expected?.file !== undefined && !semanticFileMatches(expected.file, actual.file)) {
      roleMismatches.file = { expected: expected.file, actual: actual.file };
    }
    if (actual.line !== undefined && expected?.line !== undefined && actual.line !== expected.line) {
      roleMismatches.line = { expected: expected.line, actual: actual.line };
    }
    if (Object.keys(roleMismatches).length > 0) mismatches[role] = roleMismatches;
  }
  if (Object.keys(mismatches).length > 0) {
    throw new DomainError(
      "INVALID_INPUT",
      "input",
      "Candidate Source/Sink matcher locations must match the frozen workflow endpoint locations",
      true,
      {
        mismatches,
        hint: "Do not replace a frozen validation endpoint with a nearby or intermediate probe location; use intermediate nodes only as additional_flow_steps. Omit file/line only when the endpoint matcher is intentionally broad and the CLI semantic checks will constrain the result.",
      },
    );
  }
}

export function assertDatabaseLanguage(spec: VulnerabilitySpec, path: string, manifest: DatabaseManifest): void {
  const pack = languagePackFor(spec.language);
  if (manifest.language !== undefined && !pack.aliases.includes(manifest.language) && pack.language !== manifest.language) {
    throw new DomainError(
      "DATABASE_INVALID",
      "database",
      "The database language does not match the selected Language Pack",
      false,
      { path, expected: spec.language, language: manifest.language },
    );
  }
}

export function databaseRefWithManifest(
  reference: VulnerabilitySpec["vulnerable_database"],
  manifest: DatabaseManifest,
): VulnerabilitySpec["vulnerable_database"] {
  return {
    ...reference,
    ...(manifest.canonicalPath === undefined ? {} : { canonical_path: manifest.canonicalPath }),
    ...(manifest.fingerprint === undefined ? {} : { fingerprint: manifest.fingerprint }),
    ...(manifest.codeqlVersion === undefined ? {} : { codeql_version: manifest.codeqlVersion }),
  };
}

export function locationMatches(
  expectedFile: string | undefined,
  expectedLine: number | undefined,
  location: { file: string; start_line: number },
): boolean {
  if (expectedFile === undefined || expectedLine === undefined) return false;
  const expected = normalizePath(expectedFile);
  const actual = normalizePath(location.file);
  return (actual === expected || (expected.includes("/") && actual.endsWith(`/${expected}`))) && location.start_line === expectedLine;
}

function semanticFileMatches(expected: string, actual: string): boolean {
  const expectedPath = normalizePath(expected);
  const actualPath = normalizePath(actual);
  return actualPath === expectedPath || (expectedPath.includes("/") && actualPath.endsWith(`/${expectedPath}`));
}

function normalizePath(value: string): string {
  return value.replace(/^file:\/\//, "").replaceAll("\\", "/").replace(/^\.\//, "");
}
