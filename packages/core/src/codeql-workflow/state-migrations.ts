import {
  parseSchema,
  VulnerabilitySpecSchema,
  stableDigest,
  type VulnerabilitySpec,
} from "@autovul/contracts";

/** Upgrade only the legacy field that was introduced before case identity was persisted. */
export function upgradeLegacyState(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return value;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.case_fingerprint === "string" || record.spec === undefined) {
    return value;
  }
  const spec = parseSchema(
    VulnerabilitySpecSchema,
    record.spec,
    "legacy vulnerability spec",
  );
  return {
    ...record,
    case_fingerprint: caseFingerprintFor(spec),
  };
}

export function caseFingerprintFor(spec: VulnerabilitySpec): string {
  return stableDigest(
    JSON.stringify({
      language: spec.language,
      cwe: spec.cwe,
      vulnerability_description: spec.vulnerability_description,
      patch_description: spec.patch_description,
      project_root: spec.project_root,
      vulnerable_database: databaseIdentity(spec.vulnerable_database),
      fixed_database:
        spec.fixed_database === undefined
          ? undefined
          : databaseIdentity(spec.fixed_database),
      reference_query_excluded: spec.reference_query_excluded,
    }),
  );
}

function databaseIdentity(database: VulnerabilitySpec["vulnerable_database"]): Record<string, string | undefined> {
  return {
    path: database.canonical_path ?? database.path,
    fingerprint: database.fingerprint,
    language: database.language,
    codeql_version: database.codeql_version,
  };
}
