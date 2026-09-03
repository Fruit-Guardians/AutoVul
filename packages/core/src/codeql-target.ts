import { DomainError, type TargetRef } from "@autovul/contracts";

import type { CodeqlOperationOptions, CodeqlPort } from "./ports.js";

/** Validate one immutable CodeQL target and enforce its optional expected fingerprint. */
export async function validateTargetFingerprint(
  codeql: CodeqlPort,
  target: TargetRef,
  options: CodeqlOperationOptions,
): Promise<string> {
  const manifest = await codeql.validateDatabase(target.path, options);
  if (manifest.portableFingerprint === undefined) {
    throw new DomainError(
      "DATABASE_FINGERPRINT_UNAVAILABLE",
      "database",
      `Database fingerprint is unavailable for ${target.path}`,
      false,
      { path: target.path },
    );
  }
  if (target.expected_fingerprint !== undefined && target.expected_fingerprint !== manifest.portableFingerprint) {
    throw new DomainError(
      "DATABASE_FINGERPRINT_MISMATCH",
      "database",
      `Database fingerprint differs for ${target.path}`,
      false,
      {
        path: target.path,
        expected: target.expected_fingerprint,
        observed: manifest.portableFingerprint,
      },
    );
  }
  return manifest.portableFingerprint;
}
