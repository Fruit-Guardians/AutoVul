import { DomainError } from "@autovul/contracts";
import type { ProcessResult } from "@autovul/core";

import { sanitizeOutput } from "./output.js";

export function processSucceeded(result: ProcessResult): boolean {
  return result.exitCode === 0
    && result.signal === null
    && !result.cancelled
    && !result.timedOut;
}

export function firstSanitizedLine(value: string): string | undefined {
  const line = sanitizeOutput(value).split(/\r?\n/)[0]?.trim();
  return line === undefined || line.length === 0 ? undefined : line;
}

export function codeqlProcessFailure(
  result: ProcessResult,
  stage: string,
  owner: "MissingCheck" | "Typestate",
): DomainError {
  if (result.cancelled) return new DomainError("PROCESS_CANCELLED", "process", `${owner} CodeQL ${stage} was cancelled`, false);
  if (result.timedOut) return new DomainError("PROCESS_TIMEOUT", "process", `${owner} CodeQL ${stage} timed out`, true);
  if (/not found|enoent/i.test(`${result.stderr}\n${result.stdout}`)) {
    return new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false);
  }
  return new DomainError("PROCESS_CRASHED", "process", `${owner} CodeQL ${stage} failed`, true);
}
