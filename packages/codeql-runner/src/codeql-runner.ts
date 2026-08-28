import { DomainError, stableDigest, type CodeqlEnvironment, type CodeqlDiagnostic, type DatabaseManifest } from "@autovul/contracts";
import type { FileSystemPort, ProcessPort, ProcessResult, CodeqlOperationOptions, CodeqlPort } from "@autovul/core";
import { isAbsolute, relative } from "node:path";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { sanitizeOutput } from "./output.js";

const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024;

export interface CodeqlRunnerOptions {
  readonly executable?: string;
  readonly cwd?: string;
  readonly workspaceRoot?: string;
  readonly process?: ProcessPort;
  readonly filesystem?: FileSystemPort;
  readonly maxOutputBytes?: number;
}

export class CodeqlRunner implements CodeqlPort {
  private readonly executable: string;
  private readonly cwd: string | undefined;
  private readonly workspaceRoot: string | undefined;
  private trustedRoots: readonly string[] | undefined;
  private readonly process: ProcessPort;
  private readonly filesystem: FileSystemPort;
  private readonly maxOutputBytes: number;

  constructor(options: CodeqlRunnerOptions = {}) {
    this.executable = options.executable ?? process.env.CODEQL_PATH ?? "codeql";
    this.cwd = options.cwd;
    this.workspaceRoot = options.workspaceRoot;
    this.trustedRoots = options.workspaceRoot === undefined ? undefined : [options.workspaceRoot];
    this.process = options.process ?? new NodeProcessPort();
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
    this.maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  }

  async doctor(options: CodeqlOperationOptions): Promise<CodeqlEnvironment> {
    const versionResult = await this.execute(["version"], options);
    assertSuccessful(versionResult, "version");
    const languagesResult = await this.execute(["resolve", "languages"], options);
    assertSuccessful(languagesResult, "resolve languages");
    const languages = parseLanguages(languagesResult.stdout);
    if (languages.length === 0) {
      throw new DomainError("CODEQL_EXTRACTOR_MISSING", "environment", "CodeQL reported no extractors", false, {
        command: "codeql resolve languages",
      });
    }
    return {
      schemaVersion: "v2.contracts/1",
      available: true,
      cliPath: this.executable,
      version: firstLine(versionResult.stdout || versionResult.stderr),
      languages,
      checkedAt: new Date().toISOString(),
      diagnostics: diagnosticsFor(languagesResult).map((diagnostic) => diagnostic.message),
    };
  }

  async inspectDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    return this.inspect(path, options);
  }

  async validateDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    return this.inspect(path, options);
  }

  setTrustedRoots(roots: readonly string[]): void {
    // An explicit CLI/test root is an operator decision and cannot be widened
    // by a workflow payload. The Pi host leaves it unset and binds the paths
    // supplied in the current workflow instead.
    if (this.workspaceRoot !== undefined) return;
    this.trustedRoots = [...roots];
  }

  private async inspect(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    const stat = await this.filesystem.stat(path);
    if (!stat.exists) {
      throw new DomainError("DATABASE_NOT_FOUND", "database", `Database path does not exist: ${path}`, false, { path });
    }
    if (!stat.isDirectory) {
      throw new DomainError("DATABASE_INVALID", "database", `Database path is not a directory: ${path}`, false, { path });
    }
    let canonicalPath: string;
    try {
      canonicalPath = await this.filesystem.canonicalize(path);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Database path cannot be canonicalized";
      throw new DomainError("DATABASE_INVALID", "database", message, false, { path });
    }
    if (this.trustedRoots !== undefined) {
      const canonicalRoots = (await Promise.all(this.trustedRoots.map(async (root) =>
        this.filesystem.canonicalize(root).catch(() => undefined),
      ))).filter((root): root is string => root !== undefined);
      const withinTrustedRoot = canonicalRoots.some((root) => {
        const relativePath = relative(root, canonicalPath);
        return relativePath === ""
          || (!relativePath.startsWith("..") && !isAbsolute(relativePath));
      });
      if (!withinTrustedRoot) {
        throw new DomainError(
          "DATABASE_PATH_OUTSIDE_WORKSPACE",
          "database",
          "Database path is outside the trusted workspace",
          false,
          { path, workspaceRoot: this.workspaceRoot, trustedRoots: this.trustedRoots },
        );
      }
    }
    const result = await this.execute(["resolve", "database", "--format=json", "--", canonicalPath], options);
    assertSuccessful(result, "resolve database", "DATABASE_INVALID");
    const metadata = parseDatabaseMetadata(result.stdout);
    if (metadata.language === undefined) {
      throw new DomainError("DATABASE_INVALID", "database", "CodeQL did not report formal database metadata", false, {
        path,
        canonicalPath,
      });
    }
    const diagnostics = diagnosticsFor(result);
    return {
      schemaVersion: "v2.contracts/1",
      path,
      canonicalPath,
      exists: true,
      isDirectory: true,
      valid: true,
      ...(metadata.language === undefined ? {} : { language: metadata.language }),
      ...(metadata.codeqlVersion === undefined ? {} : { codeqlVersion: metadata.codeqlVersion }),
      fingerprint: stableDigest(JSON.stringify({
        canonicalPath,
        language: metadata.language,
        codeqlVersion: metadata.codeqlVersion,
        sourceLocationPrefix: metadata.sourceLocationPrefix,
        modifiedAtMs: stat.modifiedAtMs,
      })),
      checkedAt: new Date().toISOString(),
      diagnostics,
    };
  }

  private async execute(args: readonly string[], options: CodeqlOperationOptions): Promise<ProcessResult> {
    try {
      const command = this.cwd === undefined
        ? { executable: this.executable, args, shell: false as const }
        : { executable: this.executable, args, cwd: this.cwd, shell: false as const };
      const processOptions = options.signal === undefined
        ? { timeoutMs: options.timeoutMs, maxOutputBytes: this.maxOutputBytes }
        : { signal: options.signal, timeoutMs: options.timeoutMs, maxOutputBytes: this.maxOutputBytes };
      return await this.process.execute(
        command,
        processOptions,
      );
    } catch (error: unknown) {
      const details = error instanceof Error ? error.message : "CodeQL CLI could not be started";
      if (details.includes("ENOENT") || details.includes("not found")) {
        throw new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false, {
          executable: this.executable,
        });
      }
      if (error instanceof DomainError) {
        throw error;
      }
      throw new DomainError("PROCESS_CRASHED", "process", details, true, { executable: this.executable });
    }
  }
}

function assertSuccessful(result: ProcessResult, operation: string, nonZeroCode: "DATABASE_INVALID" | "PROCESS_EXITED" = "PROCESS_EXITED"): void {
  if (result.timedOut) {
    throw new DomainError("PROCESS_TIMEOUT", "process", `CodeQL ${operation} timed out`, true, {
      operation,
      stderr: sanitizeOutput(result.stderr),
    });
  }
  if (result.cancelled) {
    throw new DomainError("PROCESS_CANCELLED", "process", `CodeQL ${operation} was cancelled`, false, { operation });
  }
  if (result.signal !== null && result.exitCode === null) {
    throw new DomainError("PROCESS_CRASHED", "process", `CodeQL ${operation} crashed`, true, {
      operation,
      signal: result.signal,
    });
  }
  if (result.exitCode !== 0) {
    throw new DomainError(nonZeroCode, nonZeroCode === "DATABASE_INVALID" ? "database" : "process", `CodeQL ${operation} failed`, false, {
      operation,
      exitCode: result.exitCode,
      stderr: sanitizeOutput(result.stderr),
      stdout: sanitizeOutput(result.stdout),
    });
  }
}

function parseLanguages(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("{") && !line.startsWith("["))
    .map((line) => line.replace(/\s+\([^)]*\)\s*$/, "").trim())
    .filter((line) => line.length > 0);
}

function firstLine(output: string): string {
  return sanitizeOutput(output).split(/\r?\n/)[0]?.trim() ?? "unknown";
}

function diagnosticsFor(result: ProcessResult): CodeqlDiagnostic[] {
  const diagnostics: CodeqlDiagnostic[] = [];
  if (result.stderr.length > 0) {
    diagnostics.push({
      schemaVersion: "v2.contracts/1",
      code: "CODEQL_STDERR",
      severity: "warning",
      message: sanitizeOutput(result.stderr),
      stream: "stderr",
      truncated: result.stderrTruncated,
    });
  }
  if (result.stdoutTruncated || result.stderrTruncated) {
    diagnostics.push({
      schemaVersion: "v2.contracts/1",
      code: "PROCESS_OUTPUT_LIMIT",
      severity: "warning",
      message: "CodeQL process output was truncated",
      truncated: true,
    });
  }
  return diagnostics;
}

function parseDatabaseMetadata(output: string): { language?: string; codeqlVersion?: string; sourceLocationPrefix?: string } {
  if (output.trim().length === 0) {
    return {};
  }
  let value: unknown;
  try {
    value = JSON.parse(output) as unknown;
  } catch {
    return {};
  }
  if (typeof value === "string" && value.length > 0) {
    return { language: value };
  }
  if (Array.isArray(value)) {
    const languages = value.filter((item): item is string => typeof item === "string" && item.length > 0);
    return languages[0] === undefined ? {} : { language: languages[0] };
  }
  if (typeof value !== "object" || value === null) {
    return {};
  }
  const record = value as Record<string, unknown>;
  const language = readString(record, "language")
    ?? readString(record, "primaryLanguage")
    ?? readStrings(record, "languages")?.[0]
    ?? readNestedLanguage(record, "language")
    ?? readNestedLanguage(record, "primaryLanguage");
  const codeqlVersion = readString(record, "codeqlVersion") ?? readString(record, "version");
  const sourceLocationPrefix = readString(record, "sourceLocationPrefix") ?? readString(record, "source_location_prefix");
  return {
    ...(language === undefined ? {} : { language }),
    ...(codeqlVersion === undefined ? {} : { codeqlVersion }),
    ...(sourceLocationPrefix === undefined ? {} : { sourceLocationPrefix }),
  };
}

function readNestedLanguage(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const nested = value as Record<string, unknown>;
  return readString(nested, "name") ?? readString(nested, "language");
}

function readStrings(record: Record<string, unknown>, key: string): string[] | undefined {
  const value = record[key];
  if (!Array.isArray(value)) {
    return undefined;
  }
  const strings = value.filter((item): item is string => typeof item === "string" && item.length > 0);
  return strings.length > 0 ? strings : undefined;
}

function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
