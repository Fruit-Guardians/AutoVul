import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

function sha256Hex(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

import {
  CONTRACTS_VERSION,
  DYNAMIC_REPRODUCTION_CONTRACT_VERSION,
  DYNAMIC_REPRODUCTION_LIMITS,
  DomainError,
  type DynamicReproductionExecutionObservation,
  type DynamicReproductionExecutionRequest,
  type DynamicReproductionWitnessArtifact,
} from "@autovul/contracts";
import {
  FORBIDDEN_ENV_VARS,
  SAFE_BASE_ENV_VARS,
  SAFE_SYSTEM_EXECUTABLES,
  validateReproductionEnvironment,
  type ArtifactStorePort,
  type DynamicReproductionPort,
  type DynamicReproductionPortOptions,
} from "@autovul/core";

import { limitOutput, sanitizeOutput } from "./output.js";
import { terminateProcessTree } from "./lsp/process-lifecycle.js";

interface CapturedStream {
  readonly chunks: Buffer[];
  size: number;
  truncated: boolean;
}

export class ControlledDynamicReproductionAdapter implements DynamicReproductionPort {
  constructor(private readonly artifacts: ArtifactStorePort) {}

  async execute(
    request: DynamicReproductionExecutionRequest,
    options: DynamicReproductionPortOptions,
  ): Promise<DynamicReproductionExecutionObservation> {
    if (options.signal?.aborted) {
      return this.buildCancelledObservation(request);
    }

    const cwd = await this.resolveAndAssertTrustedDirectory(
      request.command.cwd,
      options.trustedRoots,
    );

    const executablePath = await this.resolveAndAssertExecutable(
      request.command.executable,
      cwd,
      options.trustedRoots,
    );

    this.assertValidArguments(request.command.args);
    validateReproductionEnvironment(request.command.env);

    const { env, environmentDigest } = this.buildSanitizedEnvironment(request.command.env);

    const startTime = Date.now();
    let timedOut = false;
    let cancelled = false;
    let settled = false;
    let timeoutTimer: NodeJS.Timeout | undefined;
    let killTimer: NodeJS.Timeout | undefined;

    const child = spawn(executablePath, [...request.command.args], {
      cwd,
      env,
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });

    const maxOutputBytes = request.budget.max_output_bytes;
    const stdoutStream = this.captureStream(child.stdout, maxOutputBytes);
    const stderrStream = this.captureStream(child.stderr, maxOutputBytes);

    const terminate = (reason: "timeout" | "cancel"): void => {
      if (settled) return;
      if (reason === "timeout") timedOut = true;
      if (reason === "cancel") cancelled = true;
      terminateProcessTree(child, "SIGTERM");
      killTimer = setTimeout(() => terminateProcessTree(child, "SIGKILL"), 250);
    };

    const abortHandler = (): void => terminate("cancel");
    options.signal?.addEventListener("abort", abortHandler, { once: true });
    if (options.signal?.aborted) {
      terminate("cancel");
    }

    if (request.budget.timeout_ms > 0) {
      timeoutTimer = setTimeout(() => terminate("timeout"), request.budget.timeout_ms);
    }

    let exitCode: number | null = null;
    let signalStr: string | null = null;

    try {
      const [code, sig] = await this.waitForClose(child);
      settled = true;
      exitCode = code;
      signalStr = sig ? String(sig) : null;
    } catch (error: unknown) {
      settled = true;
      const message = error instanceof Error ? error.message : "Process failed to start";
      throw new DomainError("PROCESS_CRASHED", "process", message, true, {
        executable: request.command.executable,
      });
    } finally {
      if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
      if (killTimer !== undefined) clearTimeout(killTimer);
      options.signal?.removeEventListener("abort", abortHandler);
    }

    const elapsedMs = Date.now() - startTime;
    const stdoutRaw = Buffer.concat(stdoutStream.chunks).toString("utf8");
    const stderrRaw = Buffer.concat(stderrStream.chunks).toString("utf8");

    const stdoutProcessed = limitOutput(sanitizeOutput(stdoutRaw), maxOutputBytes);
    const stderrProcessed = limitOutput(sanitizeOutput(stderrRaw), maxOutputBytes);

    const witnesses = await this.collectWitnessArtifacts(
      request,
      cwd,
    );

    const evidenceRef = `reproduction/${request.hypothesis_id}/witnesses.json`;

    const observation: DynamicReproductionExecutionObservation = {
      schema_version: CONTRACTS_VERSION,
      contract_version: DYNAMIC_REPRODUCTION_CONTRACT_VERSION,
      exit_code: exitCode,
      signal: signalStr,
      stdout: stdoutProcessed.value,
      stderr: stderrProcessed.value,
      stdout_truncated: stdoutStream.truncated || stdoutProcessed.truncated,
      stderr_truncated: stderrStream.truncated || stderrProcessed.truncated,
      elapsed_ms: elapsedMs,
      timed_out: timedOut,
      cancelled: cancelled,
      witnesses,
      environment_digest: environmentDigest,
      evidence_ref: evidenceRef,
    };

    // Save observation & witnesses into artifact store
    const observationPath = `reproduction/${request.hypothesis_id}/observation.json`;
    await this.artifacts.writeArtifact(
      request.run_id,
      observationPath,
      JSON.stringify(observation, null, 2),
    );
    await this.artifacts.writeArtifact(
      request.run_id,
      evidenceRef,
      JSON.stringify(witnesses, null, 2),
    );

    return observation;
  }

  private async resolveAndAssertTrustedDirectory(
    rawCwd: string,
    trustedRoots: readonly string[],
  ): Promise<string> {
    if (trustedRoots.length === 0) {
      throw new DomainError(
        "DYN_UNTRUSTED_ROOT",
        "environment",
        "No trusted roots configured for dynamic reproduction",
        false,
      );
    }

    let resolvedCwd: string;
    try {
      resolvedCwd = await realpath(path.resolve(rawCwd));
    } catch {
      resolvedCwd = path.resolve(rawCwd);
    }

    const canonicalTrustedRoots = await Promise.all(
      trustedRoots.map(async (root) => {
        try {
          return await realpath(path.resolve(root));
        } catch {
          return path.resolve(root);
        }
      }),
    );

    const isTrusted = canonicalTrustedRoots.some((root) => {
      const relative = path.relative(root, resolvedCwd);
      return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
    });

    if (!isTrusted) {
      throw new DomainError(
        "DYN_UNTRUSTED_ROOT",
        "environment",
        `Working directory '${resolvedCwd}' is outside trusted roots: ${canonicalTrustedRoots.join(", ")}`,
        false,
        { cwd: resolvedCwd, trustedRoots: canonicalTrustedRoots },
      );
    }

    return resolvedCwd;
  }

  private async resolveAndAssertExecutable(
    rawExecutable: string,
    cwd: string,
    trustedRoots: readonly string[],
  ): Promise<string> {
    if (rawExecutable.length === 0 || rawExecutable.includes("\0")) {
      throw new DomainError("INVALID_INPUT", "input", "Executable must be non-empty without NUL bytes", false);
    }

    if (rawExecutable.includes("/") || rawExecutable.includes("\\")) {
      const resolved = path.resolve(cwd, rawExecutable);
      let canonical: string;
      try {
        canonical = await realpath(resolved);
      } catch {
        canonical = resolved;
      }

      const canonicalTrustedRoots = await Promise.all(
        trustedRoots.map(async (root) => {
          try {
            return await realpath(path.resolve(root));
          } catch {
            return path.resolve(root);
          }
        }),
      );

      const isTrusted = canonicalTrustedRoots.some((root) => {
        const relative = path.relative(root, canonical);
        return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
      });

      if (!isTrusted) {
        throw new DomainError(
          "DYN_UNTRUSTED_ROOT",
          "environment",
          `Executable '${canonical}' is outside trusted roots`,
          false,
          { executable: canonical, trustedRoots: canonicalTrustedRoots },
        );
      }

      return canonical;
    }

    if (SAFE_SYSTEM_EXECUTABLES.has(rawExecutable)) {
      return rawExecutable;
    }

    throw new DomainError(
      "INVALID_INPUT",
      "input",
      `Executable '${rawExecutable}' is not in approved system executables (${Array.from(SAFE_SYSTEM_EXECUTABLES).join(", ")}) and is not a path within trusted roots`,
      false,
      { executable: rawExecutable },
    );
  }

  private assertValidArguments(args: readonly string[]): void {
    for (const arg of args) {
      if (arg.includes("\0")) {
        throw new DomainError("INVALID_INPUT", "input", "Command argument contains NUL byte", false);
      }
    }
  }

  private buildSanitizedEnvironment(customEnv?: Readonly<Record<string, string>>): {
    env: Record<string, string>;
    environmentDigest: string;
  } {
    const env: Record<string, string> = {};
    for (const key of SAFE_BASE_ENV_VARS) {
      if (process.env[key] !== undefined) {
        env[key] = process.env[key]!;
      }
    }

    if (customEnv) {
      for (const [key, value] of Object.entries(customEnv)) {
        if (!FORBIDDEN_ENV_VARS.has(key.toUpperCase())) {
          env[key] = value;
        }
      }
    }

    const sortedEntries = Object.keys(env)
      .sort()
      .map((k) => `${k}=${env[k]}`)
      .join("\n");
    const environmentDigest = sha256Hex(sortedEntries);

    return { env, environmentDigest };
  }

  private async collectWitnessArtifacts(
    request: DynamicReproductionExecutionRequest,
    cwd: string,
  ): Promise<DynamicReproductionWitnessArtifact[]> {
    if (!request.witness_file_paths || request.witness_file_paths.length === 0) {
      return [];
    }

    const witnesses: DynamicReproductionWitnessArtifact[] = [];
    const maxWitnessBytes =
      request.budget.max_witness_bytes ?? DYNAMIC_REPRODUCTION_LIMITS.defaultMaxWitnessBytes;

    for (const relPath of request.witness_file_paths) {
      if (relPath.includes("\0")) {
        throw new DomainError("INVALID_INPUT", "input", "Witness path contains NUL byte", false);
      }

      const resolved = path.resolve(cwd, relPath);
      const normalizedRel = path.relative(cwd, resolved);
      if (normalizedRel.startsWith("..") || path.isAbsolute(normalizedRel)) {
        throw new DomainError(
          "DYN_WITNESS_ESCAPE",
          "policy",
          `Witness file path '${relPath}' escapes working directory '${cwd}'`,
          false,
          { relPath, cwd },
        );
      }

      try {
        const fileStat = await stat(resolved);
        if (fileStat.isFile()) {
          if (fileStat.size > maxWitnessBytes) {
            throw new DomainError(
              "DYN_WITNESS_TOO_LARGE",
              "artifact",
              `Witness file '${relPath}' (${fileStat.size} bytes) exceeds limit of ${maxWitnessBytes} bytes`,
              false,
              { relPath, size: fileStat.size, limit: maxWitnessBytes },
            );
          }

          const content = await readFile(resolved);
          const sha256 = sha256Hex(content);
          const snippet = content.subarray(0, 256).toString("utf8");

          witnesses.push({
            path: normalizedRel,
            sha256,
            size_bytes: fileStat.size,
            snippet,
          });

          // Save witness to artifact store
          const artifactRelPath = `reproduction/${request.hypothesis_id}/witnesses/${normalizedRel}`;
          await this.artifacts.writeArtifact(request.run_id, artifactRelPath, content.toString("utf8"));
        }
      } catch (err: unknown) {
        if (err instanceof DomainError) throw err;
        // If file does not exist or cannot be read, witness was not generated
      }
    }

    return witnesses;
  }

  private buildCancelledObservation(
    request: DynamicReproductionExecutionRequest,
  ): DynamicReproductionExecutionObservation {
    return {
      schema_version: CONTRACTS_VERSION,
      contract_version: DYNAMIC_REPRODUCTION_CONTRACT_VERSION,
      exit_code: null,
      signal: null,
      stdout: "",
      stderr: "",
      stdout_truncated: false,
      stderr_truncated: false,
      elapsed_ms: 0,
      timed_out: false,
      cancelled: true,
      witnesses: [],
      environment_digest: sha256Hex(""),
      evidence_ref: `reproduction/${request.hypothesis_id}/witnesses.json`,
    };
  }

  private captureStream(stream: NodeJS.ReadableStream, maxBytes: number): CapturedStream {
    const capture: CapturedStream = { chunks: [], size: 0, truncated: false };
    stream.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (capture.size >= maxBytes) {
        capture.truncated = true;
        return;
      }
      const remaining = maxBytes - capture.size;
      capture.chunks.push(buffer.subarray(0, remaining));
      capture.size += Math.min(buffer.byteLength, remaining);
      capture.truncated ||= buffer.byteLength > remaining;
    });
    return capture;
  }

  private waitForClose(child: ChildProcess): Promise<[number | null, NodeJS.Signals | null]> {
    return new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (exitCode, signal) => resolve([exitCode, signal]));
    });
  }
}
