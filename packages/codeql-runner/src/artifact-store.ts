import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  DomainError,
  CaseRunSummarySchema,
  parseSchema,
  RunManifestSchema,
  type RunId,
  type RunManifest,
  type CaseRunSummary,
} from "@pure-auto-codeql/contracts";
import type { ArtifactStorePort, FileLock, FileSystemPort } from "@pure-auto-codeql/core";
import type { CodeqlOperationOptions } from "@pure-auto-codeql/core";

export class LocalArtifactStore implements ArtifactStorePort {
  private readonly root: string;

  constructor(root: string, private readonly filesystem: FileSystemPort) {
    this.root = resolve(root);
  }

  artifactRoot(runId: RunId): string {
    return join(this.root, runId);
  }

  async findManifest(runId: RunId): Promise<RunManifest | undefined> {
    const root = this.artifactRoot(runId);
    const manifestPath = join(root, "manifest.json");
    const manifestExists = await this.filesystem.exists(manifestPath);
    if (!manifestExists && (await this.filesystem.exists(`${manifestPath}.tmp`))) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Temporary manifest detected for ${runId}`, false, { runId });
    }
    if (!manifestExists) {
      return undefined;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await this.filesystem.readText(manifestPath)) as unknown;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Manifest is not valid JSON";
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Cannot read manifest for ${runId}`, false, {
        runId,
        reason: message,
      });
    }
    try {
      return parseSchema(RunManifestSchema, parsed, "run manifest");
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Manifest schema validation failed";
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Manifest schema is invalid for ${runId}`, false, {
        runId,
        reason: message,
      });
    }
  }

  async saveManifest(manifest: RunManifest): Promise<void> {
    const parsed = parseSchema(RunManifestSchema, manifest, "run manifest");
    const root = this.artifactRoot(parsed.runId);
    await this.filesystem.ensureDirectory(root);
    await this.filesystem.writeTextAtomic(join(root, "manifest.json"), `${JSON.stringify(parsed, null, 2)}\n`);
  }

  async findCaseSummary(fingerprint: string): Promise<CaseRunSummary | undefined> {
    const path = this.caseSummaryPath(fingerprint);
    if (!(await this.filesystem.exists(path))) return undefined;
    try {
      return parseSchema(CaseRunSummarySchema, JSON.parse(await this.filesystem.readText(path)) as unknown, "case run summary");
    } catch (error: unknown) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Cannot read case summary for ${fingerprint}`, false, {
        caseFingerprint: fingerprint,
        reason: error instanceof Error ? error.message : "invalid case summary",
      });
    }
  }

  async saveCaseSummary(summary: CaseRunSummary): Promise<void> {
    const parsed = parseSchema(CaseRunSummarySchema, summary, "case run summary");
    const directory = join(this.root, "cases", parsed.case_fingerprint);
    await this.filesystem.ensureDirectory(directory);
    await this.filesystem.writeTextAtomic(this.caseSummaryPath(parsed.case_fingerprint), `${JSON.stringify(parsed, null, 2)}\n`);
  }

  async withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T> {
    const directory = join(this.root, "cases", fingerprint);
    await this.filesystem.ensureDirectory(directory);
    const lock = await this.filesystem.acquireLock(join(directory, ".lock"));
    try {
      return await operation();
    } finally {
      await lock.release();
    }
  }

  async readArtifact(runId: RunId, relativePath: string): Promise<string | undefined> {
    const path = this.safeArtifactPath(runId, relativePath);
    if (!(await this.filesystem.exists(path))) {
      return undefined;
    }
    return this.filesystem.readText(path);
  }

  async writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void> {
    const path = this.safeArtifactPath(runId, relativePath);
    await this.filesystem.writeTextAtomic(path, content);
  }

  async withRunLock<T>(runId: RunId, operation: () => Promise<T>): Promise<T> {
    const root = this.artifactRoot(runId);
    await this.filesystem.ensureDirectory(root);
    const lock = await this.filesystem.acquireLock(join(root, ".lock"));
    try {
      return await operation();
    } finally {
      await lock.release();
    }
  }

  async withRunOperation<T>(runId: RunId, options: CodeqlOperationOptions, operation: () => Promise<T>): Promise<T> {
    const root = this.artifactRoot(runId);
    await this.filesystem.ensureDirectory(root);
    const lockPath = join(root, ".workflow.lock");
    const deadline = Date.now() + Math.max(1, options.timeoutMs);
    for (;;) {
      if (options.signal?.aborted) {
        throw new DomainError("PROCESS_CANCELLED", "process", `Workflow operation for ${runId} was cancelled while waiting`, false, { runId, waitingForWorkflowLease: true });
      }
      let lock: FileLock;
      try {
        lock = await this.filesystem.acquireLock(lockPath);
      } catch (error: unknown) {
        if (!(error instanceof DomainError) || error.code !== "RUN_LOCKED") {
          throw error;
        }
        if (Date.now() >= deadline) {
          throw new DomainError("WORKFLOW_BUSY", "state", `Workflow ${runId} is busy`, true, { runId });
        }
        await waitForLease(options.signal, Math.min(25, Math.max(1, deadline - Date.now())));
        continue;
      }
      try {
        return await operation();
      } finally {
        await lock.release();
      }
    }
  }

  private safeArtifactPath(runId: RunId, relativePath: string): string {
    const root = this.artifactRoot(runId);
    const path = resolve(root, relativePath);
    const pathRelativeToRoot = relative(root, path);
    if (isAbsolute(relativePath) || pathRelativeToRoot === ".." || pathRelativeToRoot.startsWith(`..${sep}`)) {
      throw new DomainError("INVALID_INPUT", "input", "Artifact path must stay inside the run root", false, {
        runId,
        relativePath,
      });
    }
    return path;
  }

  private caseSummaryPath(fingerprint: string): string {
    return join(this.root, "cases", fingerprint, "summary.json");
  }
}

async function waitForLease(signal: AbortSignal | undefined, delayMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, delayMs);
    const abort = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      reject(new DomainError("PROCESS_CANCELLED", "process", "Workflow operation was cancelled while waiting", false, { waitingForWorkflowLease: true }));
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}
