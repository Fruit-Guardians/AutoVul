import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  DomainError,
  CaseRunSummarySchema,
  parseSchema,
  RunManifestSchema,
  type RunId,
  type RunManifest,
  type CaseRunSummary,
} from "@autovul/contracts";
import type {
  ArtifactBundleFile,
  ArtifactStorePort,
  FileLock,
  FileSystemPort,
  StagedArtifactBundle,
} from "@autovul/core";
import type { CodeqlOperationOptions } from "@autovul/core";

export class LocalArtifactStore implements ArtifactStorePort {
  private readonly root: string;
  private trustedRoot: string | undefined;

  constructor(root: string, private readonly filesystem: FileSystemPort) {
    this.root = resolve(root);
  }

  artifactRoot(runId: RunId): string {
    return join(this.root, runId);
  }

  async findManifest(runId: RunId): Promise<RunManifest | undefined> {
    const root = this.artifactRoot(runId);
    await this.assertTrustedPath(root, runId, ".");
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
    await this.assertTrustedPath(root, parsed.runId, ".");
    await this.filesystem.ensureDirectory(root);
    await this.filesystem.writeTextAtomic(join(root, "manifest.json"), `${JSON.stringify(parsed, null, 2)}\n`);
  }

  async findCaseSummary(fingerprint: string): Promise<CaseRunSummary | undefined> {
    const path = this.caseSummaryPath(fingerprint);
    await this.assertTrustedPath(path, "case", fingerprint);
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
    await this.assertTrustedPath(directory, "case", parsed.case_fingerprint);
    await this.filesystem.ensureDirectory(directory);
    await this.filesystem.writeTextAtomic(this.caseSummaryPath(parsed.case_fingerprint), `${JSON.stringify(parsed, null, 2)}\n`);
  }

  async withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T> {
    const directory = join(this.root, "cases", fingerprint);
    await this.assertTrustedPath(directory, "case", fingerprint);
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
    await this.assertTrustedPath(path, runId, relativePath);
    if (!(await this.filesystem.exists(path))) {
      return undefined;
    }
    return this.filesystem.readText(path);
  }

  async writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void> {
    const path = this.safeArtifactPath(runId, relativePath);
    await this.assertTrustedPath(path, runId, relativePath);
    await this.filesystem.writeTextAtomic(path, content);
  }

  async listArtifactPaths(runId: RunId, relativeDirectory: string): Promise<readonly string[]> {
    const directory = this.safeArtifactPath(runId, relativeDirectory);
    await this.assertTrustedPath(directory, runId, relativeDirectory);
    const directoryInfo = await this.filesystem.stat(directory);
    if (!directoryInfo.exists) return [];
    if (!directoryInfo.isDirectory) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Artifact listing target is not a directory", false, { runId, relativeDirectory });
    }
    return this.listFiles(directory, relativeDirectory);
  }

  async stageArtifactBundle(
    runId: RunId,
    operationId: string,
    targetRelativePath: string,
    files: readonly ArtifactBundleFile[],
  ): Promise<StagedArtifactBundle> {
    this.assertOperationId(operationId);
    this.assertRelativePath(targetRelativePath, "artifact bundle target");
    this.safeArtifactPath(runId, targetRelativePath);
    const stagingRelativePath = join("workflow", "internal", "staging", operationId);
    const stagingDirectory = this.safeArtifactPath(runId, stagingRelativePath);
    await this.assertTrustedPath(stagingDirectory, runId, stagingRelativePath);
    await this.filesystem.ensureDirectory(stagingDirectory);
    const fileNames = new Set<string>();
    for (const file of files) {
      this.assertRelativePath(file.relativePath, "artifact bundle file");
      const stagedRelativePath = join(stagingRelativePath, file.relativePath);
      this.safeArtifactPath(runId, stagedRelativePath);
      if (fileNames.has(file.relativePath)) {
        throw new DomainError("INVALID_INPUT", "input", "Artifact bundle contains duplicate paths", false, { runId, operationId, relativePath: file.relativePath });
      }
      fileNames.add(file.relativePath);
      await this.filesystem.writeTextAtomic(this.safeArtifactPath(runId, stagedRelativePath), file.content);
    }
    return { operationId, targetRelativePath, files: [...fileNames] };
  }

  async readStagedArtifact(runId: RunId, operationId: string, relativePath: string): Promise<string | undefined> {
    this.assertOperationId(operationId);
    this.assertRelativePath(relativePath, "staged artifact file");
    return this.readAt(runId, join("workflow", "internal", "staging", operationId, relativePath));
  }

  async promoteArtifactBundle(runId: RunId, bundle: StagedArtifactBundle): Promise<void> {
    this.assertOperationId(bundle.operationId);
    const source = this.safeArtifactPath(runId, join("workflow", "internal", "staging", bundle.operationId));
    const target = this.safeArtifactPath(runId, bundle.targetRelativePath);
    await this.assertTrustedPath(source, runId, bundle.operationId);
    await this.assertTrustedPath(dirname(target), runId, bundle.targetRelativePath);
    const targetInfo = await this.filesystem.stat(target);
    if (targetInfo.exists) {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", "Artifact bundle target already exists", false, {
        runId,
        operationId: bundle.operationId,
        targetRelativePath: bundle.targetRelativePath,
      });
    }
    await this.filesystem.ensureDirectory(resolve(target, ".."));
    await this.filesystem.promoteDirectory(source, target);
  }

  async discardArtifactBundle(runId: RunId, bundle: StagedArtifactBundle | string): Promise<void> {
    const operationId = typeof bundle === "string" ? bundle : bundle.operationId;
    this.assertOperationId(operationId);
    const stagingPath = this.safeArtifactPath(runId, join("workflow", "internal", "staging", operationId));
    await this.assertTrustedPath(stagingPath, runId, operationId);
    await this.filesystem.removeTree(stagingPath);
  }

  async discardPromotedArtifactBundle(runId: RunId, targetRelativePath: string): Promise<void> {
    const target = this.safeArtifactPath(runId, targetRelativePath);
    await this.assertTrustedPath(target, runId, targetRelativePath);
    await this.filesystem.removeTree(target);
  }

  async listStagedArtifactOperations(runId: RunId): Promise<readonly string[]> {
    const root = this.safeArtifactPath(runId, join("workflow", "internal", "staging"));
    await this.assertTrustedPath(root, runId, "workflow/internal/staging");
    const info = await this.filesystem.stat(root);
    if (!info.exists) return [];
    if (!info.isDirectory) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Artifact staging root is not a directory", false, { runId });
    const entries = await this.filesystem.listDirectory(root);
    return entries.filter((entry) => entry.isDirectory && /^[a-zA-Z0-9._-]{1,128}$/.test(entry.name)).map((entry) => entry.name);
  }

  async withRunLock<T>(runId: RunId, operation: () => Promise<T>): Promise<T> {
    const root = this.artifactRoot(runId);
    await this.assertTrustedPath(root, runId, ".");
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
    await this.assertTrustedPath(root, runId, ".");
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

  private async readAt(runId: RunId, relativePath: string): Promise<string | undefined> {
    const path = this.safeArtifactPath(runId, relativePath);
    await this.assertTrustedPath(path, runId, relativePath);
    if (!(await this.filesystem.exists(path))) return undefined;
    return this.filesystem.readText(path);
  }

  private async listFiles(directory: string, relativeDirectory: string): Promise<readonly string[]> {
    const entries = await this.filesystem.listDirectory(directory);
    const paths: string[] = [];
    for (const entry of entries) {
      const childRelativePath = join(relativeDirectory, entry.name);
      const childPath = join(directory, entry.name);
      if (entry.isDirectory) paths.push(...await this.listFiles(childPath, childRelativePath));
      else paths.push(childRelativePath);
    }
    return paths;
  }

  private assertOperationId(operationId: string): void {
    if (!/^[a-zA-Z0-9._-]{1,128}$/.test(operationId)) {
      throw new DomainError("INVALID_INPUT", "input", "Artifact operation id is invalid", false, { operationId });
    }
  }

  private assertRelativePath(path: string, field: string): void {
    if (path.length === 0 || isAbsolute(path) || path.includes("..") || path.includes("\\")) {
      throw new DomainError("INVALID_INPUT", "input", `${field} must be a safe relative path`, false, { field, path });
    }
  }

  private async assertTrustedPath(path: string, runId: RunId | "case", relativePath: string): Promise<void> {
    const trustedRoot = await this.canonicalRoot();
    let probe = path;
    for (;;) {
      const info = await this.filesystem.stat(probe);
      if (info.exists) break;
      const parent = dirname(probe);
      if (parent === probe) break;
      probe = parent;
    }
    let canonical: string;
    try {
      canonical = await this.filesystem.canonicalize(probe);
    } catch (error: unknown) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Cannot canonicalize an artifact path", false, { runId, relativePath, reason: error instanceof Error ? error.message : "canonicalization failed" });
    }
    if (canonical !== trustedRoot && !canonical.startsWith(`${trustedRoot}${sep}`)) {
      throw new DomainError("INVALID_INPUT", "input", "Artifact path escapes the trusted root", false, { runId, relativePath });
    }
  }

  private async canonicalRoot(): Promise<string> {
    if (this.trustedRoot !== undefined) return this.trustedRoot;
    await this.filesystem.ensureDirectory(this.root);
    this.trustedRoot = await this.filesystem.canonicalize(this.root);
    return this.trustedRoot;
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
