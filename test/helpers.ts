import { DomainError, type CaseRunSummary, type CodeqlEnvironment, type DatabaseManifest, type RunId, type RunManifest } from "@pure-auto-codeql/contracts";
import type {
  ArtifactStorePort,
  ClockPort,
  CodeqlOperationOptions,
  CodeqlPort,
  IdGeneratorPort,
  ProcessCommand,
  ProcessOptions,
  ProcessPort,
  ProcessResult,
} from "@pure-auto-codeql/core";

export class MemoryArtifactStore implements ArtifactStorePort {
  readonly manifests = new Map<RunId, RunManifest>();
  readonly artifacts = new Map<string, string>();
  private readonly locks = new Set<RunId>();
  private readonly operationLocks = new Set<RunId>();
  readonly caseSummaries = new Map<string, CaseRunSummary>();
  private readonly caseLocks = new Set<string>();

  artifactRoot(runId: RunId): string {
    return `/isolated/runs/${runId}`;
  }

  async findManifest(runId: RunId): Promise<RunManifest | undefined> {
    return this.manifests.get(runId);
  }

  async saveManifest(manifest: RunManifest): Promise<void> {
    this.manifests.set(manifest.runId, structuredClone(manifest));
  }

  async readArtifact(runId: RunId, relativePath: string): Promise<string | undefined> {
    return this.artifacts.get(`${runId}/${relativePath}`);
  }

  async writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void> {
    this.artifacts.set(`${runId}/${relativePath}`, content);
  }

  async withRunLock<T>(runId: RunId, operation: () => Promise<T>): Promise<T> {
    if (this.locks.has(runId)) {
      throw new DomainError("RUN_LOCKED", "artifact", `Run ${runId} is locked`, true, { runId });
    }
    this.locks.add(runId);
    try {
      return await operation();
    } finally {
      this.locks.delete(runId);
    }
  }

  async withRunOperation<T>(runId: RunId, options: CodeqlOperationOptions, operation: () => Promise<T>): Promise<T> {
    const deadline = Date.now() + options.timeoutMs;
    while (this.operationLocks.has(runId)) {
      if (options.signal?.aborted) {
        throw new DomainError("PROCESS_CANCELLED", "process", "Workflow operation was cancelled while waiting", false, { runId, waitingForWorkflowLease: true });
      }
      if (Date.now() >= deadline) {
        throw new DomainError("WORKFLOW_BUSY", "state", `Workflow ${runId} is busy`, true, { runId });
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    this.operationLocks.add(runId);
    try {
      return await operation();
    } finally {
      this.operationLocks.delete(runId);
    }
  }

  isRunOperationLocked(runId: RunId): boolean {
    return this.operationLocks.has(runId);
  }

  async findCaseSummary(fingerprint: string): Promise<CaseRunSummary | undefined> {
    const value = this.caseSummaries.get(fingerprint);
    return value === undefined ? undefined : structuredClone(value);
  }

  async saveCaseSummary(summary: CaseRunSummary): Promise<void> {
    this.caseSummaries.set(summary.case_fingerprint, structuredClone(summary));
  }

  async withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T> {
    if (this.caseLocks.has(fingerprint)) {
      throw new DomainError("RUN_LOCKED", "artifact", `Case ${fingerprint} is locked`, true, { caseFingerprint: fingerprint });
    }
    this.caseLocks.add(fingerprint);
    try {
      return await operation();
    } finally {
      this.caseLocks.delete(fingerprint);
    }
  }
}

export class FixedClock implements ClockPort {
  private tick = 0;

  now(): string {
    this.tick += 1;
    return new Date(Date.UTC(2026, 7, 23, 0, 0, this.tick)).toISOString();
  }
}

export class FixedIdGenerator implements IdGeneratorPort {
  constructor(private readonly runId: RunId = "run_test01") {}

  next(): RunId {
    return this.runId;
  }
}

export class FakeCodeqlPort implements CodeqlPort {
  environment: CodeqlEnvironment = {
    schemaVersion: "v2.contracts/1",
    available: true,
    cliPath: "/fake/codeql",
    version: "CodeQL CLI version 2.0.0",
    languages: ["python"],
    checkedAt: "2026-08-23T00:00:00.000Z",
    diagnostics: [],
  };
  database: DatabaseManifest = {
    schemaVersion: "v2.contracts/1",
    path: "/isolated/db",
    canonicalPath: "/isolated/db",
    exists: true,
    isDirectory: true,
    valid: true,
    language: "python",
    checkedAt: "2026-08-23T00:00:00.000Z",
    diagnostics: [],
  };
  failure: DomainError | undefined;
  inspectDelayMs = 0;
  readonly inspectedPaths: string[] = [];

  async doctor(_options: CodeqlOperationOptions): Promise<CodeqlEnvironment> {
    if (this.failure) {
      throw this.failure;
    }
    return this.environment;
  }

  async inspectDatabase(_path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    if (this.failure) {
      throw this.failure;
    }
    this.inspectedPaths.push(_path);
    if (this.inspectDelayMs > 0) {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, this.inspectDelayMs);
        const abort = (): void => {
          clearTimeout(timer);
          reject(new DomainError("PROCESS_CANCELLED", "process", "inspect cancelled", false));
        };
        options.signal?.addEventListener("abort", abort, { once: true });
      });
    }
    return this.database;
  }

  async validateDatabase(_path: string, _options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    if (this.failure) {
      throw this.failure;
    }
    return this.database;
  }
}

export function processResult(overrides: Partial<ProcessResult> = {}): ProcessResult {
  return {
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    cancelled: false,
    ...overrides,
  };
}

export class ScriptedProcessPort implements ProcessPort {
  readonly calls: Array<{ command: ProcessCommand; options: ProcessOptions }> = [];

  constructor(private readonly handler: (command: ProcessCommand, options: ProcessOptions) => Promise<ProcessResult> | ProcessResult) {}

  execute(command: ProcessCommand, options: ProcessOptions): Promise<ProcessResult> {
    this.calls.push({ command, options });
    return Promise.resolve(this.handler(command, options));
  }
}
