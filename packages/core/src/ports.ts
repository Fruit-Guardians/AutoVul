import type {
  CodeqlEnvironment,
  DatabaseManifest,
  QueryCandidate,
  CaseRunSummary,
  QueryCompileObservation,
  QueryDatabaseObservation,
  QueryDiagnostic,
  QueryDraftReport,
  ProbeEvidence,
  TaintQueryIntent,
  RunId,
  RunManifest,
  RunPhase,
  VulnerabilitySpec,
  VerificationLevel,
} from "@autovul/contracts";

export interface ProcessCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly shell?: false;
}

export interface ProcessOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface ProcessResult {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
}

export interface ProcessPort {
  execute(command: ProcessCommand, options: ProcessOptions): Promise<ProcessResult>;
}

export interface FileLock {
  release(): Promise<void>;
}

export interface FileSystemPort {
  ensureDirectory(path: string): Promise<void>;
  readText(path: string): Promise<string>;
  writeTextAtomic(path: string, content: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  stat(path: string): Promise<{ exists: boolean; isDirectory: boolean; modifiedAtMs?: number }>;
  remove(path: string): Promise<void>;
  removeTree(path: string): Promise<void>;
  promoteDirectory(sourcePath: string, targetPath: string): Promise<void>;
  listDirectory(path: string): Promise<readonly { name: string; isDirectory: boolean }[]>;
  canonicalize(path: string): Promise<string>;
  acquireLock(path: string): Promise<FileLock>;
}

export interface ArtifactBundleFile {
  readonly relativePath: string;
  readonly content: string;
}

export interface StagedArtifactBundle {
  readonly operationId: string;
  readonly targetRelativePath: string;
  readonly files: readonly string[];
}

export interface ArtifactStorePort {
  artifactRoot(runId: RunId): string;
  findManifest(runId: RunId): Promise<RunManifest | undefined>;
  saveManifest(manifest: RunManifest): Promise<void>;
  readArtifact(runId: RunId, relativePath: string): Promise<string | undefined>;
  writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void>;
  listArtifactPaths(runId: RunId, relativeDirectory: string): Promise<readonly string[]>;
  stageArtifactBundle(
    runId: RunId,
    operationId: string,
    targetRelativePath: string,
    files: readonly ArtifactBundleFile[],
  ): Promise<StagedArtifactBundle>;
  readStagedArtifact(runId: RunId, operationId: string, relativePath: string): Promise<string | undefined>;
  promoteArtifactBundle(runId: RunId, bundle: StagedArtifactBundle): Promise<void>;
  discardArtifactBundle(runId: RunId, bundle: StagedArtifactBundle | string): Promise<void>;
  discardPromotedArtifactBundle(runId: RunId, targetRelativePath: string): Promise<void>;
  listStagedArtifactOperations(runId: RunId): Promise<readonly string[]>;
  withRunLock<T>(runId: RunId, operation: () => Promise<T>): Promise<T>;
  /**
   * Serialize workflow mutations independently from the manifest lock. The
   * workflow lease may be held across CodeQL execution, while manifest writes
   * remain short atomic transactions.
   */
  withRunOperation<T>(runId: RunId, options: CodeqlOperationOptions, operation: () => Promise<T>): Promise<T>;
  findCaseSummary(fingerprint: string): Promise<CaseRunSummary | undefined>;
  saveCaseSummary(summary: CaseRunSummary): Promise<void>;
  withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T>;
}

export interface ClockPort {
  now(): string;
}

export interface IdGeneratorPort {
  next(): RunId;
}

export interface CodeqlOperationOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs: number;
}

export interface CodeqlPort {
  doctor(options: CodeqlOperationOptions): Promise<CodeqlEnvironment>;
  inspectDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest>;
  validateDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest>;
  /** Allow a host workflow to bind user-supplied database paths when no static root was configured. */
  setTrustedRoots?(roots: readonly string[]): void;
}

export interface QueryExecutionRequest {
  readonly runId: RunId;
  readonly candidate: QueryCandidate;
  readonly spec: VulnerabilitySpec;
  readonly artifactRoot: string;
}

export interface QueryExecutionResult {
  readonly compile: QueryCompileObservation;
  readonly vulnerable: QueryDatabaseObservation;
  readonly fixed: QueryDatabaseObservation;
  readonly diagnostics: readonly QueryDiagnostic[];
  readonly elapsedMs: number;
  readonly codeqlCliVersion?: string;
  readonly extractorInfo?: string;
  readonly cancelled?: boolean;
  readonly timedOut?: boolean;
}

/**
 * The adapter owns the CodeQL command vocabulary and SARIF decoding. Core
 * consumes only these observations and decides whether the candidate passes
 * the manifest policy.
 */
export interface QueryExecutionPort {
  execute(request: QueryExecutionRequest, options: CodeqlOperationOptions): Promise<QueryExecutionResult>;
}

export interface QueryProbeRequest {
  readonly runId: RunId;
  readonly intent: TaintQueryIntent;
  readonly spec: VulnerabilitySpec;
  readonly artifactRoot: string;
}

export interface QueryProbeExecutionPort {
  executeProbe(request: QueryProbeRequest, options: CodeqlOperationOptions): Promise<ProbeEvidence>;
}

export interface QueryDraftRequest {
  readonly runId: RunId;
  readonly candidate: QueryCandidate;
  readonly spec: VulnerabilitySpec;
  readonly artifactRoot: string;
  readonly revision: number;
  readonly draftRevisionBudget: number;
}

/**
 * Draft validation is advisory and must not mutate the formal candidate budget.
 * The CLI query execution port remains the final authority.
 */
export interface QueryDraftExecutionPort {
  executeDraft(request: QueryDraftRequest, options: CodeqlOperationOptions): Promise<QueryDraftReport>;
  /** Close a long-lived language-service session owned by the adapter. */
  close?(): Promise<void>;
}

export interface RunMutation {
  readonly phase?: RunPhase;
  readonly verificationLevel?: VerificationLevel;
}
