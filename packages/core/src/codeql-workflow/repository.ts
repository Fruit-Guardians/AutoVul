import {
  asDomainError,
  DomainError,
  parseSchema,
  QueryPackManifestSchema,
  QueryWorkflowStateSchema,
  stableDigest,
  type CaseRunSummary,
  type DomainErrorRecord,
  type QueryWorkflowState,
  type RunId,
  type RunManifest,
  type RunPhase,
} from "@autovul/contracts";

import type {
  ArtifactBundleFile,
  ArtifactStorePort,
  CodeqlOperationOptions,
  StagedArtifactBundle,
} from "../ports.js";
import { RunStatusService } from "../status-service.js";
import { caseSummaryFromState } from "./case-ledger.js";
import {
  parseRecovery,
  RECOVERY_DIRECTORY,
  recoveryPath,
  type CommitKind,
  type RecoveryPhase,
  type WorkflowCommitRecord,
  updateRecovery,
} from "./recovery.js";
import { upgradeLegacyState } from "./state-migrations.js";

const STATE_PATH = "workflow/state.json";
const STAGING_DIRECTORY = "workflow/internal/staging";
const MAX_PROJECTION_ERRORS = 8;

export interface CommitStateOptions {
  readonly operationId: string;
  readonly idempotencyKey: string;
  readonly kind: CommitKind;
  readonly workflowPhase: "query_verify" | "workflow_finalize";
  readonly referencedArtifacts: readonly string[];
  readonly candidateId?: string;
  readonly packId?: string;
  readonly stagedOperationId?: string;
}

export interface CommitStateResult {
  readonly state: QueryWorkflowState;
  readonly reconciliation: ReconciliationResult;
}

export interface ReconciliationResult {
  readonly run: RunManifest;
  readonly caseSummary: CaseRunSummary;
  readonly projectionErrors: readonly string[];
}

/**
 * Canonical workflow persistence boundary. Command modules may use raw
 * evidence access, but authoritative state, recovery metadata and success
 * projections are committed and reconciled only here.
 */
export class WorkflowRepository {
  constructor(
    private readonly artifacts: ArtifactStorePort,
    private readonly status: RunStatusService,
    private readonly clock: { now(): string },
  ) {}

  async createRun(): Promise<RunManifest> {
    return this.status.create();
  }

  async getRun(runId: RunId): Promise<RunManifest> {
    return this.status.get(runId);
  }

  artifactRoot(runId: RunId): string {
    return this.artifacts.artifactRoot(runId);
  }

  async tryGetRun(runId: RunId): Promise<RunManifest | undefined> {
    return this.artifacts.findManifest(runId);
  }

  async startRun(runId: RunId, phase?: RunPhase): Promise<RunManifest> {
    return this.status.start(runId, phase);
  }

  async failRun(runId: RunId, error: DomainErrorRecord): Promise<RunManifest> {
    return this.status.fail(runId, error);
  }

  async cancelRun(runId: RunId, error?: DomainErrorRecord): Promise<RunManifest> {
    return this.status.cancel(runId, error);
  }

  async exhaustRun(runId: RunId, error: DomainErrorRecord): Promise<RunManifest> {
    return this.status.exhaust(runId, error);
  }

  async load(runId: RunId): Promise<QueryWorkflowState> {
    const state = await this.tryLoad(runId);
    if (state === undefined) {
      throw new DomainError("ARTIFACT_NOT_FOUND", "artifact", `Query workflow state for ${runId} was not found`, false, { runId });
    }
    return state;
  }

  async tryLoad(runId: RunId): Promise<QueryWorkflowState | undefined> {
    const raw = await this.artifacts.readArtifact(runId, STATE_PATH);
    if (raw === undefined) return undefined;
    return this.parseState(raw, runId);
  }

  private parseState(raw: string, runId: RunId): QueryWorkflowState {
    try {
      return parseSchema(QueryWorkflowStateSchema, upgradeLegacyState(JSON.parse(raw) as unknown), "query workflow state");
    } catch (error: unknown) {
      if (error instanceof DomainError && error.code === "INVALID_INPUT") {
        throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Query workflow state for ${runId} is invalid`, false, { runId, reason: error.message });
      }
      throw error;
    }
  }

  /** Save a non-result workflow document; result commits use commitState. */
  async save(runId: RunId, state: QueryWorkflowState): Promise<void> {
    const parsed = parseSchema(QueryWorkflowStateSchema, state, "query workflow state");
    await this.artifacts.writeArtifact(runId, STATE_PATH, `${JSON.stringify(parsed, null, 2)}\n`);
  }

  async commitState(
    runId: RunId,
    nextState: QueryWorkflowState,
    options: CommitStateOptions,
    operationOptions: CodeqlOperationOptions,
  ): Promise<CommitStateResult> {
    const parsed = parseSchema(QueryWorkflowStateSchema, nextState, "query workflow state");
    const stateDigest = digestState(parsed);
    const current = await this.load(runId);
    if (digestState(current) === stateDigest) return { state: current, reconciliation: await this.reconcile(runId) };
    if (operationOptions.signal?.aborted) throw cancelledBeforeCommit(runId, options.operationId);

    const record = this.newRecoveryRecord(runId, stateDigest, options);
    await this.writeRecovery(record);
    let prepared = record;
    try {
      const artifactDigests = await this.referencedArtifactDigests(runId, options.referencedArtifacts);
      prepared = { ...record, artifact_digests: artifactDigests, updated_at: this.clock.now() };
      await this.writeRecovery(prepared);
      if (operationOptions.signal?.aborted) throw cancelledBeforeCommit(runId, options.operationId);
      await this.save(runId, parsed);
    } catch (error: unknown) {
      await this.tryWriteRecovery(updateRecovery(prepared, "aborted", this.clock.now(), [diagnosticCode(error)]));
      throw error;
    }

    const committed = updateRecovery(prepared, "committed", this.clock.now());
    await this.tryWriteRecovery(committed);
    const reconciliation = await this.reconcile(runId);
    const finalPhase: RecoveryPhase = reconciliation.projectionErrors.length === 0 ? "reconciled" : "projection_pending";
    await this.tryWriteRecovery(updateRecovery(committed, finalPhase, this.clock.now(), reconciliation.projectionErrors));
    return { state: parsed, reconciliation };
  }

  async reconcile(runId: RunId): Promise<ReconciliationResult> {
    const state = await this.load(runId);
    const stateDigest = digestState(state);
    const records = await this.readRecoveryRecords(runId);
    const matchingRecords = records.filter((record) => record.state_digest === stateDigest);
    for (const record of records) {
      if (record.state_digest !== stateDigest && record.phase === "prepared") {
        if (record.staged_operation_id !== undefined) await this.discardArtifactBundle(runId, record.staged_operation_id).catch(() => undefined);
        await this.tryWriteRecovery(updateRecovery(record, "aborted", this.clock.now(), ["PRE_COMMIT_NOT_COMMITTED"]));
      }
    }

    const orphanOperations = await this.artifacts.listStagedArtifactOperations(runId);
    const liveStaging = new Set(matchingRecords.filter((record) => record.phase === "prepared").map((record) => record.staged_operation_id).filter((value): value is string => value !== undefined));
    for (const operationId of orphanOperations) {
      if (!liveStaging.has(operationId)) await this.discardArtifactBundle(runId, operationId).catch(() => undefined);
    }

    if (state.pack === undefined) {
      const orphanPackPaths = await this.artifacts.listArtifactPaths(runId, "query-pack");
      if (orphanPackPaths.length > 0) await this.discardPromotedArtifactBundle(runId, "query-pack").catch(() => undefined);
    }

    let run = await this.getRun(runId);
    const projectionErrors: string[] = [];
    const passed = [...state.verifications].reverse().find((verification) => verification.status === "passed");
    const exhausted = passed === undefined && state.candidates.length >= state.spec.max_rounds && state.verifications.length >= state.spec.max_rounds && state.verifications.every((verification) => verification.status === "failed");
    try {
      if (state.pack !== undefined) {
        await this.assertPackArtifacts(runId, state.pack);
        if (run.status !== "completed") run = await this.status.reconcileComplete(runId, state.pack.verification.verification_level, "workflow_finalize");
      } else if (passed !== undefined) {
        if (run.status !== "checkpointed" || run.checkpoint?.verificationLevel !== passed.verification_level) {
          run = await this.status.reconcileCheckpoint(runId, "query_verify", passed.verification_level);
        }
      } else if (exhausted) {
        run = await this.status.reconcileExhausted(runId, new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The case candidate budget has been exhausted", false, { runId, maxCandidates: state.spec.max_rounds }).toRecord());
      }
    } catch (error: unknown) {
      if (error instanceof DomainError && error.code === "ARTIFACT_CORRUPT") throw error;
      projectionErrors.push(diagnosticCode(error));
    }

    const statusOverride: CaseRunSummary["status"] | undefined = state.pack === undefined ? undefined : "completed";
    const expectedSummary = await this.deriveCaseSummary(state, run, statusOverride, state.pack?.pack_id);
    try {
      const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
      if (existing === undefined || JSON.stringify(existing) !== JSON.stringify(expectedSummary)) {
        await this.artifacts.withCaseLock(state.case_fingerprint, async () => {
          const current = await this.artifacts.findCaseSummary(state.case_fingerprint);
          if (current === undefined || JSON.stringify(current) !== JSON.stringify(expectedSummary)) await this.artifacts.saveCaseSummary(expectedSummary);
        });
      }
    } catch (error: unknown) {
      projectionErrors.push(diagnosticCode(error));
    }

    const boundedErrors = projectionErrors.slice(0, MAX_PROJECTION_ERRORS);
    for (const record of matchingRecords) {
      if (record.phase === "prepared" || record.phase === "committed" || record.phase === "projection_pending") {
        await this.tryWriteRecovery(updateRecovery(record, boundedErrors.length === 0 ? "reconciled" : "projection_pending", this.clock.now(), boundedErrors));
      }
    }
    return { run, caseSummary: expectedSummary, projectionErrors: boundedErrors };
  }

  async deriveCaseSummary(
    state: QueryWorkflowState,
    run: { runId: RunId; status: string },
    statusOverride?: CaseRunSummary["status"],
    packId?: string,
  ): Promise<CaseRunSummary> {
    const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
    return caseSummaryFromState(state, run, this.clock.now(), existing, statusOverride, packId);
  }

  async readCaseSummary(state: QueryWorkflowState, run: { runId: RunId; status: string }): Promise<CaseRunSummary> {
    const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
    return caseSummaryFromState(state, run, this.clock.now(), existing, state.pack === undefined ? undefined : "completed", state.pack?.pack_id);
  }

  async saveCaseSummary(summary: CaseRunSummary): Promise<void> {
    await this.artifacts.saveCaseSummary(summary);
  }

  async findCaseSummary(fingerprint: string): Promise<CaseRunSummary | undefined> {
    return this.artifacts.findCaseSummary(fingerprint);
  }

  async readArtifact(runId: RunId, relativePath: string): Promise<string | undefined> {
    return this.artifacts.readArtifact(runId, relativePath);
  }

  async writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void> {
    await this.artifacts.writeArtifact(runId, relativePath, content);
  }

  async listArtifactPaths(runId: RunId, relativeDirectory: string): Promise<readonly string[]> {
    return this.artifacts.listArtifactPaths(runId, relativeDirectory);
  }

  async stageArtifactBundle(runId: RunId, operationId: string, targetRelativePath: string, files: readonly ArtifactBundleFile[]): Promise<StagedArtifactBundle> {
    return this.artifacts.stageArtifactBundle(runId, operationId, targetRelativePath, files);
  }

  async readStagedArtifact(runId: RunId, operationId: string, relativePath: string): Promise<string | undefined> {
    return this.artifacts.readStagedArtifact(runId, operationId, relativePath);
  }

  async promoteArtifactBundle(runId: RunId, bundle: StagedArtifactBundle): Promise<void> {
    return this.artifacts.promoteArtifactBundle(runId, bundle);
  }

  async discardArtifactBundle(runId: RunId, bundle: StagedArtifactBundle | string): Promise<void> {
    return this.artifacts.discardArtifactBundle(runId, bundle);
  }

  async discardPromotedArtifactBundle(runId: RunId, targetRelativePath: string): Promise<void> {
    return this.artifacts.discardPromotedArtifactBundle(runId, targetRelativePath);
  }

  withRunOperation<T>(runId: RunId, options: CodeqlOperationOptions, operation: () => Promise<T>): Promise<T> {
    return this.artifacts.withRunOperation(runId, options, operation);
  }

  withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T> {
    return this.artifacts.withCaseLock(fingerprint, operation);
  }

  private async referencedArtifactDigests(runId: RunId, paths: readonly string[]): Promise<Record<string, string>> {
    const digests: Record<string, string> = {};
    for (const path of paths) {
      const content = await this.artifacts.readArtifact(runId, path);
      if (content === undefined) {
        throw new DomainError("ARTIFACT_CORRUPT", "artifact", "A referenced workflow artifact is missing before commit", false, { runId, path });
      }
      digests[path] = stableDigest(content);
    }
    return digests;
  }

  private async assertPackArtifacts(runId: RunId, pack: QueryWorkflowState["pack"]): Promise<void> {
    if (pack === undefined) return;
    const paths = Object.values(pack.files).map((path) => `query-pack/${path}`);
    await this.referencedArtifactDigests(runId, paths);
    const rawManifest = await this.artifacts.readArtifact(runId, "query-pack/query-pack-manifest.json");
    if (rawManifest === undefined) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Committed Query Pack manifest is missing", false, { runId, packId: pack.pack_id });
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawManifest) as unknown;
    } catch {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Committed Query Pack manifest is not valid JSON", false, { runId, packId: pack.pack_id });
    }
    const manifest = parseSchema(QueryPackManifestSchema, parsed, "query pack manifest");
    if (manifest.pack_id !== pack.pack_id) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Committed Query Pack manifest identity does not match workflow state", false, { runId, packId: pack.pack_id, observedPackId: manifest.pack_id });
  }

  private newRecoveryRecord(runId: RunId, stateDigest: string, options: CommitStateOptions): WorkflowCommitRecord {
    const now = this.clock.now();
    return {
      schema_version: "workflow.commit/v1",
      operation_id: options.operationId,
      idempotency_key: options.idempotencyKey,
      run_id: runId,
      kind: options.kind,
      workflow_phase: options.workflowPhase,
      phase: "prepared",
      state_digest: stateDigest,
      artifact_paths: options.referencedArtifacts.slice(0, 64),
      staged_artifact_paths: options.stagedOperationId === undefined ? [] : [`${STAGING_DIRECTORY}/${options.stagedOperationId}`],
      artifact_digests: {},
      ...(options.stagedOperationId === undefined ? {} : { staged_operation_id: options.stagedOperationId }),
      ...(options.candidateId === undefined ? {} : { candidate_id: options.candidateId }),
      ...(options.packId === undefined ? {} : { pack_id: options.packId }),
      diagnostics: [],
      created_at: now,
      updated_at: now,
    };
  }

  private async readRecoveryRecords(runId: RunId): Promise<readonly WorkflowCommitRecord[]> {
    const paths = await this.artifacts.listArtifactPaths(runId, RECOVERY_DIRECTORY);
    const records: WorkflowCommitRecord[] = [];
    for (const path of paths) {
      if (!path.endsWith(".json")) continue;
      const raw = await this.artifacts.readArtifact(runId, path);
      if (raw === undefined) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw) as unknown;
      } catch (error: unknown) {
        throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Workflow recovery metadata is not valid JSON", false, { runId, path, reason: error instanceof Error ? error.message : "invalid json" });
      }
      records.push(parseRecovery(parsed, path));
    }
    return records;
  }

  private async writeRecovery(record: WorkflowCommitRecord): Promise<void> {
    await this.writeArtifact(record.run_id, recoveryPath(record.operation_id), `${JSON.stringify(record, null, 2)}\n`);
  }

  private async tryWriteRecovery(record: WorkflowCommitRecord): Promise<void> {
    try {
      await this.writeRecovery(record);
    } catch {
      // The authoritative state is already committed when this is called.
      // Reconciliation can reconstruct the projection even if this marker is unavailable.
    }
  }
}

function digestState(state: QueryWorkflowState): string {
  return stableDigest(JSON.stringify(state));
}

function cancelledBeforeCommit(runId: RunId, operationId: string): DomainError {
  return new DomainError("PROCESS_CANCELLED", "process", "Workflow operation was cancelled before the domain commit point", false, { runId, operationId, commitPointReached: false });
}

function diagnosticCode(error: unknown): string {
  return asDomainError(error).code.slice(0, 96);
}
