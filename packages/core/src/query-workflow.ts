import {
  asDomainError,
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryCandidateSchema,
  QueryCandidateInputSchema,
  QueryPackManifestSchema,
  ProbeEvidenceSchema,
  QueryDraftReportSchema,
  QueryVerificationSchema,
  VulnerabilitySpecSchema,
  QueryWorkflowStartInputSchema,
  QueryWorkflowStateSchema,
  QueryWorkflowStatusSchema,
  RunIdSchema,
  withRunId,
  type QueryCandidate,
  type CaseRunSummary,
  type QueryDiagnostic,
  type QueryPackManifest,
  type QueryVerification,
  type QueryWorkflowState,
  type QueryWorkflowStatus,
  type ProbeEvidence,
  type QueryDraftReport,
  type RunId,
  type VulnerabilitySpec,
  type DatabaseManifest,
  stableDigest,
} from "@pure-auto-codeql/contracts";

import type {
  ArtifactStorePort,
  ClockPort,
  CodeqlOperationOptions,
  CodeqlPort,
  QueryExecutionPort,
  QueryExecutionResult,
  QueryProbeExecutionPort,
  QueryDraftExecutionPort,
} from "./ports.js";
import { RunStatusService } from "./status-service.js";
import { normalizeQueryCandidate } from "./query-candidate.js";
import { languagePackFor, normalizeTaintIntent, qlpackForLanguage } from "./language-packs.js";

const STATE_PATH = "workflow/state.json";
export class QueryWorkflowService {
  constructor(
    private readonly statusService: RunStatusService,
    private readonly codeql: CodeqlPort,
    private readonly queries: QueryExecutionPort,
    private readonly probes: QueryProbeExecutionPort,
    private readonly drafts: QueryDraftExecutionPort,
    private readonly artifacts: ArtifactStorePort,
    private readonly clock: ClockPort,
  ) {}

  async close(): Promise<void> {
    await this.drafts.close?.();
  }

  async start(input: unknown, options: CodeqlOperationOptions = { timeoutMs: 30_000 }): Promise<QueryWorkflowStatus> {
    const spec = parseSchema(QueryWorkflowStartInputSchema, input, "vulnerability spec");
    if (spec.vulnerability_description === undefined && spec.patch_description === undefined) {
      throw new DomainError("INVALID_INPUT", "input", "VulnerabilitySpec requires a vulnerability description or patch description", false, {
        specId: spec.spec_id,
      });
    }
    if (spec.input_provenance === "user_provided" && spec.project_root === undefined) {
      throw new DomainError("INVALID_INPUT", "input", "User-provided vulnerability cases require project_root so Pi can inspect the supplied source", false, {
        specId: spec.spec_id,
      });
    }
    assertStrictSemanticLocations(spec);
    assertSupportedSemanticKinds(spec);
    this.codeql.setTrustedRoots?.([
      ...(spec.project_root === undefined ? [] : [spec.project_root]),
      spec.vulnerable_database.path,
      ...(spec.fixed_database === undefined ? [] : [spec.fixed_database.path]),
    ]);
    const databaseOptions: CodeqlOperationOptions = {
      timeoutMs: Math.min(options.timeoutMs, spec.timeout_ms),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    };
    let createdRunId: RunId | undefined;
    let persistedSpec: VulnerabilitySpec;
    try {
      persistedSpec = await this.inspectAndPersistSpec(spec, databaseOptions);
    } catch (error: unknown) {
      // Admission now happens before the canonical case lock so aliases share
      // one budget. Preserve the existing run-level cancellation/error
      // contract when database inspection itself fails.
      const run = await this.statusService.create();
      createdRunId = run.runId;
      const domainError = asDomainError(error);
      const withId = withRunId(domainError, run.runId);
      const failureSpec: VulnerabilitySpec = {
        ...spec,
        draft_revision_budget: spec.draft_revision_budget ?? 6,
      };
      const failureFingerprint = caseFingerprintFor(failureSpec);
      await this.writeState(run.runId, {
        schema_version: CONTRACTS_VERSION,
        case_fingerprint: failureFingerprint,
        spec: failureSpec,
        draft_revisions: 0,
        candidates: [],
        verifications: [],
      });
      if (withId.code === "PROCESS_CANCELLED") {
        await this.statusService.cancel(run.runId, withId.toRecord());
      } else {
        await this.statusService.fail(run.runId, withId.toRecord());
      }
      const summary = emptyCaseSummary(failureFingerprint, run.runId, failureSpec.max_rounds, this.clock.now());
      const { active_run_id: _activeRunId, ...withoutActiveRun } = summary;
      await this.artifacts.saveCaseSummary({
        ...withoutActiveRun,
        status: withId.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
        final_run_id: run.runId,
        final_phase: "workflow_start",
        finalized: false,
      });
      throw withId;
    }
    const caseFingerprint = caseFingerprintFor(persistedSpec);
    try {
      return await this.artifacts.withCaseLock(caseFingerprint, async () => {
        let existingSummary = await this.artifacts.findCaseSummary(caseFingerprint);
        if (existingSummary?.status === "active" && existingSummary.active_run_id !== undefined) {
          const activeRun = await this.artifacts.findManifest(existingSummary.active_run_id);
          if (activeRun === undefined || isTerminalRunStatus(activeRun.status)) {
            const { active_run_id: _activeRunId, ...withoutActiveRun } = existingSummary;
            const recoveredStatus = activeRun?.status === "cancelled" ? "cancelled"
              : activeRun?.status === "completed" ? "completed"
                : activeRun?.status === "budget_exhausted" ? "budget_exhausted"
                  : "failed";
            existingSummary = {
              ...withoutActiveRun,
              status: recoveredStatus,
              final_run_id: existingSummary.active_run_id,
              final_phase: activeRun?.phase ?? "workflow_start",
              finalized: recoveredStatus === "completed" ? existingSummary.finalized : false,
              updated_at: this.clock.now(),
            };
            await this.artifacts.saveCaseSummary(existingSummary);
          }
        }
        const existingRunId = existingSummary?.status === "active"
          ? existingSummary.active_run_id
          : existingSummary?.status === "completed" || existingSummary?.status === "budget_exhausted"
            ? existingSummary.final_run_id
            : undefined;
        if (existingRunId !== undefined) {
          return this.status(existingRunId);
        }

        const run = await this.statusService.create();
        createdRunId = run.runId;

        try {
          await this.statusService.start(run.runId, "workflow_start");
          const state: QueryWorkflowState = {
            schema_version: CONTRACTS_VERSION,
            case_fingerprint: caseFingerprint,
            spec: persistedSpec,
            draft_revisions: 0,
            candidates: [],
            verifications: [],
          };
          await this.writeState(run.runId, state);
          const initialSummary = emptyCaseSummary(caseFingerprint, run.runId, persistedSpec.max_rounds, this.clock.now());
          await this.artifacts.saveCaseSummary({
            ...initialSummary,
            run_ids: [...(existingSummary?.run_ids ?? []), run.runId],
          });
          return this.status(run.runId);
        } catch (error: unknown) {
          const domainError = asDomainError(error);
          const record = withRunId(domainError, run.runId).toRecord();
          if (domainError.code === "PROCESS_CANCELLED") {
            await this.statusService.cancel(run.runId, record).catch(() => undefined);
          } else {
            await this.statusService.fail(run.runId, record).catch(() => undefined);
          }
          const terminalSummary = emptyCaseSummary(caseFingerprint, run.runId, persistedSpec.max_rounds, this.clock.now());
          const { active_run_id: _activeRunId, ...withoutActiveRun } = terminalSummary;
          await this.artifacts.saveCaseSummary({
            ...withoutActiveRun,
            run_ids: [...(existingSummary?.run_ids ?? []), run.runId],
            status: domainError.code === "PROCESS_CANCELLED" ? "cancelled" : "failed",
            final_run_id: run.runId,
            final_phase: "workflow_start",
            finalized: false,
            updated_at: this.clock.now(),
          });
          throw domainError;
        }
      });
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      if (createdRunId !== undefined && domainError.details.runId !== createdRunId && domainError.code !== "WORKFLOW_BUSY") {
        const withId = withRunId(domainError, createdRunId);
        if (withId.code === "PROCESS_CANCELLED") {
          await this.statusService.cancel(createdRunId, withId.toRecord()).catch(() => undefined);
        } else {
          await this.statusService.fail(createdRunId, withId.toRecord()).catch(() => undefined);
        }
        throw withId;
      }
      throw createdRunId === undefined ? domainError : withRunId(domainError, createdRunId);
    }
  }

  private async inspectAndPersistSpec(
    spec: VulnerabilitySpec,
    options: CodeqlOperationOptions,
  ): Promise<VulnerabilitySpec> {
    const vulnerableManifest = await this.codeql.inspectDatabase(spec.vulnerable_database.path, options);
    assertDatabaseLanguage(spec, spec.vulnerable_database.path, vulnerableManifest);
    const fixedManifest = spec.fixed_database === undefined
      ? undefined
      : await this.codeql.inspectDatabase(spec.fixed_database.path, options);
    if (fixedManifest !== undefined) {
      assertDatabaseLanguage(spec, spec.fixed_database?.path ?? "", fixedManifest);
    }
    return {
      ...spec,
      draft_revision_budget: spec.draft_revision_budget ?? 6,
      vulnerable_database: databaseRefWithManifest(spec.vulnerable_database, vulnerableManifest),
      ...(spec.fixed_database === undefined || fixedManifest === undefined ? {} : {
        fixed_database: databaseRefWithManifest(spec.fixed_database, fixedManifest),
      }),
    };
  }

  async status(input: unknown): Promise<QueryWorkflowStatus> {
    const runId = parseSchema(RunIdSchema, input, "run id");
    let run = await this.statusService.get(runId);
    const state = await this.readState(runId);
    const latest = state.verifications[state.verifications.length - 1];
    let caseSummary = await this.caseSummaryFor(state, run);
    if (caseSummary.status === "budget_exhausted" && run.status !== "budget_exhausted") {
      const exhausted = new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The case candidate budget has been exhausted", false, {
        caseFingerprint: state.case_fingerprint,
        runId,
        maxCandidates: state.spec.max_rounds,
      });
      await this.statusService.exhaust(runId, exhausted.toRecord());
      run = await this.statusService.get(runId);
      const { active_run_id: _activeRunId, ...withoutActiveRun } = caseSummary;
      caseSummary = {
        ...withoutActiveRun,
        status: "budget_exhausted",
        final_run_id: runId,
        final_phase: "query_verify",
        finalized: false,
        updated_at: this.clock.now(),
      };
      await this.artifacts.withCaseLock(state.case_fingerprint, async () => {
        await this.artifacts.saveCaseSummary(caseSummary);
      });
    }
    return parseSchema(
      QueryWorkflowStatusSchema,
      {
        schema_version: CONTRACTS_VERSION,
        run: {
          runId: run.runId,
          status: run.status,
          ...(run.phase === undefined ? {} : { phase: run.phase }),
          verificationLevel: run.verificationLevel,
        },
        case_summary: caseSummary,
        spec: state.spec,
        candidates: state.candidates,
        verifications: state.verifications,
        ...(latest === undefined ? {} : { latest_verification: latest }),
        ...(state.pack === undefined ? {} : { pack: state.pack }),
      },
      "query workflow status",
    );
  }

  async probe(inputRunId: unknown, inputIntent: unknown, options: CodeqlOperationOptions): Promise<ProbeEvidence> {
    const runId = parseSchema(RunIdSchema, inputRunId, "run id");
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
        const state = await this.readState(runId);
        const intent = normalizeTaintIntent(inputIntent, state.spec.language);
        const run = await this.statusService.get(runId);
        if (run.status === "completed" || run.status === "failed" || run.status === "cancelled" || run.status === "budget_exhausted") {
          throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot probe in ${run.status} run`, false, { runId, status: run.status });
        }
        if (run.status === "created" || run.status === "checkpointed") {
          await this.statusService.start(runId, "query_probe");
        }
        const probeOptions = options.signal === undefined
          ? { timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) }
          : { signal: options.signal, timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) };
        const evidence = parseSchema(
          ProbeEvidenceSchema,
          await this.probes.executeProbe({
            runId,
            intent,
            spec: state.spec,
            artifactRoot: this.artifacts.artifactRoot(runId),
          }, probeOptions),
          "probe evidence",
        );
        await this.artifacts.writeArtifact(runId, `probes/${intent.intent_id}/probe-evidence.json`, `${JSON.stringify(evidence, null, 2)}\n`);
        return evidence;
      });
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      const withId = withRunId(domainError, runId);
      if (withId.code === "PROCESS_CANCELLED" && withId.details.waitingForWorkflowLease !== true) {
        await this.statusService.cancel(runId, withId.toRecord()).catch(() => undefined);
      } else if (withId.category === "input") {
        // A malformed intent is a repairable Pi input error. Keep the workflow
        // alive so the host Agent Loop can correct the structured intent and
        // probe again without consuming a candidate round.
      } else if (withId.code !== "WORKFLOW_BUSY") {
        await this.statusService.fail(runId, withId.toRecord()).catch(() => undefined);
      }
      throw withId;
    }
  }

  async verify(inputRunId: unknown, inputCandidate: unknown, options: CodeqlOperationOptions): Promise<QueryVerification> {
    const runId = parseSchema(RunIdSchema, inputRunId, "run id");
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
    const state = await this.readState(runId);
    let candidate = withCandidateDigest(normalizeQueryCandidate(inputCandidate, state.spec));
    candidate = await this.hydrateProbeEvidence(runId, candidate);
    assertCandidateLanguage(candidate, state.spec);
    if (candidate.spec_id !== state.spec.spec_id) {
      throw new DomainError("INVALID_INPUT", "input", "Query candidate does not belong to this vulnerability spec", false, {
        runId,
        candidateSpecId: candidate.spec_id,
        specId: state.spec.spec_id,
      });
    }
    assertCandidateSemanticKinds(candidate, state.spec);
    assertCandidateSemanticLocations(candidate, state.spec);
    assertCandidateProbeForUserCase(candidate, state.spec);
    if (candidate.round > state.spec.max_rounds) {
      throw new DomainError("INVALID_INPUT", "input", "Query candidate exceeds the workflow round budget", false, {
        runId,
        round: candidate.round,
        maxRounds: state.spec.max_rounds,
      });
    }

    const existingCandidate = state.candidates.find((item) => item.candidate_id === candidate.candidate_id);
    const existingIndex = existingCandidate === undefined ? -1 : state.candidates.indexOf(existingCandidate);
    const existing = state.verifications.find((item) => item.candidate_id === candidate.candidate_id);
    const draftArtifact = await this.artifacts.readArtifact(runId, `drafts/${candidate.candidate_id}/report.json`);
    if (draftArtifact !== undefined) {
      let draft: QueryDraftReport;
      try {
        draft = parseSchema(QueryDraftReportSchema, JSON.parse(draftArtifact) as unknown, "query draft report");
      } catch (error: unknown) {
        throw new DomainError("ARTIFACT_CORRUPT", "artifact", "The LSP draft report is not valid", false, {
          runId,
          candidateId: candidate.candidate_id,
          reason: error instanceof Error ? error.message : String(error),
        });
      }
      if (draft.status === "errors" || draft.status === "cancelled") {
        throw new DomainError("QUERY_DRAFT_INVALID", "input", "The candidate has unresolved LSP draft diagnostics; revise it before CLI verification", true, {
          runId,
          candidateId: candidate.candidate_id,
          draftStatus: draft.status,
          diagnostics: draft.diagnostics,
        });
      }
    }
    if (existingCandidate !== undefined && candidateDigest(existingCandidate) !== candidate.candidate_digest) {
      throw new DomainError("QUERY_INVALID_CANDIDATE", "input", "Candidate id was already used with different content", false, {
        runId,
        candidateId: candidate.candidate_id,
      });
    }
    if (existing !== undefined) {
      return existing;
    }
    if (existingIndex < 0 && state.candidates.length >= state.spec.max_rounds) {
      throw new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The query candidate round budget has been exhausted", false, {
        runId,
        maxRounds: state.spec.max_rounds,
      });
    }

    const run = await this.statusService.get(runId);
    if (run.status === "completed" || run.status === "failed" || run.status === "cancelled" || run.status === "budget_exhausted") {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot verify a candidate in ${run.status} run`, false, {
        runId,
        status: run.status,
      });
    }
    if (run.status === "checkpointed" || run.status === "created") {
      await this.statusService.start(runId, "query_verify");
    }

    await this.artifacts.writeArtifact(runId, `candidates/${candidate.candidate_id}/query.ql`, candidate.ql_text);
    await this.artifacts.writeArtifact(runId, `candidates/${candidate.candidate_id}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language));
    await this.artifacts.writeArtifact(runId, `candidates/${candidate.candidate_id}/candidate.json`, `${JSON.stringify(candidate, null, 2)}\n`);

    let execution: QueryExecutionResult;
    try {
      const queryOptions = options.signal === undefined
        ? { timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) }
        : { signal: options.signal, timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) };
      execution = await this.queries.execute(
        { runId, candidate, spec: state.spec, artifactRoot: this.artifacts.artifactRoot(runId) },
        queryOptions,
      );
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      const withId = domainError.details.runId === runId
        ? domainError
        : new DomainError(domainError.code, domainError.category, domainError.message, domainError.retryable, {
            ...domainError.details,
            runId,
          });
      if (withId.code === "PROCESS_CANCELLED") {
        await this.statusService.cancel(runId, withId.toRecord());
      } else {
        await this.statusService.fail(runId, withId.toRecord());
      }
      throw withId;
    }

    const baseVerification = this.evaluate(runId, candidate, state.spec, execution);
    const nextState: QueryWorkflowState = {
      ...state,
      candidates: existingCandidate === undefined
        ? [...state.candidates, candidate]
        : state.candidates.map((item) => item.candidate_id === candidate.candidate_id ? candidate : item),
      verifications: [...state.verifications, baseVerification],
    };

    if (baseVerification.status === "passed") {
      await this.statusService.checkpoint(runId, "query_verify", baseVerification.verification_level);
    }
    let caseSummary = await this.updateCaseSummary(nextState, runId, baseVerification);
    const exhausted = baseVerification.status === "failed" && nextState.candidates.length >= state.spec.max_rounds;
    if (exhausted) {
      const exhaustionError = new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The case candidate budget has been exhausted", false, {
        caseFingerprint: state.case_fingerprint,
        runId,
        maxCandidates: state.spec.max_rounds,
      });
      await this.statusService.exhaust(runId, exhaustionError.toRecord());
      caseSummary = await this.updateCaseSummary(nextState, runId, baseVerification, "budget_exhausted");
    }
    const terminalReason = baseVerification.status === "passed" ? "candidate_passed"
      : baseVerification.status === "cancelled" ? "cancelled"
        : exhausted ? "budget_exhausted" : "candidate_failed";
    const verification = parseSchema(
      QueryVerificationSchema,
      {
        ...baseVerification,
        case_summary: compactCaseSummary(caseSummary),
        terminal_reason: terminalReason,
      },
      "query verification",
    );
    const finalState: QueryWorkflowState = {
      ...nextState,
      verifications: nextState.verifications.map((item) => item.candidate_id === candidate.candidate_id ? verification : item),
    };
    await this.artifacts.writeArtifact(runId, `candidates/${candidate.candidate_id}/verification.json`, `${JSON.stringify(verification, null, 2)}\n`);
    await this.writeState(runId, finalState);
    return verification;
      });
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      if (domainError.code === "PROCESS_CANCELLED" && domainError.details.waitingForWorkflowLease !== true) {
        const withId = withRunId(domainError, runId);
        await this.statusService.cancel(runId, withId.toRecord()).catch(() => undefined);
        throw withId;
      }
      if (domainError.code === "PROCESS_CANCELLED") {
        throw withRunId(domainError, runId);
      }
      throw domainError;
    }
  }

  /** Run advisory LSP validation without adding a formal candidate or using the case budget. */
  async draft(inputRunId: unknown, inputCandidate: unknown, options: CodeqlOperationOptions): Promise<QueryDraftReport> {
    const runId = parseSchema(RunIdSchema, inputRunId, "run id");
    try {
      return await this.artifacts.withRunOperation(runId, options, async () => {
        const state = await this.readState(runId);
        let candidate = withCandidateDigest(normalizeQueryCandidate(inputCandidate, state.spec));
        candidate = await this.hydrateProbeEvidence(runId, candidate);
        assertCandidateLanguage(candidate, state.spec);
        if (candidate.spec_id !== state.spec.spec_id) {
          throw new DomainError("INVALID_INPUT", "input", "Query draft does not belong to this vulnerability spec", false, {
            runId,
            candidateSpecId: candidate.spec_id,
            specId: state.spec.spec_id,
          });
        }
        assertCandidateProbeForUserCase(candidate, state.spec);
        const run = await this.statusService.get(runId);
        if (["completed", "failed", "cancelled", "budget_exhausted"].includes(run.status)) {
          throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot draft in ${run.status} run`, false, {
            runId,
            status: run.status,
          });
        }
        if (run.status === "created" || run.status === "checkpointed") {
          await this.statusService.start(runId, "query_draft");
        }
        const draftRevisionBudget = state.spec.draft_revision_budget ?? 6;
        const revision = (state.draft_revisions ?? 0) + 1;
        if (revision > draftRevisionBudget) {
          throw new DomainError("QUERY_BUDGET_EXCEEDED", "policy", "The LSP draft revision budget has been exhausted", false, {
            runId,
            maxDraftRevisions: draftRevisionBudget,
          });
        }
        await this.writeState(runId, { ...state, draft_revisions: revision });
        await this.artifacts.writeArtifact(runId, `drafts/${candidate.candidate_id}/query.ql`, candidate.ql_text);
        await this.artifacts.writeArtifact(runId, `drafts/${candidate.candidate_id}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language));
        await this.artifacts.writeArtifact(runId, `drafts/${candidate.candidate_id}/candidate.json`, `${JSON.stringify(candidate, null, 2)}\n`);
        const draftOptions = options.signal === undefined
          ? { timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) }
          : { signal: options.signal, timeoutMs: Math.min(options.timeoutMs, state.spec.timeout_ms) };
        const report = parseSchema(
          QueryDraftReportSchema,
          await this.drafts.executeDraft({
            runId,
            candidate,
            spec: state.spec,
            artifactRoot: this.artifacts.artifactRoot(runId),
            revision,
            draftRevisionBudget,
          }, draftOptions),
          "query draft report",
        );
        await this.artifacts.writeArtifact(runId, `drafts/${candidate.candidate_id}/report.json`, `${JSON.stringify(report, null, 2)}\n`);
        return report;
      });
    } catch (error: unknown) {
      const domainError = asDomainError(error);
      const withId = withRunId(domainError, runId);
      if (withId.code === "PROCESS_CANCELLED" && withId.details.waitingForWorkflowLease !== true) {
        await this.statusService.cancel(runId, withId.toRecord()).catch(() => undefined);
      } else if (withId.category !== "input" && withId.code !== "WORKFLOW_BUSY" && withId.code !== "QUERY_BUDGET_EXCEEDED") {
        await this.statusService.fail(runId, withId.toRecord()).catch(() => undefined);
      }
      throw withId;
    }
  }

  async finalize(input: unknown, options: CodeqlOperationOptions = { timeoutMs: 30_000 }): Promise<QueryPackManifest> {
    const runId = parseSchema(RunIdSchema, input, "run id");
    return this.artifacts.withRunOperation(runId, options, async () => {
    const state = await this.readState(runId);
    const verification = [...state.verifications].reverse().find((item) => item.status === "passed");
    if (verification === undefined) {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", "A passed query verification is required before finalization", false, {
        runId,
      });
    }
    const candidate = state.candidates.find((item) => item.candidate_id === verification.candidate_id);
    if (candidate === undefined) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Verification references a missing query candidate", false, {
        runId,
        candidateId: verification.candidate_id,
      });
    }
    const packRoot = "query-pack";
    const queryText = candidate.ql_text;
    const specText = `${JSON.stringify(state.spec, null, 2)}\n`;
    const verificationText = `${JSON.stringify(verification, null, 2)}\n`;
    const candidateText = `${JSON.stringify(candidate, null, 2)}\n`;
    const intentText = candidate.intent === undefined ? undefined : `${JSON.stringify(candidate.intent, null, 2)}\n`;
    const evidence = {
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      candidate_id: candidate.candidate_id,
      vulnerable: verification.vulnerable,
      fixed: verification.fixed,
      diagnostics: verification.diagnostics,
    };
    const evidenceText = `${JSON.stringify(evidence, null, 2)}\n`;
    const pack = parseSchema(
      QueryPackManifestSchema,
      {
        schema_version: CONTRACTS_VERSION,
        pack_id: `pack-${runId}-${candidate.query_id}`,
        run_id: runId,
        spec_id: state.spec.spec_id,
        query_id: candidate.query_id,
        language: state.spec.language,
        cwe: state.spec.cwe,
        provenance: state.spec.provenance.source,
        files: {
          query: "query.ql",
          candidate: "candidate.json",
          spec: "spec.json",
          verification: "verification.json",
          qlpack: "qlpack.yml",
          evidence: "evidence.json",
          reproduce: "REPRODUCE.md",
          manifest: "query-pack-manifest.json",
          ...(candidate.intent === undefined ? {} : { exact: "exact.ql", intent: "intent.json" }),
          ...(candidate.probe_evidence === undefined ? {} : { probe_evidence: "probe-evidence.json" }),
        },
        replay: {
          working_directory: ".",
          compile: ["codeql", "query", "compile", "query.ql", "--threads=1"],
          vulnerable: ["codeql", "database", "analyze", "<vulnerable_database>", "query.ql", "--rerun", "--format=sarif-latest", "--output=vulnerable.sarif", "--threads=1"],
          ...(state.spec.fixed_database === undefined ? {} : {
            fixed: ["codeql", "database", "analyze", "<fixed_database>", "query.ql", "--rerun", "--format=sarif-latest", "--output=fixed.sarif", "--threads=1"],
          }),
          databases: {
            vulnerable: state.spec.vulnerable_database.path,
            ...(state.spec.fixed_database === undefined ? {} : { fixed: state.spec.fixed_database.path }),
          },
        },
        verification,
        integrity: {
          query: stableDigest(queryText),
          candidate: stableDigest(candidateText),
          spec: stableDigest(specText),
          verification: stableDigest(verificationText),
        },
        created_at: this.clock.now(),
        platform: "posix",
      },
      "query pack manifest",
    );
    await this.artifacts.writeArtifact(runId, `${packRoot}/query.ql`, queryText);
    await this.artifacts.writeArtifact(runId, `${packRoot}/candidate.json`, candidateText);
    await this.artifacts.writeArtifact(runId, `${packRoot}/spec.json`, specText);
    await this.artifacts.writeArtifact(runId, `${packRoot}/verification.json`, verificationText);
    await this.artifacts.writeArtifact(runId, `${packRoot}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language));
   await this.artifacts.writeArtifact(runId, `${packRoot}/evidence.json`, evidenceText);
    if (intentText !== undefined) {
      await this.artifacts.writeArtifact(runId, `${packRoot}/exact.ql`, queryText);
      await this.artifacts.writeArtifact(runId, `${packRoot}/intent.json`, intentText);
    }
    if (candidate.probe_evidence !== undefined) {
      await this.artifacts.writeArtifact(runId, `${packRoot}/probe-evidence.json`, `${JSON.stringify(candidate.probe_evidence, null, 2)}\n`);
    }
    await this.artifacts.writeArtifact(runId, `${packRoot}/REPRODUCE.md`, `# Reproduce\n\nRun from the Query Pack directory:\n\n\`codeql query compile query.ql --threads=1\`\n\n\`codeql database analyze <vulnerable_database> query.ql --rerun --format=sarif-latest --output=vulnerable.sarif --threads=1\`\n${state.spec.fixed_database === undefined ? "" : "\n\`codeql database analyze <fixed_database> query.ql --rerun --format=sarif-latest --output=fixed.sarif --threads=1\`\n"}\nThe original vulnerable database path was: ${state.spec.vulnerable_database.path}\n${state.spec.fixed_database === undefined ? "No fixed database was provided.\n" : `The original fixed database path was: ${state.spec.fixed_database.path}\n`}For relocated replay use: pure-auto-codeql query-pack verify <pack-dir> --vulnerable-db <path> [--fixed-db <path>]\nWhen the Query Pack and databases share a non-root directory, the CLI infers that directory as the trusted workspace. Use --workspace-root <path> when they are in separate locations.\n`);
    await this.artifacts.writeArtifact(runId, `${packRoot}/query-pack-manifest.json`, `${JSON.stringify(pack, null, 2)}\n`);
    await this.writeState(runId, { ...state, pack });
    await this.statusService.complete(runId, verification.verification_level, "workflow_finalize");
    await this.updateCaseSummary({ ...state, pack }, runId, verification, "completed", pack.pack_id);
    return pack;
    });
  }

  private evaluate(
    runId: RunId,
    candidate: QueryCandidate,
    spec: VulnerabilitySpec,
    execution: QueryExecutionResult,
  ): QueryVerification {
    const fixedObservation = spec.fixed_database === undefined ? notRunFixedObservation() : execution.fixed;
    const diagnostics: QueryDiagnostic[] = deduplicateDiagnostics(execution.diagnostics);
    if (execution.compile.status !== "passed") {
      if (!diagnostics.some((item) => item.code === "QUERY_COMPILE_FAILED")) {
        diagnostics.push(this.diagnostic("QUERY_COMPILE_FAILED", "compile", "Query compilation failed", candidate, runId));
      }
      return this.buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, {
        stage: diagnostics.some((item) => item.stage === "preflight") ? "preflight" : "compile",
        root_causes: diagnostics.map((item) => item.code),
        hints: [compileRepairHint(spec, candidate)],
        next_action: "revise_candidate",
      });
    }
    if (execution.vulnerable.status !== "passed") {
      if (!diagnostics.some((item) => item.code === "QUERY_ANALYZE_FAILED" || item.code === "QUERY_PROCESS_TIMEOUT" || item.code === "QUERY_PROCESS_CANCELLED" || item.code === "QUERY_PROCESS_CRASHED")) {
        diagnostics.push(this.diagnostic("QUERY_ANALYZE_FAILED", "vulnerable", "Vulnerable database analysis failed", candidate, runId));
      }
      return this.buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, {
        stage: "vulnerable",
        root_causes: diagnostics.map((item) => item.code),
        hints: ["The fixed database was not run because vulnerable analysis failed. Repair the candidate and submit one replacement draft."],
        next_action: "revise_candidate",
      });
    }
    if (!within(execution.vulnerable.result_count, spec.validation.vulnerable_min_results, spec.validation.vulnerable_max_results)) {
      diagnostics.push(this.diagnostic("QUERY_RESULT_MISMATCH", "vulnerable", "Vulnerable database result count is outside the manifest policy", candidate, runId, {
        resultCount: execution.vulnerable.result_count,
        minimum: spec.validation.vulnerable_min_results,
        maximum: spec.validation.vulnerable_max_results,
      }));
    }
    if (spec.validation.must_have_code_flow && execution.vulnerable.code_flow_count < 1) {
      diagnostics.push(this.diagnostic("QUERY_CODE_FLOW_MISSING", "vulnerable", "Vulnerable database did not produce a source-to-sink code flow", candidate, runId));
    }
    if (spec.validation.expected_rule_ids !== undefined) {
      const observed = new Set(execution.vulnerable.rule_ids);
      const missing = spec.validation.expected_rule_ids.filter((ruleId) => !observed.has(ruleId));
      if (missing.length > 0) {
        diagnostics.push(this.diagnostic("QUERY_VULNERABLE_EXPECTATION_FAILED", "vulnerable", "Vulnerable result rule ids do not satisfy the manifest expectation", candidate, runId, {
          missingRuleIds: missing,
          observedRuleIds: execution.vulnerable.rule_ids,
        }));
      }
    }
    const semanticExpectations = [
      ...(spec.validation.source === undefined ? [] : [["source", spec.validation.source] as const]),
      ...(spec.validation.sink === undefined ? [] : [["sink", spec.validation.sink] as const]),
    ];
    if (semanticExpectations.length > 0) {
      const matchingFlow = execution.vulnerable.flow_evidence.find((flow) => semanticExpectations.every(([role, expectation]) => {
        const endpoint = role === "source" ? flow.source : flow.sink;
        const endpointLocations = endpoint === undefined ? flow.path : [endpoint];
        return endpointLocations.some((location) => locationMatches(expectation.file, expectation.line, location))
          || (expectation.file === undefined && expectation.line === undefined && execution.vulnerable.semantic_matches.some((match) =>
            match.role === role && match.label.toLowerCase().includes(expectation.label.toLowerCase())));
      }));
      if (matchingFlow === undefined) {
        diagnostics.push(this.diagnostic("QUERY_SEMANTIC_MISMATCH", "vulnerable", "Vulnerable code flow does not match the manifest Source/Sink expectation", candidate, runId, {
          expected: semanticExpectations.map(([role, expectation]) => ({ role, file: expectation.file, line: expectation.line, label: expectation.label })),
          observedFlows: execution.vulnerable.flow_evidence,
          observedSemanticMatches: execution.vulnerable.semantic_matches,
        }));
      }
    }
    if (spec.input_provenance === "user_provided" && candidate.probe_evidence?.status === "passed") {
      const probeSource = candidate.probe_evidence.source.locations;
      const probeSink = candidate.probe_evidence.sink.locations;
      const matchingProbeFlow = execution.vulnerable.flow_evidence.find((flow) => {
        const sourceLocations = flow.source === undefined
          ? flow.path.slice(0, 1)
          : [flow.source];
        const sinkLocations = flow.sink === undefined
          ? flow.path.slice(-1)
          : [flow.sink];
        return sourceLocations.some((actual) => probeSource.some((expected) => locationMatches(expected.file, expected.start_line, actual)))
          && sinkLocations.some((actual) => probeSink.some((expected) => locationMatches(expected.file, expected.start_line, actual)));
      });
      if (matchingProbeFlow === undefined) {
        diagnostics.push(this.diagnostic("QUERY_SEMANTIC_MISMATCH", "vulnerable", "Vulnerable code flow does not connect the probed Source and Sink", candidate, runId, {
          expectedProbeSource: probeSource,
          expectedProbeSink: probeSink,
          observedFlows: execution.vulnerable.flow_evidence,
        }));
      }
    }
    if (spec.fixed_database === undefined) {
      diagnostics.push({
        schema_version: CONTRACTS_VERSION,
        code: "QUERY_DIFFERENTIAL_NOT_RUN",
        severity: "warning",
        message: "No fixed database was provided; differential verification was not run",
        retryable: false,
        candidate_id: candidate.candidate_id,
        run_id: runId,
        stage: "fixed",
        details: { suggestion: "Provide a fixed database to obtain differential verification" },
      });
    } else if (execution.fixed.status === "passed") {
      if (!within(execution.fixed.result_count, spec.validation.fixed_min_results, spec.validation.fixed_max_results)) {
        diagnostics.push(this.diagnostic(execution.fixed.result_count > 0 ? "QUERY_FIXED_FALSE_POSITIVE" : "QUERY_FIXED_DATABASE_MISMATCH", "fixed", "Fixed database result count is outside the manifest policy", candidate, runId, {
          resultCount: execution.fixed.result_count,
          minimum: spec.validation.fixed_min_results,
          maximum: spec.validation.fixed_max_results,
        }));
      }
    } else if (execution.fixed.status === "failed") {
      diagnostics.push(this.diagnostic("QUERY_ANALYZE_FAILED", "fixed", "Fixed database analysis failed; no differential policy comparison was made", candidate, runId));
    }
    if (execution.vulnerable.result_count === 0 && spec.validation.vulnerable_min_results > 0) {
      diagnostics.push(this.diagnostic("QUERY_EMPTY_RESULT", "vulnerable", "Vulnerable database produced no result", candidate, runId));
    }
    const passed = (spec.fixed_database === undefined || fixedObservation.status === "passed")
      && diagnostics.every((diagnostic) => diagnostic.severity !== "error");
    const repairHints = ["Use the result and flow evidence above to revise the structured draft; do not regenerate fixed QL boilerplate."];
    if (diagnostics.some((item) => item.code === "QUERY_SEMANTIC_MISMATCH")) {
      repairHints.unshift("Keep the candidate Source/Sink aligned with the workflow validation Source/Sink frozen at start; use newly probed internal or intermediate endpoints only as directed additional_flow_steps.");
    }
    if (spec.language === "cpp" && candidate.probe_evidence?.status === "passed" && diagnostics.some((item) => item.code === "QUERY_CODE_FLOW_MISSING")) {
      repairHints.unshift("C/C++ probes can match a field/array/formal endpoint without the global flow graph bridging that node to a call argument. Preserve the frozen Source/Sink and add only probe-confirmed boundary edges as directed additional_flow_steps (for example property -> call_argument), then re-run vulnerable CLI verification.");
    }
    return this.buildVerification(runId, candidate, spec, execution, fixedObservation, diagnostics, passed ? {
      stage: "policy",
      root_causes: [],
      hints: [],
      next_action: "stop",
    } : {
      stage: execution.fixed.status === "passed" ? "policy" : "fixed",
      root_causes: diagnostics.map((item) => item.code),
      hints: repairHints,
      next_action: "revise_candidate",
    });
  }

  private buildVerification(
    runId: RunId,
    candidate: QueryCandidate,
    spec: VulnerabilitySpec,
    execution: QueryExecutionResult,
    fixedObservation: QueryExecutionResult["fixed"],
    diagnostics: QueryDiagnostic[],
    repairBrief: {
      stage: "preflight" | "compile" | "vulnerable" | "fixed" | "policy";
      root_causes: string[];
      hints: string[];
      next_action: "revise_candidate" | "retry_operation" | "stop";
    },
  ): QueryVerification {
    const passed = execution.compile.status === "passed"
      && execution.vulnerable.status === "passed"
      && (spec.fixed_database === undefined || fixedObservation.status === "passed")
      && diagnostics.every((diagnostic) => diagnostic.severity !== "error");
    return parseSchema(
      QueryVerificationSchema,
      {
        schema_version: CONTRACTS_VERSION,
        verification_id: `verification-${runId}-${candidate.candidate_id}`,
        run_id: runId,
        spec_id: spec.spec_id,
        candidate_id: candidate.candidate_id,
        round: candidate.round,
        status: passed ? "passed" : "failed",
        passed,
        verification_level: passed
          ? (spec.fixed_database === undefined ? "reproduced" : "differential")
          : execution.compile.status === "passed" ? "compiled" : "generated",
        compile: execution.compile,
        vulnerable: execution.vulnerable,
        fixed: fixedObservation,
        diagnostics,
        repair_brief: repairBrief,
        elapsed_ms: execution.elapsedMs,
        ...(execution.codeqlCliVersion === undefined ? {} : { codeql_cli_version: execution.codeqlCliVersion }),
        ...(execution.extractorInfo === undefined ? {} : { extractor_info: execution.extractorInfo }),
        cancelled: execution.cancelled ?? false,
        timed_out: execution.timedOut ?? false,
      },
      "query verification",
    );
  }

  private diagnostic(
    code: QueryDiagnostic["code"],
    stage: QueryDiagnostic["stage"],
    message: string,
    candidate: QueryCandidate,
    runId: RunId,
    details: Record<string, unknown> = {},
  ): QueryDiagnostic {
    return {
      schema_version: CONTRACTS_VERSION,
      code,
      severity: "error",
      message,
      retryable: false,
      candidate_id: candidate.candidate_id,
      run_id: runId,
      ...(stage === undefined ? {} : { stage }),
      details,
    };
  }

  private async caseSummaryFor(state: QueryWorkflowState, run: { runId: RunId; status: string }): Promise<CaseRunSummary> {
    const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
    if (existing !== undefined) {
      return existing;
    }
    return caseSummaryFromState(state, run, this.clock.now());
  }

  private async updateCaseSummary(
    state: QueryWorkflowState,
    runId: RunId,
    _verification: QueryVerification,
    statusOverride?: CaseRunSummary["status"],
    packId?: string,
  ): Promise<CaseRunSummary> {
    let saved: CaseRunSummary | undefined;
    await this.artifacts.withCaseLock(state.case_fingerprint, async () => {
      const run = await this.statusService.get(runId);
      const existing = await this.artifacts.findCaseSummary(state.case_fingerprint);
      const summary = caseSummaryFromState(state, run, this.clock.now(), existing, statusOverride, packId);
      await this.artifacts.saveCaseSummary(summary);
      saved = summary;
    });
    if (saved === undefined) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Case summary was not saved", false, {
        runId,
        caseFingerprint: state.case_fingerprint,
      });
    }
    return saved;
  }

  private async hydrateProbeEvidence(runId: RunId, candidate: QueryCandidate): Promise<QueryCandidate> {
    if (candidate.probe_evidence !== undefined || candidate.intent === undefined) {
      return candidate;
    }
    const artifact = await this.artifacts.readArtifact(runId, `probes/${candidate.intent.intent_id}/probe-evidence.json`);
    if (artifact === undefined) {
      return candidate;
    }
    const evidence = parseSchema(ProbeEvidenceSchema, JSON.parse(artifact) as unknown, "probe evidence");
    if (evidence.intent_id !== candidate.intent.intent_id) {
      return candidate;
    }
    return withCandidateDigest({ ...candidate, probe_evidence: evidence });
  }

  private async readState(runId: RunId): Promise<QueryWorkflowState> {
    const raw = await this.artifacts.readArtifact(runId, STATE_PATH);
    if (raw === undefined) {
      throw new DomainError("ARTIFACT_NOT_FOUND", "artifact", `Query workflow state for ${runId} was not found`, false, { runId });
    }
    try {
      const decoded = JSON.parse(raw) as unknown;
      return parseSchema(QueryWorkflowStateSchema, upgradeLegacyState(decoded), "query workflow state");
    } catch (error: unknown) {
      if (error instanceof DomainError && error.code === "INVALID_INPUT") {
        throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Query workflow state for ${runId} is invalid`, false, {
          runId,
          reason: error.message,
        });
      }
      throw error;
    }
  }

  private async tryReadState(runId: RunId): Promise<QueryWorkflowState | undefined> {
    const raw = await this.artifacts.readArtifact(runId, STATE_PATH);
    if (raw === undefined) {
      return undefined;
    }
    return parseSchema(QueryWorkflowStateSchema, upgradeLegacyState(JSON.parse(raw) as unknown), "query workflow state");
  }

  private async writeState(runId: RunId, state: QueryWorkflowState): Promise<void> {
    const parsed = parseSchema(QueryWorkflowStateSchema, state, "query workflow state");
    await this.artifacts.writeArtifact(runId, STATE_PATH, `${JSON.stringify(parsed, null, 2)}\n`);
  }
}

function within(value: number, minimum: number, maximum: number): boolean {
  return value >= minimum && value <= maximum;
}

function notRunFixedObservation(): QueryExecutionResult["fixed"] {
  return {
    database: "fixed",
    status: "not_run",
    result_count: 0,
    code_flow_count: 0,
    rule_ids: [],
    locations: [],
    flow_evidence: [],
    semantic_matches: [],
    elapsed_ms: 0,
  };
}

function withCandidateDigest(candidate: QueryCandidate): QueryCandidate {
  return { ...candidate, candidate_digest: candidateDigest(candidate) };
}

function assertCandidateProbeForUserCase(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  if (spec.input_provenance !== "user_provided" || candidate.origin === "cli" || candidate.origin === "test") {
    return;
  }
  if (candidate.intent === undefined) {
    throw new DomainError("PROBE_FAILED", "input", "Pi candidates for user-provided cases must carry a structured intent and probe evidence", false, {
      candidateId: candidate.candidate_id,
    });
  }
  const evidence = candidate.probe_evidence;
  if (evidence === undefined || evidence.status !== "passed" || evidence.intent_id !== candidate.intent.intent_id
    || evidence.source.locations.length === 0 || evidence.sink.locations.length === 0) {
    throw new DomainError("PROBE_FAILED", "input", "Source/Sink probe evidence is required and must contain both matched node locations before CLI verification", false, {
      candidateId: candidate.candidate_id,
      intentId: candidate.intent.intent_id,
      probeStatus: evidence?.status ?? "missing",
      sourceLocations: evidence?.source.locations.length ?? 0,
      sinkLocations: evidence?.sink.locations.length ?? 0,
    });
  }
}

function candidateDigest(candidate: QueryCandidate): string {
  return stableDigest(JSON.stringify({
    schema_version: candidate.schema_version,
    candidate_id: candidate.candidate_id,
    query_id: candidate.query_id,
    spec_id: candidate.spec_id,
    language: candidate.language,
    ql_text: candidate.ql_text,
    intent: candidate.intent,
    probe_evidence: candidate.probe_evidence,
    round: candidate.round,
    origin: candidate.origin,
    parent_candidate_id: candidate.parent_candidate_id,
    rationale: candidate.rationale,
  }));
}

function locationMatches(expectedFile: string | undefined, expectedLine: number | undefined, location: { file: string; start_line: number }): boolean {
  if (expectedFile === undefined || expectedLine === undefined) {
    return false;
  }
  const normalize = (value: string): string => value.replace(/^file:\/\//, "").replaceAll("\\", "/").replace(/^\.\//, "");
  const expected = normalize(expectedFile);
  const actual = normalize(location.file);
  // A directory-qualified expectation may be reported as an absolute path or
  // as a path relative to the database source root. A bare filename is never
  // enough evidence: accepting it would reintroduce basename fallback.
  const pathMatches = actual === expected
    || (expected.includes("/") && actual.endsWith(`/${expected}`));
  return pathMatches && location.start_line === expectedLine;
}

function assertStrictSemanticLocations(spec: VulnerabilitySpec): void {
  const strict = spec.validation.strict_semantics === true || spec.input_provenance === "user_provided";
  if (!strict) {
    return;
  }
  const missing: string[] = [];
  if (spec.validation.source?.file === undefined || spec.validation.source.line === undefined) missing.push("source.file/source.line");
  if (spec.validation.sink?.file === undefined || spec.validation.sink.line === undefined) missing.push("sink.file/sink.line");
  if (spec.validation.strict_semantics === true && spec.validation.source?.kind === undefined) missing.push("source.kind");
  if (spec.validation.strict_semantics === true && spec.validation.sink?.kind === undefined) missing.push("sink.kind");
  if (missing.length > 0) {
    throw new DomainError("SPEC_SEMANTIC_LOCATION_REQUIRED", "input", "Strict differential verification requires exact Source/Sink file and line locations", false, {
      specId: spec.spec_id,
      missing,
    });
  }
}

function assertSupportedSemanticKinds(spec: VulnerabilitySpec): void {
  const pack = languagePackFor(spec.language);
  const supported = new Set(pack.capabilities.flatMap((capability) => capability.matcher_kinds));
  const unsupported = (["source", "sink"] as const)
    .map((role) => {
      const kind = spec.validation[role]?.kind;
      return kind !== undefined && !supported.has(kind) ? { role, kind } : undefined;
    })
    .filter((item) => item !== undefined);
  if (unsupported.length > 0) {
    throw new DomainError("CAPABILITY_MISMATCH", "input", "Workflow Source/Sink endpoint kinds are not supported by the selected Language Pack", false, {
      language: spec.language,
      unsupported,
      supported: [...supported],
      hint: "Choose a supported endpoint kind before starting the workflow; JavaScript/TypeScript and Java/Kotlin currently use call for a whole call, while Python and C/C++ also support call_argument.",
    });
  }
}

function assertCandidateSemanticKinds(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  if (candidate.intent === undefined) {
    return;
  }
  const mismatches: Record<string, unknown> = {};
  const expectedSourceKind = spec.validation.source?.kind;
  const expectedSinkKind = spec.validation.sink?.kind;
  if (expectedSourceKind !== undefined && candidate.intent.source.kind !== expectedSourceKind) {
    mismatches.source = { expected: expectedSourceKind, actual: candidate.intent.source.kind };
  }
  if (expectedSinkKind !== undefined && candidate.intent.sink.kind !== expectedSinkKind) {
    mismatches.sink = { expected: expectedSinkKind, actual: candidate.intent.sink.kind };
  }
  if (Object.keys(mismatches).length > 0) {
    throw new DomainError("INVALID_INPUT", "input", "Candidate Source/Sink matcher kinds must match the frozen workflow endpoint kinds", true, {
      mismatches,
      hint: "Keep the candidate endpoint kind aligned with validation.kind; use a different line only when it is the endpoint of that same matcher kind.",
    });
  }
}

function assertCandidateSemanticLocations(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  if (candidate.intent === undefined) {
    return;
  }
  const mismatches: Record<string, unknown> = {};
  for (const role of ["source", "sink"] as const) {
    const expected = spec.validation[role];
    const actual = candidate.intent[role];
    const roleMismatches: Record<string, unknown> = {};
    if (actual.file !== undefined && expected?.file !== undefined && !semanticFileMatches(expected.file, actual.file)) {
      roleMismatches.file = { expected: expected.file, actual: actual.file };
    }
    if (actual.line !== undefined && expected?.line !== undefined && actual.line !== expected.line) {
      roleMismatches.line = { expected: expected.line, actual: actual.line };
    }
    if (Object.keys(roleMismatches).length > 0) {
      mismatches[role] = roleMismatches;
    }
  }
  if (Object.keys(mismatches).length > 0) {
    throw new DomainError("INVALID_INPUT", "input", "Candidate Source/Sink matcher locations must match the frozen workflow endpoint locations", true, {
      mismatches,
      hint: "Do not replace a frozen validation endpoint with a nearby or intermediate probe location; use intermediate nodes only as additional_flow_steps. Omit file/line only when the endpoint matcher is intentionally broad and the CLI semantic checks will constrain the result.",
    });
  }
}

function semanticFileMatches(expected: string, actual: string): boolean {
  const normalize = (value: string): string => value.replace(/^file:\/\//, "").replaceAll("\\", "/").replace(/^\.\//, "");
  const expectedPath = normalize(expected);
  const actualPath = normalize(actual);
  return actualPath === expectedPath || (expectedPath.includes("/") && actualPath.endsWith(`/${expectedPath}`));
}

function caseFingerprintFor(spec: VulnerabilitySpec): string {
  return stableDigest(JSON.stringify({
    language: spec.language,
    cwe: spec.cwe,
    vulnerability_description: spec.vulnerability_description,
    patch_description: spec.patch_description,
    project_root: spec.project_root,
    vulnerable_database: databaseIdentity(spec.vulnerable_database),
    fixed_database: spec.fixed_database === undefined ? undefined : databaseIdentity(spec.fixed_database),
    reference_query_excluded: spec.reference_query_excluded,
  }));
}

function databaseIdentity(database: VulnerabilitySpec["vulnerable_database"]): Record<string, string | undefined> {
  return {
    // Canonical identity is populated by inspectAndPersistSpec before the
    // case lock. Falling back to the supplied path keeps fake/CLI fixtures
    // deterministic without weakening real admission.
    path: database.canonical_path ?? database.path,
    fingerprint: database.fingerprint,
    language: database.language,
    codeql_version: database.codeql_version,
  };
}

function compileRepairHint(spec: VulnerabilitySpec, candidate: QueryCandidate): string {
  if (candidate.intent !== undefined) {
    return `Revise only the structured ${spec.language} TaintQueryIntent (source/sink matchers, flow steps, or sanitizer); the language pack owns metadata, imports, module, PathGraph and select.`;
  }
  if (spec.language === "python") {
    return "Revise only the structured PythonPathQueryDraft; Core owns metadata, imports, module, PathGraph and select.";
  }
  return `Revise the structured ${spec.language} candidate; the language pack owns metadata, imports, module, PathGraph and select.`;
}

function assertCandidateLanguage(candidate: QueryCandidate, spec: VulnerabilitySpec): void {
  const candidatePack = languagePackFor(candidate.language);
  const workflowPack = languagePackFor(spec.language);
  if (candidatePack.language !== workflowPack.language) {
    throw new DomainError("INVALID_INPUT", "input", "Query candidate language does not match the workflow Language Pack", false, {
      candidateLanguage: candidate.language,
      workflowLanguage: spec.language,
    });
  }
}

function assertDatabaseLanguage(spec: VulnerabilitySpec, path: string, manifest: DatabaseManifest): void {
  const pack = languagePackFor(spec.language);
  if (manifest.language !== undefined && !pack.aliases.includes(manifest.language) && pack.language !== manifest.language) {
    throw new DomainError("DATABASE_INVALID", "database", "The database language does not match the selected Language Pack", false, {
      path,
      expected: spec.language,
      language: manifest.language,
    });
  }
}

function databaseRefWithManifest(
  reference: VulnerabilitySpec["vulnerable_database"],
  manifest: DatabaseManifest,
): VulnerabilitySpec["vulnerable_database"] {
  return {
    ...reference,
    ...(manifest.canonicalPath === undefined ? {} : { canonical_path: manifest.canonicalPath }),
    ...(manifest.fingerprint === undefined ? {} : { fingerprint: manifest.fingerprint }),
    ...(manifest.codeqlVersion === undefined ? {} : { codeql_version: manifest.codeqlVersion }),
  };
}

function emptyCaseSummary(fingerprint: string, runId: RunId, maxCandidates: number, updatedAt: string): CaseRunSummary {
  return {
    schema_version: CONTRACTS_VERSION,
    case_fingerprint: fingerprint,
    run_ids: [runId],
    active_run_id: runId,
    total_candidates: 0,
    max_candidates: maxCandidates,
    budget_used: 0,
    budget_remaining: maxCandidates,
    status: "active",
    finalized: false,
    candidates: [],
    updated_at: updatedAt,
  };
}

function compactCaseSummary(summary: CaseRunSummary): {
  case_fingerprint: string;
  status: CaseRunSummary["status"];
  total_candidates: number;
  max_candidates: number;
  budget_used: number;
  budget_remaining: number;
  finalized: boolean;
} {
  return {
    case_fingerprint: summary.case_fingerprint,
    status: summary.status,
    total_candidates: summary.total_candidates,
    max_candidates: summary.max_candidates,
    budget_used: summary.budget_used,
    budget_remaining: summary.budget_remaining,
    finalized: summary.finalized,
  };
}

function caseSummaryFromState(
  state: QueryWorkflowState,
  run: { runId: RunId; status: string },
  updatedAt: string,
  existing?: CaseRunSummary,
  statusOverride?: CaseRunSummary["status"],
  packId?: string,
): CaseRunSummary {
  const status = statusOverride ?? caseStatusFromRun(run.status);
  const exhaustedByCandidates = statusOverride === undefined
    && state.candidates.length >= state.spec.max_rounds
    && state.verifications.length >= state.spec.max_rounds
    && state.verifications.every((verification) => verification.status === "failed");
  const effectiveStatus = exhaustedByCandidates ? "budget_exhausted" : status;
  const retainedPackId = packId ?? existing?.pack_id;
  const candidateSummaries = state.candidates.map((candidate) => {
    const verification = state.verifications.find((item) => item.candidate_id === candidate.candidate_id);
    return {
      candidate_id: candidate.candidate_id,
      round: candidate.round,
      status: verification?.status ?? "failed" as const,
      diagnostics: verification?.diagnostics.map((item) => item.code) ?? ["QUERY_NOT_VERIFIED"],
    };
  });
  const runIds = existing?.run_ids.includes(run.runId) === true
    ? existing.run_ids
    : [...(existing?.run_ids ?? []), run.runId];
  const active = effectiveStatus === "active" ? run.runId : undefined;
  return {
    schema_version: CONTRACTS_VERSION,
    case_fingerprint: state.case_fingerprint,
    run_ids: runIds,
    ...(active === undefined ? {} : { active_run_id: active }),
    total_candidates: state.candidates.length,
    max_candidates: state.spec.max_rounds,
    budget_used: state.candidates.length,
    budget_remaining: Math.max(0, state.spec.max_rounds - state.candidates.length),
    status: effectiveStatus,
    ...(effectiveStatus === "active" ? {} : { final_run_id: run.runId }),
    ...(statusOverride === "completed" || existing?.finalized === true ? { finalized: true } : { finalized: false }),
    ...(retainedPackId === undefined ? {} : { pack_id: retainedPackId }),
    ...(effectiveStatus === "active" ? {} : { final_phase: statusOverride === "completed" ? "workflow_finalize" : "query_verify" }),
    candidates: candidateSummaries,
    updated_at: updatedAt,
  };
}

function caseStatusFromRun(status: string): CaseRunSummary["status"] {
  if (status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted") {
    return status;
  }
  return "active";
}

function isTerminalRunStatus(status: string): boolean {
  return status === "completed" || status === "failed" || status === "cancelled" || status === "budget_exhausted";
}

function deduplicateDiagnostics(diagnostics: readonly QueryDiagnostic[]): QueryDiagnostic[] {
  const seen = new Set<string>();
  return diagnostics.filter((diagnostic) => {
    const key = `${diagnostic.code}:${diagnostic.stage ?? ""}:${diagnostic.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function upgradeLegacyState(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return value;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.case_fingerprint === "string" || record.spec === undefined) {
    return value;
  }
  const spec = parseSchema(VulnerabilitySpecSchema, record.spec, "legacy vulnerability spec");
  return { ...record, case_fingerprint: caseFingerprintFor(spec) };
}
