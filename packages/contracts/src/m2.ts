import { Type, type Static } from "typebox";

import { CONTRACTS_VERSION, DomainErrorSchema } from "./errors.js";
import { RunIdSchema, VerificationLevelSchema } from "./schemas.js";
import {
  LanguageFamilySchema,
  ProbeEvidenceSchema,
  TaintMatcherKindSchema,
  TaintQueryCandidateSchema,
  TaintQueryIntentSchema,
} from "./m3.js";

export const PythonLanguageSchema = Type.Literal("python");
export type PythonLanguage = Static<typeof PythonLanguageSchema>;

export const QueryDatabaseRefSchema = Type.Object(
  {
    path: Type.String({ minLength: 1 }),
    canonical_path: Type.Optional(Type.String({ minLength: 1 })),
    language: Type.Optional(Type.String({ minLength: 1 })),
    fingerprint: Type.Optional(Type.String({ minLength: 1 })),
    codeql_version: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type QueryDatabaseRef = Static<typeof QueryDatabaseRefSchema>;

export const QuerySemanticExpectationSchema = Type.Object(
  {
    label: Type.String({ minLength: 1 }),
    description: Type.String({ minLength: 1 }),
    /** Freezes the Source/Sink endpoint shape so call and call_argument cannot drift. */
    kind: Type.Optional(TaintMatcherKindSchema),
    file: Type.Optional(Type.String({ minLength: 1 })),
    line: Type.Optional(Type.Integer({ minimum: 1 })),
    symbol: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type QuerySemanticExpectation = Static<typeof QuerySemanticExpectationSchema>;

export const QueryValidationPolicySchema = Type.Object(
  {
    vulnerable_min_results: Type.Integer({ minimum: 0 }),
    vulnerable_max_results: Type.Integer({ minimum: 0 }),
    fixed_min_results: Type.Integer({ minimum: 0 }),
    fixed_max_results: Type.Integer({ minimum: 0 }),
    must_have_code_flow: Type.Boolean(),
    expected_rule_ids: Type.Optional(Type.Array(Type.String({ minLength: 1 }))),
    source: Type.Optional(QuerySemanticExpectationSchema),
    sink: Type.Optional(QuerySemanticExpectationSchema),
    strict_semantics: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type QueryValidationPolicy = Static<typeof QueryValidationPolicySchema>;

export const VulnerabilitySpecSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    spec_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: LanguageFamilySchema,
    cwe: Type.String({ minLength: 1 }),
    /** Project source root supplied by the user; it is context for Pi and LSP, never a database input. */
    project_root: Type.Optional(Type.String({ minLength: 1 })),
    vulnerability_description: Type.Optional(Type.String({ minLength: 1 })),
    patch_description: Type.Optional(Type.String({ minLength: 1 })),
    vulnerable_database: QueryDatabaseRefSchema,
    fixed_database: Type.Optional(QueryDatabaseRefSchema),
    validation: QueryValidationPolicySchema,
    max_rounds: Type.Integer({ minimum: 1, maximum: 3 }),
    draft_revision_budget: Type.Optional(Type.Integer({ minimum: 1, maximum: 10 })),
    timeout_ms: Type.Integer({ minimum: 1 }),
    created_at: Type.String({ minLength: 1 }),
    input_provenance: Type.Union([Type.Literal("user_provided"), Type.Literal("golden_fixture")]),
    reference_query_excluded: Type.Literal(true),
    platform: Type.Optional(Type.String({ minLength: 1 })),
    extractor_prerequisites: Type.Optional(Type.Array(Type.String({ minLength: 1 }))),
    provenance: Type.Object(
      {
        fixture: Type.String({ minLength: 1 }),
        license: Type.String({ minLength: 1 }),
        source: Type.String({ minLength: 1 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type VulnerabilitySpec = Static<typeof VulnerabilitySpecSchema>;

export const PythonPathQueryDraftSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    source_predicate: Type.String({ minLength: 1 }),
    sink_predicate: Type.String({ minLength: 1 }),
    additional_flow_step: Type.Optional(Type.String({ minLength: 1 })),
    sanitizer_predicate: Type.Optional(Type.String({ minLength: 1 })),
    message: Type.String({ minLength: 1 }),
    description: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type PythonPathQueryDraft = Static<typeof PythonPathQueryDraftSchema>;

export const QueryCandidateOriginSchema = Type.Union([
  Type.Literal("pi_generated"),
  Type.Literal("pi_revised"),
  Type.Literal("cli"),
  Type.Literal("test"),
]);
export type QueryCandidateOrigin = Static<typeof QueryCandidateOriginSchema>;

export const QueryCandidateSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    candidate_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    query_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    spec_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: LanguageFamilySchema,
    ql_text: Type.String({ minLength: 1 }),
    draft: Type.Optional(PythonPathQueryDraftSchema),
    intent: Type.Optional(TaintQueryIntentSchema),
    probe_evidence: Type.Optional(ProbeEvidenceSchema),
    qlpack_yml: Type.Optional(Type.String({ minLength: 1 })),
    round: Type.Integer({ minimum: 1, maximum: 3 }),
    origin: QueryCandidateOriginSchema,
    candidate_digest: Type.Optional(Type.String({ pattern: "^[a-f0-9]{16}$" })),
    parent_candidate_id: Type.Optional(Type.String({ minLength: 1 })),
    rationale: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type QueryCandidate = Static<typeof QueryCandidateSchema>;

export const PythonPathQueryCandidateSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    candidate_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    query_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    spec_id: Type.String({ pattern: "^[a-z0-9][a-z0-9._-]{2,127}$" }),
    language: PythonLanguageSchema,
    draft: PythonPathQueryDraftSchema,
    round: Type.Integer({ minimum: 1, maximum: 3 }),
    origin: QueryCandidateOriginSchema,
    parent_candidate_id: Type.Optional(Type.String({ minLength: 1 })),
    rationale: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type PythonPathQueryCandidate = Static<typeof PythonPathQueryCandidateSchema>;
export const QueryCandidateInputSchema = Type.Union([QueryCandidateSchema, PythonPathQueryCandidateSchema, TaintQueryCandidateSchema]);
export type QueryCandidateInput = Static<typeof QueryCandidateInputSchema>;

/** Candidate shape exposed to Pi: the renderer owns raw QL boilerplate. */
export const PiQueryCandidateInputSchema = Type.Union([PythonPathQueryCandidateSchema, TaintQueryCandidateSchema]);
export type PiQueryCandidateInput = Static<typeof PiQueryCandidateInputSchema>;

export const QueryDiagnosticCodeSchema = Type.Union([
  Type.Literal("QUERY_INPUT_INVALID"),
  Type.Literal("QUERY_COMPILE_FAILED"),
  Type.Literal("QUERY_ANALYZE_FAILED"),
  Type.Literal("QUERY_RESULT_MISMATCH"),
  Type.Literal("QUERY_CODE_FLOW_MISSING"),
  Type.Literal("QUERY_FIXED_DATABASE_MISMATCH"),
  Type.Literal("QUERY_TIMEOUT"),
  Type.Literal("QUERY_CANCELLED"),
  Type.Literal("QUERY_PACK_INCOMPLETE"),
  Type.Literal("QUERY_EMPTY_RESULT"),
  Type.Literal("QUERY_VULNERABLE_EXPECTATION_FAILED"),
  Type.Literal("QUERY_FIXED_FALSE_POSITIVE"),
  Type.Literal("QUERY_DIFFERENTIAL_NOT_RUN"),
  Type.Literal("QUERY_INVALID_CANDIDATE"),
  Type.Literal("QUERY_SEMANTIC_MISMATCH"),
  Type.Literal("QUERY_PROCESS_TIMEOUT"),
  Type.Literal("QUERY_PROCESS_CANCELLED"),
  Type.Literal("QUERY_PROCESS_CRASHED"),
  Type.Literal("QUERY_METADATA_KIND_REQUIRED"),
  Type.Literal("QUERY_METADATA_ID_REQUIRED"),
  Type.Literal("QUERY_METADATA_INVALID"),
  Type.Literal("QUERY_DRAFT_INVALID"),
]);
export type QueryDiagnosticCode = Static<typeof QueryDiagnosticCodeSchema>;

export const QueryDiagnosticSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    code: QueryDiagnosticCodeSchema,
    severity: Type.Union([Type.Literal("info"), Type.Literal("warning"), Type.Literal("error")]),
    message: Type.String({ minLength: 1 }),
    retryable: Type.Boolean(),
    candidate_id: Type.Optional(Type.String({ minLength: 1 })),
    run_id: Type.Optional(RunIdSchema),
    stage: Type.Optional(Type.Union([Type.Literal("preflight"), Type.Literal("compile"), Type.Literal("vulnerable"), Type.Literal("fixed"), Type.Literal("finalize")])),
    details: Type.Record(Type.String(), Type.Unknown()),
  },
  { additionalProperties: false },
);
export type QueryDiagnostic = Static<typeof QueryDiagnosticSchema>;

export const QueryLocationSchema = Type.Object(
  {
    file: Type.String({ minLength: 1 }),
    start_line: Type.Integer({ minimum: 1 }),
    start_column: Type.Optional(Type.Integer({ minimum: 1 })),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
    end_column: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: false },
);
export type QueryLocation = Static<typeof QueryLocationSchema>;

export const QueryDraftDiagnosticSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    severity: Type.Union([Type.Literal("info"), Type.Literal("warning"), Type.Literal("error")]),
    message: Type.String({ minLength: 1 }),
    code: Type.Optional(Type.String({ minLength: 1 })),
    source: Type.Optional(Type.String({ minLength: 1 })),
    file: Type.Optional(Type.String({ minLength: 1 })),
    start_line: Type.Optional(Type.Integer({ minimum: 1 })),
    start_column: Type.Optional(Type.Integer({ minimum: 1 })),
    end_line: Type.Optional(Type.Integer({ minimum: 1 })),
    end_column: Type.Optional(Type.Integer({ minimum: 1 })),
    related_locations: Type.Array(QueryLocationSchema, { maxItems: 32 }),
  },
  { additionalProperties: false },
);
export type QueryDraftDiagnostic = Static<typeof QueryDraftDiagnosticSchema>;

export const QueryDraftReportSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    draft_id: Type.String({ minLength: 1 }),
    run_id: RunIdSchema,
    candidate_id: Type.String({ minLength: 1 }),
    revision: Type.Integer({ minimum: 1, maximum: 10 }),
    draft_revision_budget: Type.Integer({ minimum: 1, maximum: 10 }),
    status: Type.Union([Type.Literal("clean"), Type.Literal("errors"), Type.Literal("degraded"), Type.Literal("cancelled")]),
    lsp_available: Type.Boolean(),
    diagnostics: Type.Array(QueryDraftDiagnosticSchema),
    definition_locations: Type.Array(QueryLocationSchema, { maxItems: 32 }),
    hover_text: Type.Array(Type.String({ minLength: 1 }), { maxItems: 16 }),
    completion_labels: Type.Array(Type.String({ minLength: 1 }), { maxItems: 64 }),
    fallback_reason: Type.Optional(Type.String({ minLength: 1 })),
    elapsed_ms: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false },
);
export type QueryDraftReport = Static<typeof QueryDraftReportSchema>;

export const QuerySemanticMatchSchema = Type.Object(
  {
    role: Type.Union([Type.Literal("source"), Type.Literal("sink"), Type.Literal("message")]),
    label: Type.String({ minLength: 1 }),
    locations: Type.Array(QueryLocationSchema),
  },
  { additionalProperties: false },
);
export type QuerySemanticMatch = Static<typeof QuerySemanticMatchSchema>;

export const QueryFlowEvidenceSchema = Type.Object(
  {
    path: Type.Array(QueryLocationSchema, { maxItems: 128 }),
    /** A direct source/sink match can have no serialized SARIF path steps. */
    path_kind: Type.Optional(Type.Literal("direct")),
    source: Type.Optional(QueryLocationSchema),
    sink: Type.Optional(QueryLocationSchema),
    result_location: Type.Optional(QueryLocationSchema),
  },
  { additionalProperties: false },
);
export type QueryFlowEvidence = Static<typeof QueryFlowEvidenceSchema>;

export const QueryDatabaseObservationSchema = Type.Object(
  {
    database: Type.Union([Type.Literal("vulnerable"), Type.Literal("fixed")]),
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed"), Type.Literal("not_run")]),
    result_count: Type.Integer({ minimum: 0 }),
    code_flow_count: Type.Integer({ minimum: 0 }),
    rule_ids: Type.Array(Type.String({ minLength: 1 })),
    locations: Type.Array(QueryLocationSchema),
    flow_evidence: Type.Array(QueryFlowEvidenceSchema),
    semantic_matches: Type.Array(QuerySemanticMatchSchema),
    artifact_path: Type.Optional(Type.String({ minLength: 1 })),
    elapsed_ms: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false },
);
export type QueryDatabaseObservation = Static<typeof QueryDatabaseObservationSchema>;

export const QueryCompileObservationSchema = Type.Object(
  {
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed")]),
    elapsed_ms: Type.Integer({ minimum: 0 }),
    artifact_path: Type.Optional(Type.String({ minLength: 1 })),
  },
  { additionalProperties: false },
);
export type QueryCompileObservation = Static<typeof QueryCompileObservationSchema>;

export const QueryRepairBriefSchema = Type.Object(
  {
    stage: Type.Union([
      Type.Literal("preflight"),
      Type.Literal("compile"),
      Type.Literal("vulnerable"),
      Type.Literal("fixed"),
      Type.Literal("policy"),
    ]),
    root_causes: Type.Array(Type.String({ minLength: 1 })),
    hints: Type.Array(Type.String({ minLength: 1 })),
    next_action: Type.Union([
      Type.Literal("revise_candidate"),
      Type.Literal("retry_operation"),
      Type.Literal("stop"),
    ]),
  },
  { additionalProperties: false },
);
export type QueryRepairBrief = Static<typeof QueryRepairBriefSchema>;

/** Atomic, Pi-facing admission state returned with every formal verification. */
export const QueryCaseOutcomeSummarySchema = Type.Object(
  {
    case_fingerprint: Type.String({ pattern: "^[a-f0-9]{16}$" }),
    status: Type.Union([
      Type.Literal("active"),
      Type.Literal("completed"),
      Type.Literal("budget_exhausted"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
    ]),
    total_candidates: Type.Integer({ minimum: 0 }),
    max_candidates: Type.Integer({ minimum: 1, maximum: 3 }),
    budget_used: Type.Integer({ minimum: 0 }),
    budget_remaining: Type.Integer({ minimum: 0 }),
    finalized: Type.Boolean(),
  },
  { additionalProperties: false },
);
export type QueryCaseOutcomeSummary = Static<typeof QueryCaseOutcomeSummarySchema>;

export const QueryVerificationSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    verification_id: Type.String({ minLength: 1 }),
    run_id: RunIdSchema,
    spec_id: Type.String({ minLength: 1 }),
    candidate_id: Type.String({ minLength: 1 }),
    round: Type.Integer({ minimum: 1, maximum: 3 }),
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed"), Type.Literal("cancelled")]),
    passed: Type.Boolean(),
    verification_level: VerificationLevelSchema,
    compile: QueryCompileObservationSchema,
    vulnerable: QueryDatabaseObservationSchema,
    fixed: QueryDatabaseObservationSchema,
    diagnostics: Type.Array(QueryDiagnosticSchema),
    repair_brief: Type.Optional(QueryRepairBriefSchema),
    case_summary: Type.Optional(QueryCaseOutcomeSummarySchema),
    terminal_reason: Type.Optional(Type.Union([
      Type.Literal("candidate_passed"),
      Type.Literal("candidate_failed"),
      Type.Literal("budget_exhausted"),
      Type.Literal("cancelled"),
    ])),
    elapsed_ms: Type.Integer({ minimum: 0 }),
    codeql_cli_version: Type.Optional(Type.String({ minLength: 1 })),
    extractor_info: Type.Optional(Type.String({ minLength: 1 })),
    cancelled: Type.Boolean(),
    timed_out: Type.Boolean(),
  },
  { additionalProperties: false },
);
export type QueryVerification = Static<typeof QueryVerificationSchema>;

export const CaseRunSummarySchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    case_fingerprint: Type.String({ pattern: "^[a-f0-9]{16}$" }),
    run_ids: Type.Array(RunIdSchema),
    active_run_id: Type.Optional(RunIdSchema),
    total_candidates: Type.Integer({ minimum: 0 }),
    max_candidates: Type.Integer({ minimum: 1, maximum: 3 }),
    budget_used: Type.Integer({ minimum: 0 }),
    budget_remaining: Type.Integer({ minimum: 0 }),
    status: Type.Union([
      Type.Literal("active"),
      Type.Literal("completed"),
      Type.Literal("budget_exhausted"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
    ]),
    final_run_id: Type.Optional(RunIdSchema),
    final_phase: Type.Optional(Type.String({ minLength: 1 })),
    finalized: Type.Boolean(),
    pack_id: Type.Optional(Type.String({ minLength: 1 })),
    candidates: Type.Array(Type.Object(
      {
        candidate_id: Type.String({ minLength: 1 }),
        round: Type.Integer({ minimum: 1, maximum: 3 }),
        status: Type.Union([Type.Literal("passed"), Type.Literal("failed"), Type.Literal("cancelled")]),
        diagnostics: Type.Array(Type.String({ minLength: 1 })),
      },
      { additionalProperties: false },
    )),
    updated_at: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type CaseRunSummary = Static<typeof CaseRunSummarySchema>;

export const QueryPackManifestSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    pack_id: Type.String({ minLength: 1 }),
    run_id: RunIdSchema,
    spec_id: Type.String({ minLength: 1 }),
    query_id: Type.String({ minLength: 1 }),
    language: LanguageFamilySchema,
    cwe: Type.String({ minLength: 1 }),
    provenance: Type.String({ minLength: 1 }),
    files: Type.Object(
      {
        query: Type.String({ minLength: 1 }),
        candidate: Type.String({ minLength: 1 }),
        spec: Type.String({ minLength: 1 }),
        verification: Type.String({ minLength: 1 }),
        qlpack: Type.String({ minLength: 1 }),
        evidence: Type.String({ minLength: 1 }),
        reproduce: Type.String({ minLength: 1 }),
          manifest: Type.String({ minLength: 1 }),
          exact: Type.Optional(Type.String({ minLength: 1 })),
          variant: Type.Optional(Type.String({ minLength: 1 })),
          intent: Type.Optional(Type.String({ minLength: 1 })),
          probe_evidence: Type.Optional(Type.String({ minLength: 1 })),
      },
      { additionalProperties: false },
    ),
    replay: Type.Object(
      {
        working_directory: Type.String({ minLength: 1 }),
        compile: Type.Array(Type.String()),
        vulnerable: Type.Array(Type.String()),
        fixed: Type.Optional(Type.Array(Type.String())),
        databases: Type.Object(
          {
            vulnerable: Type.String({ minLength: 1 }),
            fixed: Type.Optional(Type.String({ minLength: 1 })),
          },
          { additionalProperties: false },
        ),
      },
      { additionalProperties: false },
    ),
    integrity: Type.Object(
      {
        query: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        candidate: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        spec: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        verification: Type.String({ pattern: "^[a-f0-9]{16}$" }),
      },
      { additionalProperties: false },
    ),
    verification: QueryVerificationSchema,
    created_at: Type.String({ minLength: 1 }),
    platform: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);
export type QueryPackManifest = Static<typeof QueryPackManifestSchema>;

export const QueryWorkflowStatusSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
      run: Type.Object(
      {
        runId: RunIdSchema,
        status: Type.String({ minLength: 1 }),
        phase: Type.Optional(Type.String({ minLength: 1 })),
        verificationLevel: Type.String({ minLength: 1 }),
      },
      { additionalProperties: false },
      ),
    case_summary: CaseRunSummarySchema,
    spec: VulnerabilitySpecSchema,
    candidates: Type.Array(QueryCandidateSchema),
    verifications: Type.Array(QueryVerificationSchema),
    latest_verification: Type.Optional(QueryVerificationSchema),
    pack: Type.Optional(QueryPackManifestSchema),
  },
  { additionalProperties: false },
);
export type QueryWorkflowStatus = Static<typeof QueryWorkflowStatusSchema>;

export const QueryWorkflowStateSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    case_fingerprint: Type.String({ pattern: "^[a-f0-9]{16}$" }),
    spec: VulnerabilitySpecSchema,
    draft_revisions: Type.Optional(Type.Integer({ minimum: 0, maximum: 10 })),
    candidates: Type.Array(QueryCandidateSchema),
    verifications: Type.Array(QueryVerificationSchema),
    pack: Type.Optional(QueryPackManifestSchema),
  },
  { additionalProperties: false },
);
export type QueryWorkflowState = Static<typeof QueryWorkflowStateSchema>;

export const QueryWorkflowStartInputSchema = VulnerabilitySpecSchema;
export const QueryVerifyInputSchema = QueryCandidateSchema;
export const QueryWorkflowFinalizeInputSchema = Type.Object(
  { run_id: RunIdSchema },
  { additionalProperties: false },
);

export const CodeqlQueryToolInputSchema = Type.Object(
  {
    action: Type.Union([Type.Literal("verify"), Type.Literal("probe"), Type.Literal("draft")]),
    run_id: RunIdSchema,
    candidate: Type.Optional(PiQueryCandidateInputSchema),
    intent: Type.Optional(TaintQueryIntentSchema),
  },
  { additionalProperties: false },
);

export const CodeqlWorkflowToolInputSchema = Type.Object(
  {
    action: Type.Union([Type.Literal("start"), Type.Literal("status"), Type.Literal("finalize")]),
    run_id: Type.Optional(RunIdSchema),
    spec: Type.Optional(VulnerabilitySpecSchema),
  },
  { additionalProperties: false },
);

export const QueryFailureRecordSchema = Type.Object(
  {
    schema_version: Type.Literal(CONTRACTS_VERSION),
    error: DomainErrorSchema,
    diagnostic: Type.Optional(QueryDiagnosticSchema),
  },
  { additionalProperties: false },
);
export type QueryFailureRecord = Static<typeof QueryFailureRecordSchema>;

export const M2GoldenUsageSchema = Type.Union([
  Type.Object(
    {
      input_tokens: Type.Number({ minimum: 0 }),
      output_tokens: Type.Number({ minimum: 0 }),
      total_tokens: Type.Number({ minimum: 0 }),
      cache_input_tokens: Type.Optional(Type.Number({ minimum: 0 })),
      cost_usd: Type.Optional(Type.Number({ minimum: 0 })),
    },
    { additionalProperties: false },
  ),
  Type.Object({ status: Type.Literal("unavailable") }, { additionalProperties: false }),
]);
export type M2GoldenUsage = Static<typeof M2GoldenUsageSchema>;

export const M2GoldenRunReportSchema = Type.Object(
  {
    run: Type.Integer({ minimum: 1 }),
    counted: Type.Boolean(),
    success: Type.Boolean(),
    run_id: Type.String({ minLength: 1 }),
    metadata_complete: Type.Boolean(),
    rounds: Type.Array(Type.Object(
      {
        round: Type.Integer({ minimum: 1, maximum: 3 }),
        candidate_digest: Type.String({ pattern: "^[a-f0-9]{16}$" }),
        parent_candidate_id: Type.Optional(Type.String({ minLength: 1 })),
        diagnostics: Type.Array(Type.String({ minLength: 1 })),
        elapsed_ms: Type.Optional(Type.Integer({ minimum: 0 })),
      },
      { additionalProperties: false },
    )),
    diagnostics: Type.Array(Type.String({ minLength: 1 })),
    provider: Type.String({ minLength: 1 }),
    model: Type.String({ minLength: 1 }),
    adapter_version: Type.String({ minLength: 1 }),
    parameters: Type.Record(Type.String(), Type.Union([Type.String(), Type.Number(), Type.Boolean()])),
    usage: M2GoldenUsageSchema,
    generator_calls: Type.Array(Type.Object(
      {
        round: Type.Integer({ minimum: 1, maximum: 3 }),
        input_sha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
        provider: Type.String({ minLength: 1 }),
        model: Type.String({ minLength: 1 }),
        adapter_version: Type.String({ minLength: 1 }),
        parameters: Type.Record(Type.String(), Type.Union([Type.String(), Type.Number(), Type.Boolean()])),
        usage: M2GoldenUsageSchema,
        elapsed_ms: Type.Integer({ minimum: 0 }),
      },
      { additionalProperties: false },
    )),
    generator_elapsed_ms: Type.Integer({ minimum: 0 }),
    failure_classification: Type.Optional(Type.String({ minLength: 1 })),
    replay: Type.Optional(Type.Object(
      { passed: Type.Boolean(), pack_id: Type.String({ minLength: 1 }) },
      { additionalProperties: false },
    )),
  },
  { additionalProperties: false },
);
export type M2GoldenRunReport = Static<typeof M2GoldenRunReportSchema>;

export const M2GoldenReportSchema = Type.Object(
  {
    report_schema_version: Type.Literal("v2.m2.golden-report/1"),
    evaluator_version: Type.String({ minLength: 1 }),
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed"), Type.Literal("diagnostic")]),
    successes: Type.Integer({ minimum: 0 }),
    counted_runs: Type.Integer({ minimum: 0 }),
    total: Type.Integer({ minimum: 1 }),
    admission: Type.String({ minLength: 1 }),
    runs: Type.Array(M2GoldenRunReportSchema, { minItems: 1 }),
  },
  { additionalProperties: false },
);
export type M2GoldenReport = Static<typeof M2GoldenReportSchema>;
