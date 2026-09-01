import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

import type { PiUiState } from "./types.js";

export const UI_KEY = "autovul";

export function renderUi(ctx: ExtensionContext, state: PiUiState): void {
  if (!ctx.hasUI) return;
  renderFooter(ctx, state);
  if (state.status === "running") {
    const detail = runningDetail(state);
    ctx.ui.setWidget(UI_KEY, detail.length === 0 ? undefined : [detail]);
    return;
  }
  if (state.status === "completed" && state.capability !== undefined) {
    ctx.ui.setWidget(UI_KEY, [aggregateDetail(state)]);
    return;
  }
  if (state.status === "completed" && state.packId !== undefined) {
    ctx.ui.setWidget(UI_KEY, ["pack ready · /codeql status"]);
    return;
  }
  hideWidget(ctx);
}

export function renderFooter(ctx: ExtensionContext, state: PiUiState): void {
  if (ctx.hasUI) ctx.ui.setStatus(UI_KEY, footerText(state));
}

export function hideWidget(ctx: ExtensionContext): void {
  if (ctx.hasUI) ctx.ui.setWidget(UI_KEY, undefined);
}

export function absorbDetails(state: PiUiState, value: unknown): void {
  const record = asRecord(value);
  if (record === undefined) return;
  if (absorbTypestateReplay(state, record)) return;
  absorbAggregateResult(state, record);
  absorbValidationResult(state, record);
  const run = asRecord(record.run);
  if (run !== undefined) {
    setOptionalString(state, "runId", run.runId);
    setRunStatus(state, run.status);
    setOptionalString(state, "phase", run.phase);
    setOptionalString(state, "verificationLevel", run.verificationLevel);
    setOptionalString(state, "artifactRoot", run.artifactRoot);
  }
  const candidateList = Array.isArray(record.candidates) ? record.candidates : [];
  const latestCandidate = asRecord(candidateList[candidateList.length - 1]);
  if (latestCandidate !== undefined) setOptionalNumber(state, "round", latestCandidate.round);
  const verification = asRecord(record.latest_verification) ?? asRecord(record.verification) ?? record;
  if (verification !== undefined && typeof verification.candidate_id === "string") {
    setOptionalNumber(state, "round", verification.round);
    setVerificationStatus(state, verification.status);
    setOptionalString(state, "verificationLevel", verification.verification_level);
    if (typeof verification.passed === "boolean") state.passed = verification.passed;
    const compile = asRecord(verification.compile);
    setOptionalString(state, "compile", compile?.status);
    const vulnerable = asRecord(verification.vulnerable);
    const fixed = asRecord(verification.fixed);
    setOptionalNumber(state, "vulnerableResults", vulnerable?.result_count);
    setOptionalNumber(state, "vulnerableFlows", vulnerable?.code_flow_count);
    setOptionalNumber(state, "fixedResults", fixed?.result_count);
    setOptionalNumber(state, "fixedFlows", fixed?.code_flow_count);
    state.diagnostics = Array.isArray(verification.diagnostics)
      ? verification.diagnostics.map((item) => asRecord(item)?.code).filter((item): item is string => typeof item === "string")
      : [];
    if (state.phase === "idle" || state.phase === "workflow_start") state.phase = "query_verify";
  }
  if (typeof record.pack_id === "string") {
    state.packId = record.pack_id;
    state.status = "completed";
    state.phase = "workflow_finalize";
    const packVerification = asRecord(record.verification);
    if (packVerification !== undefined) absorbDetails(state, packVerification);
  }
  const caseSummary = asRecord(record.case_summary);
  if (caseSummary?.status === "budget_exhausted") {
    state.status = "budget_exhausted";
    state.phase = "query_verify";
  }
  if (typeof record.code === "string") {
    state.status = record.code === "PROCESS_CANCELLED" ? "cancelled" : "failed";
    state.diagnostics = [record.code];
  }
  const error = asRecord(record.error);
  if (error !== undefined && typeof error.code === "string") {
    state.status = error.code === "PROCESS_CANCELLED" ? "cancelled" : "failed";
    state.diagnostics = [error.code];
  }
}

export function formatCommandResult(toolName: string, value: unknown): string {
  const record = asRecord(value);
  if (toolName === "doctor" && record !== undefined) {
    const environment = asRecord(record.environment);
    const version = typeof environment?.version === "string" ? environment.version.replace(/^CodeQL command-line toolchain release\s*/i, "") : "unavailable";
    const languages = Array.isArray(environment?.languages) ? environment.languages.filter((item): item is string => typeof item === "string") : [];
    const available = environment?.available === true;
    return `CodeQL ${available ? "✓" : "✗"} ${version}${languages.length === 0 ? "" : ` · ${languages.includes("python") ? "python ready" : "python unavailable"}`}`;
  }
  if (toolName === "status" && record !== undefined) {
    const run = asRecord(record.run) ?? record;
    const runId = typeof run.runId === "string" ? run.runId : typeof run.run_id === "string" ? run.run_id : "unknown";
    const status = typeof run.status === "string" ? run.status : "unknown";
    const phase = typeof run.phase === "string" ? run.phase : "idle";
    const verification = typeof run.verificationLevel === "string" ? run.verificationLevel : "generated";
    const artifactRoot = typeof run.artifactRoot === "string" ? `\nartifact: ${run.artifactRoot}` : "";
    return `CodeQL run ${runId}\nstatus: ${status} · phase: ${phase} · verification: ${verification}${artifactRoot}`;
  }
  return `CodeQL ${toolName} complete`;
}

export function footerText(state: PiUiState): string {
  if (state.status === "ready") return "CodeQL ready";
  if (state.status === "running") return `CodeQL ◐ ${phaseLabel(state.phase)}${state.round === undefined ? "" : ` · round ${state.round}/3`}`;
  const terminal = terminalStatusText(state);
  if (terminal !== undefined) return terminal;
  return resultSummary(state);
}

export function phaseLabel(phase: string): string {
  if (phase === "query_verify") return "verify";
  if (phase.startsWith("workflow_")) return phase.slice("workflow_".length);
  return phase;
}

export function readCandidate(value: unknown): { round?: number | undefined } | undefined {
  const record = asRecord(value);
  const candidate = asRecord(record?.candidate);
  if (candidate === undefined) return undefined;
  return { round: typeof candidate.round === "number" ? candidate.round : undefined };
}

export function toolPhase(toolName: string, args: unknown): string {
  if (toolName === "autovul_research") return "research";
  if (toolName === "autovul_run") return "run";
  if (toolName === "codeql_database") return "database";
  const action = asRecord(args)?.action;
  if (toolName === "codeql_workflow" && typeof action === "string") return `workflow_${action}`;
  return "query_verify";
}

export function toolLabel(toolName: string): string {
  if (toolName === "autovul_research") return "research";
  if (toolName === "autovul_run") return "run";
  if (toolName === "codeql_database") return "database inspection";
  if (toolName === "codeql_workflow") return "workflow";
  return "query verification";
}

function runningDetail(state: PiUiState): string {
  if (state.phase === "research") return "validating or executing a research hypothesis…";
  if (state.phase === "run") return "inspecting, cancelling, or replaying a run…";
  if (state.phase === "query_verify") return `${state.compile === "passed" ? "compile ✓" : "checking compile"} · vulnerable/fixed analysis…`;
  if (state.phase === "database") return "checking CodeQL environment/database…";
  return "persisting workflow checkpoint…";
}

function resultSummary(state: PiUiState): string {
  if (state.capability !== undefined) {
    const outcome = state.decisionOutcome ?? state.operationStatus ?? phaseLabel(state.phase);
    const verification = state.verificationLevel === undefined ? "" : ` · ${state.verificationLevel}`;
    return `AutoVul ${outcome === "invalid" ? "⚠" : "✓"} ${state.capability} · ${outcome}${verification}`;
  }
  if (state.passed === true || state.verificationLevel === "differential") return `CodeQL ✓ differential · vulnerable ${formatFlow(state.vulnerableFlows)} · fixed ${formatFlow(state.fixedFlows)}`;
  return `CodeQL ✓ ${phaseLabel(state.phase)}`;
}

function terminalStatusText(state: PiUiState): string | undefined {
  const prefix = state.capability === undefined ? "CodeQL" : `AutoVul ${state.capability}`;
  if (state.status === "blocked") return `${prefix} ⚠ blocked · ${state.diagnostics[0] ?? "environment unavailable"}`;
  if (state.status === "failed") return `${prefix} ✗ ${state.diagnostics[0] ?? "failed"}`;
  if (state.status === "cancelled") return `${prefix} ⏹ cancelled`;
  if (state.status === "budget_exhausted") return "CodeQL ⚠ budget exhausted · /codeql status";
  return undefined;
}

function absorbAggregateResult(state: PiUiState, record: Record<string, unknown>): void {
  if (record.capability !== "flow" && record.capability !== "missing_check" && record.capability !== "typestate") return;
  state.capability = record.capability;
  state.phase = "research";
  setOptionalString(state, "runId", record.run_id);
  setOptionalString(state, "verificationLevel", record.verification_level);
  if (typeof record.operation_status === "string") {
    state.operationStatus = record.operation_status;
    setAggregateStatus(state, record.operation_status);
  }
  const decision = asRecord(record.decision);
  if (typeof decision?.outcome === "string") state.decisionOutcome = decision.outcome;
  if (typeof record.artifact_ref === "string") state.artifactRef = record.artifact_ref;
  if (Array.isArray(record.revision_hints)) state.revisionHintCount = record.revision_hints.length;
  else delete state.revisionHintCount;
  state.diagnostics = Array.isArray(record.observations)
    ? record.observations.map((item) => asRecord(item)?.code).filter((item): item is string => typeof item === "string")
    : [];
}

function absorbTypestateReplay(state: PiUiState, record: Record<string, unknown>): boolean {
  if (record.capability !== "typestate"
    || (record.status !== "match" && record.status !== "environment_blocked" && record.status !== "version_difference" && record.status !== "semantic_mismatch" && record.status !== "cancelled")) return false;
  state.capability = "typestate";
  state.phase = "run";
  state.operationStatus = record.status;
  const replayDecision = asRecord(record.replay_decision) ?? asRecord(record.recorded_decision);
  if (typeof replayDecision?.outcome === "string") state.decisionOutcome = replayDecision.outcome;
  state.diagnostics = Array.isArray(record.observations)
    ? record.observations.map((item) => asRecord(item)?.code).filter((item): item is string => typeof item === "string")
    : [];
  state.status = record.status === "match" ? "completed" : record.status === "cancelled" ? "cancelled" : record.status === "environment_blocked" || record.status === "version_difference" ? "blocked" : "failed";
  return true;
}

function absorbValidationResult(state: PiUiState, record: Record<string, unknown>): void {
  if (state.phase !== "research" || state.capability === undefined || typeof record.valid !== "boolean" || !Array.isArray(record.issues)) return;
  state.status = "completed";
  state.operationStatus = "completed";
  state.decisionOutcome = record.valid ? "valid" : "invalid";
  state.diagnostics = record.issues.map((item) => asRecord(item)?.code).filter((item): item is string => typeof item === "string");
}

function setAggregateStatus(state: PiUiState, value: string): void {
  if (value === "completed") state.status = "completed";
  else if (value === "blocked") state.status = "blocked";
  else if (value === "failed") state.status = "failed";
  else if (value === "cancelled") state.status = "cancelled";
  else state.status = "running";
}

function aggregateDetail(state: PiUiState): string {
  const result = [state.capability, state.decisionOutcome, state.verificationLevel].filter((item): item is string => item !== undefined).join(" · ");
  const revision = state.revisionHintCount === undefined || state.revisionHintCount === 0 ? "" : ` · ${state.revisionHintCount} revision hint${state.revisionHintCount === 1 ? "" : "s"}`;
  const artifact = state.artifactRef === undefined ? "" : `\nartifact: ${state.artifactRef}`;
  return `${result}${revision}${artifact}`;
}

function formatFlow(value: number | undefined): string {
  if (value === undefined) return "not run";
  return `${value} flow${value === 1 ? "" : "s"}`;
}

function setRunStatus(state: PiUiState, value: unknown): void {
  if (value === "completed") state.status = "completed";
  else if (value === "failed") state.status = "failed";
  else if (value === "cancelled") state.status = "cancelled";
  else if (value === "budget_exhausted") state.status = "budget_exhausted";
  else if (typeof value === "string") state.status = "running";
}

function setVerificationStatus(state: PiUiState, value: unknown): void {
  if (value === "passed") state.status = "completed";
  else if (value === "cancelled") state.status = "cancelled";
  else if (typeof value === "string") state.status = "failed";
}

function setOptionalString(state: PiUiState, key: "runId" | "phase" | "verificationLevel" | "compile" | "artifactRoot", value: unknown): void {
  if (typeof value !== "string") return;
  if (key === "runId") state.runId = value;
  else if (key === "phase") state.phase = value;
  else if (key === "verificationLevel") state.verificationLevel = value;
  else if (key === "compile") state.compile = value;
  else state.artifactRoot = value;
}

function setOptionalNumber(state: PiUiState, key: "round" | "vulnerableResults" | "vulnerableFlows" | "fixedResults" | "fixedFlows", value: unknown): void {
  if (typeof value !== "number" || !Number.isInteger(value)) return;
  if (key === "round") state.round = value;
  else if (key === "vulnerableResults") state.vulnerableResults = value;
  else if (key === "vulnerableFlows") state.vulnerableFlows = value;
  else if (key === "fixedResults") state.fixedResults = value;
  else state.fixedFlows = value;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
