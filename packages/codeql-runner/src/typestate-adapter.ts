import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";

import {
  DomainError,
  type TypestateAnalyzerObservation,
  type TypestateCompletenessBoundary,
  type TypestateEventObservation,
  type TypestateEventSelector,
  type TypestateHypothesis,
  type TypestateIdentityEvidence,
  type TypestateLocationRef,
  type TypestateResourceObservation,
  type TypestateTrace,
  type TypestateTraceEvent,
} from "@autovul/contracts";
import type {
  CodeqlOperationOptions,
  FileSystemPort,
  ProcessPort,
  ProcessResult,
  TypestateEvidenceDigest,
  TypestateEvidenceSnapshotPort,
  TypestateEvidenceSnapshotRequest,
  TypestateExecutionPort,
  TypestateExecutionRequest,
} from "@autovul/core";

import { NodeFileSystemPort } from "./node-filesystem.js";
import { NodeProcessPort } from "./node-process.js";
import { sanitizeOutput } from "./output.js";

const MAX_OUTPUT = 256 * 1024;
export const CODEQL_TYPESTATE_ADAPTER_VERSION = "autovul.codeql-typestate/1";
const COMPLETENESS_LIMITATIONS = [
  "cross_file_aliases_excluded",
  "indirect_calls_excluded",
  "dynamic_dispatch_excluded",
  "framework_callbacks_excluded",
  "concurrency_excluded",
  "helper_semantics_excluded",
] as const;

/** The single narrow CodeQL adapter for Typestate v1. */
export class CodeqlTypestateAdapter implements TypestateExecutionPort, TypestateEvidenceSnapshotPort {
  private readonly executable: string;
  private readonly cwd: string | undefined;
  private readonly process: ProcessPort;
  private readonly filesystem: FileSystemPort;

  constructor(options: { readonly executable?: string; readonly cwd?: string; readonly process?: ProcessPort; readonly filesystem?: FileSystemPort } = {}) {
    this.executable = options.executable ?? process.env.CODEQL_PATH ?? "codeql";
    this.cwd = options.cwd;
    this.process = options.process ?? new NodeProcessPort();
    this.filesystem = options.filesystem ?? new NodeFileSystemPort();
  }

  async execute(request: TypestateExecutionRequest, options: CodeqlOperationOptions): Promise<TypestateAnalyzerObservation> {
    const unsupported = unsupportedHypothesis(request.hypothesis);
    if (unsupported !== undefined) {
      return unavailableObservation(request.hypothesis, unsupported);
    }

    const plan = makeTracePlan(request.hypothesis);
    if (plan === undefined) {
      return unavailableObservation(request.hypothesis, { code: "TSTATE_TRACE_PLAN_UNSUPPORTED", path: "/transitions" });
    }

    const root = typestateWorkspaceRoot(request.artifactRoot, request.hypothesis.hypothesis_id, request.workspace);
    const evidenceNamespace = typestateWorkspaceNamespace(request.workspace);
    await this.filesystem.ensureDirectory(root);
    const queries = renderQueries(request.hypothesis, plan);
    await this.filesystem.writeTextAtomic(join(root, "observations.ql"), queries.observations);
    await this.filesystem.writeTextAtomic(join(root, "violation.ql"), queries.violation);
    await this.filesystem.writeTextAtomic(join(root, "safe.ql"), queries.safe);
    await this.filesystem.writeTextAtomic(join(root, "qlpack.yml"), "name: autovul/typestate\nversion: 0.0.0\ndependencies:\n  codeql/javascript-all: \"*\"\n");

    const version = await this.run(["version"], root, options);
    if (!successful(version)) throw processFailure(version, "version");
    const cliVersion = firstLine(version.stdout || version.stderr);
    if (cliVersion === undefined) {
      throw new DomainError("CODEQL_RESOLVE_FAILED", "environment", "Typestate CodeQL CLI returned no version", false);
    }

    for (const queryName of ["observations", "violation", "safe"] as const) {
      const compile = await this.run(["query", "compile", "--check-only", "--format=json", join(root, `${queryName}.ql`), "--threads=1"], root, options);
      if (!successful(compile)) throw processFailure(compile, `${queryName}:compile`);
    }

    const vulnerable = await this.observeSide(root, evidenceNamespace, request.hypothesis, request.target.vulnerable.path, "vulnerable", plan, request.mode === "probe" ? false : true, options);
    const fixed = request.mode === "differential" && request.target.fixed !== undefined
      ? await this.observeSide(root, evidenceNamespace, request.hypothesis, request.target.fixed.path, "fixed", plan, true, options)
      : undefined;
    const evidenceRefs = [...vulnerable.evidenceRefs, ...(fixed?.evidenceRefs ?? [])];
    return {
      schema_version: "autovul.typestate/1",
      compile_accepted: true,
      resource: vulnerable.resource,
      events: [...vulnerable.events],
      traces: [...vulnerable.traces],
      ...(fixed === undefined ? {} : { fixed_resource: fixed.resource, fixed_events: [...fixed.events], fixed_traces: [...fixed.traces] }),
      completeness: {
        vulnerable: completeness(request.hypothesis),
        ...(fixed === undefined ? {} : { fixed: completeness(request.hypothesis) }),
      },
      capability_gaps: [],
      evidence_refs: evidenceRefs,
      analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", adapter_version: CODEQL_TYPESTATE_ADAPTER_VERSION, version: cliVersion },
    };
  }

  async snapshotEvidence(request: TypestateEvidenceSnapshotRequest): Promise<readonly TypestateEvidenceDigest[]> {
    const root = typestateWorkspaceRoot(request.artifactRoot, request.hypothesis.hypothesis_id, request.workspace);
    if (!await this.filesystem.exists(root)) return [];
    const files = await listEvidenceFiles(this.filesystem, root);
    return Promise.all(files
      .filter((path) => path.endsWith(".ql") || path.endsWith(".sarif"))
      .sort()
      .map(async (path) => ({
        evidence_ref: relative(request.artifactRoot, path).split(sep).join("/"),
        sha256: createHash("sha256").update(await this.filesystem.readText(path), "utf8").digest("hex"),
      })));
  }

  private async observeSide(
    root: string,
    evidenceNamespace: "typestate" | "typestate-replay",
    hypothesis: TypestateHypothesis,
    database: string,
    side: "vulnerable" | "fixed",
    plan: TracePlan,
    includeTraces: boolean,
    options: CodeqlOperationOptions,
  ): Promise<SideObservation> {
    const prefix = `${evidenceNamespace}/${hypothesis.hypothesis_id}/${side}`;
    const observationsPath = `${prefix}/observations.sarif`;
    const observations = await this.analyze(root, database, side, "observations", observationsPath, options);
    const resourceLocations = observations.results
      .filter((result) => result.message.includes("kind=resource"))
      .flatMap((result) => result.locations)
      .slice(0, 4);
    const resource: TypestateResourceObservation = {
      state: resourceLocations.length > 0 ? "observed" : "not_found",
      locations: resourceLocations,
      identity_evidence: resourceLocations.length > 0 ? [`direct_lexical_binding:${hypothesis.resource.id}`] : [],
    };
    const events: TypestateEventObservation[] = hypothesis.events.map((event) => {
      const locations = observations.results
        .filter((result) => result.message.includes(`kind=event|event=${event.id}`))
        .flatMap((result) => result.locations)
        .slice(0, 4);
      return { event_id: event.id, state: locations.length > 0 ? "observed" : "not_found", locations };
    });
    const traces: TypestateTrace[] = [];
    const evidenceRefs = [observationsPath];
    if (includeTraces) {
      const violationPath = `${prefix}/violation.sarif`;
      const safePath = `${prefix}/safe.sarif`;
      const violation = await this.analyze(root, database, side, "violation", violationPath, options);
      const safe = await this.analyze(root, database, side, "safe", safePath, options);
      evidenceRefs.push(violationPath, safePath);
      traces.push(...violation.results.flatMap((result) => traceFromResult(result, "violating_witness", plan.violation, hypothesis.resource.id, violationPath)));
      traces.push(...safe.results.flatMap((result) => traceFromResult(result, "safe_trace", plan.safe, hypothesis.resource.id, safePath)));
    }
    return { resource, events, traces: traces.slice(0, 8), evidenceRefs };
  }

  private async analyze(
    root: string,
    database: string,
    side: "vulnerable" | "fixed",
    queryName: "observations" | "violation" | "safe",
    evidenceRef: string,
    options: CodeqlOperationOptions,
  ): Promise<Analysis> {
    const output = join(root, side, `${queryName}.sarif`);
    await this.filesystem.ensureDirectory(join(root, side));
    const result = await this.run(["database", "analyze", database, join(root, `${queryName}.ql`), "--rerun", "--format=sarif-latest", `--output=${output}`, "--threads=1"], root, options);
    if (!successful(result)) throw processFailure(result, `${side}:${queryName}`);
    try {
      return { results: readSarifResults(JSON.parse(await this.filesystem.readText(output)) as unknown), evidenceRef };
    } catch (error: unknown) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", `Typestate CodeQL ${side}:${queryName} produced unreadable SARIF`, false, { side, queryName, reason: error instanceof Error ? error.message : "invalid SARIF" });
    }
  }

  private async run(args: readonly string[], root: string, options: CodeqlOperationOptions): Promise<ProcessResult> {
    try {
      return await this.process.execute(
        { executable: this.executable, args, cwd: this.cwd ?? root, shell: false },
        options.signal === undefined ? { timeoutMs: options.timeoutMs, maxOutputBytes: MAX_OUTPUT } : { signal: options.signal, timeoutMs: options.timeoutMs, maxOutputBytes: MAX_OUTPUT },
      );
    } catch (error: unknown) {
      if (error instanceof DomainError) throw error;
      throw new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false, { executable: this.executable });
    }
  }
}

interface Analysis { readonly results: readonly SarifResult[]; readonly evidenceRef: string; }
interface SideObservation { readonly resource: TypestateResourceObservation; readonly events: readonly TypestateEventObservation[]; readonly traces: readonly TypestateTrace[]; readonly evidenceRefs: readonly string[]; }
interface SarifResult { readonly message: string; readonly locations: readonly TypestateLocationRef[]; readonly related: readonly { readonly message: string; readonly location: TypestateLocationRef }[]; }
interface TracePlan { readonly violation: readonly PlannedEvent[]; readonly safe: readonly PlannedEvent[]; }
interface PlannedEvent { readonly eventId: string; readonly fromState: string; readonly toState: string; }
interface UnsupportedHypothesis { readonly code: string; readonly path: string; }

function typestateWorkspaceRoot(artifactRoot: string, hypothesisId: string, workspace: "primary" | "replay" | undefined): string {
  return join(artifactRoot, typestateWorkspaceNamespace(workspace), hypothesisId);
}

function typestateWorkspaceNamespace(workspace: "primary" | "replay" | undefined): "typestate" | "typestate-replay" {
  return workspace === "replay" ? "typestate-replay" : "typestate";
}

async function listEvidenceFiles(filesystem: FileSystemPort, directory: string): Promise<readonly string[]> {
  const entries = await filesystem.listDirectory(directory);
  const nested = await Promise.all(entries.map(async (entry) => entry.isDirectory
    ? listEvidenceFiles(filesystem, join(directory, entry.name))
    : [join(directory, entry.name)]));
  return nested.flat();
}

function unsupportedHypothesis(hypothesis: TypestateHypothesis): UnsupportedHypothesis | undefined {
  if (hypothesis.language !== "javascript") return { code: "TSTATE_LANGUAGE_UNSUPPORTED", path: "/language" };
  if (hypothesis.resource.kind !== "local_binding" || hypothesis.resource.identity_model !== "direct_lexical_binding") return { code: "TSTATE_IDENTITY_MODEL_UNSUPPORTED", path: "/resource/identity_model" };
  if (hypothesis.analysis_scope.kind !== "single_file_named_function" || hypothesis.analysis_scope.alias_boundary !== "direct_lexical_binding") return { code: "TSTATE_SCOPE_UNSUPPORTED", path: "/analysis_scope" };
  const identityEvents = identityChangeEvents(hypothesis);
  if (identityEvents.length !== 1) return { code: "TSTATE_IDENTITY_CHANGE_AMBIGUOUS", path: "/transitions" };
  const acquisition = hypothesis.events.find((event) => event.id === hypothesis.resource.acquisition_event);
  if (acquisition?.selector.kind !== "direct_call") return { code: "TSTATE_ACQUISITION_SELECTOR_UNSUPPORTED", path: "/resource/acquisition_event" };
  const violation = hypothesis.events.find((event) => event.id === hypothesis.violation.event);
  if (violation?.selector.kind !== "direct_call") return { code: "TSTATE_VIOLATION_SELECTOR_UNSUPPORTED", path: "/violation/event" };
  const identityIndex = hypothesis.events.findIndex((event) => event.id === identityEvents[0]);
  if (identityIndex < 0 || hypothesis.events[identityIndex]?.selector.kind !== "direct_method") return { code: "TSTATE_IDENTITY_EVENT_UNSUPPORTED", path: `/events/${Math.max(identityIndex, 0)}/selector` };
  for (const [index, event] of hypothesis.events.entries()) {
    if (event.id === hypothesis.resource.acquisition_event || event.id === hypothesis.violation.event || event.id === identityEvents[0]) {
      if (event.selector.kind === "direct_call" && event.id === hypothesis.violation.event && event.selector.argument_property === undefined) {
        return { code: "TSTATE_RESOURCE_ARGUMENT_PROPERTY_REQUIRED", path: `/events/${index}/selector/argument_property` };
      }
    }
  }
  return undefined;
}

function unavailableObservation(hypothesis: TypestateHypothesis, gap: UnsupportedHypothesis): TypestateAnalyzerObservation {
  const notRunEvents: TypestateEventObservation[] = hypothesis.events.map((event) => ({ event_id: event.id, state: "not_run", locations: [] }));
  const boundary = { status: "not_run" as const, scope: hypothesis.analysis_scope, limitations: [] };
  return {
    schema_version: "autovul.typestate/1",
    compile_accepted: "not_run",
    resource: { state: "not_run", locations: [], identity_evidence: [] },
    events: notRunEvents,
    traces: [],
    completeness: { vulnerable: boundary },
    capability_gaps: [gap],
    evidence_refs: [],
    analyzer: { analyzer_id: "codeql", available: true, evidence_kind: "real_analyzer", adapter_version: CODEQL_TYPESTATE_ADAPTER_VERSION },
  };
}

function completeness(hypothesis: TypestateHypothesis): TypestateCompletenessBoundary {
  return { status: "complete", scope: hypothesis.analysis_scope, limitations: [...COMPLETENESS_LIMITATIONS] };
}

function identityChangeEvents(hypothesis: TypestateHypothesis): string[] {
  return [...new Set(hypothesis.transitions
    .filter((transition) => transition.from_state === hypothesis.violation.from_state && transition.to_state !== transition.from_state && transition.event !== hypothesis.violation.event)
    .map((transition) => transition.event))];
}

function makeTracePlan(hypothesis: TypestateHypothesis): TracePlan | undefined {
  const acquisition = hypothesis.transitions.find((transition) => transition.event === hypothesis.resource.acquisition_event && transition.from_state === hypothesis.initial_state);
  const identityEventId = identityChangeEvents(hypothesis)[0];
  const identity = hypothesis.transitions.find((transition) => transition.event === identityEventId);
  const safeFinal = hypothesis.transitions.find((transition) => transition.event === hypothesis.violation.event && transition.from_state === identity?.to_state && transition.to_state === hypothesis.violation.to_state);
  if (acquisition === undefined || identity === undefined || safeFinal === undefined) return undefined;
  const prefix = pathBetween(acquisition.to_state, identity.from_state, hypothesis.transitions, new Set([hypothesis.violation.event]));
  const violationPrefix = pathBetween(acquisition.to_state, hypothesis.violation.from_state, hypothesis.transitions, new Set([hypothesis.violation.event]));
  if (prefix === undefined || violationPrefix === undefined) return undefined;
  const violation = [{ eventId: hypothesis.resource.acquisition_event, fromState: acquisition.from_state, toState: acquisition.to_state }, ...violationPrefix, { eventId: hypothesis.violation.event, fromState: hypothesis.violation.from_state, toState: hypothesis.violation.to_state }];
  const safe = [{ eventId: hypothesis.resource.acquisition_event, fromState: acquisition.from_state, toState: acquisition.to_state }, ...prefix, { eventId: identity.event, fromState: identity.from_state, toState: identity.to_state }, { eventId: safeFinal.event, fromState: safeFinal.from_state, toState: safeFinal.to_state }];
  return violation.length <= 8 && safe.length <= 8 ? { violation, safe } : undefined;
}

function pathBetween(from: string, to: string, transitions: TypestateHypothesis["transitions"], excludedEvents: ReadonlySet<string>): PlannedEvent[] | undefined {
  if (from === to) return [];
  const queue: Array<{ readonly state: string; readonly path: PlannedEvent[] }> = [{ state: from, path: [] }];
  const visited = new Set<string>([from]);
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) continue;
    for (const transition of transitions) {
      if (excludedEvents.has(transition.event) || transition.from_state !== current.state || visited.has(transition.to_state)) continue;
      const path = [...current.path, { eventId: transition.event, fromState: transition.from_state, toState: transition.to_state }];
      if (transition.to_state === to) return path;
      visited.add(transition.to_state);
      queue.push({ state: transition.to_state, path });
    }
  }
  return undefined;
}

function renderQueries(hypothesis: TypestateHypothesis, plan: TracePlan): { readonly observations: string; readonly violation: string; readonly safe: string } {
  const predicates = hypothesis.events.map((event, index) => selectorPredicate(`matchesEvent${index}`, event.selector)).join("\n");
  const eventRows = hypothesis.events.map((event, index) => `(marker = ${qlString(`kind=event|event=${event.id}`)} and matchesEvent${index}(call))`).join(" or\n  ");
  const header = `/**\n * @name AutoVul Typestate v1 observation adapter\n * @id autovul/typestate/observation\n * @kind problem\n * @problem.severity warning\n */\nimport javascript\n\npredicate inScope(CallExpr call) {\n  call.getLocation().getFile().getRelativePath() = ${qlString(hypothesis.analysis_scope.file)} and\n  exists(Function entry |\n    entry.getName() = ${qlString(hypothesis.analysis_scope.entry.name)} and\n    entry.getLocation().getFile() = call.getLocation().getFile() and\n    entry.getLocation().getStartLine() <= call.getLocation().getStartLine() and\n    call.getLocation().getEndLine() <= entry.getLocation().getEndLine()\n  )\n}\n\n${predicates}\n`;
  const resource = `\npredicate isAcquisition(CallExpr call) { matchesEvent${hypothesis.events.findIndex((event) => event.id === hypothesis.resource.acquisition_event)}(call) }\npredicate bindsAcquisition(CallExpr acquire, Variable resource) {\n  exists(VariableDeclarator declaration |\n    declaration.getBindingPattern().(VarDecl).getVariable() = resource and\n    declaration.getBindingPattern().(VarDecl).getName() = ${qlString(hypothesis.resource.binding_name)} and\n    (declaration.getInit() = acquire or declaration.getInit().(AwaitExpr).getOperand() = acquire)\n  )\n}\npredicate hasCurrentBinding(CallExpr authenticate) {\n  exists(Property property, VariableDeclarator declaration, PropAccess current |\n    property = authenticate.getArgument(0).(ObjectExpr).getPropertyByName(${qlString(argumentProperty(hypothesis))}) and\n    property.getInit().(VarAccess).getVariable() = declaration.getBindingPattern().(VarDecl).getVariable() and\n    declaration.getBindingPattern().(VarDecl).getName() = ${qlString(hypothesis.resource.binding_name)} and\n    declaration.getInit() = current and\n    matchesCurrentReceiver(current)\n  )\n}\npredicate matchesCurrentReceiver(PropAccess current) { ${receiverValueExpression("current", identityReceiver(hypothesis))} }\n`;
  const violationIndex = hypothesis.events.findIndex((event) => event.id === hypothesis.violation.event);
  const observation = `${header}${resource}\npredicate hasResource(CallExpr acquire) {\n  exists(Variable resource | bindsAcquisition(acquire, resource)) or\n  exists(CallExpr authenticate |\n    matchesEvent${violationIndex}(authenticate) and\n    acquire.getLocation().getStartLine() < authenticate.getLocation().getStartLine() and\n    hasCurrentBinding(authenticate)\n  )\n}\n\nfrom CallExpr call, string marker\nwhere\n  (${eventRows}) or\n  (marker = ${qlString(`kind=resource|resource=${hypothesis.resource.id}`)} and isAcquisition(call) and hasResource(call))\nselect call, "TSTATE|" + marker\n`;
  return {
    observations: observation,
    violation: `${header}${resource}${renderTracePredicates(plan.violation, hypothesis, false)}\n`,
    safe: `${header}${resource}${renderTracePredicates(plan.safe, hypothesis, true)}\n`,
  };
}

function renderTracePredicates(plan: readonly PlannedEvent[], hypothesis: TypestateHypothesis, safe: boolean): string {
  const calls = plan.map((_event, index) => `CallExpr event${index}`).join(", ");
  const where = plan.map((event, index) => `matchesEvent${hypothesis.events.findIndex((candidate) => candidate.id === event.eventId)}(event${index})`).join(" and\n  ");
  const order = plan.slice(1).map((_event, index) => `event${index}.getLocation().getStartLine() < event${index + 1}.getLocation().getStartLine()`).join(" and\n  ");
  const acquireIndex = plan.findIndex((event) => event.eventId === hypothesis.resource.acquisition_event);
  const finalIndex = plan.length - 1;
  const acquire = safe ? "" : `bindsAcquisition(event${acquireIndex}, resource)`;
  const auth = safe
    ? `property = event${finalIndex}.getArgument(0).(ObjectExpr).getPropertyByName(${qlString(argumentProperty(hypothesis))})`
    : `property = event${finalIndex}.getArgument(0).(ObjectExpr).getPropertyByName(${qlString(argumentProperty(hypothesis))}) and\n  property.getInit().(VarAccess).getVariable() = resource`;
  const identityIndex = plan.findIndex((event) => event.eventId === identityChangeEvents(hypothesis)[0]);
  const authProperty = safe ? `isCurrentBindingForProperty(event${identityIndex}, event${finalIndex}, property)` : "";
  const noIdentity = safe ? "" : `not exists(CallExpr identity | matchesEvent${hypothesis.events.findIndex((event) => event.id === identityChangeEvents(hypothesis)[0])}(identity) and event${acquireIndex}.getLocation().getStartLine() < identity.getLocation().getStartLine() and identity.getLocation().getStartLine() < event${finalIndex}.getLocation().getStartLine())`;
  const related = plan.slice(0, -1).map((event, index) => `event${index}, ${qlString(`event=${event.eventId}`)}`).join(",\n  ");
  const metadata = `TSTATE|kind=trace|state=${safe ? "safe_trace" : "violating_witness"}|resource=${hypothesis.resource.id}|events=${plan.map((event) => event.eventId).join(",")}|states=${plan.map((event) => `${event.fromState},${event.toState}`).join(";")}|`;
  const tracePredicates = safe
    ? `\npredicate isCurrentBindingForProperty(CallExpr identity, CallExpr authenticate, Property property) {\n  exists(VariableDeclarator declaration, PropAccess current |\n    property.getInit().(VarAccess).getVariable() = declaration.getBindingPattern().(VarDecl).getVariable() and\n    declaration.getBindingPattern().(VarDecl).getName() = ${qlString(hypothesis.resource.binding_name)} and\n    declaration.getInit() = current and\n    matchesCurrentReceiver(current) and\n    identity.getLocation().getEndLine() < declaration.getLocation().getStartLine() and\n    declaration.getLocation().getEndLine() < authenticate.getLocation().getStartLine()\n  )\n}\n`
    : "\n";
  return `${tracePredicates}\nfrom ${calls}, Property property${safe ? "" : ", Variable resource"}\nwhere\n  ${where} and\n  ${order}${acquire === "" ? "" : ` and\n  ${acquire}`} and\n  ${auth}${authProperty === "" ? "" : ` and\n  ${authProperty}`}\n  ${noIdentity === "" ? "" : ` and\n  ${noIdentity}`}\nselect event${finalIndex}, ${qlString(metadata + plan.slice(0, -1).map(() => " $@").join(""))},\n  ${related}`;
}

function argumentProperty(hypothesis: TypestateHypothesis): string {
  const event = hypothesis.events.find((candidate) => candidate.id === hypothesis.violation.event);
  return event?.selector.kind === "direct_call" && event.selector.argument_property !== undefined ? event.selector.argument_property : "session";
}

function identityReceiver(hypothesis: TypestateHypothesis): string {
  const event = hypothesis.events.find((candidate) => candidate.id === identityChangeEvents(hypothesis)[0]);
  return event?.selector.kind === "direct_method" ? event.selector.receiver : "req.session";
}

function selectorPredicate(name: string, selector: TypestateEventSelector): string {
  if (selector.kind === "direct_call") {
    const property = selector.argument_property === undefined ? "" : ` and exists(Property argument | argument = call.getArgument(0).(ObjectExpr).getPropertyByName(${qlString(selector.argument_property)}) and argument.getName() = ${qlString(selector.argument_property)})`;
    return `predicate ${name}(CallExpr call) { inScope(call) and call.getCallee().(VarAccess).getName() = ${qlString(selector.name)}${property} }`;
  }
  return `predicate ${name}(CallExpr call) { inScope(call) and call.getCallee().(PropAccess).getPropertyName() = ${qlString(selector.name)} and ${receiverExpression("call.getCallee().(PropAccess)", selector.receiver)} }`;
}

function receiverExpression(base: string, receiver: string): string {
  const parts = receiver.split(".");
  let expression = `${base}.getBase()`;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    if (part === undefined) continue;
    if (index === 0) expression += `.(VarAccess).getName() = ${qlString(part)}`;
    else expression += `.(PropAccess).getPropertyName() = ${qlString(part)} and ${base}.getBase()`;
  }
  if (parts.length <= 1) return expression;
  const clauses: string[] = [];
  let current = `${base}.getBase()`;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    if (part === undefined) continue;
    if (index === 0) clauses.push(`${current}.(VarAccess).getName() = ${qlString(part)}`);
    else {
      clauses.push(`${current}.(PropAccess).getPropertyName() = ${qlString(part)}`);
      current += ".(PropAccess).getBase()";
    }
  }
  return clauses.join(" and ");
}

function receiverValueExpression(base: string, receiver: string): string {
  const parts = receiver.split(".");
  const clauses: string[] = [];
  let current = base;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    if (part === undefined) continue;
    if (index === 0) clauses.push(`${current}.(VarAccess).getName() = ${qlString(part)}`);
    else {
      clauses.push(`${current}.(PropAccess).getPropertyName() = ${qlString(part)}`);
      current += ".(PropAccess).getBase()";
    }
  }
  return clauses.join(" and ");
}

function qlString(value: string): string { return JSON.stringify(value); }

function traceFromResult(result: SarifResult, state: "violating_witness" | "safe_trace", plan: readonly PlannedEvent[], resourceId: string, evidenceRef: string): TypestateTrace[] {
  const metadata = parseMetadata(result.message);
  if (metadata === undefined || !traceMetadataMatchesPlan(metadata, state, resourceId, plan)) return [inconclusiveTrace(resourceId, evidenceRef)];
  const locations = new Map<string, TypestateLocationRef>();
  for (const related of result.related) {
    const eventId = /^event=(.+)$/.exec(related.message.trim())?.[1];
    if (eventId !== undefined && !locations.has(eventId)) locations.set(eventId, related.location);
  }
  const events: TypestateTraceEvent[] = plan.map((event, index) => {
    const location = index === plan.length - 1 ? result.locations[0] : locations.get(event.eventId);
    return location === undefined
      ? { event_id: event.eventId, from_state: event.fromState, to_state: event.toState }
      : { event_id: event.eventId, from_state: event.fromState, to_state: event.toState, location };
  });
  const identityEvidence: TypestateIdentityEvidence = {
    kind: state === "safe_trace" ? "identity_change" : "same_binding",
    resource_id: resourceId,
    event_ids: plan.map((event) => event.eventId),
    locations: [...new Set(events.flatMap((event) => event.location === undefined ? [] : [event.location]))].slice(0, 4),
  };
  const complete = events.every((event) => event.location !== undefined);
  return [{
    state: complete ? state : "inconclusive",
    resource_id: resourceId,
    events,
    identity_evidence: [identityEvidence],
    ...(complete && state === "violating_witness" ? { violation_step: plan.length - 1 } : {}),
    evidence_ref: evidenceRef,
  }];
}

function inconclusiveTrace(resourceId: string, evidenceRef: string): TypestateTrace {
  return { state: "inconclusive", resource_id: resourceId, events: [], identity_evidence: [], evidence_ref: evidenceRef };
}

interface TraceMetadata {
  readonly state: string;
  readonly resource: string;
  readonly eventIds: readonly string[];
  readonly states: readonly { readonly fromState: string; readonly toState: string }[];
}

function traceMetadataMatchesPlan(metadata: TraceMetadata, state: "violating_witness" | "safe_trace", resourceId: string, plan: readonly PlannedEvent[]): boolean {
  if (metadata.state !== state || metadata.resource !== resourceId || metadata.eventIds.length !== plan.length || metadata.states.length !== plan.length) return false;
  return plan.every((event, index) => metadata.eventIds[index] === event.eventId
    && metadata.states[index]?.fromState === event.fromState
    && metadata.states[index]?.toState === event.toState);
}

function parseMetadata(message: string): TraceMetadata | undefined {
  const fields = new Map(message.split("|").map((part) => part.split("=", 2) as [string, string]));
  const state = fields.get("state");
  const resource = fields.get("resource");
  const eventField = fields.get("events");
  const stateField = fields.get("states");
  if (state === undefined || resource === undefined || eventField === undefined || stateField === undefined) return undefined;
  const eventIds = eventField === "" ? [] : eventField.split(",");
  if (eventIds.some((eventId) => eventId === "")) return undefined;
  const states: Array<{ readonly fromState: string; readonly toState: string }> = [];
  for (const pair of stateField === "" ? [] : stateField.split(";")) {
    const parts = pair.split(",");
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined || parts[0] === "" || parts[1] === "") return undefined;
    states.push({ fromState: parts[0], toState: parts[1] });
  }
  return { state, resource, eventIds, states };
}

function readSarifResults(value: unknown): SarifResult[] {
  if (value === null || typeof value !== "object") throw new Error("SARIF root must be an object");
  const runs = (value as Record<string, unknown>).runs;
  if (!Array.isArray(runs)) throw new Error("SARIF runs must be an array");
  const results: SarifResult[] = [];
  for (const run of runs) {
    if (run === null || typeof run !== "object") continue;
    const runResults = (run as Record<string, unknown>).results;
    if (!Array.isArray(runResults)) continue;
    for (const item of runResults) {
      if (item === null || typeof item !== "object") continue;
      const record = item as Record<string, unknown>;
      const message = record.message;
      const text = message !== null && typeof message === "object" && typeof (message as Record<string, unknown>).text === "string" ? (message as Record<string, unknown>).text as string : "";
      const locations = Array.isArray(record.locations) ? record.locations.flatMap(toLocation) : [];
      const relatedLocations = Array.isArray(record.relatedLocations) ? record.relatedLocations.flatMap((location) => {
        if (location === null || typeof location !== "object") return [];
        const related = location as Record<string, unknown>;
        const relatedMessage = related.message;
        const relatedText = relatedMessage !== null && typeof relatedMessage === "object" && typeof (relatedMessage as Record<string, unknown>).text === "string" ? (relatedMessage as Record<string, unknown>).text as string : "";
        const parsed = toLocation(related);
        return parsed[0] === undefined ? [] : [{ message: relatedText, location: parsed[0] }];
      }) : [];
      results.push({ message: text, locations, related: relatedLocations });
    }
  }
  return results;
}

function toLocation(value: unknown): TypestateLocationRef[] {
  if (value === null || typeof value !== "object") return [];
  const physical = (value as Record<string, unknown>).physicalLocation;
  if (physical === null || typeof physical !== "object") return [];
  const artifact = (physical as Record<string, unknown>).artifactLocation;
  const region = (physical as Record<string, unknown>).region;
  if (artifact === null || typeof artifact !== "object" || region === null || typeof region !== "object") return [];
  const file = (artifact as Record<string, unknown>).uri;
  const startLine = (region as Record<string, unknown>).startLine;
  const endLine = (region as Record<string, unknown>).endLine;
  if (typeof file !== "string" || file.length === 0 || typeof startLine !== "number" || !Number.isInteger(startLine) || startLine < 1) return [];
  return [{ file, start_line: startLine, ...(typeof endLine === "number" && Number.isInteger(endLine) && endLine >= startLine ? { end_line: endLine } : {}) }];
}

function successful(result: ProcessResult): boolean { return result.exitCode === 0 && result.signal === null && !result.cancelled && !result.timedOut; }
function firstLine(value: string): string | undefined { const line = sanitizeOutput(value).split(/\r?\n/)[0]?.trim(); return line === "" || line === undefined ? undefined : line; }
function processFailure(result: ProcessResult, stage: string): DomainError {
  if (result.cancelled) return new DomainError("PROCESS_CANCELLED", "process", `Typestate CodeQL ${stage} was cancelled`, false);
  if (result.timedOut) return new DomainError("PROCESS_TIMEOUT", "process", `Typestate CodeQL ${stage} timed out`, true);
  if (/not found|enoent/i.test(`${result.stderr}\n${result.stdout}`)) return new DomainError("CODEQL_CLI_NOT_FOUND", "environment", "CodeQL CLI was not found", false);
  return new DomainError("PROCESS_CRASHED", "process", `Typestate CodeQL ${stage} failed`, true);
}
