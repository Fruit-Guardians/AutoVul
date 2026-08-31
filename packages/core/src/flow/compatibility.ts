import type { FlowEndpoint, FlowModel, TaintLocationConstraint, TaintMatcher, TaintQueryIntent } from "@autovul/contracts";
import { DomainError, FLOW_HYPOTHESIS_VERSION } from "@autovul/contracts";

export interface LegacyFlowCompatibilityContext {
  readonly cwe: string;
  readonly message: string;
  readonly description?: string;
  readonly rationale?: string;
  readonly evidence_refs?: readonly string[];
  readonly variant?: "exact" | "semantic";
}

export interface LegacyFlowProjection {
  readonly model: FlowModel;
  readonly context: LegacyFlowCompatibilityContext;
}

/**
 * Preserve query semantics while separating presentation metadata from the
 * analyzer-independent Flow hypothesis.  A legacy self-edge remains explicit
 * so the projection is deterministic and reversible at the semantic level.
 */
export function projectTaintIntentToFlow(intent: TaintQueryIntent): LegacyFlowProjection {
  const source = endpointWithLocation(intent.source, intent.source_location, "/source");
  const sink = endpointWithLocation(intent.sink, intent.sink_location, "/sink");
  return {
    model: {
      schema_version: FLOW_HYPOTHESIS_VERSION,
      model_id: intent.intent_id,
      language: intent.language,
      flow_mode: intent.flow_mode,
      source,
      sink,
      ...(intent.additional_flow === undefined && intent.additional_flow_steps === undefined ? {} : {
        steps: [
          ...(intent.additional_flow ?? []).map((endpoint) => ({ from: endpoint as FlowEndpoint, to: endpoint as FlowEndpoint })),
          ...(intent.additional_flow_steps ?? []).map((step) => ({ from: step.from as FlowEndpoint, to: step.to as FlowEndpoint })),
        ],
      }),
      ...(intent.sanitizer === undefined ? {} : { barriers: intent.sanitizer.map((endpoint) => ({ endpoint: endpoint as FlowEndpoint })) }),
    },
    context: {
      cwe: intent.cwe,
      message: intent.message,
      ...(intent.description === undefined ? {} : { description: intent.description }),
      ...(intent.rationale === undefined ? {} : { rationale: intent.rationale }),
      ...(intent.evidence_refs === undefined ? {} : { evidence_refs: intent.evidence_refs }),
      ...(intent.variant === undefined ? {} : { variant: intent.variant }),
    },
  };
}

/**
 * Adapter-facing projection for the already verified CodeQL language packs.
 * Flow presentation fields are deliberately replaced by stable compatibility
 * metadata; no Flow semantic is dropped.
 */
export function projectFlowToTaintIntent(model: FlowModel): TaintQueryIntent {
  const source = matcherFromEndpoint(model.source);
  const sink = matcherFromEndpoint(model.sink);
  const sourceLocation = locationFromEndpoint(model.source);
  const sinkLocation = locationFromEndpoint(model.sink);
  return {
    schema_version: "v2.contracts/1", intent_id: model.model_id, language: model.language, cwe: "CWE-20", query_kind: "path-problem", flow_mode: model.flow_mode,
    source, sink, message: `AutoVul Flow ${model.model_id}`,
    ...(sourceLocation === undefined ? {} : { source_location: sourceLocation }),
    ...(sinkLocation === undefined ? {} : { sink_location: sinkLocation }),
    ...(model.steps === undefined ? {} : { additional_flow_steps: model.steps.map((step) => ({ from: matcherFromEndpoint(step.from), to: matcherFromEndpoint(step.to) })) }),
    ...(model.barriers === undefined ? {} : { sanitizer: model.barriers.map((barrier) => matcherFromEndpoint(barrier.endpoint)) }),
  };
}

function endpointWithLocation(matcher: TaintMatcher, location: TaintLocationConstraint | undefined, path: string): FlowEndpoint {
  if (location === undefined) return matcher as FlowEndpoint;
  const result: Record<string, unknown> = { ...matcher };
  for (const [key, value] of Object.entries(location)) {
    if (value === undefined) continue;
    if (result[key] !== undefined && result[key] !== value) {
      throw new DomainError("INTENT_INVALID", "input", `Legacy location conflicts with matcher selector at ${path}/${key}`, false, { path: `${path}/${key}` });
    }
    result[key] = value;
  }
  return result as FlowEndpoint;
}

function matcherFromEndpoint(endpoint: FlowEndpoint): TaintMatcher {
  const { start_line: _start, end_line: _end, ...matcher } = endpoint;
  return matcher as TaintMatcher;
}

function locationFromEndpoint(endpoint: FlowEndpoint): TaintLocationConstraint | undefined {
  const location = {
    ...(endpoint.file === undefined ? {} : { file: endpoint.file }),
    ...(endpoint.symbol === undefined ? {} : { symbol: endpoint.symbol }),
    ...(endpoint.start_line === undefined ? {} : { start_line: endpoint.start_line }),
    ...(endpoint.end_line === undefined ? {} : { end_line: endpoint.end_line }),
  };
  return Object.keys(location).length === 0 ? undefined : location;
}
