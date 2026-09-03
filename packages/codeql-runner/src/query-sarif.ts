import type {
  QueryCandidate,
  QueryFlowEvidence,
  QueryLocation,
  QuerySemanticMatch,
} from "@autovul/contracts";

export function summarizeSarif(value: unknown): {
  result_count: number;
  code_flow_count: number;
  rule_ids: string[];
  locations: QueryLocation[];
  flow_evidence: QueryFlowEvidence[];
  semantic_matches: QuerySemanticMatch[];
} {
  if (typeof value !== "object" || value === null) {
    return { result_count: 0, code_flow_count: 0, rule_ids: [], locations: [], flow_evidence: [], semantic_matches: [] };
  }
  const root = value as Record<string, unknown>;
  const runs = Array.isArray(root.runs) ? root.runs : [];
  const results: unknown[] = [];
  for (const run of runs) {
    if (typeof run !== "object" || run === null) {
      continue;
    }
    const runResults = (run as Record<string, unknown>).results;
    if (Array.isArray(runResults)) {
      results.push(...runResults);
    }
  }
  const ruleIds = new Set<string>();
  const semanticMatches = new Map<string, QuerySemanticMatch>();
  const locations: QueryLocation[] = [];
  const flowEvidence: QueryFlowEvidence[] = [];
  let codeFlowCount = 0;
  for (const result of results) {
    if (typeof result !== "object" || result === null) {
      continue;
    }
    const record = result as Record<string, unknown>;
    const flowEvidenceStart = flowEvidence.length;
    if (typeof record.ruleId === "string" && record.ruleId.length > 0) {
      ruleIds.add(record.ruleId);
    }
    if (Array.isArray(record.codeFlows) && record.codeFlows.length > 0) {
      codeFlowCount += 1;
      for (const codeFlow of record.codeFlows) {
        const path: QueryLocation[] = [];
        const messages: Array<{ label: string; location: QueryLocation }> = [];
        if (typeof codeFlow === "object" && codeFlow !== null) {
          const threads = (codeFlow as Record<string, unknown>).threadFlows;
          if (Array.isArray(threads)) {
            for (const thread of threads) {
              if (typeof thread !== "object" || thread === null) {
                continue;
              }
              const flowLocations = (thread as Record<string, unknown>).locations;
              if (!Array.isArray(flowLocations)) {
                continue;
              }
              for (const flowLocation of flowLocations) {
                if (typeof flowLocation !== "object" || flowLocation === null) {
                  continue;
                }
                const flowRecord = flowLocation as Record<string, unknown>;
                const parsed = parseLocation(flowRecord.location ?? flowLocation);
                if (parsed === undefined) {
                  continue;
                }
                path.push(parsed);
                const message = flowRecord.message;
                if (typeof message === "object" && message !== null && typeof (message as Record<string, unknown>).text === "string") {
                  messages.push({ label: (message as Record<string, unknown>).text as string, location: parsed });
                }
              }
            }
          }
        }
        const evidence: QueryFlowEvidence = {
          path,
          ...(path[0] === undefined ? {} : { source: path[0] }),
          ...(path[path.length - 1] === undefined ? {} : { sink: path[path.length - 1] }),
        };
        flowEvidence.push(evidence);
        for (const item of messages) {
          const normalized = item.label.trim();
          if (normalized.length === 0) {
            continue;
          }
          const lower = normalized.toLowerCase();
          const role = lower.includes("sink") ? "sink" : lower.includes("source") ? "source" : "message";
          const key = `${role}:${normalized}`;
          const previous = semanticMatches.get(key);
          semanticMatches.set(key, {
            role,
            label: normalized,
            locations: [...(previous?.locations ?? []), item.location],
          });
        }
      }
    }
    const resultLocations = record.locations;
    const parsedResultLocations: QueryLocation[] = [];
    if (Array.isArray(resultLocations)) {
      for (const location of resultLocations) {
        const parsed = parseLocation(location);
        if (parsed !== undefined) {
          locations.push(parsed);
          parsedResultLocations.push(parsed);
        }
      }
    }
    if (parsedResultLocations[0] !== undefined) {
      for (let index = flowEvidenceStart; index < flowEvidence.length; index += 1) {
        const evidence = flowEvidence[index];
        if (evidence !== undefined) {
          flowEvidence[index] = { ...evidence, result_location: parsedResultLocations[0] };
        }
      }
    }
  }
  return {
    result_count: results.length,
    code_flow_count: codeFlowCount,
    rule_ids: [...ruleIds].sort(),
    locations,
    flow_evidence: flowEvidence,
    semantic_matches: [...semanticMatches.values()].sort((left, right) => left.label.localeCompare(right.label)),
  };
}

export function synthesizeDirectStructuredFlow(
  summary: ReturnType<typeof summarizeSarif>,
  candidate: QueryCandidate,
): ReturnType<typeof summarizeSarif> {
  if (summary.code_flow_count > 0 || summary.result_count === 0 || summary.locations.length === 0) {
    return summary;
  }
  const intent = candidate.intent;
  const probe = candidate.probe_evidence;
  if (intent === undefined
    || probe?.status !== "passed"
    || (intent.language !== "c" && intent.language !== "cpp")
    || intent.source.kind !== "property"
    || intent.sink.kind !== "call"
    || intent.sink.argument_index !== 1) {
    return summary;
  }
  const direct = summary.locations.find((location) => probe.source.locations.some((expected) => sameLocation(expected, location))
    && probe.sink.locations.some((expected) => sameLocation(expected, location)));
  if (direct === undefined) {
    return summary;
  }
  return {
    ...summary,
    code_flow_count: 1,
    flow_evidence: [{ path: [direct], path_kind: "direct", source: direct, sink: direct, result_location: direct }],
  };
}

function sameLocation(left: { file: string; start_line: number }, right: { file: string; start_line: number }): boolean {
  const normalize = (value: string): string => value.replace(/^file:\/\//, "").replaceAll("\\", "/").replace(/^\.\//, "");
  const expected = normalize(left.file);
  const actual = normalize(right.file);
  return (expected === actual || (expected.includes("/") && actual.endsWith(`/${expected}`)))
    && left.start_line === right.start_line;
}

function parseLocation(value: unknown): QueryLocation | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const physical = (value as Record<string, unknown>).physicalLocation;
  if (typeof physical !== "object" || physical === null) {
    return undefined;
  }
  const artifact = (physical as Record<string, unknown>).artifactLocation;
  const region = (physical as Record<string, unknown>).region;
  if (typeof artifact !== "object" || artifact === null || typeof region !== "object" || region === null) {
    return undefined;
  }
  const uri = (artifact as Record<string, unknown>).uri;
  const startLine = (region as Record<string, unknown>).startLine;
  if (typeof uri !== "string" || typeof startLine !== "number" || !Number.isInteger(startLine) || startLine < 1) {
    return undefined;
  }
  const startColumn = (region as Record<string, unknown>).startColumn;
  const endLine = (region as Record<string, unknown>).endLine;
  const endColumn = (region as Record<string, unknown>).endColumn;
  return {
    file: uri,
    start_line: startLine,
    ...(typeof startColumn === "number" && Number.isInteger(startColumn) && startColumn > 0 ? { start_column: startColumn } : {}),
    ...(typeof endLine === "number" && Number.isInteger(endLine) && endLine > 0 ? { end_line: endLine } : {}),
    ...(typeof endColumn === "number" && Number.isInteger(endColumn) && endColumn > 0 ? { end_column: endColumn } : {}),
  };
}


