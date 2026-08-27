/**
 * Diagnostic-only CLI feedback-loop generator. Round one has valid
 * Source/Sink probes but a sanitizer that blocks the observed flow; round two
 * removes it after the evaluator returns the authoritative CLI repair brief.
 */
const input = JSON.parse(await readStdin());
const source = input?.source_context?.files?.find((file) => file?.path?.endsWith("/app.py"));
if (input?.language !== "python" || typeof source?.content !== "string"
  || !/os\.getenv\s*\(/.test(source.content) || !/os\.system\s*\(/.test(source.content)) {
  throw new Error("DIAGNOSTIC_CLI_REPAIR_SOURCE_PATTERN_NOT_FOUND");
}

const round = Number.isInteger(input.round) ? input.round : 1;
const intent = {
  schema_version: "v2.contracts/1",
  intent_id: "diagnostic-python-command-injection-cli-repair",
  language: "python",
  cwe: "CWE-078",
  query_kind: "path-problem",
  flow_mode: "taint",
  source: { kind: "environment", name: "getenv" },
  sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
  message: "Environment-controlled command reaches os.system.",
  ...(round === 1 ? { sanitizer: [{ kind: "call", module: "os", member: "getenv" }] } : {}),
};
process.stdout.write(JSON.stringify({
  candidate: {
    candidate_id: `diagnostic-cli-repair-${round}`,
    query_id: `diagnostic-cli-repair-${round}`,
    intent,
    rationale: round === 1 ? "Initial candidate for CLI feedback." : "Repaired after authoritative CLI feedback.",
  },
  metadata: {
    provider: "diagnostic-fixture",
    model: "deterministic-cli-repair-feedback",
    adapter_version: "m4-diagnostic-cli-repair/1",
    parameters: { invalid_first_round: true, failure_stage: "vulnerable-flow" },
    usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 },
  },
}));

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}
